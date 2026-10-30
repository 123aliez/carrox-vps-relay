// nginx conf rendering + syntax check + reload.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	templatePath    = "/opt/vps-relay/templates/site.conf.tmpl"
	nginxPidPath    = "/usr/local/nginx/logs/nginx.pid"
	hostNginxConf   = "/usr/local/nginx/conf/nginx.conf"
	hostNginxPrefix = "/usr/local/nginx"
	// 宿主 Nginx 静态编译了 stream，容器内的 Alpine Nginx 是动态模块，要显式加载才能解析 stream 块。
	streamModulePath = "/usr/lib/nginx/modules/ngx_stream_module.so"
)

type renderCtx struct {
	Domain         string
	Upstream       string
	UpstreamScheme string
	UpstreamHost   string
	UpstreamPort   int
	UpstreamIsIP   bool
	Owner          string
	CFZone         string
	CFRecordID     string
	CFRecordIDV6   string
	CreatedUTC     string
	MetaJSON       string
}

func parseUpstream(raw string) (scheme, host string, port int, isIP bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, false, fmt.Errorf("upstream URL invalid: %w", err)
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", 0, false, fmt.Errorf("upstream scheme must be http/https, got %q", scheme)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", 0, false, fmt.Errorf("upstream host empty")
	}
	portStr := u.Port()
	if portStr == "" {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	} else {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return "", "", 0, false, fmt.Errorf("upstream port invalid: %q", portStr)
		}
		port = p
	}
	isIP = net.ParseIP(host) != nil
	return
}

func renderSite(meta SiteMeta) ([]byte, error) {
	return renderSiteWithTemplate(meta, templatePath)
}

func renderSiteWithTemplate(meta SiteMeta, path string) ([]byte, error) {
	scheme, host, port, isIP, err := parseUpstream(meta.Upstream)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	ctx := renderCtx{
		Domain:         meta.Domain,
		Upstream:       meta.Upstream,
		UpstreamScheme: scheme,
		UpstreamHost:   host,
		UpstreamPort:   port,
		UpstreamIsIP:   isIP,
		Owner:          meta.Owner,
		CFZone:         meta.CFZone,
		CFRecordID:     meta.CFRecordID,
		CFRecordIDV6:   meta.CFRecordIDV6,
		CreatedUTC:     meta.Created,
		MetaJSON:       string(mustJSON(meta)),
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return buf.Bytes(), nil
}

// confPath returns the (enabled) on-disk path for a managed site.
func confPath(domain string) string {
	return filepath.Join(confDir, "relay-"+domain+".conf")
}

// nginxSyntaxCheck runs `nginx -t` against the *full* host nginx config tree
// (with the new file already in place). We use the alpine `nginx` binary that
// the container image ships; it parses the same set of directives we use in
// templates so this is a sound syntax gate.
func nginxSyntaxCheck() error {
	ctx, cancel := contextWithTimeout(8 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx,
		"nginx", "-p", hostNginxPrefix, "-c", hostNginxConf,
		"-g", "load_module "+streamModulePath+";", "-t",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %v\n%s", err, string(out))
	}
	return nil
}

// nginxReload sends SIGHUP to the host nginx master via its pid file.
func nginxReload() error {
	b, err := os.ReadFile(nginxPidPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", nginxPidPath, err)
	}
	pidStr := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("parse pid %q: %w", pidStr, err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(syscallSIGHUP)
}

// contextWithTimeout is a tiny shim so test code can swap context implementations.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
