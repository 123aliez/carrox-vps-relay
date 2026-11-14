// nginx conf rendering + syntax check + reload.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	SNI443         bool
	Domain         string
	Upstream       string
	UpstreamScheme string
	UpstreamHost   string
	UpstreamAddr   string // host 为 IPv6 字面量时带方括号，仅用于 proxy_pass
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
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return "", "", 0, false, errors.New("上游地址只能包含协议、主机和端口，不支持路径或参数")
	}
	host = u.Hostname()
	if host == "" {
		return "", "", 0, false, fmt.Errorf("upstream host empty")
	}
	if !validUpstreamHost(host) {
		return "", "", 0, false, errors.New("上游主机名无效，只能是域名或 IP")
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

var upstreamLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// validUpstreamHost 只接受 IP 字面量或严格的 DNS 名称（允许单标签，不允许末尾点）。
func validUpstreamHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 || !upstreamLabelRE.MatchString(strings.ToLower(label)) {
			return false
		}
	}
	return true
}

// upstreamAddr 在 IPv6 字面量外加方括号，其余原样返回。
func upstreamAddr(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func renderSite(meta SiteMeta) ([]byte, error) {
	on, err := sniMode(liveSNIPaths(), liveRelayFS())
	if err != nil {
		return nil, err
	}
	return renderSiteMode(meta, filepath.Dir(templatePath), on)
}

func renderSiteMode(meta SiteMeta, dir string, sni bool) ([]byte, error) {
	name := "site.conf.tmpl"
	if meta.Reality != nil {
		name = "reality.conf.tmpl"
	}
	return renderSiteTemplateMode(meta, filepath.Join(dir, name), sni)
}

func renderSiteWithTemplate(meta SiteMeta, path string) ([]byte, error) {
	return renderSiteTemplateMode(meta, path, false)
}

func renderSiteTemplateMode(meta SiteMeta, path string, sni bool) ([]byte, error) {
	// Reality 站点的 upstream 仅在 relay-meta JSON 中保留展示（direct 模式无上游），
	// 模板不消费它，跳过解析避免 direct 的空 upstream 阻断渲染。
	scheme, host, port, isIP := "", "", 0, false
	if meta.Reality == nil {
		var err error
		scheme, host, port, isIP, err = parseUpstream(meta.Upstream)
		if err != nil {
			return nil, err
		}
	}
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	ctx := renderCtx{
		SNI443:         sni,
		Domain:         meta.Domain,
		Upstream:       meta.Upstream,
		UpstreamScheme: scheme,
		UpstreamHost:   host,
		UpstreamAddr:   upstreamAddr(host),
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
	if err := syncSNI443(); err != nil {
		return err
	}
	return nginxSyntaxCheckRaw()
}

func nginxSyntaxCheckRaw() error {
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
	return nginxReloadWith(nginxSyntaxCheck, nginxReloadRaw, applyXrayRuntime, log.Print)
}

// HUP 成功后不能向普通配置事务报告失败，Xray 的失败由托管进程退避恢复。
func nginxReloadWith(syncConfig, hup, apply func() error, report func(...any)) error {
	if err := syncConfig(); err != nil {
		return err
	}
	if err := hup(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		var failure *xrayApplyFailure
		if errors.As(err, &failure) && failure.submitted {
			report("警告：Nginx 已重载，Xray 监督器已接收配置，正在退避重试：", err)
		} else {
			report("警告：Nginx 已重载，Xray 配置尚未提交；面板服务运行时每 30 秒对账补偿：", err)
		}
	}
	return nil
}

func nginxReloadRaw() error {
	b, err := os.ReadFile(nginxPidPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", nginxPidPath, err)
	}
	pidStr := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("parse pid %q: %w", pidStr, err)
	}
	if pid <= 1 {
		return fmt.Errorf("Nginx master PID 无效")
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

// 面板的传统模板继续供安装脚本逐字替换，SNI 模板只由 Go 渲染。
func renderPanel(domain, dir string, sni bool) ([]byte, error) {
	name := "panel-ssl.conf.tmpl"
	if sni {
		name = "panel-sni.conf.tmpl"
	}
	tmpl, err := template.ParseFiles(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, struct{ Domain string }{domain})
	return out.Bytes(), err
}

// 还原站点后恢复 Nginx 和 Xray，使已完成的部分重载也能回退。
func restoreRelayRuntime() error {
	return nginxReload()
}
