// Site model: scan nginx conf.d for files this tool manages, probe their
// liveness, and expose the result as a list ready for the API.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var confDir = "/usr/local/nginx/conf/conf.d"

const (
	sslDir    = "/usr/local/nginx/conf/ssl"
	relayHead = "# ====== vps-relay managed: DO NOT HAND EDIT ======"
)

// On-disk JSON header stored in the conf file: every byte of authoritative
// state we keep (cf record ids, original upstream, creation timestamp).
type SiteMeta struct {
	Reality          *RealityMeta `json:"reality,omitempty"`
	V                int          `json:"v"`
	Domain           string       `json:"domain"`
	Upstream         string       `json:"upstream"`
	Owner            string       `json:"owner,omitempty"`
	CFZone           string       `json:"cf_zone"`
	CFRecordID       string       `json:"cf_record_id"`
	CFRecordIDV6     string       `json:"cf_record_id_v6,omitempty"`
	Created          string       `json:"created"`
	DNS              *DNSChange   `json:"dns,omitempty"`
	CertificateOwned bool         `json:"certificate_owned,omitempty"`
}

// Site is what the API returns: meta + runtime probes.
type Site struct {
	SiteMeta

	RealityError    string `json:"reality_error,omitempty"`
	RealityPaused   bool   `json:"reality_paused,omitempty"`
	Enabled         bool   `json:"enabled"`
	DeletionPending bool   `json:"deletion_pending,omitempty"`
	ConfPath        string `json:"-"`
	CertNotAfter    string `json:"cert_not_after,omitempty"`
	CertDaysLeft    int    `json:"cert_days_left"`
	DNSResolvedTo   string `json:"dns_resolved_to,omitempty"`
	UpstreamOK      bool   `json:"upstream_ok"`
	EdgeOK          bool   `json:"edge_ok"`
}

var metaRE = regexp.MustCompile(`#\s*relay-meta:\s*(\{.*\})`)

func scanSites(keyID string, isAdmin bool) ([]Site, []string, error) {
	enabled, err := filepath.Glob(filepath.Join(confDir, "relay-*.conf"))
	if err != nil {
		return nil, nil, err
	}
	disabled, err := filepath.Glob(filepath.Join(confDir, "relay-*.conf.disabled"))
	if err != nil {
		return nil, nil, err
	}
	pending, err := filepath.Glob(filepath.Join(confDir, "relay-*.conf*.relay-delete.bak"))
	if err != nil {
		return nil, nil, err
	}
	// 隔离的删除备份仍列在面板，支持清理失败或进程中断后重试。
	files := append(append(filterPanel(enabled), filterPanel(disabled)...), filterPanel(pending)...)

	var (
		out  []Site
		warn []string
		wg   sync.WaitGroup
		mu   sync.Mutex
	)
	for _, fp := range files {
		fp := fp
		meta, err := readSiteMeta(fp)
		if err != nil {
			warn = append(warn, fmt.Sprintf("%s: %v", filepath.Base(fp), err))
			continue
		}
		// Ownership filter: admin sees all; user sees only their own sites.
		// Sites without an owner field are treated as admin-owned.
		if !isAdmin {
			if meta.Reality != nil {
				continue
			}
			owner := meta.Owner
			if owner == "" {
				owner = "admin"
			}
			if owner != keyID {
				continue
			}
		}
		deleting := strings.HasSuffix(fp, ".relay-delete.bak")
		if deleting {
			warn = append(warn, meta.Domain+" 删除尚未完成，请再次删除重试")
		}
		s := Site{SiteMeta: meta, ConfPath: fp, Enabled: !strings.HasSuffix(fp, ".disabled") && !deleting, DeletionPending: deleting}
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeSite(&s)
			mu.Lock()
			out = append(out, s)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out, warn, nil
}

func filterPanel(in []string) []string {
	out := in[:0]
	for _, p := range in {
		name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(p), ".relay-delete.bak"), ".disabled")
		if name == "relay-panel.conf" || name == sniDefaultName {
			continue
		}
		out = append(out, p)
	}
	return out
}

func readSiteMeta(path string) (SiteMeta, error) {
	var m SiteMeta
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	// Only scan first 20 lines.
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	head := string(buf[:n])
	mt := metaRE.FindStringSubmatch(head)
	if len(mt) < 2 {
		return m, fmt.Errorf("missing relay-meta header")
	}
	if err := json.Unmarshal([]byte(mt[1]), &m); err != nil {
		return m, fmt.Errorf("invalid relay-meta JSON: %w", err)
	}
	if m.Domain == "" {
		return m, fmt.Errorf("relay-meta.domain is empty")
	}
	return m, nil
}

func probeSite(s *Site) {
	// Cert
	if not, days, err := certInfo(s.Domain); err == nil {
		s.CertNotAfter = not
		s.CertDaysLeft = days
	}
	// DNS
	if ip := dnsResolve(s.Domain); ip != "" {
		s.DNSResolvedTo = ip
	}
	// Upstream
	if s.Reality != nil {
		if realityModeOf(s.Reality) == realityModeDirect {
			// direct 无上游可拨测；true 表示“不构成上游故障”，不代表公网连通性已验证。
			s.UpstreamOK = true
		} else {
			s.UpstreamOK = tcpDial(net.JoinHostPort(s.Reality.UpstreamHost, fmt.Sprint(s.Reality.UpstreamPort)), 3*time.Second)
		}
	} else {
		s.UpstreamOK = httpReachable(s.Upstream, 3*time.Second)
	}
	// Edge
	s.EdgeOK = httpReachable("https://"+s.Domain+"/", 3*time.Second)
}

func certInfo(domain string) (notAfter string, daysLeft int, err error) {
	out, err := exec.Command(
		"openssl", "x509", "-in",
		filepath.Join(sslDir, domain, "fullchain.pem"),
		"-noout", "-enddate",
	).Output()
	if err != nil {
		return "", 0, err
	}
	line := strings.TrimSpace(string(out))
	// notAfter=Jul 16 15:55:30 2026 GMT
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", 0, fmt.Errorf("unexpected openssl output: %q", line)
	}
	val := strings.TrimSpace(line[idx+1:])
	t, err := time.Parse("Jan 2 15:04:05 2006 MST", val)
	if err != nil {
		return val, 0, err
	}
	return t.UTC().Format(time.RFC3339), int(time.Until(t).Hours() / 24), nil
}

func dnsResolve(domain string) string {
	out, err := exec.Command("dig", "+short", "+time=2", "@1.1.1.1", domain, "A").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if net.ParseIP(line) != nil {
			return line
		}
	}
	return ""
}

var probeClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:       nil, // default; we don't pin
		ResponseHeaderTimeout: 3 * time.Second,
	},
}

func httpReachable(rawURL string, timeout time.Duration) bool {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	req.Header.Set("User-Agent", "vps-relay-probe/1.0")
	res, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	// Treat any HTTP response (including 4xx/5xx) as "TCP/TLS reachable".
	return res.StatusCode > 0
}
