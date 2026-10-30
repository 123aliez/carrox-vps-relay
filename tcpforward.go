// 四层 TCP 转发：Nginx stream 原样转发字节、不解 TLS，用于 Reality 等不能走七层反代的节点。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	streamDir       = "/usr/local/nginx/conf/stream.d"
	tcpTemplatePath = "/opt/vps-relay/templates/tcp.conf.tmpl"
	// 导出的链接含节点凭据，不放进 Nginx 配置目录。
	tcpLinkDir = "/etc/vps-relay/tcp-links"

	tcpPortMin     = 1024
	tcpPortMax     = 65535
	tcpAutoPortMin = 20000
	tcpAutoPortMax = 29999
	tcpLabelMax    = 64
	tcpLinkMax     = 2048

	tcpDeleteSuffix = ".relay-delete.bak"

	// Nginx 重载时 bind 失败会重试约 2.5 秒，其间目标端口可能短暂打开，稳定时间要超过它。
	tcpPortStable  = 3 * time.Second
	tcpPortTimeout = 10 * time.Second
)

// TCPForwardMeta 存在配置文件的 relay-meta 注释里，不含任何凭据。
type TCPForwardMeta struct {
	V            int    `json:"v"`
	ListenPort   int    `json:"listen_port"`
	UpstreamHost string `json:"upstream_host"`
	UpstreamPort int    `json:"upstream_port"`
	Label        string `json:"label,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Created      string `json:"created"`
}

// TCPForward 是 API 返回的元数据加运行时探测结果。
type TCPForward struct {
	TCPForwardMeta

	HasLink         bool `json:"has_link"`
	Listening       bool `json:"listening"`
	UpstreamOK      bool `json:"upstream_ok"`
	DeletionPending bool `json:"deletion_pending,omitempty"`
}

var streamIncludeRE = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+\S*stream\.d/\*\.conf[ \t]*;`)

func tcpConfPath(port int) string {
	return filepath.Join(streamDir, fmt.Sprintf("relay-tcp-%d.conf", port))
}

func tcpLinkPath(port int) string {
	return filepath.Join(tcpLinkDir, fmt.Sprintf("%d.link", port))
}

// streamEnabled 判断宿主 nginx.conf 是否已引入 stream.d。
func streamEnabled(conf []byte) bool {
	return streamIncludeRE.Match(conf)
}

// parseRealityLink 校验 VLESS + Reality 链接并返回原节点地址。
// 链接含凭据，错误信息一律不回显原文（url.Parse 的错误会带上原文）。
func parseRealityLink(raw string) (string, int, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, errors.New("节点链接格式无效")
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return "", 0, errors.New("只支持 vless:// 链接")
	}
	if u.User == nil || u.User.Username() == "" {
		return "", 0, errors.New("节点链接缺少 UUID")
	}
	q := u.Query()
	if !strings.EqualFold(q.Get("security"), "reality") {
		return "", 0, errors.New("只支持 security=reality 的节点")
	}
	if q.Get("sni") == "" || q.Get("pbk") == "" {
		return "", 0, errors.New("节点链接缺少 sni 或 pbk")
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if host == "" || err != nil || port < 1 || port > tcpPortMax {
		return "", 0, errors.New("节点链接缺少有效的地址或端口")
	}
	return host, port, nil
}

// rewriteRealityLink 只替换地址和端口，查询参数原样保留。
func rewriteRealityLink(raw, edge string, port int, label string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("节点链接格式无效")
	}
	name := label
	if name == "" {
		name = "relay"
		if u.Fragment != "" {
			name = u.Fragment + "-relay"
		}
	}
	u.Host = net.JoinHostPort(edge, strconv.Itoa(port))
	u.Fragment = name
	u.RawFragment = ""
	return u.String(), nil
}

// parseTCPUpstream 解析手填的 IP:端口。
func parseTCPUpstream(raw string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, errors.New("上游格式应为 IP:端口")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, errors.New("上游端口无效")
	}
	return host, port, nil
}

// validateTCPUpstream 只接受公网 IP：上游写域名时，一旦解析失败，Nginx 全局重载都会失败。
func validateTCPUpstream(host string, port int, edge string) error {
	if port < 1 || port > tcpPortMax {
		return errors.New("上游端口无效")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("上游必须是 IP 地址，不支持域名")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return errors.New("上游不能是内网或保留地址")
	}
	if ip.Equal(net.ParseIP(edge)) {
		return errors.New("上游不能是中转机自身")
	}
	return nil
}

func validateTCPListenPort(port int) error {
	if port < tcpPortMin || port > tcpPortMax {
		return fmt.Errorf("入口端口须在 %d-%d 之间", tcpPortMin, tcpPortMax)
	}
	return nil
}

func validateTCPLabel(label string) error {
	if utf8.RuneCountInString(label) > tcpLabelMax {
		return fmt.Errorf("备注不能超过 %d 个字符", tcpLabelMax)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return errors.New("备注不能包含控制字符")
		}
	}
	return nil
}

func renderTCPForward(meta TCPForwardMeta) ([]byte, error) {
	return renderTCPForwardWithTemplate(meta, tcpTemplatePath)
}

func renderTCPForwardWithTemplate(meta TCPForwardMeta, path string) ([]byte, error) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"ListenPort": meta.ListenPort,
		"Upstream":   net.JoinHostPort(meta.UpstreamHost, strconv.Itoa(meta.UpstreamPort)),
		"MetaJSON":   mustJSON(meta),
	})
	if err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return buf.Bytes(), nil
}

func readTCPMeta(path string) (TCPForwardMeta, error) {
	var meta TCPForwardMeta
	b, err := os.ReadFile(path)
	if err != nil {
		return meta, err
	}
	m := metaRE.FindSubmatch(b)
	if m == nil {
		return meta, fmt.Errorf("%s 缺少 relay-meta", path)
	}
	if err := json.Unmarshal(m[1], &meta); err != nil {
		return meta, fmt.Errorf("%s 元数据无效: %w", path, err)
	}
	return meta, nil
}

func tcpDial(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func tcpPortListening(port int) bool {
	return tcpDial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
}

// waitTCPPort 等待重载生效：SIGHUP 是异步的，宿主 Nginx 拒绝新配置时也不会报错，只能看端口。
func waitTCPPort(port int, want bool) error {
	return waitTCPPortFor(port, want, tcpPortStable, tcpPortTimeout)
}

func waitTCPPortFor(port int, want bool, stable, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var since time.Time
	for {
		if tcpPortListening(port) == want {
			if since.IsZero() {
				since = time.Now()
			}
			if time.Since(since) >= stable {
				return nil
			}
		} else {
			since = time.Time{}
		}
		if time.Now().After(deadline) {
			if want {
				return fmt.Errorf("端口 %d 未开始监听，宿主 Nginx 可能拒绝了新配置", port)
			}
			return fmt.Errorf("端口 %d 仍在监听，宿主 Nginx 可能拒绝了新配置", port)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// tcpPortAvailable 检查端口未被托管配置或其他进程占用。
func tcpPortAvailable(port int) error {
	for _, path := range []string{tcpConfPath(port), tcpConfPath(port) + tcpDeleteSuffix} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return fmt.Errorf("端口 %d 已有转发", port)
		}
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("端口 %d 已被占用", port)
	}
	_ = ln.Close()
	return nil
}

func allocateTCPPort() (int, error) {
	span := tcpAutoPortMax - tcpAutoPortMin + 1
	start := rand.Intn(span)
	for i := 0; i < span; i++ {
		port := tcpAutoPortMin + (start+i)%span
		if tcpPortAvailable(port) == nil {
			return port, nil
		}
	}
	return 0, errors.New("没有可用的入口端口")
}

type tcpLifecycle struct {
	render     func(TCPForwardMeta) ([]byte, error)
	write      func(string, []byte, os.FileMode) error
	remove     func(string) error
	rename     func(string, string) error
	check      func() error
	reload     func() error
	waitPort   func(int, bool) error
	writeLink  func(int, string) error
	removeLink func(int) error
}

func liveTCPLifecycle() tcpLifecycle {
	return tcpLifecycle{
		render: renderTCPForward,
		write: func(path string, data []byte, mode os.FileMode) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			return atomicWrite(path, data, mode)
		},
		remove: os.Remove, rename: os.Rename,
		check: nginxSyntaxCheck, reload: nginxReload, waitPort: waitTCPPort,
		writeLink: func(port int, link string) error {
			if err := os.MkdirAll(tcpLinkDir, 0o700); err != nil {
				return err
			}
			return atomicWrite(tcpLinkPath(port), []byte(link), 0o600)
		},
		removeLink: func(port int) error {
			if err := os.Remove(tcpLinkPath(port)); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
	}
}

func provisionTCPForward(meta TCPForwardMeta, link string, ops tcpLifecycle) error {
	rendered, err := ops.render(meta)
	if err != nil {
		return err
	}
	path := tcpConfPath(meta.ListenPort)
	configWritten := false
	reloaded := false
	rollback := func(cause error) error {
		if configWritten {
			cause = errors.Join(cause, ops.remove(path))
		}
		if reloaded {
			cause = errors.Join(cause, ops.reload(), ops.waitPort(meta.ListenPort, false))
		}
		if link != "" {
			cause = errors.Join(cause, ops.removeLink(meta.ListenPort))
		}
		return cause
	}
	if link != "" {
		if err := ops.writeLink(meta.ListenPort, link); err != nil {
			return fmt.Errorf("保存链接失败: %w", err)
		}
	}
	if err := ops.write(path, rendered, 0o644); err != nil {
		return rollback(fmt.Errorf("写入配置失败: %w", err))
	}
	configWritten = true
	if err := ops.check(); err != nil {
		return rollback(err)
	}
	if err := ops.reload(); err != nil {
		return rollback(fmt.Errorf("Nginx 重载失败: %w", err))
	}
	reloaded = true
	if err := ops.waitPort(meta.ListenPort, true); err != nil {
		return rollback(err)
	}
	return nil
}

// removeTCPForward 中 staged 表示上次删除已把配置移成备份，这次只是重试。
func removeTCPForward(port int, staged bool, ops tcpLifecycle) error {
	path := tcpConfPath(port)
	backup := path + tcpDeleteSuffix
	if !staged {
		if err := ops.rename(path, backup); err != nil {
			return fmt.Errorf("移除配置失败: %w", err)
		}
	}
	restore := func(cause error) error {
		if staged {
			return cause
		}
		return errors.Join(cause, ops.rename(backup, path))
	}
	if err := ops.check(); err != nil {
		return restore(err)
	}
	if err := ops.reload(); err != nil {
		return restore(fmt.Errorf("Nginx 重载失败: %w", err))
	}
	if err := ops.waitPort(port, false); err != nil {
		if staged {
			return err
		}
		// 重载没有生效，磁盘配置要和仍在运行的转发保持一致。
		return errors.Join(err, ops.rename(backup, path), ops.reload())
	}
	// 备份最后删：清理失败时它还在，面板能显示“删除未完成”并重试。
	if err := ops.removeLink(port); err != nil {
		return fmt.Errorf("转发已停止，清理链接失败，请再次删除重试: %w", err)
	}
	if err := ops.remove(backup); err != nil {
		return fmt.Errorf("转发已停止，清理配置备份失败，请再次删除重试: %w", err)
	}
	return nil
}

func scanTCPForwards() ([]TCPForward, []string, error) {
	paths, err := filepath.Glob(filepath.Join(streamDir, "relay-tcp-*.conf"))
	if err != nil {
		return nil, nil, err
	}
	pending, err := filepath.Glob(filepath.Join(streamDir, "relay-tcp-*.conf"+tcpDeleteSuffix))
	if err != nil {
		return nil, nil, err
	}
	forwards := make([]TCPForward, 0, len(paths)+len(pending))
	var warnings []string
	add := func(path string, deleting bool) {
		meta, err := readTCPMeta(path)
		if err != nil {
			warnings = append(warnings, err.Error())
			return
		}
		_, statErr := os.Stat(tcpLinkPath(meta.ListenPort))
		forwards = append(forwards, TCPForward{TCPForwardMeta: meta, HasLink: statErr == nil, DeletionPending: deleting})
	}
	for _, path := range paths {
		add(path, false)
	}
	for _, path := range pending {
		add(path, true)
	}
	var wg sync.WaitGroup
	for i := range forwards {
		wg.Add(1)
		go func(f *TCPForward) {
			defer wg.Done()
			f.Listening = tcpPortListening(f.ListenPort)
			f.UpstreamOK = tcpDial(net.JoinHostPort(f.UpstreamHost, strconv.Itoa(f.UpstreamPort)), 3*time.Second)
		}(&forwards[i])
	}
	wg.Wait()
	return forwards, warnings, nil
}

func hostStreamEnabled() bool {
	conf, err := os.ReadFile(hostNginxConf)
	return err == nil && streamEnabled(conf)
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if authIsAdmin(r) {
		return true
	}
	writeErr(w, http.StatusForbidden, "需要管理员权限")
	return false
}

func tcpForwardsList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	forwards, warnings, err := scanTCPForwards()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  hostStreamEnabled(),
		"forwards": forwards,
		"warnings": warnings,
	})
}

type tcpCreateReq struct {
	Link       string `json:"link"`
	Upstream   string `json:"upstream"`
	ListenPort int    `json:"listen_port"`
	Label      string `json:"label"`
}

func tcpForwardsCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
	var req tcpCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Link = strings.TrimSpace(req.Link)
	req.Upstream = strings.TrimSpace(req.Upstream)
	req.Label = strings.TrimSpace(req.Label)
	if (req.Link == "") == (req.Upstream == "") {
		writeErr(w, http.StatusBadRequest, "节点链接和上游地址必须且只能填一个")
		return
	}
	if len(req.Link) > tcpLinkMax {
		writeErr(w, http.StatusBadRequest, "节点链接过长")
		return
	}
	if err := validateTCPLabel(req.Label); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !hostStreamEnabled() {
		writeErr(w, http.StatusPreconditionFailed, "宿主 nginx.conf 未引入 stream.d/*.conf，无法创建 TCP 转发")
		return
	}
	edge := edgeIPv4()
	if net.ParseIP(edge) == nil {
		writeErr(w, http.StatusInternalServerError, "无法检测边缘 IPv4")
		return
	}

	var host string
	var upstreamPort int
	var err error
	if req.Link != "" {
		host, upstreamPort, err = parseRealityLink(req.Link)
	} else {
		host, upstreamPort, err = parseTCPUpstream(req.Upstream)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateTCPUpstream(host, upstreamPort, edge); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	port := req.ListenPort
	if port == 0 {
		if port, err = allocateTCPPort(); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	} else {
		if err := validateTCPListenPort(port); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := tcpPortAvailable(port); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	}

	var link string
	if req.Link != "" {
		if link, err = rewriteRealityLink(req.Link, edge, port, req.Label); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	meta := TCPForwardMeta{
		V: 1, ListenPort: port, UpstreamHost: host, UpstreamPort: upstreamPort,
		Label: req.Label, Owner: authKeyID(r), Created: time.Now().UTC().Format(time.RFC3339),
	}
	if err := provisionTCPForward(meta, link, liveTCPLifecycle()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"forward": TCPForward{TCPForwardMeta: meta, HasLink: link != "", Listening: true},
		"link":    link,
	})
}

// parseTCPPortParam 只接受纯数字，防止路径参数拼进文件路径。
func parseTCPPortParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || validateTCPListenPort(port) != nil {
		writeErr(w, http.StatusBadRequest, "端口无效")
		return 0, false
	}
	return port, true
}

func tcpForwardLink(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	port, ok := parseTCPPortParam(w, r)
	if !ok {
		return
	}
	b, err := os.ReadFile(tcpLinkPath(port))
	if os.IsNotExist(err) {
		writeErr(w, http.StatusNotFound, "该转发没有保存链接")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取链接失败")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"link": string(b)})
}

func tcpForwardsDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	port, ok := parseTCPPortParam(w, r)
	if !ok {
		return
	}
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
	staged := false
	if _, err := os.Stat(tcpConfPath(port)); os.IsNotExist(err) {
		if _, err := os.Stat(tcpConfPath(port) + tcpDeleteSuffix); err != nil {
			writeErr(w, http.StatusNotFound, "转发不存在")
			return
		}
		staged = true
	}
	if err := removeTCPForward(port, staged, liveTCPLifecycle()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": port})
}
