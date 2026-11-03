// Reality 入口与 SNI 迁移共用的链接、端口及权限检查。
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	streamDir       = "/usr/local/nginx/conf/stream.d"
	tcpPortMax      = 65535
	tcpLabelMax     = 64
	tcpLinkMax      = 2048
	tcpDeleteSuffix = ".relay-delete.bak"
)

var streamIncludeRE = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+\S*stream\.d/\*\.conf[ \t]*;`)

// 历史转发配置仍参与端口占用检查，不创建、删除或改写这些文件。
func tcpConfPath(port int) string {
	return filepath.Join(streamDir, fmt.Sprintf("relay-tcp-%d.conf", port))
}

// 判断宿主 nginx.conf 是否已引入 stream.d。
func streamEnabled(conf []byte) bool {
	return streamIncludeRE.Match(conf)
}

// 链接含凭据，解析错误不能回显链接原文。
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

// 上游仅接受公网 IP，避免域名解析失败影响 Nginx 全局重载。
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

func tcpDial(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// 检查历史配置及本机监听占用，供 Reality 创建入口前保护共享端口。
func tcpPortAvailable(port int) error {
	return tcpPortAvailableWith(port, os.Stat, net.Listen)
}

// 注入文件探测及监听检查，验证共享端口保护时无需真正监听。
func tcpPortAvailableWith(port int, stat func(string) (os.FileInfo, error), listen func(string, string) (net.Listener, error)) error {
	for _, path := range []string{tcpConfPath(port), tcpConfPath(port) + tcpDeleteSuffix} {
		if _, err := stat(path); !os.IsNotExist(err) {
			return fmt.Errorf("端口 %d 已有转发", port)
		}
	}
	ln, err := listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("端口 %d 已被占用", port)
	}
	_ = ln.Close()
	return nil
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if authIsAdmin(r) {
		return true
	}
	writeErr(w, http.StatusForbidden, "需要管理员权限")
	return false
}
