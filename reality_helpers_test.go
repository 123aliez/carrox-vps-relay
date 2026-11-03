package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "11111111-2222-3333-4444-555555555555"
const testLink = "vless://" + testUUID + "@198.51.100.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cisco.com&fp=chrome&pbk=PUBKEY_x-1&sid=abcd&type=tcp&headerType=none#Reality-node"

func TestParseRealityLink(t *testing.T) {
	host, port, err := parseRealityLink(testLink)
	if err != nil || host != "198.51.100.7" || port != 443 {
		t.Fatalf("host=%q port=%d err=%v", host, port, err)
	}
	bad := map[string]string{
		"非 vless":   strings.Replace(testLink, "vless://", "vmess://", 1),
		"非 reality": strings.Replace(testLink, "security=reality", "security=tls", 1),
		"缺 UUID":    strings.Replace(testLink, testUUID+"@", "", 1),
		"缺 sni":     strings.Replace(testLink, "sni=www.cisco.com&", "", 1),
		"缺 pbk":     strings.Replace(testLink, "pbk=PUBKEY_x-1&", "", 1),
		"缺端口":       strings.Replace(testLink, ":443", "", 1),
		"端口超范围":     strings.Replace(testLink, ":443", ":70000", 1),
		"格式错误":      "vless://" + testUUID + "@bad host:443?security=reality",
	}
	for name, raw := range bad {
		_, _, err := parseRealityLink(raw)
		if err == nil {
			t.Errorf("%s: 应该报错", name)
		} else if strings.Contains(err.Error(), testUUID) {
			t.Errorf("%s: 错误信息泄露了 UUID: %v", name, err)
		}
	}
}

func TestValidateTCPUpstream(t *testing.T) {
	const edge = "203.0.113.9"
	if err := validateTCPUpstream("198.51.100.7", 443, edge); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.com", "127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "::1", edge} {
		if err := validateTCPUpstream(host, 443, edge); err == nil {
			t.Errorf("%s 应该被拒绝", host)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if err := validateTCPUpstream("198.51.100.7", port, edge); err == nil {
			t.Errorf("端口 %d 应该被拒绝", port)
		}
	}
}

func TestValidateTCPListenPort(t *testing.T) {
	for _, port := range []int{tcpPortMin, 24443, 29999, 31000, tcpPortMax} {
		if err := validateTCPListenPort(port); err != nil {
			t.Errorf("%d: %v", port, err)
		}
	}
	for _, port := range []int{-1, 22, 80, 443, 1023, 8443, 30000, 30001, 30500, 30999, 65536} {
		if err := validateTCPListenPort(port); err == nil {
			t.Errorf("%d 应该被拒绝", port)
		}
	}
}

type portCheckListener struct {
	net.Listener
	closed bool
}

func (ln *portCheckListener) Close() error { ln.closed = true; return nil }

func TestRealityPortAvailablePreservesLegacyAndListenerChecks(t *testing.T) {
	for _, state := range []string{"free", "legacy-active", "legacy-pending", "stat-error", "occupied"} {
		t.Run(state, func(t *testing.T) {
			ln := &portCheckListener{}
			listens, stats := 0, 0
			err := tcpPortAvailableWith(realityInboundPort, func(path string) (os.FileInfo, error) {
				stats++
				if path != tcpConfPath(realityInboundPort) && path != tcpConfPath(realityInboundPort)+tcpDeleteSuffix {
					t.Fatal("未检查共享端口的历史配置", path)
				}
				if state == "legacy-active" && !strings.HasSuffix(path, tcpDeleteSuffix) || state == "legacy-pending" && strings.HasSuffix(path, tcpDeleteSuffix) {
					return nil, nil
				}
				if state == "stat-error" {
					return nil, os.ErrPermission
				}
				return nil, os.ErrNotExist
			}, func(network, address string) (net.Listener, error) {
				listens++
				if network != "tcp4" || address != ":30001" {
					t.Fatal("检查了错误的共享端口", network, address)
				}
				if state == "occupied" {
					return nil, errors.New("地址已被占用")
				}
				return ln, nil
			})
			if (err == nil) != (state == "free") {
				t.Fatal("端口可用性结果错误", state, err)
			}
			if state == "free" {
				if stats != 2 || listens != 1 || !ln.closed {
					t.Fatal("可用端口必须检查历史配置并释放探测监听", stats, listens, ln.closed)
				}
			} else if state != "occupied" && listens != 0 {
				t.Fatal("历史配置占用或不可读时不得尝试监听")
			}
		})
	}
}

func TestValidateTCPLabel(t *testing.T) {
	if err := validateTCPLabel(strings.Repeat("中", tcpLabelMax)); err != nil {
		t.Fatal(err)
	}
	if err := validateTCPLabel(strings.Repeat("中", tcpLabelMax+1)); err == nil {
		t.Fatal("超长备注应该被拒绝")
	}
	if err := validateTCPLabel("a\nserver {"); err == nil {
		t.Fatal("换行应该被拒绝")
	}
}

func TestStreamEnabled(t *testing.T) {
	on := []string{"stream {\n    include stream.d/*.conf;\n}\n", "stream {\n\tinclude /usr/local/nginx/conf/stream.d/*.conf ;\n}\n"}
	for _, conf := range on {
		if !streamEnabled([]byte(conf)) {
			t.Errorf("应判定为已启用: %q", conf)
		}
	}
	off := []string{"http {\n    include conf.d/*.conf;\n}\n", "# include stream.d/*.conf;\n"}
	for _, conf := range off {
		if streamEnabled([]byte(conf)) {
			t.Errorf("应判定为未启用: %q", conf)
		}
	}
}

func TestPanelCertDomain(t *testing.T) {
	https := "server {\n    listen 443 ssl;\n    ssl_certificate     /usr/local/nginx/conf/ssl/panel.example.com/fullchain.pem;\n}\n"
	if got := panelCertDomain([]byte(https)); got != "panel.example.com" {
		t.Fatalf("got %q", got)
	}
	for _, conf := range []string{
		"server {\n    listen 80;\n}\n",
		"# ssl_certificate /usr/local/nginx/conf/ssl/panel.example.com/fullchain.pem;\n",
	} {
		if got := panelCertDomain([]byte(conf)); got != "" {
			t.Errorf("%q: 不应判定为启用 HTTPS，got %q", conf, got)
		}
	}
	tmpl, err := os.ReadFile("templates/panel-ssl.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	rendered := strings.ReplaceAll(string(tmpl), "{{.Domain}}", "panel.example.com")
	if got := panelCertDomain([]byte(rendered)); got != "panel.example.com" {
		t.Fatalf("模板里的证书路径匹配不到: %q", got)
	}
}

func TestAtomicWriteCleansUpTempFileOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "1.link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(target, []byte("secret"), 0o600); err == nil {
		t.Fatal("目标是目录时应该失败")
	}
	left, err := filepath.Glob(filepath.Join(dir, ".relay-tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("残留了含凭据的临时文件: %v", left)
	}
}
