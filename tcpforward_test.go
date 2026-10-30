package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestRewriteRealityLink(t *testing.T) {
	got, err := rewriteRealityLink(testLink, "203.0.113.9", 24443, "")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(testLink, "198.51.100.7:443", "203.0.113.9:24443", 1)
	want = strings.Replace(want, "#Reality-node", "#Reality-node-relay", 1)
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// 导出的链接要能再次通过校验，且地址已是中转入口。
	host, port, err := parseRealityLink(got)
	if err != nil || host != "203.0.113.9" || port != 24443 {
		t.Fatalf("host=%q port=%d err=%v", host, port, err)
	}
	labeled, err := rewriteRealityLink(testLink, "2001:db8::1", 24443, "美西 中转")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(labeled, "@[2001:db8::1]:24443?") {
		t.Fatalf("IPv6 地址未加方括号: %s", labeled)
	}
	if strings.Contains(labeled, "Reality-node") || !strings.Contains(labeled, "#%E7%BE%8E%E8%A5%BF%20%E4%B8%AD%E8%BD%AC") {
		t.Fatalf("备注未生效: %s", labeled)
	}
}

func TestParseTCPUpstream(t *testing.T) {
	host, port, err := parseTCPUpstream("198.51.100.7:8443")
	if err != nil || host != "198.51.100.7" || port != 8443 {
		t.Fatalf("host=%q port=%d err=%v", host, port, err)
	}
	for _, raw := range []string{"198.51.100.7", "198.51.100.7:abc", ""} {
		if _, _, err := parseTCPUpstream(raw); err == nil {
			t.Errorf("%q 应该报错", raw)
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
	for _, port := range []int{tcpPortMin, 24443, tcpPortMax} {
		if err := validateTCPListenPort(port); err != nil {
			t.Errorf("%d: %v", port, err)
		}
	}
	for _, port := range []int{-1, 22, 80, 443, 1023, 65536} {
		if err := validateTCPListenPort(port); err == nil {
			t.Errorf("%d 应该被拒绝", port)
		}
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

func TestRenderAndReadTCPForward(t *testing.T) {
	meta := TCPForwardMeta{V: 1, ListenPort: 24443, UpstreamHost: "198.51.100.7", UpstreamPort: 443, Label: `a;b{c}"$d`, Owner: "admin", Created: "2026-10-30T00:00:00Z"}
	out, err := renderTCPForwardWithTemplate(meta, "templates/tcp.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{relayHead, "listen 24443;", "proxy_pass 198.51.100.7:443;", "proxy_timeout 1h;"} {
		if !strings.Contains(text, want) {
			t.Errorf("缺少 %q:\n%s", want, text)
		}
	}
	path := filepath.Join(t.TempDir(), "relay-tcp-24443.conf")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTCPMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != meta {
		t.Fatalf("元数据往返不一致: %+v", got)
	}

	meta.UpstreamHost = "2001:db8::1"
	out, err = renderTCPForwardWithTemplate(meta, "templates/tcp.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "proxy_pass [2001:db8::1]:443;") {
		t.Fatalf("IPv6 上游未加方括号:\n%s", out)
	}
}

// fakeTCPOps 用内存记录文件状态，并可让指定步骤失败。
type fakeTCPOps struct {
	files   map[string]bool
	links   map[int]bool
	calls   []string
	failAt  string
	reloads int
}

func newFakeTCPOps() *fakeTCPOps {
	return &fakeTCPOps{files: map[string]bool{}, links: map[int]bool{}}
}

func (f *fakeTCPOps) step(name string) error {
	f.calls = append(f.calls, name)
	if f.failAt == name {
		return errors.New(name + " failed")
	}
	return nil
}

func (f *fakeTCPOps) ops() tcpLifecycle {
	return tcpLifecycle{
		render: func(TCPForwardMeta) ([]byte, error) {
			return []byte("conf"), f.step("render")
		},
		write: func(path string, _ []byte, _ os.FileMode) error {
			if err := f.step("write"); err != nil {
				return err
			}
			f.files[path] = true
			return nil
		},
		remove: func(path string) error {
			if err := f.step("remove"); err != nil {
				return err
			}
			delete(f.files, path)
			return nil
		},
		rename: func(from, to string) error {
			if err := f.step("rename"); err != nil {
				return err
			}
			delete(f.files, from)
			f.files[to] = true
			return nil
		},
		check: func() error { return f.step("check") },
		reload: func() error {
			f.reloads++
			return f.step("reload")
		},
		waitPort: func(int, bool) error { return f.step("wait") },
		writeLink: func(port int, _ string) error {
			if err := f.step("writeLink"); err != nil {
				return err
			}
			f.links[port] = true
			return nil
		},
		removeLink: func(port int) error {
			if err := f.step("removeLink"); err != nil {
				return err
			}
			delete(f.links, port)
			return nil
		},
	}
}

var testTCPMeta = TCPForwardMeta{V: 1, ListenPort: 24443, UpstreamHost: "198.51.100.7", UpstreamPort: 443}

func TestProvisionTCPForward(t *testing.T) {
	f := newFakeTCPOps()
	if err := provisionTCPForward(testTCPMeta, "vless://new", f.ops()); err != nil {
		t.Fatal(err)
	}
	if !f.files[tcpConfPath(24443)] || !f.links[24443] {
		t.Fatalf("配置或链接未写入: %+v %+v", f.files, f.links)
	}
	want := "render writeLink write check reload wait"
	if got := strings.Join(f.calls, " "); got != want {
		t.Fatalf("调用顺序 %q，期望 %q", got, want)
	}
}

func TestProvisionTCPForwardWithoutLink(t *testing.T) {
	f := newFakeTCPOps()
	if err := provisionTCPForward(testTCPMeta, "", f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.links) != 0 || strings.Contains(strings.Join(f.calls, " "), "writeLink") {
		t.Fatalf("没有链接时不应写链接文件: %v", f.calls)
	}
}

func TestProvisionTCPForwardRollback(t *testing.T) {
	cases := []struct {
		stage       string
		wantReloads int
	}{
		{"render", 0}, {"writeLink", 0}, {"write", 0}, {"check", 0}, {"reload", 1}, {"wait", 2},
	}
	for _, tc := range cases {
		t.Run(tc.stage, func(t *testing.T) {
			f := newFakeTCPOps()
			f.failAt = tc.stage
			err := provisionTCPForward(testTCPMeta, "vless://new", f.ops())
			if err == nil {
				t.Fatal("应该返回错误")
			}
			if len(f.files) != 0 || len(f.links) != 0 {
				t.Fatalf("回滚后有残留: %+v %+v", f.files, f.links)
			}
			if f.reloads != tc.wantReloads {
				t.Fatalf("重载 %d 次，期望 %d 次: %v", f.reloads, tc.wantReloads, f.calls)
			}
		})
	}
}

func TestRemoveTCPForward(t *testing.T) {
	f := newFakeTCPOps()
	path := tcpConfPath(24443)
	f.files[path] = true
	f.links[24443] = true
	if err := removeTCPForward(24443, false, f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.files) != 0 || len(f.links) != 0 {
		t.Fatalf("删除后有残留: %+v %+v", f.files, f.links)
	}
}

func TestRemoveTCPForwardRestoresOnFailure(t *testing.T) {
	for _, stage := range []string{"check", "reload", "wait"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeTCPOps()
			path := tcpConfPath(24443)
			f.files[path] = true
			f.links[24443] = true
			f.failAt = stage
			if err := removeTCPForward(24443, false, f.ops()); err == nil {
				t.Fatal("应该返回错误")
			}
			if !f.files[path] || f.files[path+tcpDeleteSuffix] {
				t.Fatalf("配置未恢复: %+v", f.files)
			}
			if !f.links[24443] {
				t.Fatal("转发还在运行，链接不应被删除")
			}
		})
	}
}

// 清理失败后备份必须留着，这样面板能显示“删除未完成”，再次删除能完成清理。
func TestRemoveTCPForwardCleanupFailureCanRetry(t *testing.T) {
	for _, stage := range []string{"removeLink", "remove"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeTCPOps()
			path := tcpConfPath(24443)
			f.files[path] = true
			f.links[24443] = true
			f.failAt = stage
			if err := removeTCPForward(24443, false, f.ops()); err == nil {
				t.Fatal("应该返回错误")
			}
			if f.files[path] || !f.files[path+tcpDeleteSuffix] {
				t.Fatalf("应保留备份待重试: %+v", f.files)
			}
			f.failAt = ""
			if err := removeTCPForward(24443, true, f.ops()); err != nil {
				t.Fatal(err)
			}
			if len(f.files) != 0 || len(f.links) != 0 {
				t.Fatalf("重试后有残留: %+v %+v", f.files, f.links)
			}
		})
	}
}

// 重试时配置已是备份，失败也不能把它恢复成活动配置。
func TestRemoveTCPForwardStagedKeepsBackupOnFailure(t *testing.T) {
	for _, stage := range []string{"check", "reload", "wait"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeTCPOps()
			path := tcpConfPath(24443)
			f.files[path+tcpDeleteSuffix] = true
			f.failAt = stage
			if err := removeTCPForward(24443, true, f.ops()); err == nil {
				t.Fatal("应该返回错误")
			}
			if f.files[path] || !f.files[path+tcpDeleteSuffix] {
				t.Fatalf("备份状态不对: %+v", f.files)
			}
		})
	}
}

func TestWaitTCPPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := waitTCPPortFor(port, true, 600*time.Millisecond, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitTCPPortFor(port, false, 600*time.Millisecond, 3*time.Second); err != nil {
		t.Fatal(err)
	}
}

// 重载被拒绝前端口可能短暂打开，不能当成功。
func TestWaitTCPPortRejectsTransientListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// 关闭前能连续命中几次，验证中断后稳定计时会重置。
	timer := time.AfterFunc(1200*time.Millisecond, func() { ln.Close() })
	defer timer.Stop()
	if err := waitTCPPortFor(port, true, 1600*time.Millisecond, 2500*time.Millisecond); err == nil {
		t.Fatal("短暂监听不应判定为成功")
	}
}

func TestTCPPortStableExceedsNginxBindRetry(t *testing.T) {
	if tcpPortStable <= 2500*time.Millisecond || tcpPortTimeout <= tcpPortStable {
		t.Fatalf("stable=%v timeout=%v", tcpPortStable, tcpPortTimeout)
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

func TestTCPHandlersRequireAdmin(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"list":   tcpForwardsList,
		"create": tcpForwardsCreate,
		"link":   tcpForwardLink,
		"delete": tcpForwardsDelete,
	}
	for name, handler := range handlers {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: 状态码 %d，期望 403", name, rec.Code)
		}
	}
}
