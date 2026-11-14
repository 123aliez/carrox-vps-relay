package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseUpstreamHostValidation(t *testing.T) {
	for _, ok := range []string{
		"https://origin.example.com:8443", "http://1.2.3.4",
		"http://[2001:db8::1]:8080", "http://backend:3000",
	} {
		if _, _, _, _, err := parseUpstream(ok); err != nil {
			t.Errorf("%s 应被接受: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://[fe80::1%25x%20y]", "http://a;b.example.com", "http://a$b.example.com",
		"http://a\"b.example.com", "http://a%20b.example.com", "http://example.com.",
	} {
		if _, _, _, _, err := parseUpstream(bad); err == nil {
			t.Errorf("%s 应被拒绝", bad)
		}
	}
}

func TestValidUpstreamHost(t *testing.T) {
	if !validUpstreamHost("localhost") || !validUpstreamHost("::1") {
		t.Error("localhost / ::1 应有效")
	}
	for _, h := range []string{"", "a.", "-a.com", "a b", "a;b", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "a"} {
		if validUpstreamHost(h) {
			t.Errorf("%q 应无效", h)
		}
	}
}

func reqWithRole(method, target, role string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader("{}"))
	ctx := context.WithValue(r.Context(), ctxKeyID, "u1")
	ctx = context.WithValue(ctx, ctxRole, role)
	return r.WithContext(ctx)
}

func TestSitesAdoptRequiresAdmin(t *testing.T) {
	w := httptest.NewRecorder()
	sitesAdopt(w, reqWithRole(http.MethodPost, "/api/sites/adopt", "user"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("普通用户应得到 403，实际 %d", w.Code)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Real-IP", "1.1.1.1")
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 1.1.1.1")
	if got := clientIP(r); got != "1.1.1.1" {
		t.Errorf("got %q", got)
	}
	r.Header.Del("X-Real-IP")
	if got := clientIP(r); got != "10.0.0.1" {
		t.Errorf("RemoteAddr 回退: got %q", got)
	}
	r.RemoteAddr = "[::1]:1234"
	if got := clientIP(r); got != "::1" {
		t.Errorf("IPv6: got %q", got)
	}
	r.RemoteAddr = "weird"
	if got := clientIP(r); got != "weird" {
		t.Errorf("原值回退: got %q", got)
	}
}

func TestRecordFailPurgesExpired(t *testing.T) {
	failsMu.Lock()
	old := fails
	fails = make(map[string]*failEntry)
	old2 := time.Now().Add(-2 * failWindow)
	for i := 0; i < maxFailEntries+5; i++ {
		fails[time.Duration(i).String()] = &failEntry{count: 1, firstAt: old2}
	}
	fails["blocked"] = &failEntry{count: 9, firstAt: old2, blockedUntil: time.Now().Add(time.Hour)}
	failsMu.Unlock()
	defer func() { failsMu.Lock(); fails = old; failsMu.Unlock() }()

	recordFail("new")
	failsMu.Lock()
	defer failsMu.Unlock()
	if len(fails) != 2 || fails["new"] == nil || fails["blocked"] == nil {
		t.Fatalf("过期条目应被清理，剩余 %d", len(fails))
	}
}

func TestLoginOversizedBody(t *testing.T) {
	body := `{"token":"` + strings.Repeat("a", 10000) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.77:1"
	w := httptest.NewRecorder()
	loginHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超大请求体应返回 400，实际 %d", w.Code)
	}
}

func TestValidKeyID(t *testing.T) {
	for _, ok := range []string{"user01", "a-b_c", "A"} {
		if !validKeyID(ok) {
			t.Errorf("%q 应有效", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "a b", ".hidden", strings.Repeat("a", 33)} {
		if validKeyID(bad) {
			t.Errorf("%q 应无效", bad)
		}
	}
	if _, err := addKey("../x", "user", ""); err == nil {
		t.Error("addKey 应拒绝非法 ID")
	}
}

func TestMaskKey(t *testing.T) {
	if got := maskKey("abcdEFGH1234"); got != "abcd••••••••" {
		t.Errorf("got %q", got)
	}
	if got := maskKey("abc"); got != "•••" {
		t.Errorf("got %q", got)
	}
	if got := maskKey(""); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestWriteNginxErr(t *testing.T) {
	e := errors.New("nginx -t failed: secret path /etc/x")
	w := httptest.NewRecorder()
	writeNginxErr(w, reqWithRole("POST", "/", "admin"), 422, e)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "secret path") {
		t.Errorf("管理员应看到全文: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	writeNginxErr(w, reqWithRole("POST", "/", "user"), 502, e)
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret") ||
		!strings.Contains(w.Body.String(), "配置校验或重载失败，请联系管理员查看日志") {
		t.Errorf("普通用户应只看到固定提示: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	writeNginxErr(w, reqWithRole("POST", "/", "user"), 502, errors.New("example.com 存在 AAAA 记录"))
	if !strings.Contains(w.Body.String(), "AAAA") {
		t.Errorf("普通用户应看到非 nginx 的原始错误: %s", w.Body.String())
	}
}
