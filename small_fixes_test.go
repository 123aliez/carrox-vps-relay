package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogoutHandlerClearsCookie(t *testing.T) {
	for _, proto := range []string{"", "https"} {
		req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		rec := httptest.NewRecorder()
		logoutHandler(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
			t.Fatalf("响应异常: %d %s", rec.Code, rec.Body.String())
		}
		cs := rec.Result().Cookies()
		if len(cs) != 1 {
			t.Fatalf("cookie 数量 %d", len(cs))
		}
		c := cs[0]
		if c.Name != cookieName || c.Value != "" || c.Path != "/" || !c.HttpOnly || c.MaxAge != -1 || c.SameSite != http.SameSiteLaxMode || c.Secure != (proto == "https") {
			t.Fatalf("cookie 属性异常: %+v", c)
		}
	}
}

func TestUpstreamProbeIgnoresCertButEdgeVerifies(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if !httpReachableWith(upstreamProbeClient, srv.URL, 3*time.Second) {
		t.Fatal("自签名上游应判定为可达")
	}
	if httpReachable(srv.URL, 3*time.Second) {
		t.Fatal("边缘探测必须校验证书")
	}
	tr := upstreamProbeClient.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("上游探测客户端应跳过证书校验")
	}
	if pt := probeClient.Transport.(*http.Transport); pt.TLSClientConfig != nil && pt.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("probeClient 不应跳过校验")
	}
	_ = tls.Config{}
}

func TestRenderIPv6Upstream(t *testing.T) {
	cases := map[string]string{
		"http://[2001:db8::1]:8080":  "proxy_pass http://[2001:db8::1]:8080;",
		"http://203.0.113.5:8080":    "proxy_pass http://203.0.113.5:8080;",
		"https://origin.example.com": "proxy_pass https://origin.example.com:443;",
	}
	for up, want := range cases {
		out, err := renderSiteMode(SiteMeta{V: 2, Domain: "a.example.com", Upstream: up, Owner: "admin"}, "templates", false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), want) {
			t.Fatalf("%s 缺少 %q", up, want)
		}
	}
	out, _ := renderSiteMode(SiteMeta{V: 2, Domain: "a.example.com", Upstream: "http://[2001:db8::1]:8080", Owner: "admin"}, "templates", false)
	if !strings.Contains(string(out), "proxy_pass http://[2001:db8::1]:80;") {
		t.Fatal("ACME 透传 proxy_pass 应带方括号")
	}
}

func TestParseUpstreamRejectsExtras(t *testing.T) {
	for _, raw := range []string{"https://h.example.com/path", "https://h.example.com/?a=1", "https://h.example.com?", "https://h.example.com#x", "https://u:p@h.example.com", "https://u@h.example.com"} {
		if _, _, _, _, err := parseUpstream(raw); err == nil || !strings.Contains(err.Error(), "上游地址只能包含") {
			t.Fatalf("%q 应被拒绝: %v", raw, err)
		}
	}
	for _, raw := range []string{"https://h.example.com", "https://h.example.com/", "http://1.2.3.4:8080", "http://[2001:db8::1]:8080"} {
		if _, _, _, _, err := parseUpstream(raw); err != nil {
			t.Fatalf("%q 应通过: %v", raw, err)
		}
	}
}

func TestCFListZonesPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 3
		if r.URL.Query().Get("page") == "1" {
			n = 50
		} else if r.URL.Query().Get("page") != "2" {
			t.Errorf("意外页码 %q", r.URL.Query().Get("page"))
		}
		var items []string
		for i := 0; i < n; i++ {
			items = append(items, fmt.Sprintf(`{"id":"z%d","name":"n%d","status":"active"}`, i, i))
		}
		fmt.Fprintf(w, `{"success":true,"errors":[],"result":[%s]}`, strings.Join(items, ","))
	}))
	defer srv.Close()
	old := cfBase
	cfBase = srv.URL
	defer func() { cfBase = old }()
	zones, err := cfListZones("tok")
	if err != nil || len(zones) != 53 {
		t.Fatalf("zones=%d err=%v", len(zones), err)
	}
}

func TestValidEdgeIPv4(t *testing.T) {
	for s, want := range map[string]bool{
		"203.0.113.9":              true,
		"2001:db8::1":              false,
		"::ffff:1.2.3.4":           false,
		"<html>bad gateway</html>": false,
		"":                         false,
	} {
		if got := validEdgeIPv4(s); got != want {
			t.Errorf("%q: got %v want %v", s, got, want)
		}
	}
}

func TestParseRealityOutboundFailFast(t *testing.T) {
	if _, err := parseRealityOutbound(testLink); err != nil {
		t.Fatalf("合法链接应通过: %v", err)
	}
	cases := []struct{ name, link, msg string }{
		{"UUID", strings.Replace(testLink, testUUID, "not-a-uuid", 1), "UUID"},
		{"pbk 长度", strings.Replace(testLink, "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbk=AAAA", 1), "pbk"},
		{"pbk 字符", strings.Replace(testLink, "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbk=!!!!", 1), "pbk"},
		{"sid 非 hex", strings.Replace(testLink, "sid=abcd", "sid=zzzz", 1), "sid"},
		{"sid 过长", strings.Replace(testLink, "sid=abcd", "sid=0123456789abcdef01", 1), "sid"},
	}
	for _, c := range cases {
		_, err := parseRealityOutbound(c.link)
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Fatalf("%s: err=%v", c.name, err)
		}
		if strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "zzzz") {
			t.Fatalf("%s: 错误信息泄露链接内容: %v", c.name, err)
		}
	}
}
