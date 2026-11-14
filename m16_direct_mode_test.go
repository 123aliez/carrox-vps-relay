package main

// M16 direct 出口模式：自持出口（本机 freedom 直连），与 transit 链式中转并存。

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func m16Direct() SiteMeta {
	m := m15Site()
	m.Domain = "direct.example.com"
	m.Reality = &RealityMeta{Mode: realityModeDirect, Label: "自持出口"}
	return m
}

// direct 渲染：freedom outbound、路由含 inboundTag、无上游字段。
func TestM16DirectModeRendering(t *testing.T) {
	site := m16Direct()
	keys := fixtureRealityKeys(t)
	entry := realityEntry{FrontendUUID: "11111111-2222-4333-8444-555555555555"}
	data, err := renderXrayConfig([]SiteMeta{site}, keys, map[string]realityEntry{site.Domain: entry})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"protocol": "freedom"`)) || bytes.Contains(data, []byte("vnext")) {
		t.Fatal("direct 入口应渲染 freedom outbound 且无上游 vnext")
	}
	var config struct {
		Outbounds []struct {
			Tag      string
			Protocol string
		}
		Routing struct {
			Rules []struct {
				InboundTag  []string
				User        []string
				OutboundTag string
			}
		}
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ob := range config.Outbounds {
		if ob.Tag == "to-"+site.Domain {
			found = true
			if ob.Protocol != "freedom" {
				t.Fatal("direct 出口必须是 freedom")
			}
		}
	}
	if !found {
		t.Fatal("缺少 direct 出口")
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag == "to-"+site.Domain {
			if len(rule.InboundTag) != 1 || rule.InboundTag[0] != "reality-in" {
				t.Fatal("direct 路由必须绑定 inboundTag reality-in")
			}
		}
	}
	last := config.Outbounds[len(config.Outbounds)-1]
	if last.Tag != "block" || last.Protocol != "blackhole" {
		t.Fatal("缺少阻断兜底")
	}
}

// 混合渲染：direct 与 transit 各自命中正确出口。
func TestM16MixedDirectAndTransitRendering(t *testing.T) {
	direct := m16Direct()
	transit := m15Reality()
	keys := fixtureRealityKeys(t)
	entries := map[string]realityEntry{
		direct.Domain:  {FrontendUUID: "11111111-2222-4333-8444-555555555555"},
		transit.Domain: fixtureRealityEntry(t),
	}
	data, err := renderXrayConfig([]SiteMeta{direct, transit}, keys, entries)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []struct {
			Tag      string
			Protocol string
		}
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	protocols := map[string]string{}
	for _, ob := range config.Outbounds {
		protocols[ob.Tag] = ob.Protocol
	}
	if protocols["to-"+direct.Domain] != "freedom" || protocols["to-"+transit.Domain] != "vless" {
		t.Fatal("混合入口出口协议错误", protocols)
	}
	if protocols["block"] != "blackhole" {
		t.Fatal("缺少阻断兜底")
	}
}

// 机密校验：direct 要求元数据与 Outbound 全空；未知模式拒绝。
func TestM16DirectEntryValidation(t *testing.T) {
	site := m16Direct()
	empty := realityEntry{FrontendUUID: "11111111-2222-4333-8444-555555555555"}
	if !validRealityEntry(site, empty) {
		t.Fatal("direct 模式空 Outbound 应有效")
	}
	if validRealityEntry(site, realityEntry{FrontendUUID: "11111111-2222-4333-8444-555555555555", Outbound: realityOutbound{UUID: fixtureBackendUUID}}) {
		t.Fatal("direct 模式不允许残留上游配置")
	}
	bad := site
	bad.Reality = &RealityMeta{Mode: "unknown", Label: "x"}
	if validRealityEntry(bad, empty) {
		t.Fatal("未知模式必须拒绝")
	}
	hostLeak := site
	hostLeak.Reality = &RealityMeta{Mode: realityModeDirect, UpstreamHost: "198.51.100.7", Label: "x"}
	if validRealityEntry(hostLeak, empty) {
		t.Fatal("direct 模式元数据不允许残留上游")
	}
}

// API 闸门：direct 拒绝非空 link；未知 mode 拒绝；均在写文件前。
func TestM16DirectCreateGate(t *testing.T) {
	p := tempSNIPaths(t)
	original := confDir
	confDir = p.conf
	defer func() { confDir = original }()
	cases := []struct {
		name string
		body map[string]string
	}{
		{"direct 带链接", map[string]string{"domain": "gate.example.com", "link": testLink, "mode": "direct"}},
		{"未知模式", map[string]string{"domain": "gate.example.com", "mode": "socks"}},
	}
	for _, tc := range cases {
		body, err := json.Marshal(tc.body)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		realityCreateWithMode(w, adminRequest("POST", "/api/reality", bytes.NewReader(body)), func() bool { return true })
		if w.Code != 400 || strings.Contains(w.Body.String(), testUUID) {
			t.Fatal("应在写文件前安全拒绝：", tc.name, w.Code, w.Body.String())
		}
	}
}

// direct 模板渲染：无上游也不得阻断（renderSiteMode 对 Reality 跳过 parseUpstream）。
func TestM16DirectSiteTemplateRenders(t *testing.T) {
	site := m16Direct()
	data, err := renderSiteMode(site, "templates", true)
	if err != nil {
		t.Fatal("direct 站点模板渲染失败", err)
	}
	if !bytes.Contains(data, []byte(`"mode":"direct"`)) {
		t.Fatal("relay-meta 应包含 direct 模式")
	}
	if !bytes.Contains(data, []byte("relay-camouflage")) {
		t.Fatal("Reality 站点应回落伪装页")
	}
}

// normalizeRealityMode：缺省 transit、未知拒绝（大小写归一化由 API 层完成）。
func TestM16NormalizeRealityMode(t *testing.T) {
	for raw, want := range map[string]string{"": realityModeTransit, "transit": realityModeTransit, "direct": realityModeDirect} {
		mode, ok := normalizeRealityMode(raw)
		if !ok || mode != want {
			t.Fatal("模式规范化错误", raw, mode)
		}
	}
	if _, ok := normalizeRealityMode("hybrid"); ok {
		t.Fatal("未知模式必须拒绝")
	}
}
