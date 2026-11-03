package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const fixtureFrontendUUID = "11111111-1111-4111-8111-111111111111"
const fixtureBackendUUID = "22222222-2222-4222-8222-222222222222"

func fixtureRealityKeys(t *testing.T) realityKeys {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return realityKeys{base64.RawURLEncoding.EncodeToString(private.Bytes()), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "0123456789abcdef"}
}
func fixtureRealityEntry(t *testing.T) realityEntry {
	keys := fixtureRealityKeys(t)
	return realityEntry{fixtureFrontendUUID, realityOutbound{fixtureBackendUUID, "198.51.100.7", 443, "xtls-rprx-vision", "backend.example.com", "chrome", keys.PublicKey, "0123456789abcdef", "/test"}}
}
func tempXrayPaths(t *testing.T) xrayPaths {
	t.Helper()
	return xrayPaths{filepath.Join(t.TempDir(), "xray")}
}
func TestM15XrayKeysGenerationAndReuse(t *testing.T) {
	p := tempXrayPaths(t)
	fs := liveRelayFS()
	writes := 0
	write := fs.write
	fs.write = func(path string, data []byte, mode os.FileMode) error { writes++; return write(path, data, mode) }
	first, err := loadOrCreateXrayKeys(p, fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealityKeys(first); err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{first.PrivateKey, first.PublicKey} {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(raw) != 32 || len(encoded) != 43 || strings.Contains(encoded, "=") {
			t.Fatal("X25519 编码或长度错误")
		}
	}
	short, err := hex.DecodeString(first.ShortID)
	if err != nil || len(short) != 8 || len(first.ShortID) != 16 {
		t.Fatal("shortId 格式错误")
	}
	second, err := loadOrCreateXrayKeys(p, fs)
	if err != nil || second != first || writes != 1 {
		t.Fatal("应复用原密钥且不重写文件", err, writes)
	}
	for path, want := range map[string]os.FileMode{p.root: 0700, p.keys(): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal("密钥权限错误", err)
		}
	}
	id, err := newRealityUUID()
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Fatal("前端 UUID 不是 v4")
	}
	other, err := newRealityUUID()
	if err != nil || other == id {
		t.Fatal("入口应有独立身份")
	}
	putTestFile(t, p.keys(), []byte(`{"private_key":"损坏的密钥"}`))
	if _, err := loadOrCreateXrayKeys(p, fs); err == nil {
		t.Fatal("损坏的密钥不可静默替换")
	}
}
func TestM15BackendRealityParsing(t *testing.T) {
	got, err := parseRealityOutbound(testLink + "")
	if err != nil || got.UUID != testUUID || got.Host != "198.51.100.7" || got.Port != 443 || got.Flow != "xtls-rprx-vision" || got.SNI != "www.cisco.com" || got.Fingerprint != "chrome" || got.ShortID != "abcd" {
		t.Fatal("出站参数解析错误", err)
	}
	minimal := strings.Replace(testLink, "&fp=chrome", "", 1)
	minimal = strings.Replace(minimal, "&flow=xtls-rprx-vision", "", 1)
	minimal = strings.Replace(minimal, "&type=tcp", "", 1)
	minimal = strings.Replace(minimal, "#Reality-node", "&spx=%2Fhello%3Fa%3Db#Reality-node", 1)
	got, err = parseRealityOutbound(minimal)
	if err != nil || got.Fingerprint != "chrome" || got.Flow != "" || got.SpiderX != "/hello?a=b" {
		t.Fatal("可选参数默认值错误", err)
	}
	invalid := []string{
		strings.Replace(testLink, "vless://", "vmess://", 1),
		strings.Replace(testLink, "security=reality", "security=tls", 1),
		strings.Replace(testLink, "type=tcp", "type=ws", 1),
		strings.Replace(testLink, "type=tcp", "type=grpc", 1),
		strings.Replace(testLink, "xtls-rprx-vision", "invalid-flow", 1),
		strings.Replace(testLink, "sni=www.cisco.com&", "", 1),
		strings.Replace(testLink, "pbk=PUBKEY_x-1&", "", 1),
		"vless://" + testUUID + "@bad host:443?security=reality",
	}
	for _, raw := range invalid {
		_, err := parseRealityOutbound(raw)
		if err == nil {
			t.Fatal("应拒绝不支持的后端链接")
		}
		if strings.Contains(err.Error(), testUUID) || strings.Contains(err.Error(), raw) {
			t.Fatal("错误信息泄露凭据")
		}
	}
}
func TestM15ExportFrontendLink(t *testing.T) {
	keys := fixtureRealityKeys(t)
	link := exportRealityLink(fixtureFrontendUUID, "203.0.113.9", "cover.example.com", "", keys)
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal("导出链接不是 URL")
	}
	if u.User.Username() != fixtureFrontendUUID || u.Host != "203.0.113.9:443" || u.Fragment != "cover.example.com" {
		t.Fatal("前端身份、入口或备注错误")
	}
	want := url.Values{"encryption": {"none"}, "flow": {"xtls-rprx-vision"}, "security": {"reality"}, "sni": {"cover.example.com"}, "fp": {"chrome"}, "pbk": {keys.PublicKey}, "sid": {keys.ShortID}, "type": {"tcp"}}
	if u.Query().Encode() != want.Encode() {
		t.Fatal("前端握手参数错误")
	}
	if strings.Contains(link, fixtureBackendUUID) || strings.Contains(link, keys.PrivateKey) {
		t.Fatal("导出链接不应包含后端 UUID 或前端私钥")
	}
	named, err := url.Parse(exportRealityLink(fixtureFrontendUUID, "203.0.113.9", "cover.example.com", "测试备注", keys))
	if err != nil || named.Fragment != "测试备注" {
		t.Fatal("备注未正确编码")
	}
}
func TestM15XrayConfigGoldenAndPublicMetadata(t *testing.T) {
	site := m15Reality()
	keys := fixtureRealityKeys(t)
	entry := fixtureRealityEntry(t)
	entries := map[string]realityEntry{site.Domain: entry}
	data, err := renderXrayConfig([]SiteMeta{site}, keys, entries)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "xray.json", data)
	text, err := renderSiteMode(site, "templates", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{entry.FrontendUUID, entry.Outbound.UUID, keys.PrivateKey, keys.PublicKey, keys.ShortID, "internal_port"} {
		if bytes.Contains(text, []byte(secret)) {
			t.Fatal("公开站点配置中出现了机密或旧内部端口")
		}
	}
	other := site
	other.Domain = "a.example.com"
	another := entry
	another.FrontendUUID = "33333333-3333-4333-8333-333333333333"
	entries[other.Domain] = another
	first, err := renderXrayConfig([]SiteMeta{site, other, site}, keys, entries)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderXrayConfig([]SiteMeta{other, site}, keys, entries)
	if err != nil {
		t.Fatal(err)
	}
	requireBytes(t, first, second)
	var config struct {
		Inbounds []struct {
			Port           int
			Settings       struct{ Clients []struct{ Email string } }
			StreamSettings struct {
				RealitySettings struct {
					Dest        string
					Xver        int
					ServerNames []string
				}
				Sockopt struct{ AcceptProxyProtocol bool }
			}
		}
		Outbounds []struct {
			Tag      string
			Protocol string
		}
		Routing struct {
			Rules []struct {
				User        []string
				OutboundTag string
			}
		}
	}
	if err := json.Unmarshal(first, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config.Inbounds[0]
	if inbound.Port != 30001 || !inbound.StreamSettings.Sockopt.AcceptProxyProtocol || inbound.StreamSettings.RealitySettings.Dest != "127.0.0.1:8443" || inbound.StreamSettings.RealitySettings.Xver != 1 {
		t.Fatal("入站或本机回落配置错误")
	}
	if inbound.Settings.Clients[0].Email != "a.example.com" || len(inbound.Settings.Clients) != 2 || config.Routing.Rules[0].OutboundTag != "to-a.example.com" {
		t.Fatal("用户路由或排序错误")
	}
	last := config.Outbounds[len(config.Outbounds)-1]
	if last.Tag != "block" || last.Protocol != "blackhole" || config.Routing.Rules[len(config.Routing.Rules)-1].OutboundTag != "block" {
		t.Fatal("缺少阻断兜底")
	}
}
func TestM15XraySyncExcludesInactiveAndRecoversAfterValidationFailure(t *testing.T) {
	p := tempSNIPaths(t)
	xp := tempXrayPaths(t)
	fs := liveRelayFS()
	putTestFile(t, p.marker(), []byte(sni443Config))
	site := m15Reality()
	path := putMeta(t, p, site, "")
	keys := fixtureRealityKeys(t)
	if err := privateJSON(fs, xp.keys(), keys); err != nil {
		t.Fatal(err)
	}
	entry := fixtureRealityEntry(t)
	if err := saveRealityEntry(xp, site.Domain, entry, fs); err != nil {
		t.Fatal(err)
	}
	for i, suffix := range []string{".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		off := site
		off.Domain = string(rune('a'+i)) + ".example.com"
		putMeta(t, p, off, suffix)
	}
	checks := 0
	check := func(string) error { checks++; return nil }
	if err := syncRelayConfig(p, fs, xp, check); err != nil {
		t.Fatal(err)
	}
	original := readTestFile(t, xp.config())
	requireBytes(t, readTestFile(t, p.derived()[0]), []byte("cover.example.com 127.0.0.1:30001;\n"))
	writes := 0
	write := fs.write
	fs.write = func(path string, b []byte, m os.FileMode) error { writes++; return write(path, b, m) }
	if err := syncRelayConfig(p, fs, xp, check); err != nil || writes != 0 || checks != 1 {
		t.Fatal("配置不变不能重写或再次校验", err, writes, checks)
	}
	if err := syncRelayConfig(p, fs, xp, func(string) error {
		t.Fatal("内容不变时不得调用 Xray 校验")
		return errors.New("Xray 不可用")
	}); err != nil {
		t.Fatal(err)
	}
	entry.Outbound.SNI = "changed.example.com"
	if err := saveRealityEntry(xp, site.Domain, entry, fs); err != nil {
		t.Fatal(err)
	}
	fail := func(string) error { return errors.New("含凭据的校验输出：" + fixtureBackendUUID) }
	if err := syncRelayConfig(p, fs, xp, fail); err != nil {
		t.Fatal("Xray 校验失败不应阻断普通业务", err)
	}
	if _, err := os.Stat(xp.config()); !os.IsNotExist(err) {
		t.Fatal("全部入口校验失败应停止 Xray")
	}
	requireBytes(t, readTestFile(t, p.derived()[0]), nil)
	sites := []Site{{SiteMeta: site, Enabled: true}}
	annotateRealityHealth(sites, xp, fs)
	if !sites[0].RealityPaused || strings.Contains(sites[0].RealityError, fixtureBackendUUID) {
		t.Fatal("校验失败应显示脱敏暂停状态", sites)
	}
	if _, err := os.Stat(filepath.Join(xp.root, "config.candidate.json")); !os.IsNotExist(err) {
		t.Fatal("候选机密文件未清理")
	}
	if err := syncRelayConfig(p, fs, xp, check); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(readTestFile(t, xp.config()), original) {
		t.Fatal("再次同步应恢复并应用有效配置")
	}
	for _, secretPath := range []string{xp.keys(), xp.entry(site.Domain), xp.config()} {
		info, err := os.Stat(secretPath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("机密文件权限错误")
		}
	}
	if err := os.Rename(path, path+".disabled"); err != nil {
		t.Fatal(err)
	}
	if err := syncRelayConfig(p, fs, xp, check); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(xp.config()); !os.IsNotExist(err) {
		t.Fatal("没有入口时应清除运行配置")
	}
	desired, err := desiredXrayConfig(p, xp, fs)
	if err != nil || len(desired) != 0 {
		t.Fatal("没有入口时应要求停止 Xray", err)
	}
	requireBytes(t, readTestFile(t, p.derived()[0]), []byte{})
}

// 通过同步函数产生真实候选文件，再调用 Xray 的只校验模式，不启动监听。
func TestM15XrayCandidateRealValidation(t *testing.T) {
	if _, err := os.Stat("/usr/local/bin/xray"); os.IsNotExist(err) {
		t.Skip("未安装 /usr/local/bin/xray")
	} else if err != nil {
		t.Fatal(err)
	}
	golden := readTestFile(t, "testdata/m15/xray.json")
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid-json"}[invalid], func(t *testing.T) {
			p, fs := tempXrayPaths(t), liveRelayFS()
			site := m15Reality()
			if err := privateJSON(fs, p.keys(), fixtureRealityKeys(t)); err != nil {
				t.Fatal(err)
			}
			if err := saveRealityEntry(p, site.Domain, fixtureRealityEntry(t), fs); err != nil {
				t.Fatal(err)
			}
			var candidate string
			checks := 0
			check := func(path string) error {
				candidate, checks = path, checks+1
				requireBytes(t, readTestFile(t, path), golden)
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("候选文件权限必须为 0600", err)
				}
				if invalid {
					if err := atomicWrite(path, []byte(`{"test_only_secret":"broken-json"`), 0600); err != nil {
						t.Fatal(err)
					}
				}
				err := testXrayConfig(path)
				if !invalid && err != nil {
					t.Fatal("真实 Xray 未接受有效夹具候选配置", err)
				}
				if invalid && (err == nil || err.Error() != "Xray 配置校验失败") {
					t.Fatal("损坏的 JSON 必须校验失败且不回显输出", err)
				}
				return err
			}
			if err := syncXrayConfig([]SiteMeta{site}, p, fs, check); err != nil {
				t.Fatal(err)
			}
			if checks == 0 {
				t.Fatal("未执行真实候选配置校验")
			}
			if _, err := os.Stat(candidate); !os.IsNotExist(err) {
				t.Fatal("候选文件未清理", err)
			}
			if invalid {
				if _, err := os.Stat(p.config()); !os.IsNotExist(err) {
					t.Fatal("无效候选配置不得发布", err)
				}
			} else {
				requireBytes(t, readTestFile(t, p.config()), golden)
			}
		})
	}
}

type fakeXrayChild struct {
	done     chan struct{}
	once     sync.Once
	autoStop bool
	signals  chan os.Signal
	kills    atomic.Int32
}

func newFakeXrayChild(auto bool) *fakeXrayChild {
	return &fakeXrayChild{done: make(chan struct{}), autoStop: auto, signals: make(chan os.Signal, 4)}
}
func (c *fakeXrayChild) exit()       { c.once.Do(func() { close(c.done) }) }
func (c *fakeXrayChild) Wait() error { <-c.done; return errors.New("测试退出") }
func (c *fakeXrayChild) Signal(signal os.Signal) error {
	c.signals <- signal
	if c.autoStop {
		c.exit()
	}
	return nil
}
func (c *fakeXrayChild) Kill() error { c.kills.Add(1); c.exit(); return nil }

type fakeXrayTimer struct {
	duration time.Duration
	tick     chan time.Time
}
type fakeXrayClock struct{ timers chan fakeXrayTimer }

func newFakeXrayClock() *fakeXrayClock { return &fakeXrayClock{make(chan fakeXrayTimer, 128)} }
func (c *fakeXrayClock) after(d time.Duration) <-chan time.Time {
	tick := make(chan time.Time, 1)
	c.timers <- fakeXrayTimer{d, tick}
	return tick
}
func (c *fakeXrayClock) next(t *testing.T, want time.Duration) chan time.Time {
	t.Helper()
	for {
		select {
		case timer := <-c.timers:
			if timer.duration == want {
				return timer.tick
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("未收到 %s 计时器", want)
		}
	}
}
func receiveChild(t *testing.T, children <-chan *fakeXrayChild) *fakeXrayChild {
	t.Helper()
	select {
	case child := <-children:
		return child
	case <-time.After(2 * time.Second):
		t.Fatal("未启动子进程")
		return nil
	}
}
func TestM15XraySupervisorOnlyRestartsChangedConfigAndStops(t *testing.T) {
	children := make(chan *fakeXrayChild, 8)
	clock := newFakeXrayClock()
	var starts atomic.Int32
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) {
		starts.Add(1)
		child := newFakeXrayChild(true)
		children <- child
		return child, nil
	}})
	defer m.Close()
	if err := m.Apply([]byte("配置 A")); err != nil {
		t.Fatal(err)
	}
	old := receiveChild(t, children)
	if err := m.Apply([]byte("配置 A")); err != nil || starts.Load() != 1 {
		t.Fatal("配置不变不应重启", err)
	}
	if err := m.Apply([]byte("配置 B")); err != nil {
		t.Fatal(err)
	}
	receiveChild(t, children)
	if starts.Load() != 2 || !m.Running() {
		t.Fatal("配置变化应重启")
	}
	select {
	case signal := <-old.signals:
		if signal != syscall.SIGTERM {
			t.Fatal(signal)
		}
	default:
		t.Fatal("旧进程未收到 SIGTERM")
	}
	if err := m.Apply(nil); err != nil || m.Running() {
		t.Fatal("无入口时必须停止进程", err)
	}
}
func TestM15XraySupervisorBackoffAndLock(t *testing.T) {
	children := make(chan *fakeXrayChild, 16)
	clock := newFakeXrayClock()
	var busy atomic.Bool
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { child := newFakeXrayChild(true); children <- child; return child, nil }, lock: func() (func(), error) {
		if busy.Load() {
			return nil, errors.New("事务进行中")
		}
		return func() {}, nil
	}})
	defer m.Close()
	if err := m.Apply([]byte("测试配置")); err != nil {
		t.Fatal(err)
	}
	child := receiveChild(t, children)
	for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		child.exit()
		tick := clock.next(t, delay)
		if m.Running() {
			t.Fatal("退出后运行状态应更新")
		}
		tick <- time.Now()
		child = receiveChild(t, children)
	}
	busy.Store(true)
	child.exit()
	clock.next(t, 30*time.Second) <- time.Now()
	tick := clock.next(t, time.Second)
	select {
	case <-children:
		t.Fatal("配置事务进行中不可启动或覆盖磁盘配置")
	default:
	}
	busy.Store(false)
	tick <- time.Now()
	receiveChild(t, children)
}
func TestM15XraySupervisorEscalatesAndRecoversStartFailure(t *testing.T) {
	clock := newFakeXrayClock()
	children := make(chan *fakeXrayChild, 8)
	var attempts atomic.Int32
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) {
		n := attempts.Add(1)
		if n == 2 {
			return nil, errors.New("测试启动失败")
		}
		child := newFakeXrayChild(n != 1)
		children <- child
		return child, nil
	}})
	defer m.Close()
	if err := m.Apply([]byte("旧配置")); err != nil {
		t.Fatal(err)
	}
	original := receiveChild(t, children)
	defer original.exit()
	result := make(chan error, 1)
	go func() { result <- m.Apply([]byte("新配置")) }()
	clock.next(t, 5*time.Second) <- time.Now()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("应报告启动失败")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("重启未完成")
	}
	if original.kills.Load() != 1 {
		t.Fatal("SIGTERM 超时后应 SIGKILL")
	}
	retry := clock.next(t, time.Second)
	// 结束旧进程的等待计时器可能已经失效，最后登记的同长计时器才是启动重试。
	draining := true
	for draining {
		select {
		case timer := <-clock.timers:
			if timer.duration == time.Second {
				retry = timer.tick
			}
		default:
			draining = false
		}
	}
	retry <- time.Now()
	receiveChild(t, children)
	if err := m.Apply([]byte("新配置")); err != nil {
		t.Fatal(err)
	}
	if !m.Running() {
		t.Fatal("启动失败后应退避恢复")
	}
	if err := m.Apply([]byte("旧配置")); err != nil {
		t.Fatal("调用方回退后应能恢复旧配置", err)
	}
	receiveChild(t, children)
}
func TestM15XrayStderrSummaryDoesNotExposeSecrets(t *testing.T) {
	stderr := &xrayStderr{}
	_, _ = stderr.Write([]byte("failed to load config privateKey=" + fixtureRealityKeys(t).PrivateKey + " uuid=" + fixtureBackendUUID))
	summary := stderr.summary()
	if strings.Contains(summary, fixtureBackendUUID) || strings.Contains(summary, fixtureRealityKeys(t).PrivateKey) || !strings.Contains(summary, "配置加载失败") {
		t.Fatal("stderr 摘要不应回显凭据")
	}
}

func TestM15RealityRejectsUnsupportedBackendBeforeProvision(t *testing.T) {
	p := tempSNIPaths(t)
	original := confDir
	confDir = p.conf
	defer func() { confDir = original }()
	for _, link := range []string{strings.Replace(testLink, "type=tcp", "type=ws", 1), strings.Replace(testLink, "xtls-rprx-vision", "unsupported", 1), strings.Replace(testLink, "fp=chrome", "fp=illegal-fingerprint", 1)} {
		body, err := json.Marshal(map[string]string{"domain": "cover.example.com", "link": link})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		realityCreateWithMode(w, adminRequest("POST", "/api/reality", bytes.NewReader(body)), func() bool { return true })
		if w.Code != 400 || strings.Contains(w.Body.String(), testUUID) {
			t.Fatal("不支持的链接必须在写文件和签发证书前安全拒绝", w.Code)
		}
	}
}

func TestM15XrayControlAppliesOnlyAfterReloadRequest(t *testing.T) {
	var starts atomic.Int32
	m := newXraySupervisor(xrayProcessOps{start: func([]byte) (xrayChild, error) { starts.Add(1); return newFakeXrayChild(true), nil }})
	defer m.Close()
	var config []byte
	var readErr error
	handler := xrayControlHandler(m, func() ([]byte, error) { return config, readErr })
	apply := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/apply", nil))
		if w.Code != want || strings.Contains(w.Body.String(), fixtureBackendUUID) {
			t.Fatal("控制接口状态或脱敏错误", w.Code)
		}
	}
	config = []byte("候选配置 A")
	if starts.Load() != 0 {
		t.Fatal("仅写候选配置不能启动进程")
	}
	apply(200)
	if starts.Load() != 1 || !m.Running() {
		t.Fatal("重载请求应应用运行配置")
	}
	apply(200)
	if starts.Load() != 1 {
		t.Fatal("重复请求不应重启")
	}
	config = []byte("候选配置 B")
	readErr = errors.New(fixtureBackendUUID)
	apply(500)
	if starts.Load() != 1 || !m.Running() {
		t.Fatal("读配置失败应保留现有进程")
	}
	readErr = nil
	apply(200)
	if starts.Load() != 2 {
		t.Fatal("配置变化应重启")
	}
	config = nil
	apply(200)
	if m.Running() {
		t.Fatal("空配置应停止")
	}
}

func TestM15AdoptionCannotExposeSecretsOrBypassManagedSitePermissions(t *testing.T) {
	p := tempSNIPaths(t)
	original := confDir
	confDir = p.conf
	defer func() { confDir = original }()
	managed := putMeta(t, p, m15Reality(), "")
	secret := filepath.Join(filepath.Dir(p.conf), "keys.json")
	putTestFile(t, secret, []byte(`{"private_key":"TEST-ONLY-SECRET"}`))
	alias := filepath.Join(p.conf, "alias.conf")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	panel := filepath.Join(p.conf, "relay-panel.conf")
	putTestFile(t, panel, readTestFile(t, "testdata/legacy/panel.conf"))
	for _, test := range []struct {
		source string
		status int
	}{
		{managed, 422}, {panel, 422}, {alias, 400}, {p.conf + "/../keys.json", 400},
	} {
		before := configTree(t, p, true)
		body, err := json.Marshal(map[string]string{"domain": "new.example.com", "upstream": "https://198.51.100.7", "conf_path": test.source})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		sitesAdopt(w, adminRequest("POST", "/api/sites/adopt", bytes.NewReader(body)))
		if w.Code != test.status || strings.Contains(w.Body.String(), "TEST-ONLY-SECRET") {
			t.Fatal("接管接口应在读写机密或变更托管配置前拒绝", w.Code)
		}
		after := configTree(t, p, true)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("拒绝接管后不应改动文件")
		}
	}
}
