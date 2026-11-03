package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func m15Site() SiteMeta {
	return SiteMeta{V: 2, Domain: "site.example.com", Upstream: "https://198.51.100.7:443", Owner: "admin", Created: "2026-11-02T00:00:00Z"}
}
func m15Reality() SiteMeta {
	m := m15Site()
	m.Domain = "cover.example.com"
	m.Reality = &RealityMeta{"198.51.100.7", 443, "入口"}
	return m
}
func requireBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("内容不一致\n实际:\n%s\n预期:\n%s", got, want)
	}
}
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func putTestFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
}
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata/m15", name)
	if os.Getenv("UPDATE_M15_GOLDEN") == "1" {
		putTestFile(t, path, got)
	}
	requireBytes(t, got, readTestFile(t, path))
}
func TestM15TemplatesAndGolden(t *testing.T) {
	for _, sni := range []bool{false, true} {
		site, err := renderSiteMode(m15Site(), "templates", sni)
		if err != nil {
			t.Fatal(err)
		}
		panel, err := renderPanel("panel.example.com", "templates", sni)
		if err != nil {
			t.Fatal(err)
		}
		reality, err := renderSiteMode(m15Reality(), "templates", sni)
		if err != nil {
			t.Fatal(err)
		}
		if !sni {
			requireBytes(t, site, readTestFile(t, "testdata/legacy/site.conf"))
			requireBytes(t, panel, readTestFile(t, "testdata/legacy/panel.conf"))
			if bytes.Contains(reality, []byte("8443")) || bytes.Contains(reality, []byte("ssl_certificate")) {
				t.Fatal("普通模式不应生成 Reality HTTPS 块")
			}
		} else {
			checkGolden(t, "site.conf", site)
			checkGolden(t, "panel.conf", panel)
			checkGolden(t, "reality.conf", reality)
			for name, data := range map[string][]byte{"site": site, "panel": panel, "reality": reality} {
				for _, want := range []string{"listen 127.0.0.1:8443 ssl proxy_protocol;", "set_real_ip_from 127.0.0.1;", "real_ip_header proxy_protocol;"} {
					if !bytes.Contains(data, []byte(want)) {
						t.Errorf("%s 缺少 %s", name, want)
					}
				}
				if listensOn(data, "443") {
					t.Errorf("%s 不应继续监听 443", name)
				}
			}
			requireBytes(t, bytes.Split(site, []byte("\nserver {\n"))[1], bytes.Split(readTestFile(t, "testdata/legacy/site.conf"), []byte("\nserver {\n"))[1])
		}
	}
	data, err := renderSNIDerived([]SiteMeta{m15Reality()})
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"sni.map"} {
		checkGolden(t, name, data[i])
	}
	checkGolden(t, "relay-443.conf", []byte(sni443Config))
	checkGolden(t, sniDefaultName, []byte(sniDefaultConfig))
	// 安装脚本的 sed 路径保持可用，不能残留新增 Go 模板变量。
	out, err := exec.Command("bash", "deploy/render-panel-conf.sh", "panel.example.com", "templates/panel-ssl.conf.tmpl").Output()
	if err != nil {
		t.Fatal(err)
	}
	requireBytes(t, out, readTestFile(t, "testdata/legacy/panel.conf"))
}

func tempSNIPaths(t *testing.T) sniPaths {
	t.Helper()
	root := t.TempDir()
	p := sniPaths{conf: filepath.Join(root, "conf.d"), stream: filepath.Join(root, "stream.d"), backup: filepath.Join(root, "backup"), binary: filepath.Join(root, "sbin/nginx"), nginxConf: filepath.Join(root, "nginx.conf"), templates: "templates"}
	for _, dir := range []string{p.conf, p.stream} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	previousBackup := sniBackupDir
	sniBackupDir = p.backup
	t.Cleanup(func() { sniBackupDir = previousBackup })
	return p
}
func putMeta(t *testing.T, p sniPaths, m SiteMeta, suffix string) string {
	t.Helper()
	path := filepath.Join(p.conf, "relay-"+m.Domain+".conf"+suffix)
	data, err := renderSiteMode(m, "templates", false)
	if err != nil {
		t.Fatal(err)
	}
	putTestFile(t, path, data)
	return path
}
func TestM15Sync(t *testing.T) {
	p := tempSNIPaths(t)
	fs := liveRelayFS()
	writes := 0
	write := fs.write
	fs.write = func(p string, b []byte, m os.FileMode) error { writes++; return write(p, b, m) }
	putMeta(t, p, m15Reality(), "")
	if err := syncSNI443With(p, fs); err != nil || writes != 0 {
		t.Fatal("普通模式必须无操作", err, writes)
	}
	putTestFile(t, p.marker(), []byte(sni443Config))
	a := m15Reality()
	a.Domain = "a.example.com"
	a.Reality = &RealityMeta{"198.51.100.7", 443, ""}
	putMeta(t, p, a, "")
	for i, suffix := range []string{".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		m := m15Reality()
		m.Domain = fmt.Sprintf("off%d.example.com", i)
		m.Reality = &RealityMeta{"198.51.100.9", 443, ""}
		putMeta(t, p, m, suffix)
	}
	putMeta(t, p, m15Site(), "")
	if err := syncSNI443With(p, fs); err != nil {
		t.Fatal(err)
	}
	requireBytes(t, readTestFile(t, p.derived()[0]), []byte("a.example.com 127.0.0.1:30001;\ncover.example.com 127.0.0.1:30001;\n"))
	if writes != 1 {
		t.Fatal(writes)
	}
	if err := syncSNI443With(p, fs); err != nil || writes != 1 {
		t.Fatal("内容不变不应写入", err, writes)
	}
	for _, m := range []SiteMeta{a, m15Reality()} {
		if err := os.Remove(filepath.Join(p.conf, "relay-"+m.Domain+".conf")); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncSNI443With(p, fs); err != nil {
		t.Fatal(err)
	}
	for _, path := range p.derived() {
		requireBytes(t, readTestFile(t, path), []byte{})
	}
	fs.write = func(string, []byte, os.FileMode) error { return errors.New("磁盘故障") }
	putMeta(t, p, m15Reality(), "")
	if err := syncSNI443With(p, fs); err == nil {
		t.Fatal("同步失败必须返回错误")
	}
}
func TestM15DerivedSortingDeduplication(t *testing.T) {
	a := m15Reality()
	b := m15Reality()
	b.Domain = "a.example.com"
	b.Reality = &RealityMeta{"2001:db8::7", 8443, ""}
	first, err := renderSNIDerived([]SiteMeta{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderSNIDerived([]SiteMeta{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("输入顺序和重复项不能改变输出")
	}
	if !bytes.Contains(first[0], []byte("a.example.com 127.0.0.1:30001;")) {
		t.Fatal("所有域名应共用 Xray 入站")
	}

}
func adminRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	return r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxRole, "admin"), ctxKeyID, "admin"))
}
func TestM15RealityHandlersAndReservedPorts(t *testing.T) {
	for _, handler := range []http.HandlerFunc{realityCreate, realityStatus, realityLink} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	// 编辑接口在读取请求体和访问外部服务前拒绝 Reality 入口。
	p := tempSNIPaths(t)
	original := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = original })
	putMeta(t, p, m15Reality(), "")
	r := adminRequest("PUT", "/api/sites/cover.example.com", strings.NewReader(`{"upstream":"https://198.51.100.8"}`))
	r.SetPathValue("domain", "cover.example.com")
	w := httptest.NewRecorder()
	sitesEdit(w, r)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "删除重建") {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, handler := range []http.HandlerFunc{sitesToggle, sitesDelete} {
		r := r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxRole, "user"), ctxKeyID, "admin"))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 403 {
			t.Fatal("Reality 入口只能由管理员操作", w.Code)
		}
	}
	for _, port := range []int{8443, 30000, 30500, 30999} {
		if validateTCPListenPort(port) == nil {
			t.Fatal(port)
		}
	}
}
func TestM15PrivateLinkAndCamouflage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "links")
	if err := saveRealityLinkAt(dir, "cover.example.com", testLink); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "cover.example.com.link"): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal(path, info, err)
		}
	}
	page := filepath.Join(t.TempDir(), "page")
	if err := ensureCamouflageAt(page); err != nil {
		t.Fatal(err)
	}
	b := readTestFile(t, filepath.Join(page, "index.html"))
	for _, word := range []string{"代理", "面板", "vps-relay"} {
		if bytes.Contains(b, []byte(word)) {
			t.Fatal(word)
		}
	}
	putTestFile(t, filepath.Join(page, "index.html"), []byte("原有页面"))
	if err := ensureCamouflageAt(page); err != nil {
		t.Fatal(err)
	}
	requireBytes(t, readTestFile(t, filepath.Join(page, "index.html")), []byte("原有页面"))
}

type migrationHarness struct {
	ops             sniMigrationOps
	checks, reloads int
	verified        []bool
	names           [][]string
	fail            string
	failed          bool
}

func newMigrationHarness(t *testing.T) *migrationHarness {
	t.Helper()
	p := tempSNIPaths(t)
	h := &migrationHarness{}
	h.ops = sniMigrationOps{paths: p, fs: liveRelayFS(), portFree: func(int) bool { return true }, now: time.Now,
		renderSite:  func(m SiteMeta, on bool) ([]byte, error) { return renderSiteMode(m, "templates", on) },
		renderPanel: func(d string, on bool) ([]byte, error) { return renderPanel(d, "templates", on) },
	}
	h.ops.check = func() error { h.checks++; return h.step("check") }
	h.ops.reload = func() error { h.reloads++; return h.step("reload") }
	h.ops.verify = func(on bool, names []string) error {
		h.verified = append(h.verified, on)
		h.names = append(h.names, append([]string{}, names...))
		return h.step("verify")
	}
	putTestFile(t, p.binary, []byte("ELF ssl_preread module"))
	putTestFile(t, p.nginxConf, []byte("stream {\n include stream.d/*.conf;\n}\n"))
	putMeta(t, p, m15Site(), "")
	for i, suffix := range []string{".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		m := m15Site()
		m.Domain = fmt.Sprintf("off%d.example.com", i)
		putMeta(t, p, m, suffix)
	}
	putTestFile(t, filepath.Join(p.conf, "relay-panel.conf"), readTestFile(t, "testdata/legacy/panel.conf"))
	return h
}
func (h *migrationHarness) step(stage string) error {
	if h.fail == stage && !h.failed {
		h.failed = true
		return errors.New("注入失败: " + stage)
	}
	return nil
}

type treeFile struct {
	Data string
	Mode os.FileMode
}

func configTree(t *testing.T, p sniPaths, includeBackup bool) map[string]treeFile {
	t.Helper()
	out := map[string]treeFile{}
	err := filepath.WalkDir(filepath.Dir(p.conf), func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !includeBackup && path == p.backup {
			return filepath.SkipDir
		}
		if e.IsDir() {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		out[path] = treeFile{string(readTestFile(t, path)), info.Mode().Perm()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestM15MigrationEnableDisable(t *testing.T) {
	h := newMigrationHarness(t)
	before := configTree(t, h.ops.paths, false)
	var out bytes.Buffer
	if err := migrateSNI443("enable", h.ops, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if on, err := sniMode(h.ops.paths, h.ops.fs); err != nil || !on {
		t.Fatal(on, err)
	}
	requireBytes(t, readTestFile(t, h.ops.paths.defaultSite()), []byte(sniDefaultConfig))
	if h.checks != 1 || h.reloads != 1 || !reflect.DeepEqual(h.verified, []bool{true}) {
		t.Fatal(h.checks, h.reloads, h.verified)
	}
	if !reflect.DeepEqual(h.names[0], []string{"panel.example.com", "site.example.com"}) {
		t.Fatal(h.names)
	}
	files, err := managedSNIFiles(h.ops.paths, h.ops.fs)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data := readTestFile(t, file.path)
		if !listensOn(data, "8443") || listensOn(data, "443") {
			t.Fatal("所有状态的站点都须重渲染", file.path)
		}
	}
	backups, err := filepath.Glob(filepath.Join(h.ops.paths.backup, "sni443-*/manifest.json"))
	if err != nil || len(backups) != 1 {
		t.Fatal(backups, err)
	}
	var manifest sniManifest
	if err := json.Unmarshal(readTestFile(t, backups[0]), &manifest); err != nil {
		t.Fatal(err)
	}
	created := 0
	for _, s := range manifest.Files {
		if !s.Existed {
			created++
		} else {
			backup := filepath.Join(filepath.Dir(backups[0]), "files", strings.TrimPrefix(s.Path, "/"))
			requireBytes(t, readTestFile(t, backup), []byte(before[s.Path].Data))
		}
	}
	if created != 3 {
		t.Fatal("新文件清单不完整", created)
	}
	// 已开启时不再做前置监听检查或改动文件。
	enabled := configTree(t, h.ops.paths, true)
	h.ops.portFree = func(int) bool { t.Fatal("幂等 enable 不应检查端口"); return false }
	if err := migrateSNI443("enable", h.ops, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(enabled, configTree(t, h.ops.paths, true)) {
		t.Fatal("幂等操作修改了文件")
	}
	if err := migrateSNI443("disable", h.ops, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
		t.Fatal("disable 未恢复传统输出")
	}
	if !reflect.DeepEqual(h.verified, []bool{true, false}) {
		t.Fatal(h.verified)
	}
}
func TestM15MigrationRollback(t *testing.T) {
	for _, action := range []string{"enable", "disable"} {
		for _, stage := range []string{"check", "reload", "verify", "write"} {
			t.Run(action+"/"+stage, func(t *testing.T) {
				h := newMigrationHarness(t)
				if action == "disable" {
					if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
						t.Fatal(err)
					}
				}
				before := configTree(t, h.ops.paths, false)
				h.fail = stage
				if stage == "write" {
					write := h.ops.fs.write
					h.ops.fs.write = func(path string, b []byte, m os.FileMode) error {
						if strings.HasPrefix(path, h.ops.paths.conf+"/") && !h.failed {
							h.failed = true
							return errors.New("注入写入失败")
						}
						return write(path, b, m)
					}
				}
				oldReloads := h.reloads
				var out bytes.Buffer
				if err := migrateSNI443(action, h.ops, &out); err == nil {
					t.Fatal("应返回原始迁移错误")
				}
				if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
					t.Fatal("回退未逐字节恢复原文件或删除新文件")
				}
				if h.reloads <= oldReloads || h.verified[len(h.verified)-1] != (action == "disable") {
					t.Fatal("回退必须重载并核验旧模式", h.reloads, h.verified)
				}
				if !strings.Contains(out.String(), "已还原") {
					t.Fatal(out.String())
				}
			})
		}
	}
}
func TestM15MigrationPreflightNoWrites(t *testing.T) {
	for _, condition := range []string{"binary", "include", "port", "unmanaged-ipv4", "unmanaged-ipv6", "unmanaged-address", "unmanaged-quoted"} {
		t.Run(condition, func(t *testing.T) {
			h := newMigrationHarness(t)
			switch condition {
			case "binary":
				putTestFile(t, h.ops.paths.binary, []byte("ELF"))
			case "include":
				putTestFile(t, h.ops.paths.nginxConf, []byte("# include stream.d/*.conf;\n"))
			case "port":
				h.ops.portFree = func(int) bool { return false }
			default:
				address := map[string]string{"unmanaged-ipv4": "443", "unmanaged-ipv6": "[::]:443", "unmanaged-address": "203.0.113.9:443", "unmanaged-quoted": `"443"`}[condition]
				putTestFile(t, filepath.Join(h.ops.paths.conf, "custom.conf"), []byte("server { listen "+address+" ssl; }\n"))
			}
			before := configTree(t, h.ops.paths, true)
			if err := migrateSNI443("enable", h.ops, io.Discard); err == nil {
				t.Fatal("应拒绝迁移")
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, true)) {
				t.Fatal("前置检查失败不允许写文件")
			}
			if h.checks != 0 || h.reloads != 0 {
				t.Fatal(h.checks, h.reloads)
			}
		})
	}
}
func TestM15MigrationHTTPPanelUntouched(t *testing.T) {
	h := newMigrationHarness(t)
	path := filepath.Join(h.ops.paths.conf, "relay-panel.conf")
	original := []byte("server { listen 80; server_name panel.example.com; }\n")
	putTestFile(t, path, original)
	for _, action := range []string{"enable", "disable"} {
		if err := migrateSNI443(action, h.ops, io.Discard); err != nil {
			t.Fatal(err)
		}
		requireBytes(t, readTestFile(t, path), original)
	}
}
func TestM15MigrationRefusesAnyRealityState(t *testing.T) {
	for _, suffix := range []string{"", ".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		t.Run(suffix, func(t *testing.T) {
			h := newMigrationHarness(t)
			if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
				t.Fatal(err)
			}
			putMeta(t, h.ops.paths, m15Reality(), suffix)
			before := configTree(t, h.ops.paths, true)
			if err := migrateSNI443("disable", h.ops, io.Discard); err == nil {
				t.Fatal("必须拒绝含 Reality 入口的回退")
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, true)) {
				t.Fatal("拒绝回退不能改文件")
			}
			var out bytes.Buffer
			if err := migrateSNI443("status", h.ops, &out); err != nil || !strings.Contains(out.String(), "1 个") {
				t.Fatal(err, out.String())
			}
		})
	}
}
func TestM15MigrationBackupFailureNoMutation(t *testing.T) {
	h := newMigrationHarness(t)
	before := configTree(t, h.ops.paths, false)
	write := h.ops.fs.write
	h.ops.fs.write = func(p string, b []byte, m os.FileMode) error {
		if strings.HasPrefix(p, h.ops.paths.backup+"/") {
			return errors.New("备份失败")
		}
		return write(p, b, m)
	}
	if err := migrateSNI443("enable", h.ops, io.Discard); err == nil {
		t.Fatal("备份失败必须终止")
	}
	if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
		t.Fatal("备份失败不能修改源配置")
	}
}

func TestM15RealityEditAllStates(t *testing.T) {
	for _, suffix := range []string{".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		t.Run(suffix, func(t *testing.T) {
			p := tempSNIPaths(t)
			original := confDir
			confDir = p.conf
			defer func() { confDir = original }()
			putMeta(t, p, m15Reality(), suffix)
			r := adminRequest("PUT", "/", strings.NewReader(`{}`))
			r.SetPathValue("domain", "cover.example.com")
			w := httptest.NewRecorder()
			sitesEdit(w, r)
			if w.Code != 422 || !strings.Contains(w.Body.String(), "删除重建") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
func TestM15RealityDeleteCleanupAndRollback(t *testing.T) {
	p := tempSNIPaths(t)
	fs := liveRelayFS()
	putTestFile(t, p.marker(), []byte(sni443Config))
	path := putMeta(t, p, m15Reality(), "")
	if err := syncSNI443With(p, fs); err != nil {
		t.Fatal(err)
	}
	meta, err := readSiteMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(meta.Reality, m15Reality().Reality) {
		t.Fatal("Reality 元数据未保留")
	}
	failCheck := true
	failLink := false
	linkExists := true
	ops := siteLifecycle{rename: os.Rename, remove: os.Remove, syncDerived: func() error { return syncSNI443With(p, fs) },
		check: func() error {
			if err := syncSNI443With(p, fs); err != nil {
				return err
			}
			if failCheck {
				return errors.New("检查失败")
			}
			return nil
		}, reload: func() error { return syncSNI443With(p, fs) },
		removeLink: func(string) error {
			if failLink {
				return errors.New("清理失败")
			}
			linkExists = false
			return nil
		},
	}
	if err := removeManagedSite(meta, "", path, false, ops); err == nil {
		t.Fatal("应报告检查失败")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("检查失败应还原活动文件", err)
	}
	if !bytes.Contains(readTestFile(t, p.derived()[0]), []byte(meta.Domain)) {
		t.Fatal("检查失败回退应立即恢复派生映射")
	}
	failCheck = false
	failLink = true
	if err := removeManagedSite(meta, "", path, false, ops); err == nil {
		t.Fatal("应报告链接清理失败")
	}
	if _, err := os.Stat(path + tcpDeleteSuffix); err != nil {
		t.Fatal("清理失败须保留待删除配置", err)
	}
	if !linkExists || len(readTestFile(t, p.derived()[0])) != 0 {
		t.Fatal("链接应保留且路由应停止")
	}
	failLink = false
	if err := removeManagedSite(meta, "", path, true, ops); err != nil {
		t.Fatal(err)
	}
	if linkExists {
		t.Fatal("删除成功应清理链接")
	}
	if _, err := os.Stat(path + tcpDeleteSuffix); !os.IsNotExist(err) {
		t.Fatal("备份未清理", err)
	}
}
func TestM15DirectoryLockNoFileMutation(t *testing.T) {
	p := tempSNIPaths(t)
	before := configTree(t, p, true)
	unlock, err := lockConfigDirectory(p.conf)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockConfigDirectory(p.conf); err == nil {
		second()
		t.Fatal("独立文件描述符不能同时取得目录锁")
	}
	unlock()
	third, err := lockConfigDirectory(p.conf)
	if err != nil {
		t.Fatal(err)
	}
	third()
	if !reflect.DeepEqual(before, configTree(t, p, true)) {
		t.Fatal("加锁不能创建或改写文件")
	}
}

func TestM15RealityHiddenFromOrdinaryUsers(t *testing.T) {
	p := tempSNIPaths(t)
	original := confDir
	confDir = p.conf
	defer func() { confDir = original }()
	putMeta(t, p, m15Reality(), "")
	sites, _, err := scanSites("admin", false)
	if err != nil || len(sites) != 0 {
		t.Fatal("普通用户不应看到 Reality 入口", err)
	}
}
func TestM15RealityModePrecondition(t *testing.T) {
	tempSNIPaths(t)
	w := httptest.NewRecorder()
	realityCreateWithMode(w, adminRequest("POST", "/api/reality", strings.NewReader(`{}`)), func() bool { return false })
	if w.Code != 412 || !strings.Contains(w.Body.String(), "sni443 enable") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestM15ListenParsing(t *testing.T) {
	for _, conf := range []string{
		`server { listen "443" ssl; }`,
		`server { listen '[::]:443' ssl; }`,
		`server { server_name "a#b"; listen 443 ssl; }`,
		"# listen 80;\nserver { listen\n443 ssl; }",
	} {
		if !listensOn([]byte(conf), "443") {
			t.Fatal("应识别 443 监听", conf)
		}
	}
	for _, conf := range []string{
		"# listen 443;\nserver { listen 8443 ssl; }",
		`log_format x "listen 443;"; server { listen 80; }`,
		`server { set $x listen; listen 8443; }`,
	} {
		if listensOn([]byte(conf), "443") {
			t.Fatal("不应把注释或字符串识别为监听", conf)
		}
	}
}
