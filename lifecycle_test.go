package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeLifecycle struct {
	ops                               siteLifecycle
	files                             map[string][]byte
	checks, reloads, cleanups, writes int
	failStage                         string
	existingCertificate               bool
	f                                 *fakeCF
	t                                 *testing.T
}

func newFakeLifecycle(t *testing.T, f *fakeCF) *fakeLifecycle {
	l := &fakeLifecycle{files: map[string][]byte{}, f: f, t: t}
	l.ops = siteLifecycle{
		certificateExists: func(string, string) bool { return l.existingCertificate },
		issue: func(string, string, string) error {
			_, writes := f.snapshot()
			if len(writes) != 0 {
				t.Fatal("证书准备前不应改 DNS")
			}
			if l.failStage == "issue" {
				return errors.New("模拟签发失败")
			}
			return nil
		},
		cleanup: func(string, string, string) error {
			l.cleanups++
			if l.failStage == "cleanup" {
				return errors.New("模拟部分清理后失败")
			}
			return nil
		},
		render: func(meta SiteMeta) ([]byte, error) { return json.Marshal(meta) },
		write: func(path string, b []byte, _ os.FileMode) error {
			l.writes++
			if l.failStage == "write" && l.writes == 1 || l.failStage == "commit" && l.writes == 2 {
				return errors.New("模拟落盘失败")
			}
			l.files[path] = append([]byte(nil), b...)
			return nil
		},
		remove: func(path string) error { delete(l.files, path); return nil },
		rename: func(from, to string) error {
			b, ok := l.files[from]
			if !ok {
				return os.ErrNotExist
			}
			l.files[to] = b
			delete(l.files, from)
			return nil
		},
		check: func() error {
			l.checks++
			if l.failStage == "check" {
				return errors.New("模拟配置错误")
			}
			return nil
		},
		reload: func() error {
			l.reloads++
			if l.reloads == 1 {
				_, writes := f.snapshot()
				if len(writes) != 0 && l.failStage != "delete-reload" {
					t.Fatal("首次加载反代前不应改 DNS")
				}
				if l.failStage == "reload" || l.failStage == "delete-reload" {
					return errors.New("模拟重载失败")
				}
			}
			return nil
		},
	}
	return l
}

func testMeta() SiteMeta {
	return SiteMeta{V: 2, Domain: originRecord.Name, Upstream: "https://23.95.8.179", Owner: "admin"}
}

func TestPartialCertificateCleanupKeepsInactiveRecoveryForRetry(t *testing.T) {
	f := newFakeCF(t, originRecord)
	l := newFakeLifecycle(t, f)
	meta, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
	if err != nil {
		t.Fatal(err)
	}
	path := confPath(meta.Domain)
	l.failStage = "cleanup"
	if err = removeManagedSite(meta, "token", path, false, l.ops); err == nil {
		t.Fatal("应报告部分清理失败")
	}
	if _, ok := l.files[path]; ok {
		t.Fatal("禁止恢复可能引用缺失证书的活动配置")
	}
	if _, ok := l.files[path+".relay-delete.bak"]; !ok {
		t.Fatal("缺少删除恢复信息")
	}
	l.failStage = ""
	if err = removeManagedSite(meta, "token", path, true, l.ops); err != nil {
		t.Fatal(err)
	}
	if len(l.files) != 0 {
		t.Fatal("重试未完成清理", l.files)
	}
}

func TestPendingDeletePathRemainsDiscoverable(t *testing.T) {
	for _, suffix := range []string{"", ".disabled"} {
		t.Run(suffix, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "relay-pending.conf")
			backup := base + suffix + ".relay-delete.bak"
			if err := os.WriteFile(backup, []byte("恢复信息"), 0600); err != nil {
				t.Fatal(err)
			}
			path, staged, err := resolveSiteDeletePath(base)
			if err != nil || !staged || path != base+suffix {
				t.Fatal(path, staged, err)
			}
		})
	}
}

func TestProvisionStagesAndRollbackPreserveOrigin(t *testing.T) {
	for _, stage := range []string{"issue", "write", "check", "reload", "patch", "commit", "lost-patch-response"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeCF(t, originRecord)
			l := newFakeLifecycle(t, f)
			l.failStage = stage
			f.mu.Lock()
			f.failPatch = stage == "patch"
			f.losePatchResponse = stage == "lost-patch-response"
			f.mu.Unlock()
			_, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
			if err == nil {
				t.Fatal("应返回阶段错误")
			}
			records, _ := f.snapshot()
			if len(records) != 1 || !sameRecord(records[originRecord.ID], originRecord) {
				t.Fatalf("破坏了原记录: %+v", records)
			}
			if len(l.files) != 0 {
				t.Fatalf("回滚后残留配置: %v", l.files)
			}
		})
	}
}

func TestProvisionSuccessStoresRecoveryBeforeSwitch(t *testing.T) {
	f := newFakeCF(t, originRecord)
	l := newFakeLifecycle(t, f)
	meta, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
	if err != nil {
		t.Fatal(err)
	}
	if meta.DNS == nil || meta.DNS.Pending || meta.CFRecordID != originRecord.ID || !sameRecord(*meta.DNS.Before, originRecord) {
		t.Fatalf("恢复信息不完整: %+v", meta)
	}
	var saved SiteMeta
	if err = json.Unmarshal(l.files[confPath(meta.Domain)], &saved); err != nil {
		t.Fatal(err)
	}
	if saved.DNS.Pending || saved.DNS.Before.Content != originRecord.Content {
		t.Fatal(saved.DNS)
	}
	if l.reloads != 1 || l.cleanups != 0 {
		t.Fatal(l.reloads, l.cleanups)
	}
}

func TestReusedDNSAndExistingCertificateSurviveFailure(t *testing.T) {
	rec := originRecord
	rec.Content = "38.6.76.28"
	f := newFakeCF(t, rec)
	l := newFakeLifecycle(t, f)
	l.existingCertificate = true
	l.failStage = "commit"
	if _, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops); err == nil {
		t.Fatal("应报告落盘失败")
	}
	records, writes := f.snapshot()
	if len(records) != 1 || len(writes) != 0 || l.cleanups != 0 {
		t.Fatal(records, writes, l.cleanups)
	}
}

func TestUncertainCreateKeepsRecoverableConfiguration(t *testing.T) {
	f := newFakeCF(t)
	l := newFakeLifecycle(t, f)
	f.mu.Lock()
	f.loseCreateResponse = true
	f.mu.Unlock()
	_, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
	if err == nil || !strings.Contains(err.Error(), "结果不确定") {
		t.Fatal(err)
	}
	records, _ := f.snapshot()
	if len(records) != 1 || len(l.files) != 1 || l.cleanups != 0 {
		t.Fatal(records, l.files, l.cleanups)
	}
}

func TestDeleteDNSFailureCanBeRetried(t *testing.T) {
	f := newFakeCF(t, originRecord)
	l := newFakeLifecycle(t, f)
	meta, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failPatch = true
	f.mu.Unlock()
	if err = removeManagedSite(meta, "token", confPath(meta.Domain), false, l.ops); err == nil {
		t.Fatal("应报告恢复失败")
	}
	if len(l.files) != 1 || l.cleanups != 0 {
		t.Fatal("恢复失败应保留现场")
	}
	f.mu.Lock()
	f.failPatch = false
	f.mu.Unlock()
	if err = removeManagedSite(meta, "token", confPath(meta.Domain), false, l.ops); err != nil {
		t.Fatal(err)
	}
	records, _ := f.snapshot()
	if len(l.files) != 0 || !sameRecord(records[originRecord.ID], originRecord) {
		t.Fatal(records, l.files)
	}
}

func TestDeleteReloadFailureRestoresConfigurationForRetry(t *testing.T) {
	f := newFakeCF(t, originRecord)
	l := newFakeLifecycle(t, f)
	meta, err := provisionSite(testMeta(), "token", "38.6.76.28", testZone, l.ops)
	if err != nil {
		t.Fatal(err)
	}
	l.reloads = 0
	l.failStage = "delete-reload"
	if err = removeManagedSite(meta, "token", confPath(meta.Domain), false, l.ops); err == nil {
		t.Fatal("应报告重载失败")
	}
	if _, ok := l.files[confPath(meta.Domain)]; !ok || l.cleanups != 0 {
		t.Fatal("应保留配置和证书")
	}
	l.failStage = ""
	l.reloads = 1
	if err = removeManagedSite(meta, "token", confPath(meta.Domain), false, l.ops); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySiteDeletionKeepsUnknownDNSAndCertificates(t *testing.T) {
	f := newFakeCF(t, originRecord)
	l := newFakeLifecycle(t, f)
	meta := testMeta()
	meta.V = 1
	meta.CFRecordID = originRecord.ID
	meta.CFZone = testZone.Name
	l.files[confPath(meta.Domain)] = []byte("旧配置")
	if err := removeManagedSite(meta, "", confPath(meta.Domain), false, l.ops); err != nil {
		t.Fatal(err)
	}
	records, writes := f.snapshot()
	if len(records) != 1 || len(writes) != 0 || l.cleanups != 0 {
		t.Fatal(records, writes, l.cleanups)
	}
}

func TestTemplatePreservesDNSMetadataAcrossEdit(t *testing.T) {
	original := originRecord
	meta := testMeta()
	meta.DNS = &DNSChange{Mode: "replaced", ZoneID: testZone.ID, Before: &original, After: original}
	meta.Upstream = "https://23.95.8.179"
	meta.Owner = "ad\"min中文" // 上游已禁止参数，改用 Owner 覆盖元数据转义
	data, err := renderSiteWithTemplate(meta, "templates/site.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay-test.conf")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := readSiteMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Upstream != meta.Upstream || saved.DNS == nil || !sameRecord(*saved.DNS.Before, original) {
		t.Fatalf("元数据丢失: %+v", saved)
	}
	if !strings.Contains(string(data), "proxy_pass https://23.95.8.179:443;") || !strings.Contains(string(data), "proxy_ssl_name        $host;") {
		t.Fatal("IP 上游应保留入口 Host/SNI 并默认 443")
	}
}
