package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 直接复用假 CF 的处理器，不监听端口，覆盖远程写成功但响应丢失的路径。
func sixthMemoryCF(t *testing.T, records ...cfRecord) *fakeCF {
	t.Helper()
	f := &fakeCF{records: map[string]cfRecord{}}
	for _, record := range records {
		f.records[record.ID] = record
	}
	previous := cfClient
	cfClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		f.serveHTTP(w, r)
		return w.Result(), nil
	})}
	t.Cleanup(func() { cfClient = previous })
	return f
}

func sixthSiteOps() siteLifecycle {
	ops := liveSiteLifecycle()
	ops.issue, ops.cleanup = func(string, string, string) error { return nil }, func(string, string, string) error { return nil }
	ops.certificateExists = func(string, string) bool { return true }
	ops.render = func(meta SiteMeta) ([]byte, error) { return renderSiteMode(meta, "templates", false) }
	ops.check, ops.reload = func() error { return nil }, func() error { return nil }
	return ops
}

func sixthInterrupt(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if value := recover(); value != "模拟被杀" {
			t.Fatalf("未在指定边界中断: %v", value)
		}
	}()
	run()
}

func TestM15BoundaryDeleteCommittedCertificateNeverRestoresActiveSite(t *testing.T) {
	for _, failure := range []string{"cleanup", "backup", "killed", "killed-backup", "killed-cert-commit"} {
		t.Run(failure, func(t *testing.T) {
			p, journal := operationPaths(t)
			meta := m15Site()
			meta.CertificateOwned = true
			path := putMeta(t, p, meta, "")
			home, certRoot := filepath.Join(t.TempDir(), "acme"), filepath.Join(t.TempDir(), "ssl")
			certPath := filepath.Join(certRoot, meta.Domain)
			putTestFile(t, filepath.Join(home, meta.Domain+"_ecc", meta.Domain+".conf"), []byte("Le_ReloadCmd='old'\n"))
			putTestFile(t, filepath.Join(certPath, "fullchain.pem"), []byte("old certificate"))
			putTestFile(t, filepath.Join(certPath, "key.pem"), []byte("old key"))
			unlock, ok := lockSiteRequest(httptest.NewRecorder())
			if !ok {
				t.Fatal("无法取得配置锁")
			}
			ops := sixthSiteOps()
			// 模拟全局 nginx -t：活动配置不能引用已经删除的证书。
			check := func() error {
				if _, err := os.Stat(path); err == nil {
					if _, err := os.Stat(certPath); err != nil {
						return errors.New("活动站点引用缺失证书")
					}
				}
				return nil
			}
			ops.check, ops.reload = check, check
			ops.cleanup = func(domain, _, _ string) error {
				assertNoOperationLog(t, journal)
				certOps := liveACMETransactionOps()
				certOps.prepare, certOps.commit = beginNginxMutation, commitNginxMutation
				certOps.reload = check
				certOps.step = func(step string) {
					if step == "done" && failure == "killed-cert-commit" {
						assertNoOperationLog(t, journal)
						panic("模拟被杀")
					}
				}
				certOps.run = func(_ []string, env []string, _ io.Reader) error {
					for _, value := range env {
						if strings.HasPrefix(value, "VPS_RELAY_CERT_STAGE=") {
							if err := os.RemoveAll(strings.TrimPrefix(value, "VPS_RELAY_CERT_STAGE=")); err != nil {
								return err
							}
						}
						if strings.HasPrefix(value, "ACME_HOME=") {
							if err := os.RemoveAll(filepath.Join(strings.TrimPrefix(value, "ACME_HOME="), domain+"_ecc")); err != nil {
								return err
							}
						}
					}
					return nil
				}
				if err := runACMETransaction(domain, "remove", home, certRoot, p.backup, []string{"fake"}, nil, nil, certOps); err != nil {
					return err
				}
				assertNoOperationLog(t, journal)
				manifests, _ := filepath.Glob(filepath.Join(p.backup, "acme-*", "manifest.json"))
				if len(manifests) != 1 {
					t.Fatal("缺少证书提交清单")
				}
				var record acmeTransaction
				if err := json.Unmarshal(readTestFile(t, manifests[0]), &record); err != nil || record.State != "done" {
					t.Fatal("证书未提交", err)
				}
				for _, target := range record.Targets {
					if _, err := os.Stat(target.Backup); !os.IsNotExist(err) {
						t.Fatal("证书备份尚未永久删除", err)
					}
				}
				if failure == "killed" {
					panic("模拟被杀")
				}
				if failure == "cleanup" {
					return errors.New("子事务提交后清理失败")
				}
				return nil
			}
			if failure == "backup" || failure == "killed-backup" {
				ops.discardBackup = func(string) error {
					assertNoOperationLog(t, journal)
					if failure == "killed-backup" {
						panic("模拟被杀")
					}
					return errors.New("清理恢复元数据失败")
				}
			}
			if strings.HasPrefix(failure, "killed") {
				sixthInterrupt(t, func() { _ = removeManagedSite(meta, "", path, false, ops) })
			} else if err := removeManagedSite(meta, "", path, false, ops); err == nil {
				unlock()
				t.Fatal("后续清理失败应返回错误")
			}
			// 不执行统一完成出口，模拟父进程被杀；边界后清理不得重新开启父日志。
			activeNginxOperation.Store(nil)
			unlock()
			assertNoOperationLog(t, journal)
			if err := recoverACMETransactions(p.backup, check, beginNginxMutation); err != nil {
				t.Fatal(err)
			}
			if err := reconcileNginxWith(journal, check); err != nil {
				t.Fatal("已提交证书删除不得使后续写入永久阻塞", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("不得复活引用已删除证书的活动配置", err)
			}
			if _, err := os.Stat(path + tcpDeleteSuffix); err != nil {
				t.Fatal("应保留删除恢复元数据供重试", err)
			}
			w := httptest.NewRecorder()
			nextUnlock, ok := lockSiteRequest(w)
			if !ok {
				t.Fatal("后续写操作被阻塞", w.Body.String())
			}
			nextUnlock()
		})
	}
}

func TestM15BoundaryDNSRollbackFailureKeepsSiteAndSecrets(t *testing.T) {
	for _, mode := range []string{"uncertain-create", "failed-restore", "killed-during-dns", "killed-before-retain-write", "killed-after-metadata-write"} {
		t.Run(mode, func(t *testing.T) {
			p, journal := operationPaths(t)
			f := sixthMemoryCF(t)
			if mode == "failed-restore" {
				f.records[originRecord.ID] = originRecord
			} else {
				f.loseCreateResponse = mode == "uncertain-create" || mode == "killed-before-retain-write"
			}
			meta := testMeta()
			meta.Reality = &RealityMeta{UpstreamHost: "23.95.8.179", UpstreamPort: 443}
			ops := sixthSiteOps()
			writes := 0
			ops.write = func(path string, data []byte, modeBits os.FileMode) error {
				writes++
				if writes == 2 && mode == "failed-restore" {
					f.failPatch = true
					return errors.New("DNS 已生效，元数据更新失败")
				}
				if writes == 2 && mode == "killed-before-retain-write" {
					panic("模拟被杀")
				}
				if writes == 1 {
					return writeNginxFile(path, data, modeBits)
				}
				if err := atomicWrite(path, data, modeBits); err != nil {
					return err
				}
				if mode == "killed-after-metadata-write" {
					panic("模拟被杀")
				}
				return nil
			}
			ops.writeMetadata = ops.write
			if mode == "killed-during-dns" {
				original := cfClient.Transport
				cfClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := original.RoundTrip(r)
					if r.Method == "POST" {
						_ = response.Body.Close()
						panic("模拟被杀")
					}
					return response, err
				})
			}
			op := startNginxOperation(false)
			defer op.close()
			if err := beginNginxMutation(); err != nil {
				t.Fatal(err)
			}
			var created SiteMeta
			var err error
			run := func() { created, err = provisionSite(meta, "token", "38.6.76.28", testZone, ops) }
			if strings.HasPrefix(mode, "killed") {
				sixthInterrupt(t, run)
			} else {
				run()
				if !errors.Is(err, errSiteRetained) {
					t.Fatal("必须向 Reality 外层传递保留现场语义", err)
				}
				if err := cleanupRealityProvisionFailure(created.Domain, err, func(string) error {
					t.Fatal("DNS 恢复失败时不得删除入口配置和机密")
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertNoOperationLog(t, journal)
			path := confPath(meta.Domain)
			before := readTestFile(t, path)
			if err := reconcileNginxWith(journal, func() error { t.Fatal("保留现场不能再恢复旧快照"); return nil }); err != nil {
				t.Fatal(err)
			}
			requireBytes(t, readTestFile(t, path), before)
			saved, err := readSiteMeta(path)
			if err != nil || saved.DNS == nil || saved.DNS.After.Content != "38.6.76.28" {
				t.Fatal("恢复元数据丢失", err)
			}
			if mode == "failed-restore" && (saved.DNS.Before == nil || saved.DNS.Before.Content != originRecord.Content) {
				t.Fatal("原始 DNS 快照丢失")
			}
			if mode == "killed-after-metadata-write" && (saved.DNS.Pending || saved.DNS.After.ID == "") {
				t.Fatal("不能用旧快照撤销已保存的远程记录 ID")
			}
			records, _ := f.snapshot()
			for _, record := range records {
				if record.Content != "38.6.76.28" {
					t.Fatal("未覆盖远程写入已生效的失败链")
				}
			}
			if len(records) != 1 {
				t.Fatal(records, p)
			}
		})
	}
}

func TestM15BoundaryTCPSecretCleanupCannotRestoreForward(t *testing.T) {
	for _, killed := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "killed"}[killed], func(t *testing.T) {
			p, journal := operationPaths(t)
			path := filepath.Join(p.conf, filepath.Base(tcpConfPath(24443)))
			putTestFile(t, path, []byte("active forward"))
			link := filepath.Join(t.TempDir(), "link")
			putTestFile(t, link, []byte("private link"))
			mapPath := func(path string) string { return filepath.Join(p.conf, filepath.Base(path)) }
			ops := newFakeTCPOps().ops()
			ops.rename = func(from, to string) error { return renameNginxFile(mapPath(from), mapPath(to)) }
			ops.remove = func(path string) error { return removeNginxFile(mapPath(path)) }
			ops.commit = commitNginxMutation
			ops.removeLink = func(int) error {
				assertNoOperationLog(t, journal)
				if err := os.Remove(link); err != nil {
					return err
				}
				if killed {
					panic("模拟被杀")
				}
				return errors.New("链接删除后清理失败")
			}
			if killed {
				sixthInterrupt(t, func() { _ = removeTCPForward(24443, false, ops) })
			} else if err := removeTCPForward(24443, false, ops); err == nil {
				t.Fatal("应报告清理失败")
			}
			assertNoOperationLog(t, journal)
			if err := reconcileNginxWith(journal, func() error { t.Fatal("不能恢复已停止的转发"); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("复活了已删除链接的 TCP 转发")
			}
		})
	}
}

func TestM15BoundaryFailedRealityCleanupLoadsIsolationBeforeDeletingSecrets(t *testing.T) {
	for _, failure := range []string{"reload", "cleanup", "killed"} {
		t.Run(failure, func(t *testing.T) {
			p, journal := operationPaths(t)
			domain := "reality.example.com"
			path := filepath.Join(p.conf, "relay-"+domain+".conf")
			putTestFile(t, path, []byte("active reality"))
			secrets := filepath.Join(t.TempDir(), "entry.json")
			putTestFile(t, secrets, []byte("secret"))
			loadedIsolation := false
			cleanup := func() error {
				return cleanupFailedRealityWith(domain, resolveSiteDeletePath, renameNginxFile, func(string) error {
					assertNoOperationLog(t, journal)
					if !loadedIsolation {
						t.Fatal("机密删除早于隔离配置的重载")
					}
					if err := os.Remove(secrets); err != nil {
						return err
					}
					if failure == "killed" {
						panic("模拟被杀")
					}
					return errors.New("部分机密已删除")
				}, func() error {
					if failure == "reload" {
						return errors.New("隔离重载失败")
					}
					loadedIsolation = true
					return nil
				})
			}
			if failure == "killed" {
				sixthInterrupt(t, func() { _ = cleanup() })
			} else if err := cleanup(); err == nil {
				t.Fatal("应报告失败")
			}
			if failure == "reload" {
				if _, err := os.Stat(secrets); err != nil {
					t.Fatal("不可回头点之前失败必须保留机密", err)
				}
				if err := reconcileNginxWith(journal, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				requireBytes(t, readTestFile(t, path), []byte("active reality"))
			} else {
				assertNoOperationLog(t, journal)
				if err := reconcileNginxWith(journal, func() error { t.Fatal("已删除机密的入口不能复活"); return nil }); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestM15BoundaryMigrationEndsGeneralJournalBeforeManifest(t *testing.T) {
	for _, failVerify := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable-disable", true: "recover"}[failVerify], func(t *testing.T) {
			h := newMigrationHarness(t)
			previous := confDir
			confDir = h.ops.paths.conf
			t.Cleanup(func() { confDir = previous })
			journal := nginxPendingPath()
			h.ops.commit = commitNginxMutation
			verify := h.ops.verify
			h.ops.verify = func(on bool, domains []string) error {
				if err := beginNginxMutation(); err != nil {
					return err
				}
				return verify(on, domains)
			}
			write := h.ops.fs.write
			finished := 0
			h.ops.fs.write = func(path string, data []byte, mode os.FileMode) error {
				if filepath.Base(path) == "manifest.json" {
					var record sniManifest
					if err := json.Unmarshal(data, &record); err != nil {
						return err
					}
					if record.State == "done" || record.State == "recovered" {
						assertNoOperationLog(t, journal)
						finished++
					}
				}
				return write(path, data, mode)
			}
			if failVerify {
				h.fail = "verify"
			}
			err := migrateSNI443("enable", h.ops, io.Discard)
			if failVerify {
				if err == nil || finished != 1 {
					t.Fatal("失败后恢复清单未与通用日志分离", err, finished)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := migrateSNI443("disable", h.ops, io.Discard); err != nil || finished != 2 {
					t.Fatal(err, finished)
				}
			}
			assertNoOperationLog(t, journal)
		})
	}
}

func TestM15BoundaryRealityReadinessRollbackKeepsSiteWhenDNSReleaseFails(t *testing.T) {
	p, journal := operationPaths(t)
	f := sixthMemoryCF(t, originRecord)
	meta := testMeta()
	meta.Reality = &RealityMeta{UpstreamHost: "23.95.8.179", UpstreamPort: 443}
	ops := sixthSiteOps()
	created, err := provisionRealityWith(meta, func(meta SiteMeta) (SiteMeta, error) {
		return provisionSite(meta, "token", "38.6.76.28", testZone, ops)
	}, func() error {
		f.failPatch = true
		return errors.New("Xray 未就绪")
	}, func(meta SiteMeta) error {
		return removeManagedSite(meta, "token", confPath(meta.Domain), false, ops)
	})
	if !errors.Is(err, errSiteRetained) {
		t.Fatal("就绪回滚中的 DNS 失败也必须保留入口", err)
	}
	if err := cleanupRealityProvisionFailure(created.Domain, err, func(string) error {
		t.Fatal("不得在 DNS 仍指向边缘时删除入口机密")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertNoOperationLog(t, journal)
	if err := reconcileNginxWith(journal, func() error { t.Fatal("不能撤销保留现场"); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := readSiteMeta(filepath.Join(p.conf, "relay-"+meta.Domain+".conf")); err != nil {
		t.Fatal("丢失了恢复元数据", err)
	}
}

func TestM15BoundaryCannotCommitStopsCertificateDeletion(t *testing.T) {
	p, journal := operationPaths(t)
	meta := m15Site()
	meta.CertificateOwned = true
	path := putMeta(t, p, meta, "")
	ops := sixthSiteOps()
	ops.commit = func() error { return errors.New("日志无法删除") }
	ops.cleanup = func(string, string, string) error {
		t.Fatal("边界提交失败不能开始永久删除证书")
		return nil
	}
	if err := removeManagedSite(meta, "", path, false, ops); err == nil {
		t.Fatal("无法结束日志必须返回错误")
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("不可回头点之前失败必须保留可恢复日志", err)
	}
	if err := reconcileNginxWith(journal, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("尚未删除证书时应能恢复活动配置", err)
	}
}

func TestM15BoundaryTCPBackupCleanupDoesNotReopenJournal(t *testing.T) {
	for _, failure := range []string{"none", "error", "killed"} {
		t.Run(failure, func(t *testing.T) {
			p, journal := operationPaths(t)
			path := filepath.Join(p.conf, filepath.Base(tcpConfPath(24443)))
			putTestFile(t, path, []byte("active forward"))
			mapPath := func(path string) string { return filepath.Join(p.conf, filepath.Base(path)) }
			ops := newFakeTCPOps().ops()
			ops.rename = func(from, to string) error { return renameNginxFile(mapPath(from), mapPath(to)) }
			ops.commit = commitNginxMutation
			ops.removeLink = func(int) error { assertNoOperationLog(t, journal); return nil }
			ops.discardBackup = func(backup string) error {
				assertNoOperationLog(t, journal)
				if failure == "killed" {
					panic("模拟被杀")
				}
				if failure == "error" {
					return errors.New("备份清理失败")
				}
				return os.Remove(mapPath(backup))
			}
			if failure == "killed" {
				sixthInterrupt(t, func() { _ = removeTCPForward(24443, false, ops) })
			} else if err := removeTCPForward(24443, false, ops); (err != nil) != (failure == "error") {
				t.Fatal(err)
			}
			assertNoOperationLog(t, journal)
			if err := reconcileNginxWith(journal, func() error { t.Fatal("不得额外 HUP 或恢复旧转发"); return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}
