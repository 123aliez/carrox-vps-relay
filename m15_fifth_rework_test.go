package main

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func operationPaths(t *testing.T) (sniPaths, string) {
	t.Helper()
	p := tempSNIPaths(t)
	previous := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = previous })
	return p, nginxPendingPath()
}

func assertNoOperationLog(t *testing.T, journal string) {
	t.Helper()
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("操作已一致，不应残留日志", err)
	}
}

func TestM15OperationJournalSuccessfulEditHasNoExtraHUP(t *testing.T) {
	p, journal := operationPaths(t)
	path := filepath.Join(p.conf, "site.conf")
	putTestFile(t, path, []byte("before"))
	w := httptest.NewRecorder()
	unlock, ok := lockSiteRequest(w)
	if !ok {
		t.Fatal(w.Body.String())
	}
	var hups int
	var loaded []byte
	ops := liveSiteEditOps()
	ops.check = func() error { return nil }
	ops.reload = func() error {
		return nginxReloadWith(ops.check, func() error {
			hups++
			loaded = readTestFile(t, path)
			return nil
		}, func() error { return errors.New("Xray 故障") }, func(...any) {})
	}
	status, err := commitSiteEdit(path, []byte("successful edit"), ops)
	if err != nil || status != 200 || !completeNginxRequest(w) {
		unlock()
		t.Fatal(status, err, w.Body.String())
	}
	unlock()
	assertNoOperationLog(t, journal)
	if hups != 1 || string(loaded) != "successful edit" {
		t.Fatal("成功操作只能一次 HUP，Xray 故障不能回滚", hups, string(loaded))
	}
	if _, err := os.Stat(path + ".relay.bak"); !os.IsNotExist(err) {
		t.Fatal("备份清理不完整")
	}
	// 已正常结束后，管理员的无关改动不触发任何恢复或额外 HUP。
	putTestFile(t, path, []byte("later administrator edit"))
	added := filepath.Join(p.conf, "another.conf")
	putTestFile(t, added, []byte("legitimate new file"))
	if err := reconcileNginxWith(journal, func() error { t.Fatal("无日志不应重载"); return nil }); err != nil {
		t.Fatal(err)
	}
	unlock, ok = lockSiteRequest(httptest.NewRecorder())
	if !ok {
		t.Fatal("成功后的下个请求不应尝试恢复")
	}
	unlock()
	requireBytes(t, readTestFile(t, path), []byte("later administrator edit"))
	requireBytes(t, readTestFile(t, added), []byte("legitimate new file"))
}

func TestM15OperationJournalRollbackCompletionAndFailure(t *testing.T) {
	for _, failure := range []string{"none", "rename", "reload", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			p, journal := operationPaths(t)
			path := filepath.Join(p.conf, "site.conf")
			putTestFile(t, path, []byte("original"))
			unlock, ok := lockSiteRequest(httptest.NewRecorder())
			if !ok {
				t.Fatal("不能取得操作锁")
			}
			ops := liveSiteEditOps()
			ops.check = func() error { return errors.New("候选检查失败") }
			var loaded []byte
			ops.reload = func() error {
				if failure == "reload" {
					return errors.New("回滚 HUP 失败")
				}
				loaded = readTestFile(t, path)
				return nil
			}
			if failure == "rename" {
				ops.rename = func(string, string) error { return errors.New("回滚写入失败") }
			}
			if failure == "cleanup" {
				ops.check = func() error { return nil }
				ops.remove = func(string) error { return errors.New("备份清理失败") }
			}
			if _, err := commitSiteEdit(path, []byte("candidate"), ops); err == nil {
				unlock()
				t.Fatal("失败操作应报告错误")
			}
			unlock()
			if failure == "none" {
				assertNoOperationLog(t, journal)
				requireBytes(t, loaded, []byte("original"))
				return
			}
			if _, err := os.Stat(journal); err != nil {
				t.Fatal("回滚或清理失败必须保留日志", err)
			}
			if err := reconcileNginxWith(journal, func() error {
				loaded = readTestFile(t, path)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			requireBytes(t, loaded, []byte("original"))
			assertNoOperationLog(t, journal)
		})
	}
}

func TestM15OperationJournalRequiresExplicitCompletion(t *testing.T) {
	p, journal := operationPaths(t)
	path := filepath.Join(p.conf, "site.conf")
	putTestFile(t, path, []byte("before"))
	unlock, ok := lockSiteRequest(httptest.NewRecorder())
	if !ok {
		t.Fatal("无法取得操作锁")
	}
	ops := liveSiteEditOps()
	ops.check, ops.reload = func() error { return nil }, func() error { return nil }
	if _, err := commitSiteEdit(path, []byte("unfinished request"), ops); err != nil {
		unlock()
		t.Fatal(err)
	}
	// 即使已 HUP，统一出口没有显式完成标记也必须留下日志。
	unlock()
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("默认完成标记不应为真", err)
	}
	if err := reconcileNginxWith(journal, func() error {
		requireBytes(t, readTestFile(t, path), []byte("before"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertNoOperationLog(t, journal)
}

func TestM15OperationJournalInterruptedWriteRestoresBeforeReload(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "empty"}[empty], func(t *testing.T) {
			p, journal := operationPaths(t)
			path := filepath.Join(p.conf, "site.conf")
			if !empty {
				putTestFile(t, path, []byte("original"))
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotInvariantTrees(t, p.conf)
			if err := beginNginxMutation(); err != nil {
				t.Fatal(err)
			}
			// 模拟写文件后、重载之前被杀，没有任何完成标记。
			putTestFile(t, path, []byte("interrupted candidate"))
			putTestFile(t, filepath.Join(p.conf, "new.conf"), []byte("new candidate"))
			hups := 0
			if err := reconcileNginxWith(journal, func() error {
				if !reflect.DeepEqual(before, snapshotInvariantTrees(t, p.conf)) {
					t.Fatal("重载前未完整恢复快照及权限")
				}
				hups++
				return nil
			}); err != nil || hups != 1 {
				t.Fatal(err, hups)
			}
			assertNoOperationLog(t, journal)
		})
	}
}

func TestM15OperationJournalRestoringCanResume(t *testing.T) {
	p, journal := operationPaths(t)
	a, b := filepath.Join(p.conf, "a.conf"), filepath.Join(p.conf, "b.conf")
	putTestFile(t, a, []byte("original a"))
	putTestFile(t, b, []byte("original b"))
	if err := beginNginxMutation(); err != nil {
		t.Fatal(err)
	}
	record, err := parseNginxPending(readTestFile(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	record.Restoring = true
	if err := saveNginxPending(journal, record); err != nil {
		t.Fatal(err)
	}
	// 模拟恢复到一半再次被杀。
	putTestFile(t, a, []byte("original a"))
	putTestFile(t, b, []byte("not yet restored"))
	added := filepath.Join(p.conf, "new.conf")
	putTestFile(t, added, []byte("new candidate"))
	if err := reconcileNginxWith(journal, func() error { return errors.New("HUP 暂时失败") }); err == nil {
		t.Fatal("恢复后的重载失败仍须保留日志")
	}
	if restored, err := parseNginxPending(readTestFile(t, journal)); err != nil || !restored.Restoring {
		t.Fatal("恢复状态未保留", err)
	}
	if err := reconcileNginxWith(journal, func() error {
		requireBytes(t, readTestFile(t, a), []byte("original a"))
		requireBytes(t, readTestFile(t, b), []byte("original b"))
		if _, err := os.Stat(added); !os.IsNotExist(err) {
			t.Fatal("恢复未删除候选文件")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertNoOperationLog(t, journal)
}

func TestM15OperationJournalCorruptionPreservesScene(t *testing.T) {
	for _, raw := range []string{"not json", "null", "[]", "{}", `{"loaded":"old design"}`, `{"roots":null}`, `{"roots":[]}`, `{"roots":["relative"]}`, `{"roots":["/tmp/owned"],"files":[{"path":"/tmp/outside.conf"}]}`} {
		t.Run(raw, func(t *testing.T) {
			p, journal := operationPaths(t)
			putTestFile(t, filepath.Join(p.conf, "site.conf"), []byte("preserve"))
			before := snapshotInvariantTrees(t, p.conf)
			putTestFile(t, journal, []byte(raw))
			if err := reconcileNginxWith(journal, func() error { t.Fatal("损坏记录不能重载"); return nil }); err == nil {
				t.Fatal("损坏记录应报告错误")
			}
			if err := beginNginxMutation(); err == nil {
				t.Fatal("不能覆盖损坏记录")
			}
			if !reflect.DeepEqual(before, snapshotInvariantTrees(t, p.conf)) || !bytes.Equal(readTestFile(t, journal), []byte(raw)) {
				t.Fatal("损坏记录必须保留现场")
			}
		})
	}
}

func TestM15OperationJournalRequestsRemainSerialized(t *testing.T) {
	p, journal := operationPaths(t)
	path := filepath.Join(p.conf, "site.conf")
	putTestFile(t, path, []byte("initial"))
	unlock, ok := lockSiteRequest(httptest.NewRecorder())
	if !ok {
		t.Fatal("无法取得首个请求锁")
	}
	if err := writeNginxFile(path, []byte("first request"), 0644); err != nil {
		unlock()
		t.Fatal(err)
	}
	entered, done := make(chan struct{}), make(chan error, 1)
	var hups atomic.Int32
	go func() {
		w := httptest.NewRecorder()
		secondUnlock, ok := lockSiteRequest(w)
		if !ok {
			done <- errors.New(w.Body.String())
			return
		}
		close(entered)
		if err := writeNginxFile(path, []byte("second request"), 0644); err != nil {
			secondUnlock()
			done <- err
			return
		}
		record, err := parseNginxPending(readTestFile(t, journal))
		if err == nil && (len(record.Files) != 1 || string(record.Files[0].Data) != "first request") {
			err = errors.New("第二个请求踩了首个请求的日志")
		}
		hups.Add(1)
		if err == nil && !completeNginxRequest(w) {
			err = errors.New(w.Body.String())
		}
		secondUnlock()
		done <- err
	}()
	select {
	case <-entered:
		unlock()
		t.Fatal("两个写请求同时进入")
	case <-time.After(20 * time.Millisecond):
	}
	hups.Add(1)
	if !completeNginxRequest(httptest.NewRecorder()) {
		unlock()
		t.Fatal("首个请求未完成")
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertNoOperationLog(t, journal)
	if hups.Load() != 2 {
		t.Fatal("不应有额外 HUP")
	}
}

func TestM15OperationJournalACMEChildCommitsParentLog(t *testing.T) {
	h := newACMEScriptHarness(t)
	previous := confDir
	confDir = h.p.conf
	defer func() { confDir = previous }()
	unlock, err := lockConfigDirectory(confDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	path := filepath.Join(confDir, "parent.conf")
	putTestFile(t, path, []byte("original"))
	if err := beginNginxMutation(); err != nil {
		t.Fatal(err)
	}
	journal := nginxPendingPath()
	putTestFile(t, path, []byte("parent in progress"))
	if err := runACMEProcess(h.command("renew"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// 证书子事务一经提交，父快照不能再撤销已加载的配置。
	assertNoOperationLog(t, journal)
	requireBytes(t, readTestFile(t, path), []byte("parent in progress"))
}

func TestM15OperationJournalBorrowingStillRecoversCertificates(t *testing.T) {
	p, journal := operationPaths(t)
	path := filepath.Join(p.conf, "parent.conf")
	putTestFile(t, path, []byte("original"))
	if err := beginNginxMutation(); err != nil {
		t.Fatal(err)
	}
	before := readTestFile(t, journal)
	putTestFile(t, path, []byte("parent in progress"))
	certRoot := t.TempDir()
	cert, backup := filepath.Join(certRoot, "cert.pem"), filepath.Join(certRoot, "before.pem")
	putTestFile(t, cert, []byte("interrupted certificate"))
	putTestFile(t, backup, []byte("original certificate"))
	manifest := filepath.Join(p.backup, "acme-interrupted", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeACMETransaction(manifest, acmeTransaction{
		State: "in-progress", Publishing: true,
		Targets: []acmeTarget{{Path: cert, Backup: backup, Existed: true}},
	}); err != nil {
		t.Fatal(err)
	}
	hups := 0
	borrowed, err := recoverBeforeNginxOperation(true, func() error {
		hups++
		requireBytes(t, readTestFile(t, cert), []byte("original certificate"))
		requireBytes(t, readTestFile(t, path), []byte("parent in progress"))
		return nil
	}, beginNginxMutation)
	if err != nil || !borrowed || hups != 1 {
		t.Fatal(borrowed, err, hups)
	}
	requireBytes(t, readTestFile(t, journal), before)
}
