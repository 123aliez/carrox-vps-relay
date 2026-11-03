package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestM15MigrationRecoversEveryInterruptedWrite(t *testing.T) {
	for _, action := range []string{"enable", "disable"} {
		prepare := func(t *testing.T) *migrationHarness {
			h := newMigrationHarness(t)
			if action == "disable" {
				if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
			}
			return h
		}
		baseline := prepare(t)
		steps := 0
		write, remove := baseline.ops.fs.write, baseline.ops.fs.remove
		baseline.ops.fs.write = func(p string, b []byte, m os.FileMode) error {
			err := write(p, b, m)
			if err == nil {
				steps++
			}
			return err
		}
		baseline.ops.fs.remove = func(p string) error {
			err := remove(p)
			if err == nil {
				steps++
			}
			return err
		}
		if err := migrateSNI443(action, baseline.ops, io.Discard); err != nil {
			t.Fatal(err)
		}
		for interrupt := 1; interrupt <= steps; interrupt++ {
			t.Run(fmt.Sprintf("%s/step-%d", action, interrupt), func(t *testing.T) {
				h := prepare(t)
				before := configTree(t, h.ops.paths, false)
				mutations := 0
				onMutation := func() {
					mutations++
					if mutations == interrupt {
						panic("模拟进程中断")
					}
				}
				write, remove := h.ops.fs.write, h.ops.fs.remove
				h.ops.fs.write = func(p string, b []byte, m os.FileMode) error {
					err := write(p, b, m)
					if err == nil {
						onMutation()
					}
					return err
				}
				h.ops.fs.remove = func(p string) error {
					err := remove(p)
					if err == nil {
						onMutation()
					}
					return err
				}
				func() {
					defer func() {
						if recover() != "模拟进程中断" {
							t.Fatal("未在预期步骤中断")
						}
					}()
					_ = migrateSNI443(action, h.ops, io.Discard)
				}()
				h.ops.fs.write, h.ops.fs.remove = write, remove
				pending, err := latestPendingMigration(h.ops.paths, h.ops.fs)
				if err != nil {
					t.Fatal(err)
				}
				var status bytes.Buffer
				if err := migrateSNI443("status", h.ops, &status); err != nil {
					t.Fatal(err)
				}
				if pending == "" {
					// 发布进度前没有业务变更；写完 done 后则已完整核验。
					if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) && len(h.verified) == 0 {
						t.Fatal("无进度记录却留下部分变更")
					}
					return
				}
				if !strings.Contains(status.String(), "recover") {
					t.Fatal(status.String())
				}
				interrupted := configTree(t, h.ops.paths, true)
				for _, retry := range []string{"enable", "disable"} {
					if err := migrateSNI443(retry, h.ops, io.Discard); err == nil || !strings.Contains(err.Error(), "recover") {
						t.Fatal("必须先恢复", err)
					}
				}
				if !reflect.DeepEqual(interrupted, configTree(t, h.ops.paths, true)) {
					t.Fatal("拒绝操作时写了文件")
				}
				if err := migrateSNI443("recover", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
					t.Fatal("恢复未逐字节还原")
				}
				if !bytes.Contains(readTestFile(t, filepath.Join(pending, "manifest.json")), []byte(`"state": "recovered"`)) {
					t.Fatal("未标记 recovered")
				}
			})
		}
	}
}

func TestM15MigrationMarkerOrderAndRecoveryRetry(t *testing.T) {
	h := newMigrationHarness(t)
	var paths []string
	write := h.ops.fs.write
	h.ops.fs.write = func(p string, b []byte, mode os.FileMode) error {
		if !strings.HasPrefix(p, h.ops.paths.backup+"/") {
			paths = append(paths, p)
		}
		return write(p, b, mode)
	}
	if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
		t.Fatal(err)
	}
	if paths[len(paths)-1] != h.ops.paths.marker() {
		t.Fatal("开启标记必须最后写入", paths)
	}
	remove := h.ops.fs.remove
	first := ""
	h.ops.fs.remove = func(p string) error {
		if first == "" {
			first = p
			if err := remove(p); err != nil {
				return err
			}
			panic("中断")
		}
		return remove(p)
	}
	func() { defer func() { _ = recover() }(); _ = migrateSNI443("disable", h.ops, io.Discard) }()
	if first != h.ops.paths.marker() {
		t.Fatal("关闭标记必须最先删除", first)
	}
	h.ops.fs.remove, h.ops.fs.write = remove, write
	h.fail = "verify"
	if err := migrateSNI443("recover", h.ops, io.Discard); err == nil {
		t.Fatal("核验失败应保留进度")
	}
	if pending, err := latestPendingMigration(h.ops.paths, h.ops.fs); err != nil || pending == "" {
		t.Fatal(pending, err)
	}
	if err := migrateSNI443("recover", h.ops, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestM15PendingMigrationBlocksAllMutationAPIsAndStartup(t *testing.T) {
	p := tempSNIPaths(t)
	oldConf := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = oldConf })
	backup := filepath.Join(p.backup, "sni443-20260101")
	if err := os.MkdirAll(backup, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeSNIManifest(backup, sniManifest{State: "in-progress", Direction: "enable"}, liveRelayFS()); err != nil {
		t.Fatal(err)
	}
	before := configTree(t, p, true)
	for name, handler := range map[string]http.HandlerFunc{
		"create": sitesCreate, "edit": sitesEdit, "toggle": sitesToggle, "delete": sitesDelete, "adopt": sitesAdopt,
		"tcp-create": tcpForwardsCreate, "tcp-delete": tcpForwardsDelete, "reality": realityCreate,
		"cf-token": cfTokenSave, "key-create": keysCreate, "key-delete": keysDelete,
	} {
		w := httptest.NewRecorder()
		handler(w, adminRequest("POST", "/", strings.NewReader(`{}`)))
		if w.Code != 409 || !strings.Contains(w.Body.String(), "recover") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, configTree(t, p, true)) {
		t.Fatal("封锁期间不允许写文件")
	}
	holder, err := lockConfigDirectory(confDir)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	sitesCreate(w, adminRequest("POST", "/", strings.NewReader(`{}`)))
	holder()
	if w.Code != 409 || !strings.Contains(w.Body.String(), "recover") {
		t.Fatal("迁移进程仍持锁时也应返回 409", w.Code)
	}
	called := false
	if err := initializeXrayRuntime(ensureNoSNIMigration, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("启动期间不得同步或启动 Xray")
	}
	if err := initializeXrayRuntime(func() error { return nil }, func() error { return errors.New("校验失败") }); err == nil {
		t.Fatal("应向日志返回启动故障")
	}
	var renewalLog bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&renewalLog)
	defer log.SetOutput(previousOutput)
	renewExpiringCerts()
	renewPanelCert()
	if !strings.Contains(renewalLog.String(), "recover") || !reflect.DeepEqual(before, configTree(t, p, true)) {
		t.Fatal("续期应记录并跳过所有写入和重载")
	}
}

func TestM15RealityCreationRollsBackAfterHUPWithoutReadyXray(t *testing.T) {
	p := tempSNIPaths(t)
	oldConf := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = oldConf })
	meta := m15Reality()
	path := filepath.Join(p.conf, "relay-"+meta.Domain+".conf")
	var loaded []byte
	var logs int
	ops := liveSiteLifecycle()
	ops.check = func() error { return nil }
	ops.reload = func() error {
		return nginxReloadWith(func() error { return nil }, func() error {
			data, err := os.ReadFile(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			loaded = data
			return nil
		}, func() error { return errors.New("Xray 未就绪") }, func(...any) { logs++ })
	}
	removedSecrets := false
	ops.removeLink = func(string) error { removedSecrets = true; return nil }
	_, err := provisionRealityWith(meta, func(meta SiteMeta) (SiteMeta, error) {
		putTestFile(t, path, []byte("新入口"))
		return meta, ops.reload()
	}, func() error { return errors.New("端口未就绪") }, func(meta SiteMeta) error { return removeManagedSite(meta, "", path, false, ops) })
	if err == nil || !strings.Contains(err.Error(), "Xray 未就绪") || len(loaded) != 0 || !removedSecrets || logs != 2 {
		t.Fatal("未就绪时必须撤下入口并再次重载", err, logs)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("回滚后仍有活动配置")
	}
}

func TestM15HUPSuccessXrayFailureKeepsDiskAndLoadedConfigConsistent(t *testing.T) {
	applyFails := func() error { return errors.New("Xray 启动失败") }
	logs := 0
	logger := func(...any) { logs++ }
	p := tempSNIPaths(t)
	oldConf := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = oldConf })
	path := filepath.Join(p.conf, "site.conf")
	putTestFile(t, path, []byte("旧配置"))
	var loaded []byte
	ops := liveSiteEditOps()
	ops.check = func() error { return nil }
	ops.reload = func() error {
		return nginxReloadWith(func() error { return nil }, func() error { loaded = readTestFile(t, path); return nil }, applyFails, logger)
	}
	if status, err := commitSiteEdit(path, []byte("新配置"), ops); err != nil || status != 200 {
		t.Fatal(status, err)
	}
	requireBytes(t, readTestFile(t, path), loaded)
	if string(loaded) != "新配置" || logs != 1 {
		t.Fatal("不应因 Xray 失败回退已加载的编辑")
	}
	f := newFakeTCPOps()
	tcpOps := f.ops()
	var loadedTCP map[string]bool
	tcpOps.reload = func() error {
		return nginxReloadWith(func() error { return nil }, func() error {
			loadedTCP = map[string]bool{}
			for path, on := range f.files {
				if strings.HasSuffix(path, ".conf") {
					loadedTCP[path] = on
				}
			}
			return nil
		}, applyFails, logger)
	}
	if err := provisionTCPForward(testTCPMeta, "", tcpOps); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loadedTCP, f.files) {
		t.Fatal("TCP 创建磁盘与已加载配置不一致")
	}
	if err := removeTCPForward(testTCPMeta.ListenPort, false, tcpOps); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loadedTCP, f.files) {
		t.Fatal("TCP 删除磁盘与已加载配置不一致")
	}
	if logs != 3 {
		t.Fatal("每次应记录 Xray 失败", logs)
	}
}

func TestM15CleanupKeepsSecretsWhenIsolationFails(t *testing.T) {
	operationPaths(t)
	removed, synced := false, false
	err := cleanupFailedRealityWith("cover.example.com", func(string) (string, bool, error) { return "active.conf", false, nil }, func(string, string) error { return errors.New("rename 失败") }, func(string) error { removed = true; return nil }, func() error { synced = true; return nil })
	if err == nil || removed || synced {
		t.Fatal("隔离失败必须保留机密且不执行同步", err)
	}
	order := []string{}
	err = cleanupFailedRealityWith("cover.example.com", func(string) (string, bool, error) { return "active.conf", false, nil }, func(string, string) error { order = append(order, "隔离"); return nil }, func(string) error { order = append(order, "清理"); return nil }, func() error { order = append(order, "同步重载"); return nil })
	if err != nil || strings.Join(order, ",") != "隔离,同步重载,清理" {
		t.Fatal(order, err)
	}
}

func TestM15XrayReadinessFailureAndRetry(t *testing.T) {
	clock := newFakeXrayClock()
	var attempts atomic.Int32
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { return newFakeXrayChild(true), nil }, ready: func(<-chan struct{}) error {
		if attempts.Add(1) == 1 {
			return errors.New("未监听")
		}
		return nil
	}})
	defer m.Close()
	if err := m.Apply([]byte("配置")); err == nil || m.Running() || m.LastError() == "" {
		t.Fatal("未就绪不能报告运行")
	}
	clock.next(t, time.Second) <- time.Now()
	deadline := time.Now().Add(time.Second)
	for !m.Running() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.Running() || m.LastError() != "" {
		t.Fatal("退避后就绪应清除故障")
	}
	if !m.ReadyFor([]byte("配置")) || m.ReadyFor([]byte("另一份配置")) {
		t.Fatal("就绪还必须匹配本次入口配置")
	}
	for _, kind := range []string{"timeout", "exit", "ready"} {
		t.Run(kind, func(t *testing.T) {
			clock := newFakeXrayClock()
			done := make(chan struct{})
			result := make(chan error, 1)
			go func() { result <- waitXrayReady(done, func() bool { return kind == "ready" }, clock.after) }()
			timer := clock.next(t, 5*time.Second)
			if kind == "timeout" {
				timer <- time.Now()
			}
			if kind == "exit" {
				close(done)
			}
			select {
			case err := <-result:
				if (err == nil) != (kind == "ready") {
					t.Fatal(kind, err)
				}
			case <-time.After(time.Second):
				t.Fatal("就绪等待未结束")
			}
		})
	}
}

func TestM15XrayReadinessStateAndEarlyExit(t *testing.T) {
	for _, exitEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(exitEarly), func(t *testing.T) {
			children := make(chan *fakeXrayChild, 1)
			clock := newFakeXrayClock()
			probe := make(chan struct{})
			m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { child := newFakeXrayChild(true); children <- child; return child, nil }, ready: func(done <-chan struct{}) error {
				select {
				case <-done:
					return errors.New("提前退出")
				case <-probe:
					return nil
				}
			}})
			defer m.Close()
			result := make(chan error, 1)
			go func() { result <- m.Apply([]byte("候选配置")) }()
			child := receiveChild(t, children)
			if m.Running() || m.ReadyFor([]byte("候选配置")) {
				t.Fatal("仅启动进程还不算就绪")
			}
			if exitEarly {
				child.exit()
			} else {
				close(probe)
			}
			select {
			case err := <-result:
				if (err != nil) != exitEarly {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("未返回就绪结果")
			}
			if m.Running() == exitEarly {
				t.Fatal("运行状态未反映就绪结果")
			}
		})
	}
}

func TestM15ACMENormalExitAlsoCleansResidualChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	cmd := exec.Command("sh", "-c", `sleep 30 >/dev/null 2>&1 & echo "$! $$" > "$1"; exit 0`, "acme-test", pidFile)
	if err := runACMEProcess(cmd, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	pids := strings.Fields(string(readTestFile(t, pidFile)))
	if len(pids) != 2 {
		t.Fatal(pids)
	}
	pgid, err := strconv.Atoi(pids[1])
	if err != nil {
		t.Fatal(err)
	}
	if acmeGroupAlive(pgid) {
		t.Fatal("正常返回后不应遗留后台任务")
	}
}

func TestM15ACMETimeoutKillsGroupBeforeReleasingLock(t *testing.T) {
	p := tempSNIPaths(t)
	oldConf := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = oldConf })
	unlock, err := lockConfigDirectory(confDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	pidFile := filepath.Join(t.TempDir(), "pids")
	cmd := exec.Command("sh", "-c", `sleep 30 & echo "$! $$" > "$1"; wait`, "acme-test", pidFile)
	if err := runACMEProcess(cmd, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatal(err)
	}
	pids := strings.Fields(string(readTestFile(t, pidFile)))
	if len(pids) != 2 {
		t.Fatal(pids)
	}
	pgid, err := strconv.Atoi(pids[1])
	if err != nil {
		t.Fatal(err)
	}
	if acmeGroupAlive(pgid) {
		t.Fatal("返回后仍有可执行的残留子进程")
	}
	if other, err := lockConfigDirectory(confDir); err == nil {
		other()
		t.Fatal("受控进程不能提前释放父进程锁")
	}
}

func TestM15InheritedReloadLockHelper(t *testing.T) {
	if os.Getenv("M15_LOCK_HELPER") == "" {
		return
	}
	confDir = os.Getenv("M15_LOCK_DIR")
	unlock, err := lockReloadConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestM15OnlyControlledACMETreeCanReuseLock(t *testing.T) {
	p := tempSNIPaths(t)
	oldConf := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = oldConf })
	unlock, err := lockConfigDirectory(confDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	cmd := exec.Command(os.Args[0], "-test.run=^TestM15InheritedReloadLockHelper$")
	cmd.Env = append(os.Environ(), "M15_LOCK_HELPER=1", "M15_LOCK_DIR="+confDir)
	if err := runACMEProcess(cmd, 5*time.Second); err != nil {
		t.Fatal("受控子进程应复用真实锁", err)
	}
	for _, flag := range []string{"1", "3"} {
		manual := exec.Command(os.Args[0], "-test.run=^TestM15InheritedReloadLockHelper$")
		manual.Env = append(os.Environ(), "M15_LOCK_HELPER=1", "M15_LOCK_DIR="+confDir, "VPS_RELAY_CONFIG_LOCK_HELD="+flag)
		if flag == "3" {
			wrong, err := os.CreateTemp(t.TempDir(), "not-a-lock")
			if err != nil {
				t.Fatal(err)
			}
			defer wrong.Close()
			manual.ExtraFiles = []*os.File{wrong}
		}
		if err := manual.Run(); err == nil {
			t.Fatal("手动执行时不得用环境变量或伪描述符逃逸锁")
		}
	}
	t.Setenv("VPS_RELAY_CONFIG_LOCK_HELD", "1")
	if release, err := lockReloadConfiguration(); err == nil {
		release()
		t.Fatal("仅环境变量不能绕过锁")
	}
	if other, err := lockConfigDirectory(confDir); err == nil {
		other()
		t.Fatal("受控子进程关闭描述符不应解锁父进程")
	}
}
