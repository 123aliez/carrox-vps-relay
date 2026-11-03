package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// 子进程使用真实脚本和真实 flock，不启动服务或监听端口。
func TestM15LockRunCLIHelper(t *testing.T) {
	if os.Getenv("M15_LOCK_RUN_HELPER") == "" {
		return
	}
	confDir = os.Getenv("M15_LOCK_RUN_CONF")
	sniBackupDir = os.Getenv("M15_LOCK_RUN_BACKUP")
	for i, arg := range os.Args {
		if arg == "--" {
			args := os.Args[i+1:]
			if len(args) > 1 && args[0] == "acme-transaction" {
				acmeCertificateRoot = os.Getenv("M15_CERT_ROOT")
				ops := liveACMETransactionOps()
				ops.reload = func() error { return nil }
				ops.validate = func(dir string) error {
					for _, name := range []string{"fullchain.pem", "key.pem"} {
						if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
							return err
						}
					}
					return nil
				}
				if err := acmeTransactionCLIWith(args[1:], ops); err != nil {
					t.Fatal(err)
				}
				return
			}
			if len(args) < 3 || args[0] != "lock-run" || args[1] != "--" {
				t.Fatal("无效测试命令")
			}
			if err := execWithConfigLock(args[2:]); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("缺少测试命令")
}

type acmeScriptHarness struct {
	p                                  sniPaths
	root, script, state, cert, actions string
	env                                []string
}

func newACMEScriptHarness(t *testing.T) acmeScriptHarness {
	t.Helper()
	p := tempSNIPaths(t)
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	home := filepath.Join(root, "acme")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	writeScript := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeScript(filepath.Join(bin, "vps-relay"), `exec "$M15_TEST_BINARY" -test.run=^TestM15LockRunCLIHelper$ -- "$@"`+"\n")
	writeScript(filepath.Join(home, "acme.sh"), `
[ "${VPS_RELAY_CONFIG_LOCK_HELD:-}" = 3 ]
[ -d /proc/self/fd/3 ]
if [ "${M15_ACME_DELAY:-}" = 1 ]; then
  echo ready > "$M15_READY"
  while [ ! -e "$M15_CONTINUE" ]; do sleep 0.01; done
fi
echo acme >> "$M15_ACTIONS"
echo changed > "$ACME_HOME/account.conf"
case " $* " in
  *" --install-cert "*)
    echo installed > "$VPS_RELAY_CERT_STAGE/fullchain.pem"
    echo key > "$VPS_RELAY_CERT_STAGE/key.pem"
    mkdir -p "$ACME_HOME/test-only.example.com_ecc"
    echo "Le_ReloadCmd='old'" > "$ACME_HOME/test-only.example.com_ecc/test-only.example.com.conf"
    ;;
esac
`)
	// 所有证书写入和删除都落在夹具目录，不碰宿主的真实路径。
	writeScript(filepath.Join(bin, "install"), `echo install >> "$M15_ACTIONS"`+"\n")
	writeScript(filepath.Join(bin, "rm"), `echo remove >> "$M15_ACTIONS"; /bin/rm "$@"`+"\n")
	script, err := filepath.Abs("scripts/relay-acme.sh")
	if err != nil {
		t.Fatal(err)
	}
	h := acmeScriptHarness{p: p, root: root, script: script, state: filepath.Join(home, "account.conf"), cert: filepath.Join(root, "certificates/test-only.example.com/fullchain.pem"), actions: filepath.Join(root, "actions")}
	putTestFile(t, h.state, []byte("原状态"))
	putTestFile(t, h.cert, []byte("原证书"))
	h.env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "M15_LOCK_RUN_HELPER=1", "M15_TEST_BINARY="+os.Args[0], "M15_LOCK_RUN_CONF="+p.conf, "M15_LOCK_RUN_BACKUP="+p.backup, "M15_CERT_ROOT="+filepath.Join(root, "certificates"), "CF_API_TOKEN=TEST-ONLY", "ACME_HOME="+home, "M15_ACTIONS="+h.actions, "M15_STATE="+h.state, "M15_CERT="+h.cert)
	return h
}
func (h acmeScriptHarness) command(action string) *exec.Cmd {
	cmd := exec.Command("bash", h.script, "test-only.example.com", action)
	cmd.Env = append([]string{}, h.env...)
	return cmd
}
func TestM15ManualACMEAllBranchesAreLockedBeforeAnyWrite(t *testing.T) {
	for _, action := range []string{"issue", "renew", "remove"} {
		for _, block := range []string{"busy", "in-progress"} {
			t.Run(action+"/"+block, func(t *testing.T) {
				h := newACMEScriptHarness(t)
				if block == "busy" {
					unlock, err := lockConfigDirectory(h.p.conf)
					if err != nil {
						t.Fatal(err)
					}
					defer unlock()
				} else {
					backup := filepath.Join(h.p.backup, "sni443-pending")
					if err := os.MkdirAll(backup, 0700); err != nil {
						t.Fatal(err)
					}
					if err := writeSNIManifest(backup, sniManifest{State: "in-progress"}, liveRelayFS()); err != nil {
						t.Fatal(err)
					}
				}
				before := configTree(t, h.p, true)
				cmd := h.command(action)
				cmd.Env = append(cmd.Env, "VPS_RELAY_CONFIG_LOCK_HELD=1")
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatal("手工入口必须拒绝执行")
				}
				if block == "in-progress" && !bytes.Contains(out, []byte("recover")) {
					t.Fatal(string(out))
				}
				requireBytes(t, readTestFile(t, h.state), []byte("原状态"))
				requireBytes(t, readTestFile(t, h.cert), []byte("原证书"))
				if _, err := os.Stat(h.actions); !os.IsNotExist(err) {
					t.Fatal("拒绝前已执行 ACME 或证书动作")
				}
				if !reflect.DeepEqual(before, configTree(t, h.p, true)) {
					t.Fatal("拒绝时改动了配置")
				}
			})
		}
	}
}
func TestM15PanelACMEScriptReusesActualLockForEveryBranch(t *testing.T) {
	for _, action := range []string{"issue", "renew", "remove"} {
		t.Run(action, func(t *testing.T) {
			h := newACMEScriptHarness(t)
			previous := confDir
			confDir = h.p.conf
			t.Cleanup(func() { confDir = previous })
			unlock, err := lockConfigDirectory(confDir)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			if err := runACMEProcess(h.command(action), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if len(readTestFile(t, h.actions)) == 0 {
				t.Fatal("受控脚本没有执行")
			}
			if other, err := lockConfigDirectory(confDir); err == nil {
				other()
				t.Fatal("脚本不能释放父进程锁")
			}
		})
	}
}
func TestM15ManualACMEHoldsLockForWholeScript(t *testing.T) {
	h := newACMEScriptHarness(t)
	ready, proceed := filepath.Join(h.root, "ready"), filepath.Join(h.root, "continue")
	cmd := h.command("renew")
	cmd.Env = append(cmd.Env, "M15_ACME_DELAY=1", "M15_READY="+ready, "M15_CONTINUE="+proceed)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.WriteFile(proceed, []byte("go"), 0600); _ = cmd.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("脚本未开始")
		}
		time.Sleep(time.Millisecond)
	}
	if unlock, err := lockConfigDirectory(h.p.conf); err == nil {
		unlock()
		t.Fatal("脚本执行期间锁应被占用")
	}
	if err := os.WriteFile(proceed, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockConfigDirectory(h.p.conf)
	if err != nil {
		t.Fatal("脚本结束后应释放锁", err)
	}
	unlock()
}

func TestM15DamagedRealitySecretsDoNotBlockOrdinaryLifecycles(t *testing.T) {
	for _, damage := range []string{"entry-missing", "entry-json", "entry-fields", "keys-json", "keys-missing", "entry-semantic", "all-semantic", "shared-semantic"} {
		t.Run(damage, func(t *testing.T) {
			p, xp, fs := tempSNIPaths(t), tempXrayPaths(t), liveRelayFS()
			oldConf := confDir
			confDir = p.conf
			t.Cleanup(func() { confDir = oldConf })
			putTestFile(t, p.marker(), []byte(sni443Config))
			healthy, broken := m15Reality(), m15Reality()
			healthy.Domain = "healthy.example.com"
			putMeta(t, p, healthy, "")
			putMeta(t, p, broken, "")
			if err := privateJSON(fs, xp.keys(), fixtureRealityKeys(t)); err != nil {
				t.Fatal(err)
			}
			for _, site := range []SiteMeta{healthy, broken} {
				if err := saveRealityEntry(xp, site.Domain, fixtureRealityEntry(t), fs); err != nil {
					t.Fatal(err)
				}
			}
			var starts atomic.Int32
			manager := newXraySupervisor(xrayProcessOps{start: func([]byte) (xrayChild, error) { starts.Add(1); return newFakeXrayChild(true), nil }})
			defer manager.Close()
			checkConfig := func(path string) error {
				data := readTestFile(t, path)
				var value any
				if err := json.Unmarshal(data, &value); err != nil {
					return err
				}
				if bytes.Contains(data, []byte("invalid-fingerprint")) || (damage == "shared-semantic" && bytes.Contains(data, []byte("shared-failure-marker")) && bytes.Contains(data, []byte(healthy.Domain)) && bytes.Contains(data, []byte(broken.Domain))) {
					return errors.New("校验器机密输出：" + fixtureBackendUUID + fixtureRealityKeys(t).PrivateKey)
				}
				return nil
			}
			syncConfig := func() error { return syncRelayConfig(p, fs, xp, checkConfig) }
			apply := func() error {
				data, err := desiredXrayConfig(p, xp, fs)
				if err != nil {
					return err
				}
				return manager.Apply(data)
			}
			if err := syncConfig(); err != nil {
				t.Fatal(err)
			}
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "entry-missing":
				if err := os.Remove(xp.entry(broken.Domain)); err != nil {
					t.Fatal(err)
				}
			case "entry-json":
				putTestFile(t, xp.entry(broken.Domain), []byte("INVALID-"+fixtureBackendUUID))
			case "entry-fields":
				putTestFile(t, xp.entry(broken.Domain), []byte(`{"frontend_uuid":"bad","outbound":{}}`))
			case "keys-json":
				putTestFile(t, xp.keys(), []byte("INVALID-"+fixtureRealityKeys(t).PrivateKey))
			case "keys-missing":
				if err := os.Remove(xp.keys()); err != nil {
					t.Fatal(err)
				}
			case "entry-semantic", "all-semantic", "shared-semantic":
				entry := fixtureRealityEntry(t)
				entry.Outbound.Fingerprint = "invalid-fingerprint"
				if damage == "shared-semantic" {
					entry.Outbound.Fingerprint = "firefox"
					entry.Outbound.SpiderX = "/shared-failure-marker"
				}
				if err := saveRealityEntry(xp, broken.Domain, entry, fs); err != nil {
					t.Fatal(err)
				}
				if damage == "all-semantic" {
					if err := saveRealityEntry(xp, healthy.Domain, entry, fs); err != nil {
						t.Fatal(err)
					}
				}
			}
			var messages bytes.Buffer
			previousLog := log.Writer()
			log.SetOutput(&messages)
			defer log.SetOutput(previousLog)
			reload := func() error { return nginxReloadWith(syncConfig, func() error { return nil }, apply, log.Print) }
			// Cloudflare 经内存 HTTP transport 执行，覆盖真实站点创建和 DNS 回滚路径，无本地监听。
			f := &fakeCF{records: map[string]cfRecord{originRecord.ID: originRecord}}
			previousClient := cfClient
			cfClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				f.serveHTTP(w, r)
				return w.Result(), nil
			})}
			t.Cleanup(func() { cfClient = previousClient })
			ops := siteLifecycle{issue: func(string, string, string) error { return nil }, cleanup: func(string, string, string) error { return nil }, certificateExists: func(string, string) bool { return true }, render: func(meta SiteMeta) ([]byte, error) { return renderSiteMode(meta, "templates", true) }, write: atomicWrite, remove: os.Remove, rename: os.Rename, check: syncConfig, reload: reload}
			meta, err := provisionSite(testMeta(), "TEST-ONLY", "38.6.76.28", testZone, ops)
			if err != nil {
				t.Fatal("普通站点创建失败", err)
			}
			path := confPath(meta.Domain)
			meta.Upstream = "https://23.95.8.180"
			data, err := ops.render(meta)
			if err != nil {
				t.Fatal(err)
			}
			editOps := liveSiteEditOps()
			editOps.check, editOps.reload = syncConfig, reload
			if _, err := commitSiteEdit(path, data, editOps); err != nil {
				t.Fatal("普通站点编辑失败", err)
			}
			if err := removeManagedSite(meta, "TEST-ONLY", path, false, ops); err != nil {
				t.Fatal("普通站点删除失败", err)
			}
			if err := reload(); err != nil {
				t.Fatal("证书续期共用重载路径失败", err)
			}
			pauseAll := strings.HasPrefix(damage, "keys-") || damage == "all-semantic" || damage == "shared-semantic"
			wantMap := "healthy.example.com 127.0.0.1:30001;\n"
			if pauseAll {
				wantMap = ""
			}
			requireBytes(t, readTestFile(t, p.derived()[0]), []byte(wantMap))
			if pauseAll {
				if manager.Running() {
					t.Fatal("全部入口暂停时必须停止 Xray")
				}
				if _, err := os.Stat(xp.config()); !os.IsNotExist(err) {
					t.Fatal("应移除旧运行配置")
				}
			} else {
				config := readTestFile(t, xp.config())
				if !manager.ReadyFor(config) || bytes.Contains(config, []byte(broken.Domain)) || !bytes.Contains(config, []byte(healthy.Domain)) {
					t.Fatal("只应排除损坏入口")
				}
			}
			sites := []Site{{SiteMeta: healthy, Enabled: true}, {SiteMeta: broken, Enabled: true}}
			annotateRealityHealth(sites, xp, fs)
			if !sites[1].RealityPaused || sites[1].RealityError == "" || sites[0].RealityPaused != pauseAll {
				t.Fatal("入口状态未显示暂停原因", sites)
			}
			serialized, err := json.Marshal(sites)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{fixtureBackendUUID, fixtureFrontendUUID, fixtureRealityKeys(t).PrivateKey} {
				if bytes.Contains(serialized, []byte(secret)) || strings.Contains(messages.String(), secret) {
					t.Fatal("状态或日志泄漏机密")
				}
			}
		})
	}
}

func TestM15ReconcileRepairsMissedNotificationsAndReadFailures(t *testing.T) {
	var starts atomic.Int32
	m := newXraySupervisor(xrayProcessOps{start: func([]byte) (xrayChild, error) { starts.Add(1); return newFakeXrayChild(true), nil }})
	defer m.Close()
	if err := m.Apply([]byte("旧配置")); err != nil {
		t.Fatal(err)
	}
	if err := notifyXrayService(filepath.Join(t.TempDir(), "missing.sock"), true); err == nil {
		t.Fatal("应模拟通知丢失")
	}
	data := []byte("磁盘新配置")
	readFails := true
	reconcile := func() error {
		return reconcileXrayWith(m, func() (func(), error) { return func() {}, nil }, func() error { return nil }, func() ([]byte, error) {
			if readFails {
				return nil, errors.New("读盘暂时失败")
			}
			return data, nil
		})
	}
	if err := reconcile(); err == nil || !m.ReadyFor([]byte("旧配置")) {
		t.Fatal("读盘失败应保留运行配置")
	}
	readFails = false
	if err := reconcile(); err != nil || !m.ReadyFor(data) || starts.Load() != 2 {
		t.Fatal("通知丢失后对账未补偿", err)
	}
	for i := 0; i < 3; i++ {
		if err := reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if starts.Load() != 2 {
		t.Fatal("配置一致时不应重启")
	}
	readFails = true
	if err := reconcile(); err == nil {
		t.Fatal("应报告暂时读盘失败")
	}
	readFails = false
	if err := reconcile(); err != nil || m.LastError() != "" || starts.Load() != 2 {
		t.Fatal("读盘恢复后应清除过期错误且不重启", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); runXrayReconciliation(ctx, ticks, reconcile, func(string) {}) }()
	data = nil
	ticks <- time.Now()
	deadline := time.Now().Add(time.Second)
	for m.Running() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if m.Running() {
		t.Fatal("周期对账应停止无入口的遗留进程")
	}
}

func TestM15ReconciliationRespectsMigrationAndExistingBackoff(t *testing.T) {
	var attempts atomic.Int32
	clock := newFakeXrayClock()
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { attempts.Add(1); return nil, errors.New("暂时失败") }})
	defer m.Close()
	data := []byte("已提交的配置")
	if err := m.Apply(data); err == nil {
		t.Fatal("应模拟启动失败")
	}
	lock := func() (func(), error) { return func() {}, nil }
	for i := 0; i < 3; i++ {
		if err := reconcileXrayWith(m, lock, func() error { return nil }, func() ([]byte, error) { return data, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if attempts.Load() != 1 {
		t.Fatal("对账不得绕过已有退避")
	}
	read := false
	if err := reconcileXrayWith(m, lock, func() error { return migrationRecoveryError() }, func() ([]byte, error) { read = true; return []byte("新配置"), nil }); err == nil || read {
		t.Fatal("迁移未恢复前不得读取或应用配置")
	}
}

func TestM15ControlResponseReportsActualSubmission(t *testing.T) {
	clock := newFakeXrayClock()
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { return nil, errors.New("启动失败") }})
	readFails := false
	handler := xrayControlHandler(m, func() ([]byte, error) {
		if readFails {
			return nil, errors.New("读取失败")
		}
		return []byte("配置"), nil
	})
	check := func(wantSubmitted bool) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/apply", nil))
		if w.Code != 500 || (w.Header().Get("X-Relay-Xray-Submitted") == "1") != wantSubmitted {
			t.Fatal(w.Code, w.Header())
		}
	}
	check(true)
	readFails = true
	check(false)
	readFails = false
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	check(false)
}
func TestM15ReloadLogsDistinguishSubmittedAndUnsubmittedFailures(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		var output string
		err := nginxReloadWith(func() error { return nil }, func() error { return nil }, func() error { return &xrayApplyFailure{submitted: submitted, cause: errors.New("失败")} }, func(args ...any) { output = fmt.Sprint(args...) })
		if err != nil || strings.Contains(output, "正在退避重试") != submitted || strings.Contains(output, "每 30 秒对账补偿") == submitted {
			t.Fatal(submitted, output, err)
		}
	}
}

func TestM15XrayRetryCannotOverwriteMissedNewConfiguration(t *testing.T) {
	xp := tempXrayPaths(t)
	putTestFile(t, xp.config(), []byte("通知丢失的新配置"))
	child, err := liveXrayProcessOps(xp).start([]byte("旧内存配置"))
	if err == nil || child != nil {
		t.Fatal("不得用旧配置启动或覆盖新配置")
	}
	requireBytes(t, readTestFile(t, xp.config()), []byte("通知丢失的新配置"))
}

func TestM15MissingKeysWithExistingEntriesNeverRegeneratesIdentity(t *testing.T) {
	xp := tempXrayPaths(t)
	if err := saveRealityEntry(xp, "cover.example.com", fixtureRealityEntry(t), liveRelayFS()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateXrayKeys(xp, liveRelayFS()); err == nil {
		t.Fatal("存在入口时不得悄悄替换前端身份")
	}
	if _, err := os.Stat(xp.keys()); !os.IsNotExist(err) {
		t.Fatal("不应生成替代密钥")
	}
}
func TestM15OccupiedXrayPortCannotBeMistakenForReadiness(t *testing.T) {
	var occupied atomic.Bool
	occupied.Store(true)
	var starts atomic.Int32
	clock := newFakeXrayClock()
	m := newXraySupervisor(xrayProcessOps{after: clock.after, portFree: func() error {
		return checkXrayPortFree(func(string, string) (net.Listener, error) {
			if occupied.Load() {
				return nil, syscall.EADDRINUSE
			}
			return &testXrayListener{}, nil
		})
	}, start: func([]byte) (xrayChild, error) { starts.Add(1); return newFakeXrayChild(true), nil }})
	defer m.Close()
	if err := m.Apply([]byte("配置")); err == nil || m.Running() || starts.Load() != 0 || !strings.Contains(m.LastError(), "30001") {
		t.Fatal("占用端口时不能启动或报告就绪", err)
	}
	occupied.Store(false)
	clock.next(t, time.Second) <- time.Now()
	deadline := time.Now().Add(time.Second)
	for !m.Running() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.ReadyFor([]byte("配置")) || starts.Load() != 1 {
		t.Fatal("端口释放后应正常启动")
	}
}

type testXrayListener struct{}

func (*testXrayListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (*testXrayListener) Close() error              { return nil }
func (*testXrayListener) Addr() net.Addr            { return &net.TCPAddr{} }
