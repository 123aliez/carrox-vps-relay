package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestM15I1OrdinaryModeHasNoExtraWrites(t *testing.T) {
	p, xp, fs := tempSNIPaths(t), tempXrayPaths(t), liveRelayFS()
	putMeta(t, p, m15Site(), "")
	before := configTree(t, p, true)
	fs.write = func(string, []byte, os.FileMode) error { t.Fatal("普通模式不应写派生文件"); return nil }
	fs.chmod = func(string, os.FileMode) error { t.Fatal("普通模式不应改权限"); return nil }
	fs.mkdir = func(string, os.FileMode) error { t.Fatal("普通模式不应建目录"); return nil }
	fs.remove = func(string) error { t.Fatal("普通模式不应删文件"); return nil }
	if err := syncRelayConfig(p, fs, xp, func(string) error { t.Fatal("普通模式不校验 Xray"); return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := desiredXrayConfig(p, xp, fs)
	if err != nil || len(data) != 0 {
		t.Fatal(err)
	}
	putTestFile(t, xp.config(), []byte("stale"))
	if _, err := liveXrayProcessOps(xp).start([]byte("stale")); err == nil || !strings.Contains(err.Error(), "磁盘配置已变化") {
		t.Fatal("普通模式不得启动或崩溃拉起 Xray", err)
	}
	if err := reconcileNginxWith(filepath.Join(t.TempDir(), "absent"), func() error { t.Fatal("无事务不应重载"); return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, configTree(t, p, true)) {
		t.Fatal("普通同步改动配置")
	}
	h := newACMEScriptHarness(t)
	before = configTree(t, h.p, true)
	cmd := exec.Command(os.Args[0], "-test.run=^TestM15LockRunCLIHelper$", "--", "lock-run", "--", "/bin/true")
	cmd.Env = h.env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	if !reflect.DeepEqual(before, configTree(t, h.p, true)) {
		t.Fatal("只读 lock-run 产生配置写入")
	}
}

func TestM15I3XrayPrivateFilesystemFailuresAreIsolated(t *testing.T) {
	for _, failure := range []string{"read", "write", "chmod", "mkdir", "remove"} {
		t.Run(failure, func(t *testing.T) {
			p, xp, fs := tempSNIPaths(t), tempXrayPaths(t), liveRelayFS()
			site := m15Reality()
			putTestFile(t, p.marker(), []byte(sni443Config))
			putMeta(t, p, site, "")
			if err := privateJSON(fs, xp.keys(), fixtureRealityKeys(t)); err != nil {
				t.Fatal(err)
			}
			if err := saveRealityEntry(xp, site.Domain, fixtureRealityEntry(t), fs); err != nil {
				t.Fatal(err)
			}
			putTestFile(t, xp.config(), []byte("old"))
			private := func(path string) bool { return strings.HasPrefix(path, xp.root) }
			bad := errors.New("不应回显 " + fixtureBackendUUID)
			switch failure {
			case "read":
				read := fs.read
				fs.read = func(path string) ([]byte, error) {
					if path == xp.config() {
						return nil, bad
					}
					return read(path)
				}
			case "write":
				write := fs.write
				fs.write = func(path string, b []byte, m os.FileMode) error {
					if private(path) {
						return bad
					}
					return write(path, b, m)
				}
			case "chmod":
				chmod := fs.chmod
				fs.chmod = func(path string, m os.FileMode) error {
					if private(path) {
						return bad
					}
					return chmod(path, m)
				}
			case "mkdir":
				mkdir := fs.mkdir
				fs.mkdir = func(path string, m os.FileMode) error {
					if private(path) {
						return bad
					}
					return mkdir(path, m)
				}
			case "remove":
				remove := fs.remove
				fs.remove = func(path string) error {
					if private(path) {
						return bad
					}
					return remove(path)
				}
			}
			check := func(string) error { return nil }
			if failure == "remove" {
				check = func(string) error { return bad }
			}
			if err := syncRelayConfig(p, fs, xp, check); err != nil {
				t.Fatal("私有材料故障阻断 Nginx", err)
			}
			requireBytes(t, readTestFile(t, p.derived()[0]), nil)
			data, err := desiredXrayConfig(p, xp, fs)
			if err != nil || len(data) != 0 {
				t.Fatal("暂停后不得再读旧坏配置", err)
			}
			sites := []Site{{SiteMeta: site, Enabled: true}}
			annotateRealityRouting(sites, p, fs)
			if !sites[0].RealityPaused || strings.Contains(sites[0].RealityError, fixtureBackendUUID) {
				t.Fatal("状态未安全展示暂停", sites)
			}
		})
	}
}

func TestM15I4PendingMigrationDoesNotCreateControlFiles(t *testing.T) {
	p := tempSNIPaths(t)
	root := filepath.Join(p.backup, "sni443-pending")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeSNIManifest(root, sniManifest{State: "in-progress"}, liveRelayFS()); err != nil {
		t.Fatal(err)
	}
	xp := xrayPaths{filepath.Join(t.TempDir(), "must-not-exist")}
	m := newXraySupervisor(xrayProcessOps{})
	defer m.Close()
	if close, err := startXrayControl(xp, m); err == nil {
		close()
		t.Fatal("迁移中启动了控制接口")
	}
	if _, err := os.Stat(xp.root); !os.IsNotExist(err) {
		t.Fatal("迁移中创建了控制目录")
	}
}

func TestM15I5ACMEOutputIsSanitized(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "printf '%s' \"$M15_SECRET\"; exit 1")
	cmd.Env = append(os.Environ(), "M15_SECRET="+fixtureBackendUUID+fixtureRealityKeys(t).PrivateKey)
	if err := runACMEProcess(cmd, time.Second); err == nil || strings.Contains(err.Error(), fixtureBackendUUID) || strings.Contains(err.Error(), fixtureRealityKeys(t).PrivateKey) {
		t.Fatal("证书错误泄露机密", err)
	}
}

func TestM15I6DisableRestoresOriginalBytesAndRemovesDirectory(t *testing.T) {
	h := newMigrationHarness(t)
	for _, name := range []string{"relay-site.example.com.conf", "relay-panel.conf"} {
		path := filepath.Join(h.ops.paths.conf, name)
		putTestFile(t, path, append(readTestFile(t, path), []byte("# 保留迁移前的自定义字节\n")...))
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
	}
	before := configTree(t, h.ops.paths, false)
	if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := migrateSNI443("disable", h.ops, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
		t.Fatal("未还原原始字节或权限")
	}
	if _, err := os.Stat(filepath.Dir(h.ops.paths.derived()[0])); !os.IsNotExist(err) {
		t.Fatal("空的 map 目录残留")
	}
	for _, port := range []int{8443, 30000, 30001, 30999} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			h := newMigrationHarness(t)
			putTestFile(t, filepath.Join(h.ops.paths.stream, "relay-tcp.conf"), []byte("server { listen [::]:"+strconv.Itoa(port)+"; proxy_pass 198.51.100.7:443; }"))
			before := configTree(t, h.ops.paths, true)
			if err := migrateSNI443("enable", h.ops, io.Discard); err == nil {
				t.Fatal("已有保留端口转发必须拒绝迁移")
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, true)) {
				t.Fatal("前置拒绝改动了配置")
			}
		})
	}
}

func TestM15I6RecoveryRestoresMapDirectoryState(t *testing.T) {
	for _, existed := range []bool{false, true} {
		t.Run(strconv.FormatBool(existed), func(t *testing.T) {
			h := newMigrationHarness(t)
			dir := filepath.Dir(h.ops.paths.derived()[0])
			if existed {
				if err := os.MkdirAll(dir, 0750); err != nil {
					t.Fatal(err)
				}
			}
			h.fail = "check"
			if err := migrateSNI443("enable", h.ops, io.Discard); err == nil {
				t.Fatal("应注入迁移失败")
			}
			info, err := os.Stat(dir)
			if existed {
				if err != nil || info.Mode().Perm() != 0750 {
					t.Fatal("未保留原空目录权限", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("失败后残留新建 map 目录")
			}
		})
	}
}

func TestM15I7ParentDeathHelper(t *testing.T) {
	switch os.Getenv("M15_PARENT_DEATH") {
	case "parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestM15I7ParentDeathHelper$")
		cmd.Env = append(os.Environ(), "M15_PARENT_DEATH=child")
		configureXrayChild(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("M15_CHILD_PID"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(os.Getenv("M15_CHILD_READY")); err == nil {
				os.Exit(0)
			}
			time.Sleep(time.Millisecond)
		}
		_ = cmd.Process.Kill()
		t.Fatal("子进程未就绪")
	case "child":
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("M15_CHILD_READY"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Second)
		}
	}
}

func TestM15I7ParentDeathKillsEvenTermIgnoringChild(t *testing.T) {
	root := t.TempDir()
	pidPath, ready := filepath.Join(root, "pid"), filepath.Join(root, "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestM15I7ParentDeathHelper$")
	cmd.Env = append(os.Environ(), "M15_PARENT_DEATH=parent", "M15_CHILD_PID="+pidPath, "M15_CHILD_READY="+ready)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	pid, err := strconv.Atoi(string(readTestFile(t, pidPath)))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if os.IsNotExist(err) {
			return
		}
		if err == nil {
			end := strings.LastIndexByte(string(data), ')')
			if end >= 0 && strings.HasPrefix(string(data[end+1:]), " Z") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("父进程退出后残留活跃子进程")
}

func TestM15I7UnchangedApplyPreservesCrashBackoff(t *testing.T) {
	var starts atomic.Int32
	clock := newFakeXrayClock()
	m := newXraySupervisor(xrayProcessOps{after: clock.after, start: func([]byte) (xrayChild, error) { starts.Add(1); return nil, errors.New("临时失败") }})
	defer m.Close()
	data := []byte("same desired config")
	if err := m.Apply(data); err == nil {
		t.Fatal("应注入启动失败")
	}
	tick := clock.next(t, time.Second)
	if err := m.Apply(data); err != nil || starts.Load() != 1 {
		t.Fatal("相同期望绕过了退避", err, starts.Load())
	}
	tick <- time.Now()
	clock.next(t, 2*time.Second)
	if starts.Load() != 2 {
		t.Fatal("退避到期未重试")
	}
}

func invariantCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"test-only.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func TestM15I8ACMETransactionFailuresAndEveryInterruptedStep(t *testing.T) {
	cert, key := invariantCertificate(t)
	newCert, newKey := invariantCertificate(t)
	for _, failure := range []string{"script", "invalid-certificate", "reload", "interrupt-1", "interrupt-2", "interrupt-3", "interrupt-4", "interrupt-5", "interrupt-6", "interrupt-7", "interrupt-8"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			home, certRoot, backup := filepath.Join(root, "home"), filepath.Join(root, "ssl"), filepath.Join(root, "backup")
			domain := "test-only.example.com"
			conf := filepath.Join(home, domain+"_ecc", domain+".conf")
			putTestFile(t, conf, []byte("Le_ReloadCmd='original-command'\n"))
			putTestFile(t, filepath.Join(certRoot, domain, "fullchain.pem"), cert)
			putTestFile(t, filepath.Join(certRoot, domain, "key.pem"), key)
			before := snapshotInvariantTrees(t, home, certRoot)
			loaded := append([]byte{}, cert...)
			steps := 0
			hups := 0
			ops := liveACMETransactionOps()
			ops.run = func(_ []string, env []string, _ io.Reader) error {
				values := map[string]string{}
				for _, item := range env {
					if i := strings.IndexByte(item, '='); i >= 0 {
						values[item[:i]] = item[i+1:]
					}
				}
				stageHome, stageCert := values["ACME_HOME"], values["VPS_RELAY_CERT_STAGE"]
				if filepath.Dir(stageHome) != home || filepath.Dir(stageCert) != certRoot {
					t.Fatal("暂存目录必须位于目标卷内")
				}
				putTestFile(t, filepath.Join(stageHome, domain+"_ecc", domain+".conf"), []byte("Le_RealFullChainPath='"+stageCert+"/fullchain.pem'\nLe_ReloadCmd='broken-command'\n"))
				putTestFile(t, filepath.Join(stageCert, "fullchain.pem"), newCert)
				putTestFile(t, filepath.Join(stageCert, "key.pem"), newKey)
				if failure == "script" {
					putTestFile(t, filepath.Join(stageCert, "key.pem"), []byte("truncated"))
					return errors.New("签发或安装失败")
				}
				if failure == "invalid-certificate" {
					putTestFile(t, filepath.Join(stageCert, "key.pem"), []byte("truncated"))
				}
				return nil
			}
			ops.reload = func() error {
				hups++
				if failure == "reload" && hups == 1 {
					return errors.New("语法或 HUP 失败")
				}
				loaded = readTestFile(t, filepath.Join(certRoot, domain, "fullchain.pem"))
				return nil
			}
			ops.step = func(string) {
				steps++
				if failure == "interrupt-"+strconv.Itoa(steps) {
					panic("中断")
				}
			}
			var runErr error
			interrupted := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if value != "中断" {
							panic(value)
						}
						interrupted = true
					}
				}()
				runErr = runACMETransaction(domain, "renew", home, certRoot, backup, []string{"fake"}, nil, nil, ops)
			}()
			if strings.HasPrefix(failure, "interrupt-") && !interrupted {
				t.Fatal("未在步骤中断", steps)
			}
			if !strings.HasPrefix(failure, "interrupt-") && runErr == nil {
				t.Fatal("失败事务返回成功")
			}
			if err := recoverACMETransactions(backup, ops.reload); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, snapshotInvariantTrees(t, home, certRoot)) || !bytes.Equal(loaded, cert) {
				t.Fatal("未逐字节恢复证书、状态或已加载证书")
			}
			if err := recoverACMETransactions(backup, ops.reload); err != nil {
				t.Fatal("恢复不能重试", err)
			}
		})
	}
	// 成功发布的状态不得留下暂存目录或不可执行的旧重载命令。
	root := t.TempDir()
	home, certRoot := filepath.Join(root, "home"), filepath.Join(root, "ssl")
	domain := "test-only.example.com"
	putTestFile(t, filepath.Join(home, "account.conf"), nil)
	homeBefore, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	ops := liveACMETransactionOps()
	ops.reload = func() error { return nil }
	ops.run = func(_ []string, env []string, _ io.Reader) error {
		var sh, sc string
		for _, value := range env {
			if strings.HasPrefix(value, "ACME_HOME=") {
				sh = strings.TrimPrefix(value, "ACME_HOME=")
			}
			if strings.HasPrefix(value, "VPS_RELAY_CERT_STAGE=") {
				sc = strings.TrimPrefix(value, "VPS_RELAY_CERT_STAGE=")
			}
		}
		putTestFile(t, filepath.Join(sh, domain+"_ecc", domain+".conf"), []byte("Le_RealFullChainPath='"+sc+"/fullchain.pem'\nLe_ReloadCmd='invalid'\n"))
		putTestFile(t, filepath.Join(sc, "fullchain.pem"), cert)
		putTestFile(t, filepath.Join(sc, "key.pem"), key)
		return nil
	}
	if err := runACMETransaction(domain, "issue", home, certRoot, filepath.Join(root, "backup"), []string{"fake"}, nil, nil, ops); err != nil {
		t.Fatal(err)
	}
	homeAfter, err := os.Stat(home)
	if err != nil || !os.SameFile(homeBefore, homeAfter) {
		t.Fatal("不能重命名 ACME 挂载根目录", err)
	}
	state := string(readTestFile(t, filepath.Join(home, domain+"_ecc", domain+".conf")))
	if strings.Contains(state, "stage-") || strings.Contains(state, "invalid") || !strings.Contains(state, filepath.Join(certRoot, domain)) {
		t.Fatal("发布状态仍指向暂存位置或旧命令", state)
	}
	line := strings.Split(strings.Split(state, "Le_ReloadCmd='__ACME_BASE64__START_")[1], "_END__'")[0]
	command, err := base64.StdEncoding.DecodeString(line)
	if err != nil || !strings.HasSuffix(string(command), " nginx-reload") {
		t.Fatal("保存的重载命令不可用")
	}
	for _, path := range []string{filepath.Join(certRoot, domain, "key.pem")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("发布权限错误", err)
		}
	}
}

func TestM15I8NewIssueAndReferencedRemovalRollback(t *testing.T) {
	cert, key := invariantCertificate(t)
	for _, action := range []string{"issue", "remove"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			home, certRoot := filepath.Join(root, "home"), filepath.Join(root, "ssl")
			domain := "test-only.example.com"
			putTestFile(t, filepath.Join(home, "account.conf"), []byte("original"))
			if action == "remove" {
				putTestFile(t, filepath.Join(certRoot, domain, "fullchain.pem"), cert)
				putTestFile(t, filepath.Join(certRoot, domain, "key.pem"), key)
			}
			before := snapshotInvariantTrees(t, home, certRoot)
			ops := liveACMETransactionOps()
			calls := 0
			ops.reload = func() error {
				calls++
				if calls == 1 {
					return errors.New("候选仍引用已删除证书或 HUP 失败")
				}
				return nil
			}
			ops.run = func(_ []string, env []string, _ io.Reader) error {
				var stage string
				for _, value := range env {
					if strings.HasPrefix(value, "VPS_RELAY_CERT_STAGE=") {
						stage = strings.TrimPrefix(value, "VPS_RELAY_CERT_STAGE=")
					}
				}
				if action == "remove" {
					return os.RemoveAll(stage)
				}
				putTestFile(t, filepath.Join(stage, "fullchain.pem"), cert)
				putTestFile(t, filepath.Join(stage, "key.pem"), key)
				return nil
			}
			if err := runACMETransaction(domain, action, home, certRoot, filepath.Join(root, "backup"), []string{"fake"}, nil, nil, ops); err == nil {
				t.Fatal("发布重载失败必须失败并还原")
			}
			if !reflect.DeepEqual(before, snapshotInvariantTrees(t, home, certRoot)) || calls != 2 {
				t.Fatal("新证书未撤下，或被引用证书未恢复", calls)
			}
		})
	}
}

func snapshotInvariantTrees(t *testing.T, roots ...string) map[string]treeFile {
	t.Helper()
	out := map[string]treeFile{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
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
	}
	return out
}
