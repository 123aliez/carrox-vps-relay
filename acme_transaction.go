package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var acmeCertificateRoot = sslDir

type acmeTarget struct {
	Path    string `json:"path"`
	Stage   string `json:"stage"`
	Backup  string `json:"backup"`
	Existed bool   `json:"existed"`
}
type acmeTransaction struct {
	State       string       `json:"state"`
	Publishing  bool         `json:"publishing,omitempty"`
	Targets     []acmeTarget `json:"targets"`
	Temporary   []string     `json:"temporary,omitempty"`
	CreatedDirs []string     `json:"created_dirs,omitempty"`
}
type acmeTransactionOps struct {
	prepare    func() error
	consistent func()
	commit     func() error
	run        func([]string, []string, io.Reader) error
	validate   func(string) error
	reload     func() error
	step       func(string)
}

func liveACMETransactionOps() acmeTransactionOps {
	return acmeTransactionOps{
		run: func(args, env []string, input io.Reader) error {
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env, cmd.Stdin = env, input
			if lock := inheritedConfigLock(); lock != nil {
				defer lock.Close()
				cmd.ExtraFiles = []*os.File{lock}
			} else if lock, err := duplicateConfigLock(confDir); err != nil {
				return err
			} else if lock != nil {
				defer lock.Close()
				cmd.ExtraFiles = []*os.File{lock}
				cmd.Env = append(cmd.Env, "VPS_RELAY_CONFIG_LOCK_HELD=3")
			}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Run(); err != nil {
				return errors.New("ACME 步骤失败，原证书与状态已保留")
			}
			return nil
		},
		validate: func(dir string) error {
			_, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem"))
			if err != nil {
				return errors.New("签发的证书或私钥不完整，未安装")
			}
			return nil
		}, reload: nginxReload, step: func(string) {},
	}
}

func writeACMETransaction(path string, record acmeTransaction) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}

// ACME 只写隔离副本；全部成功并校验证书对后才发布，发布过程由持久化清单恢复。
func runACMETransaction(domain, action, home, certRoot, backupRoot string, args, env []string, input io.Reader, ops acmeTransactionOps) error {
	if ops.step == nil {
		ops.step = func(string) {}
	}
	if validateSNIDomain(domain) != nil || (action != "issue" && action != "renew" && action != "remove") || len(args) == 0 {
		return errors.New("ACME 事务参数无效")
	}
	home, err := filepath.EvalSymlinks(home)
	if err != nil {
		return errors.New("无法读取 ACME 状态目录")
	}
	if err := os.MkdirAll(backupRoot, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(backupRoot, "acme-")
	if err != nil {
		return err
	}
	manifest := filepath.Join(dir, "manifest.json")
	id := ".relay-" + filepath.Base(dir)
	stageHome, backupHome := filepath.Join(home, id+"-stage"), filepath.Join(home, id+"-original")
	// 暂存与目标同卷，兼容 Docker 的独立 ACME/Nginx 挂载，且不重命名挂载根目录。
	certTarget := acmeTarget{Path: filepath.Join(certRoot, domain), Stage: filepath.Join(certRoot, id+"-stage"), Backup: filepath.Join(certRoot, id+"-original")}
	if _, err := os.Lstat(certTarget.Path); err == nil {
		certTarget.Existed = true
	} else if !os.IsNotExist(err) {
		return err
	}
	stageCert := certTarget.Stage
	record := acmeTransaction{State: "in-progress", Targets: []acmeTarget{certTarget}, Temporary: []string{stageHome, backupHome, stageCert, certTarget.Backup}}
	if _, err := os.Stat(certRoot); os.IsNotExist(err) {
		record.CreatedDirs = append(record.CreatedDirs, certRoot)
	} else if err != nil {
		return err
	}
	// 清单先于任何业务路径变更，复制中断时原文件仍完整。
	if err := writeACMETransaction(manifest, record); err != nil {
		return err
	}
	ops.step("manifest")
	fail := func(cause error) error {
		recoveryErr := recoverACMETransaction(manifest, ops.reload, ops.prepare)
		if recoveryErr == nil && ops.consistent != nil {
			ops.consistent()
		}
		return errors.Join(cause, recoveryErr)
	}
	if err := copyACMETree(home, stageHome); err != nil {
		return fail(err)
	}
	if certTarget.Existed {
		if err := copyACMETree(certTarget.Path, stageCert); err != nil {
			return fail(err)
		}
	} else if err := os.MkdirAll(stageCert, 0700); err != nil {
		return fail(err)
	}
	if err := rewriteACMEState(stageHome, home, stageHome, filepath.Join(certRoot, domain), stageCert, ":"); err != nil {
		return fail(err)
	}
	childEnv := make([]string, 0, len(env)+2)
	for _, value := range env {
		if !strings.HasPrefix(value, "ACME_HOME=") && !strings.HasPrefix(value, "VPS_RELAY_CERT_STAGE=") {
			childEnv = append(childEnv, value)
		}
	}
	childEnv = append(childEnv, "ACME_HOME="+stageHome, "VPS_RELAY_CERT_STAGE="+stageCert)
	if err := ops.run(args, childEnv, input); err != nil {
		return fail(err)
	}
	ops.step("script")
	if action != "remove" {
		if err := ops.validate(stageCert); err != nil {
			return fail(err)
		}
		if err := os.Chmod(filepath.Join(stageCert, "key.pem"), 0600); err != nil {
			return fail(err)
		}
		if info, err := os.Stat(filepath.Join(certRoot, domain, "fullchain.pem")); err == nil {
			if err := os.Chmod(filepath.Join(stageCert, "fullchain.pem"), info.Mode().Perm()); err != nil {
				return fail(err)
			}
		} else if !os.IsNotExist(err) {
			return fail(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	if info, err := os.Stat(executable); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fail(errors.New("面板重载命令不可执行，未发布证书"))
	}
	command := "'" + strings.ReplaceAll(executable, "'", "'\\''") + "' nginx-reload"
	if err := rewriteACMEState(stageHome, stageHome, home, stageCert, filepath.Join(certRoot, domain), command); err != nil {
		return fail(err)
	}
	homeTargets, err := acmeHomeTargets(home, stageHome, backupHome)
	if err != nil {
		return fail(err)
	}
	record.Targets = append(homeTargets, certTarget)
	newDirs := map[string]bool{}
	for _, target := range homeTargets {
		for parent := filepath.Dir(target.Path); parent != home && strings.HasPrefix(parent, home+string(filepath.Separator)); parent = filepath.Dir(parent) {
			if _, err := os.Stat(parent); os.IsNotExist(err) {
				newDirs[parent] = true
			} else if err != nil {
				return fail(err)
			}
		}
	}
	for path := range newDirs {
		record.CreatedDirs = append(record.CreatedDirs, path)
	}
	sort.Slice(record.CreatedDirs, func(i, j int) bool { return len(record.CreatedDirs[i]) > len(record.CreatedDirs[j]) })
	record.Publishing = true
	if err := writeACMETransaction(manifest, record); err != nil {
		return fail(err)
	}
	ops.step("publishing")
	if ops.prepare != nil {
		if err := ops.prepare(); err != nil {
			return fail(err)
		}
	}
	for _, target := range record.Targets {
		if err := os.MkdirAll(filepath.Dir(target.Path), 0700); err != nil {
			return fail(err)
		}
		if target.Existed {
			if err := os.MkdirAll(filepath.Dir(target.Backup), 0700); err != nil {
				return fail(err)
			}
			if err := os.Rename(target.Path, target.Backup); err != nil {
				return fail(err)
			}
			ops.step("backup")
		}
		if _, err := os.Lstat(target.Stage); err == nil {
			if err := os.Rename(target.Stage, target.Path); err != nil {
				return fail(err)
			}
		} else if !os.IsNotExist(err) {
			return fail(err)
		}
		ops.step("publish")
	}
	// 手工 remove 也必须检查；仍被活动配置引用的证书不能被删除。
	if err := ops.reload(); err != nil {
		return fail(err)
	}
	ops.step("reload")
	// 必须先结束父配置日志，再提交证书子事务及永久清理备份；失败仍能恢复证书。
	if ops.commit != nil {
		if err := ops.commit(); err != nil {
			return fail(err)
		}
	}
	record.State = "done"
	if err := writeACMETransaction(manifest, record); err != nil {
		return fail(err)
	}
	ops.step("done")
	for _, target := range record.Targets {
		_ = os.RemoveAll(target.Backup)
	}
	for _, path := range record.Temporary {
		_ = os.RemoveAll(path)
	}
	if action == "remove" {
		removeEmptyACMEDirs(filepath.Join(home, domain+"_ecc"))
	}
	if ops.consistent != nil {
		ops.consistent()
	}
	return nil
}

func acmeHomeTargets(home, stage, backup string) ([]acmeTarget, error) {
	paths := map[string]bool{}
	for _, root := range []string{home, stage} {
		err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path != root && strings.HasPrefix(e.Name(), ".relay-acme-") {
				if e.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if e.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			paths[rel] = true
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(paths))
	for path := range paths {
		names = append(names, path)
	}
	sort.Strings(names)
	var targets []acmeTarget
	for _, name := range names {
		target := acmeTarget{Path: filepath.Join(home, name), Stage: filepath.Join(stage, name), Backup: filepath.Join(backup, name)}
		if _, err := os.Lstat(target.Path); err == nil {
			target.Existed = true
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func removeEmptyACMEDirs(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return
		}
		removeEmptyACMEDirs(filepath.Join(root, entry.Name()))
	}
	_ = os.Remove(root)
}

func copyACMETree(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if filepath.Base(source) != "acme.sh" {
			resolved, err := filepath.EvalSymlinks(source)
			if err != nil {
				return err
			}
			return copyACMETree(resolved, target)
		}
		link, err := os.Readlink(source)
		if err != nil {
			return err
		}
		return os.Symlink(link, target)
	}
	if info.IsDir() {
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".relay-acme-") {
				continue
			}
			if err := copyACMETree(filepath.Join(source, entry.Name()), filepath.Join(target, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if strings.HasSuffix(source, ".conf") || strings.HasSuffix(source, ".key") || filepath.Base(source) == "key.pem" {
		mode = 0600
	}
	return os.WriteFile(target, data, mode)
}

func rewriteACMEState(root, oldHome, newHome, oldCert, newCert, command string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".conf") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(strings.ReplaceAll(string(data), oldHome, newHome), oldCert, newCert)
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "Le_ReloadCmd=") {
				lines[i] = "Le_ReloadCmd='__ACME_BASE64__START_" + base64.StdEncoding.EncodeToString([]byte(command)) + "_END__'"
			}
		}
		return atomicWrite(path, []byte(strings.Join(lines, "\n")), 0600)
	})
}

func recoverACMETransaction(manifest string, reload func() error, prepare ...func() error) error {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var record acmeTransaction
	if json.Unmarshal(data, &record) != nil {
		return errors.New("证书事务记录损坏")
	}
	if record.State != "in-progress" {
		cleanupFinishedACME(record)
		return nil
	}
	// 发布后回滚可能发生在一次已提交的重载之后，先重新取得配置快照。
	if record.Publishing && len(prepare) > 0 && prepare[0] != nil {
		if err := prepare[0](); err != nil {
			return err
		}
	}
	changed := false
	for _, target := range record.Targets {
		if _, err := os.Lstat(target.Backup); err == nil {
			if err := os.RemoveAll(target.Path); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target.Path), 0700); err != nil {
				return err
			}
			if err := os.Rename(target.Backup, target.Path); err != nil {
				return err
			}
			changed = true
		} else if !os.IsNotExist(err) {
			return err
		} else if !target.Existed {
			if _, err := os.Lstat(target.Path); err == nil {
				changed = true
			}
			if err := os.RemoveAll(target.Path); err != nil {
				return err
			}
		}
	}
	if changed || record.Publishing {
		if err := reload(); err != nil {
			return err
		}
	}
	record.State = "recovered"
	if err := writeACMETransaction(manifest, record); err != nil {
		return err
	}
	for _, target := range record.Targets {
		_ = os.RemoveAll(target.Stage)
	}
	for _, path := range record.Temporary {
		_ = os.RemoveAll(path)
	}
	for _, path := range record.CreatedDirs {
		_ = os.Remove(path)
	}
	return nil
}

func cleanupFinishedACME(record acmeTransaction) {
	if record.State != "done" && record.State != "recovered" {
		return
	}
	for _, path := range record.Temporary {
		_ = os.RemoveAll(path)
	}
	if record.State == "recovered" {
		for _, path := range record.CreatedDirs {
			_ = os.Remove(path)
		}
	}
}

func recoverACMETransactions(root string, reload func() error, prepare ...func() error) error {
	paths, err := filepath.Glob(filepath.Join(root, "acme-*", "manifest.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := recoverACMETransaction(path, reload, prepare...); err != nil {
			return err
		}
	}
	return nil
}

// 使用固定根目录，避免调用者用环境变量指定证书发布路径。
func acmeTransactionCLI(args []string) error {
	return acmeTransactionCLIWith(args, liveACMETransactionOps())
}

func acmeTransactionCLIWith(args []string, ops acmeTransactionOps) error {
	if ops.prepare == nil {
		ops.prepare = beginNginxMutation
	}
	if ops.commit == nil {
		ops.commit = commitNginxMutation
	}
	if len(args) < 4 || args[2] != "--" {
		return errors.New("证书事务参数无效")
	}
	inherited := configLockInherited()
	unlock, err := lockReloadConfiguration()
	if err != nil {
		return err
	}
	defer unlock()
	if err := ensureNoSNIMigration(); err != nil {
		return err
	}
	borrowed, err := recoverBeforeNginxOperation(inherited, ops.reload, ops.prepare)
	if err != nil {
		return err
	}
	op := startNginxOperation(borrowed)
	defer op.close()
	previousConsistent := ops.consistent
	ops.consistent = func() {
		markNginxConsistent()
		if previousConsistent != nil {
			previousConsistent()
		}
	}
	if err := ops.prepare(); err != nil {
		return err
	}
	home := os.Getenv("ACME_HOME")
	if home == "" {
		home = "/root/.acme.sh"
	}
	err = runACMETransaction(args[0], args[1], home, acmeCertificateRoot, sniBackupDir, args[3:], os.Environ(), os.Stdin, ops)
	if finishErr := op.finish(); finishErr != nil {
		op.consistent.Store(false)
		return errors.Join(err, finishErr)
	}
	return err
}
