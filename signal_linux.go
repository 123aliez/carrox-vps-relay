//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var syscallSIGHUP = syscall.SIGHUP
var configLocksMu sync.Mutex
var configLocks = map[string]*os.File{}

// 对已有配置目录加锁，不创建文件；与 docker exec 中的迁移进程互斥。
func lockConfigDirectory(path string) (func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法锁定配置目录: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("配置目录正被其他进程修改: %w", err)
	}
	configLocksMu.Lock()
	configLocks[path] = f
	configLocksMu.Unlock()
	return func() {
		configLocksMu.Lock()
		delete(configLocks, path)
		configLocksMu.Unlock()
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// 面板异常退出时也结束子进程，避免宿主 PID 命名空间里遗留监听。
func configureXrayChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// 仅受控 ACME 子进程树继承真实锁描述符，环境变量本身不能跳过加锁。
func duplicateConfigLock(path string) (*os.File, error) {
	configLocksMu.Lock()
	defer configLocksMu.Unlock()
	f := configLocks[path]
	if f == nil {
		return nil, nil
	}
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), path), nil
}
func inheritedConfigLock() *os.File {
	if os.Getenv("VPS_RELAY_CONFIG_LOCK_HELD") != "3" {
		return nil
	}
	fd, err := syscall.Dup(3)
	if err != nil {
		return nil
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "inherited-config-lock")
	info, err := f.Stat()
	expected, statErr := os.Stat(confDir)
	if err == nil && statErr == nil && info.IsDir() && os.SameFile(info, expected) && syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		return f
	}
	_ = f.Close()
	return nil
}
func configLockInherited() bool {
	f := inheritedConfigLock()
	if f == nil {
		return false
	}
	_ = f.Close()
	return true
}

func lockReloadConfiguration() (func(), error) {
	if f := inheritedConfigLock(); f != nil {
		// 不解锁共享描述符；父进程等待整棵受控进程树结束后释放锁。
		return func() { _ = f.Close() }, nil
	}
	return lockConfigDirectory(confDir)
}

// 用持锁的当前进程直接替换成目标命令，避免另建进程组逃出 ACME 超时控制。
func execWithConfigLock(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lock-run 缺少命令")
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
	if _, err := recoverBeforeNginxOperation(inherited, nginxReload, beginNginxMutation); err != nil {
		return err
	}
	locked, err := duplicateConfigLock(confDir)
	if err != nil {
		return err
	}
	if locked == nil {
		locked = inheritedConfigLock()
	}
	if locked == nil {
		return fmt.Errorf("无法传递真实配置锁")
	}
	defer locked.Close()
	command, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "VPS_RELAY_CONFIG_LOCK_HELD=") {
			env = append(env, item)
		}
	}
	env = append(env, "VPS_RELAY_CONFIG_LOCK_HELD=3")
	if err := syscall.Dup2(int(locked.Fd()), 3); err != nil {
		return err
	}
	return syscall.Exec(command, args, env)
}

func configureACMEGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killACMEGroup(cmd *exec.Cmd)      { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }

// 已被收养的僵尸不再执行代码；其余同组进程必须结束后才能释放配置锁。
func waitACMEGroup(pgid int) {
	for acmeGroupAlive(pgid) {
		time.Sleep(10 * time.Millisecond)
	}
}
func acmeGroupAlive(pgid int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return syscall.Kill(-pgid, 0) == nil
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 3 || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		group, err := strconv.Atoi(fields[2])
		if err == nil && group == pgid {
			return true
		}
	}
	return false
}
