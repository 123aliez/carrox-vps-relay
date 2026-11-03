package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type xrayChild interface {
	Wait() error
	Signal(os.Signal) error
	Kill() error
}
type xrayProcessOps struct {
	start    func([]byte) (xrayChild, error)
	ready    func(<-chan struct{}) error
	portFree func() error
	after    func(time.Duration) <-chan time.Time
	lock     func() (func(), error)
	log      func(string)
}
type xrayCommand struct {
	data  []byte
	close bool
	reply chan error
}
type xrayHandle struct {
	child xrayChild
	done  chan struct{}
}
type xraySupervisor struct {
	commands  chan xrayCommand
	done      chan struct{}
	running   atomic.Bool
	lastError atomic.Pointer[string]
	applied   atomic.Pointer[[32]byte]
	requested atomic.Pointer[[32]byte]
}

func newXraySupervisor(ops xrayProcessOps) *xraySupervisor {
	if ops.after == nil {
		ops.after = time.After
	}
	if ops.log == nil {
		ops.log = func(string) {}
	}
	if ops.lock == nil {
		ops.lock = func() (func(), error) { return func() {}, nil }
	}
	if ops.ready == nil {
		ops.ready = func(done <-chan struct{}) error {
			select {
			case <-done:
				return errors.New("Xray 在就绪前退出")
			default:
				return nil
			}
		}
	}
	m := &xraySupervisor{commands: make(chan xrayCommand), done: make(chan struct{})}
	go m.loop(ops)
	return m
}
func (m *xraySupervisor) request(c xrayCommand) error {
	c.reply = make(chan error, 1)
	select {
	case m.commands <- c:
	case <-m.done:
		return &xrayApplyFailure{cause: errors.New("Xray 进程管理已停止")}
	}
	select {
	case err := <-c.reply:
		return err
	case <-m.done:
		select {
		case err := <-c.reply:
			return err
		default:
			return errors.New("Xray 进程管理已停止")
		}
	}
}
func (m *xraySupervisor) Apply(data []byte) error {
	err := m.request(xrayCommand{data: append([]byte{}, data...)})
	if err == nil {
		return nil
	}
	var failure *xrayApplyFailure
	if errors.As(err, &failure) {
		return err
	}
	return &xrayApplyFailure{submitted: true, cause: err}
}

func (m *xraySupervisor) Close() error  { return m.request(xrayCommand{close: true}) }
func (m *xraySupervisor) Running() bool { return m.running.Load() }
func (m *xraySupervisor) LastError() string {
	if message := m.lastError.Load(); message != nil {
		return *message
	}
	return ""
}
func (m *xraySupervisor) ReadyFor(data []byte) bool {
	applied := m.applied.Load()
	return m.Running() && applied != nil && *applied == sha256.Sum256(data)
}
func (m *xraySupervisor) failed(message string) { m.lastError.Store(&message); m.running.Store(false) }
func stopXrayChild(h *xrayHandle, after func(time.Duration) <-chan time.Time) error {
	select {
	case <-h.done:
		return nil
	default:
	}
	_ = h.child.Signal(syscall.SIGTERM)
	select {
	case <-h.done:
		return nil
	case <-after(5 * time.Second):
	}
	_ = h.child.Kill()
	select {
	case <-h.done:
		return nil
	case <-after(time.Second):
		return errors.New("Xray 子进程未能结束")
	}
}
func (m *xraySupervisor) loop(ops xrayProcessOps) {
	defer close(m.done)
	var desired, runningData []byte
	var current *xrayHandle
	var retry <-chan time.Time
	delay := time.Second
	schedule := func() { retry = ops.after(delay); delay = min(30*time.Second, delay*2) }
	start := func() error {
		if ops.portFree != nil {
			if err := ops.portFree(); err != nil {
				m.failed("Xray 监听端口 30001 已被占用或无法绑定，等待重试")
				ops.log("Xray 监听端口 30001 已被占用或无法绑定，等待重试")
				schedule()
				return errors.New("Xray 监听端口 30001 已被占用或无法绑定")
			}
		}
		child, err := ops.start(desired)
		if err != nil {
			m.failed("Xray 启动失败，等待重试")
			ops.log("Xray 启动失败，等待重试")
			schedule()
			return errors.New("启动 Xray 失败")
		}
		h := &xrayHandle{child: child, done: make(chan struct{})}
		current = h
		runningData = append([]byte{}, desired...)
		retry = nil
		go func() { _ = child.Wait(); close(h.done) }()
		if err := ops.ready(h.done); err != nil {
			m.failed("Xray 未能在 5 秒内就绪，等待重试")
			ops.log("Xray 就绪失败，等待重试")
			if stopXrayChild(h, ops.after) == nil {
				current = nil
			}
			schedule()
			return errors.New("Xray 就绪失败")
		}
		select {
		case <-h.done:
			current = nil
			m.failed("Xray 在就绪前退出，等待重试")
			schedule()
			return errors.New("Xray 在就绪前退出")
		default:
		}
		sum := sha256.Sum256(runningData)
		m.applied.Store(&sum)
		m.lastError.Store(nil)
		m.running.Store(true)
		return nil
	}
	for {
		var exited <-chan struct{}
		if current != nil {
			exited = current.done
		}
		select {
		case command := <-m.commands:
			if command.close {
				var err error
				if current != nil {
					err = stopXrayChild(current, ops.after)
				}
				m.running.Store(false)
				command.reply <- err
				return
			}
			changed := !bytes.Equal(desired, command.data)
			if changed {
				delay = time.Second
			}
			desired = append([]byte{}, command.data...)
			requestedSum := sha256.Sum256(desired)
			m.requested.Store(&requestedSum)
			if !changed && retry != nil {
				command.reply <- nil
				continue
			}
			if current != nil && m.running.Load() && bytes.Equal(runningData, desired) {
				select {
				case <-current.done:
					current = nil
					m.running.Store(false)
				default:
					command.reply <- nil
					continue
				}
			}
			if current != nil {
				if err := stopXrayChild(current, ops.after); err != nil {
					m.failed("Xray 旧进程尚未结束，等待重试")
					schedule()
					command.reply <- err
					continue
				}
				current = nil
				m.running.Store(false)
			}
			retry = nil
			if len(desired) == 0 {
				runningData = nil
				m.lastError.Store(nil)
				command.reply <- nil
				continue
			}
			command.reply <- start()
		case <-exited:
			current = nil
			m.running.Store(false)
			if len(desired) > 0 {
				m.failed("Xray 子进程意外退出，等待重试")
				ops.log("Xray 子进程意外退出，等待重试")
				schedule()
			}
		case <-retry:
			retry = nil
			if len(desired) == 0 {
				continue
			}
			// 崩溃重启不能覆盖另一个进程正在校验的候选配置。
			unlock, err := ops.lock()
			if err != nil {
				retry = ops.after(time.Second)
				continue
			}
			if current != nil {
				if err := stopXrayChild(current, ops.after); err != nil {
					schedule()
					unlock()
					continue
				}
				current = nil
			}
			_ = start()
			unlock()
		}
	}
}

// 只记录错误类别和字节数，不将子进程可能回显的配置或凭据写进日志。
type xrayStderr struct {
	mu     sync.Mutex
	sample []byte
	total  int
}

func (s *xrayStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += len(p)
	remaining := 4096 - len(s.sample)
	if remaining > 0 {
		s.sample = append(s.sample, p[:min(remaining, len(p))]...)
	}
	return len(p), nil
}
func (s *xrayStderr) summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total == 0 {
		return ""
	}
	kind := "子进程错误输出"
	if bytes.Contains(s.sample, []byte("address already in use")) {
		kind = "监听端口被占用"
	} else if bytes.Contains(s.sample, []byte("failed to load")) {
		kind = "配置加载失败"
	}
	return fmt.Sprintf("Xray：%s（stderr %d 字节）", kind, s.total)
}

type execXrayChild struct {
	cmd    *exec.Cmd
	stderr *xrayStderr
}

func (c *execXrayChild) Wait() error {
	err := c.cmd.Wait()
	if summary := c.stderr.summary(); summary != "" {
		log.Print(summary)
	}
	return err
}
func (c *execXrayChild) Signal(signal os.Signal) error { return c.cmd.Process.Signal(signal) }
func (c *execXrayChild) Kill() error                   { return c.cmd.Process.Kill() }
func liveXrayProcessOps(p xrayPaths) xrayProcessOps {
	return xrayProcessOps{
		start: func(data []byte) (xrayChild, error) {
			current, err := desiredXrayConfig(liveSNIPaths(), p, liveRelayFS())
			if err != nil || !bytes.Equal(current, data) {
				return nil, errors.New("Xray 磁盘配置已变化，等待对账")
			}

			stderr := &xrayStderr{}
			cmd := exec.Command("/usr/local/bin/xray", "run", "-c", p.config())
			cmd.Stderr = stderr
			configureXrayChild(cmd)
			if err := cmd.Start(); err != nil {
				return nil, errors.New("启动 Xray 失败")
			}
			return &execXrayChild{cmd, stderr}, nil
		}, portFree: func() error { return checkXrayPortFree(net.Listen) }, ready: func(done <-chan struct{}) error {
			return waitXrayReady(done, func() bool { return tcpDial("127.0.0.1:30001", 100*time.Millisecond) }, time.After)
		}, after: time.After, lock: func() (func(), error) {
			unlock, err := lockConfigDirectory(confDir)
			if err != nil {
				return nil, err
			}
			if err := ensureNoSNIMigration(); err != nil {
				unlock()
				return nil, err
			}
			return unlock, nil
		}, log: func(message string) { log.Print(message) },
	}
}

var serviceXray atomic.Pointer[xraySupervisor]

func xrayRunning() bool { manager := serviceXray.Load(); return manager != nil && manager.Running() }
func desiredXrayConfig(p sniPaths, xpaths xrayPaths, fs relayFS) ([]byte, error) {
	on, err := sniMode(p, fs)
	if err != nil || !on {
		return nil, err
	}
	sniMap, err := fs.read(p.derived()[0])
	if err != nil || len(bytes.TrimSpace(sniMap)) == 0 {
		return nil, err
	}
	data, err := fs.read(xpaths.config())
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}
func applyXrayRuntime() error {
	data, err := desiredXrayConfig(liveSNIPaths(), liveXrayPaths(), liveRelayFS())
	if err != nil {
		message := "读取 Xray 配置失败"
		if m := serviceXray.Load(); m != nil {
			m.lastError.Store(&message)
		}
		return &xrayApplyFailure{cause: errors.New(message)}
	}
	if manager := serviceXray.Load(); manager != nil {
		return manager.Apply(data)
	}
	return notifyXrayService(liveXrayPaths().socket(), len(data) > 0)
}

// 独立 CLI 和证书脚本通过仅 root 可访问的 Unix socket 请求服务进程重启子进程。
func notifyXrayService(socket string, required bool) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 13 * time.Second}
	response, err := client.Post("http://xray/apply", "application/json", strings.NewReader(""))
	if err != nil {
		if !required && (errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)) {
			return nil
		}
		return &xrayApplyFailure{cause: errors.New("无法通知面板托管 Xray，请确认面板服务正在运行")}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusOK {
		return &xrayApplyFailure{submitted: response.Header.Get("X-Relay-Xray-Submitted") == "1", cause: errors.New("面板更新 Xray 失败")}
	}
	return nil
}
func startXrayControl(p xrayPaths, m *xraySupervisor) (func(), error) {
	if err := ensureNoSNIMigration(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.root, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(p.root, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(p.socket()); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("Xray 控制路径已被其他文件占用")
		}
		conn, dialErr := net.DialTimeout("unix", p.socket(), time.Second)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("已有面板进程在托管 Xray")
		}
		if err := os.Remove(p.socket()); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", p.socket())
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p.socket(), 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	handler := xrayControlHandler(m, func() ([]byte, error) {
		if err := ensureNoSNIMigration(); err != nil {
			return nil, err
		}
		return desiredXrayConfig(liveSNIPaths(), p, liveRelayFS())
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return func() { _ = server.Close(); _ = os.Remove(p.socket()) }, nil
}

func xrayControlHandler(m *xraySupervisor, read func() ([]byte, error)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apply", func(w http.ResponseWriter, r *http.Request) {
		data, err := read()
		if err == nil {
			err = m.Apply(data)
			var failure *xrayApplyFailure
			if err == nil || errors.As(err, &failure) && failure.submitted {
				w.Header().Set("X-Relay-Xray-Submitted", "1")
			}
		}
		if err != nil {
			http.Error(w, "更新 Xray 失败", 500)
			return
		}
		w.WriteHeader(200)
	})
	return mux
}

// 就绪探测与计时可替换，测试不启动真实 Xray，也不监听本机端口。
func waitXrayReady(done <-chan struct{}, dial func() bool, after func(time.Duration) <-chan time.Time) error {
	deadline := after(5 * time.Second)
	for {
		select {
		case <-done:
			return errors.New("Xray 在就绪前退出")
		case <-deadline:
			return errors.New("Xray 就绪超时")
		default:
		}
		if dial() {
			select {
			case <-deadline:
				return errors.New("Xray 就绪超时")
			case <-done:
				return errors.New("Xray 在就绪前退出")
			default:
				return nil
			}
		}
		select {
		case <-done:
			return errors.New("Xray 在就绪前退出")
		case <-deadline:
			return errors.New("Xray 就绪超时")
		case <-after(50 * time.Millisecond):
		}
	}
}
func xrayLastError() string {
	if m := serviceXray.Load(); m != nil {
		return m.LastError()
	}
	return "Xray 托管尚未启动"
}

func confirmRealityRuntime(domain string) error {
	if err := checkRealityEntryHealth(domain, liveSNIPaths(), liveXrayPaths(), liveRelayFS()); err != nil {
		return err
	}
	// Nginx 重载阶段的 Apply 已等待最多 5 秒，这里不绕过退避再次强行启动。
	data, err := desiredXrayConfig(liveSNIPaths(), liveXrayPaths(), liveRelayFS())
	if err != nil {
		return errors.New("读取 Xray 配置失败")
	}
	manager := serviceXray.Load()
	if manager == nil || !manager.ReadyFor(data) {
		return errors.New("Xray 尚未应用入口配置并就绪")
	}
	return nil
}

func checkRealityEntryHealth(domain string, p sniPaths, xp xrayPaths, fs relayFS) error {
	files, err := managedSNIFiles(p, fs)
	if err != nil {
		return errors.New("入口配置不可读")
	}
	sites := enabledRealitySites(files)
	found := false
	for _, site := range sites {
		if site.Domain == domain {
			found = true
		}
	}
	if !found {
		return errors.New("入口配置未启用")
	}
	material := loadRealityMaterial(sites, xp, fs)
	annotateRealityValidation(&material, xp, fs)
	if message := material.Errors[domain]; message != "" {
		return errors.New(message)
	}
	return nil
}

// 标记失败发生在提交之前还是之后，重载日志不把通知失败误称为监督器重试。
type xrayApplyFailure struct {
	submitted bool
	cause     error
}

func (e *xrayApplyFailure) Error() string { return e.cause.Error() }
func (e *xrayApplyFailure) Unwrap() error { return e.cause }
func checkXrayPortFree(listen func(string, string) (net.Listener, error)) error {
	listener, err := listen("tcp4", "127.0.0.1:30001")
	if err != nil {
		return errors.New("Xray 监听端口 30001 已被占用或无法绑定")
	}
	return listener.Close()
}

// 定期读取已经生成并校验的磁盘配置，补偿读盘失败和 CLI 通知丢失。
func reconcileXrayWith(m *xraySupervisor, lock func() (func(), error), guard func() error, read func() ([]byte, error)) error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := guard(); err != nil {
		return err
	}
	data, err := read()
	if err != nil {
		message := "Xray 对账读取配置失败，下次对账重试"
		m.lastError.Store(&message)
		return &xrayApplyFailure{cause: errors.New(message)}
	}
	if m.ReadyFor(data) {
		m.lastError.Store(nil)
		return nil
	}
	if len(data) == 0 && !m.Running() && m.LastError() == "" {
		return nil
	}
	requested := m.requested.Load()
	// 已提交的同一配置保留原有指数退避，不用周期性对账强行启动。
	if requested != nil && *requested == sha256.Sum256(data) && !m.Running() && len(data) > 0 {
		return nil
	}
	return m.Apply(data)
}
func startXrayReconciler(parent context.Context, m *xraySupervisor, control func()) func() {
	ctx, cancel := context.WithCancel(parent)
	ticker := time.NewTicker(30 * time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runXrayReconciliation(ctx, ticker.C, func() error {
			return reconcileXrayWith(m, func() (func(), error) { return lockConfigDirectory(confDir) }, ensureNoSNIMigration, func() ([]byte, error) {
				control()
				if err := recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation); err != nil {
					return nil, err
				}
				if err := reconcileNginxWith(nginxPendingPath(), nginxReload); err != nil {
					return nil, err
				}
				if err := syncSNI443Runtime(); err != nil {
					return nil, err
				}
				return desiredXrayConfig(liveSNIPaths(), liveXrayPaths(), liveRelayFS())
			})
		}, func(message string) { log.Print(message) })
	}()
	return func() { cancel(); ticker.Stop(); <-done }
}
func runXrayReconciliation(ctx context.Context, ticks <-chan time.Time, reconcile func() error, report func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			if err := reconcile(); err != nil {
				report("Xray 本轮对账未完成，30 秒后再次对账：" + err.Error())
			}
		}
	}
}
