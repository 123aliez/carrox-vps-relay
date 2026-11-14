// vps-relay entry point.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	version    = "M16"
	listenAddr = "127.0.0.1:8787"
)

func main() {
	if len(os.Args) > 1 {
		var err error
		if len(os.Args) == 3 && os.Args[1] == "sni443" {
			var unlock func()
			unlock, err = lockConfigDirectory(confDir)
			if err == nil {
				defer unlock()
				if os.Args[2] == "enable" || os.Args[2] == "disable" {
					err = ensureNoSNIMigration()
					if err == nil {
						err = recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation)
					}
					if err == nil {
						err = reconcileNginxWith(nginxPendingPath(), nginxReload)
					}
				}
				if err == nil {
					mayFinish := os.Args[2] == "enable" || os.Args[2] == "disable"
					if os.Args[2] == "recover" {
						pending, pendingErr := latestPendingMigration(liveSNIPaths(), liveRelayFS())
						mayFinish = pendingErr == nil && pending != ""
					}
					err = migrateSNI443(os.Args[2], liveSNIMigrationOps(), os.Stdout)
					if mayFinish && ensureNoSNIMigration() == nil {
						err = errors.Join(err, finishNginxMutation())
					}
				}
			}
		} else if len(os.Args) >= 4 && os.Args[1] == "lock-run" && os.Args[2] == "--" {
			err = execWithConfigLock(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[1] == "acme-transaction" {
			err = acmeTransactionCLI(os.Args[2:])
		} else if len(os.Args) == 2 && os.Args[1] == "nginx-reload" {
			err = runNginxReloadCommand()
		} else {
			err = fmt.Errorf("用法：vps-relay sni443 enable|disable|status|recover")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := runPanelService(); err != nil {
		log.Fatal(err)
	}
}

func runPanelService() error {
	loadKeyTable()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	manager := newXraySupervisor(liveXrayProcessOps(liveXrayPaths()))
	serviceXray.Store(manager)
	defer func() { _ = manager.Close(); serviceXray.Store(nil) }()
	var closeControl func()
	control := func() {
		if closeControl != nil || ensureNoSNIMigration() != nil {
			return
		}
		var err error
		closeControl, err = startXrayControl(liveXrayPaths(), manager)
		if err != nil {
			log.Print("警告：Xray 控制接口不可用，面板继续运行，周期对账会重试")
		}
	}
	defer func() {
		if closeControl != nil {
			closeControl()
		}
	}()
	if err := initializeXrayRuntime(ensureNoSNIMigration, func() error {
		unlock, err := lockConfigDirectory(confDir)
		if err != nil {
			return err
		}
		defer unlock()
		if err := ensureNoSNIMigration(); err != nil {
			return err
		}
		control()
		if err := recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation); err != nil {
			return err
		}
		if err := reconcileNginxWith(nginxPendingPath(), nginxReload); err != nil {
			return err
		}
		on, err := sniMode(liveSNIPaths(), liveRelayFS())
		if err != nil || !on {
			return err
		}
		if err := ensureNoSNIMigration(); err != nil {
			return err
		}
		if err := syncSNI443Runtime(); err != nil {
			return err
		}
		return applyXrayRuntime()
	}); err != nil {
		message := "Reality 启动暂停，请检查面板日志或执行 sni443 status"
		manager.lastError.Store(&message)
		log.Printf("！！！Reality 启动已暂停，面板继续运行：%v", err)
	}
	defer startXrayReconciler(ctx, manager, control)()
	mux := http.NewServeMux()
	registerAPIRoutes(mux)
	registerUIRoutes(mux)
	server := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	go autoRenewLoop()
	log.Printf("vps-relay listening on %s (%s)", listenAddr, version)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
		return nil
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// 迁移中断时只开放面板读取和恢复指令，绝不读取混合配置启动 Xray。
func initializeXrayRuntime(guard, initialize func() error) error {
	if err := guard(); err != nil {
		return err
	}
	return initialize()
}

func runNginxReloadCommand() error {
	inherited := configLockInherited()
	unlock, err := lockReloadConfiguration()
	if err != nil {
		return fmt.Errorf("证书文件可能已安装，重载尚未执行，请稍后重试：%w", err)
	}
	defer unlock()
	if err := ensureNoSNIMigration(); err != nil {
		return err
	}
	borrowed, err := recoverBeforeNginxOperation(inherited, nginxReload, beginNginxMutation)
	if err != nil {
		return err
	}
	op := startNginxOperation(borrowed)
	defer op.close()
	if err := beginNginxMutation(); err != nil {
		return err
	}
	if err := nginxReload(); err != nil {
		return err
	}
	markNginxConsistent()
	if err := op.finish(); err != nil {
		op.consistent.Store(false)
		return err
	}
	return nil
}
