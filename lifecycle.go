package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// 所有站点写操作串行，避免同域重复创建及 Nginx 全局检查相互干扰。
var siteMutationMu sync.Mutex

// 创建失败但 DNS 或运行态尚不确定时，保留完整站点供重试，禁止外层继续清理。
var errSiteRetained = errors.New("站点材料已保留供重试")

type siteLifecycle struct {
	issue             func(string, string, string) error
	cleanup           func(string, string, string) error
	certificateExists func(string, string) bool
	render            func(SiteMeta) ([]byte, error)
	write             func(string, []byte, os.FileMode) error
	writeMetadata     func(string, []byte, os.FileMode) error
	remove            func(string) error
	discardBackup     func(string) error
	removeLink        func(string) error
	syncDerived       func() error
	rename            func(string, string) error
	check             func() error
	reload            func() error
	consistent        func()
	commit            func() error
}

func liveSiteLifecycle() siteLifecycle {
	return siteLifecycle{
		issue: acmeIssue, cleanup: acmeRemove, render: renderSite,
		write: writeNginxFile, remove: removeNginxFile, rename: renameNginxFile,
		writeMetadata: atomicWrite, discardBackup: os.Remove,
		check: nginxSyntaxCheck, reload: nginxReload, consistent: markNginxConsistent, commit: commitNginxMutation,
		removeLink: func(domain string) error {
			if err := removeRealitySecrets(domain); err != nil {
				return err
			}
			return syncSNI443()
		}, syncDerived: restoreRelayRuntime,
		certificateExists: func(domain, owner string) bool {
			// 无法确认不存在的材料，一律保留。
			for _, path := range []string{filepath.Join(sslDir, domain), filepath.Join(acmeHome(owner), domain+"_ecc"), filepath.Join(persistentAcmeHome(owner), domain+"_ecc")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					return true
				}
			}
			return false
		},
	}
}

func (ops siteLifecycle) commitBoundary() error {
	if ops.commit != nil {
		return ops.commit()
	}
	return nil
}

func writeManagedSite(meta SiteMeta, path string, ops siteLifecycle) error {
	rendered, err := ops.render(meta)
	if err != nil {
		return err
	}
	return ops.write(path, rendered, 0o644)
}

// DNS 操作前已有完整恢复计划；边界后只原子补记结果，不为元数据清理重新开启旧事务。
func persistSiteMetadata(meta SiteMeta, path string, ops siteLifecycle) error {
	if ops.writeMetadata != nil {
		ops.write = ops.writeMetadata
	}
	return writeManagedSite(meta, path, ops)
}

func provisionSite(meta SiteMeta, token, edge string, zone cfZone, ops siteLifecycle) (SiteMeta, error) {
	change, err := planDNS(token, zone, meta.Domain, edge)
	if err != nil {
		return meta, err
	}
	meta.V = 2
	meta.DNS = change
	meta.CFZone = zone.Name
	meta.CFRecordID = change.After.ID
	meta.CertificateOwned = !ops.certificateExists(meta.Domain, meta.Owner)
	path := confPath(meta.Domain)
	configWritten := false
	dnsAttempted := false
	rollback := func(cause error) (SiteMeta, error) {
		if dnsAttempted {
			if restoreErr := change.release(token); restoreErr != nil {
				// 保留可恢复的元数据和本地反代，避免 DNS 仍指向本机时丢失服务。
				meta.CFRecordID = change.After.ID
				persistErr := persistSiteMetadata(meta, path, ops)
				return meta, errors.Join(cause, errSiteRetained, fmt.Errorf("DNS 恢复失败，已保留站点供重试: %w", restoreErr), persistErr, ops.commitBoundary())
			}
		}
		if configWritten {
			if removeErr := ops.remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				return meta, errors.Join(cause, fmt.Errorf("清理配置失败: %w", removeErr))
			}
			if reloadErr := ops.reload(); reloadErr != nil {
				// 仍在使用证书的旧 worker 未退出时，不能清除其材料。
				persistErr := persistSiteMetadata(meta, path, ops)
				return meta, errors.Join(cause, errSiteRetained, fmt.Errorf("回滚重载失败，保留站点材料: %w", reloadErr), persistErr, ops.commitBoundary())
			}
		}
		if meta.CertificateOwned {
			// 活动配置已撤下并重载；清理可能永久提交证书删除，不能再恢复活动配置。
			if err := ops.commitBoundary(); err != nil {
				return meta, errors.Join(cause, err)
			}
			if cleanupErr := ops.cleanup(meta.Domain, token, meta.Owner); cleanupErr != nil {
				return meta, errors.Join(cause, cleanupErr)
			}
		}
		if ops.consistent != nil {
			ops.consistent()
		}
		return meta, cause
	}
	// DNS-01 不依赖入口 A 记录，先准备证书和可用反代，再切换流量。
	if err := ops.issue(meta.Domain, token, meta.Owner); err != nil {
		return rollback(fmt.Errorf("签发证书失败: %w", err))
	}
	if err := writeManagedSite(meta, path, ops); err != nil {
		return rollback(fmt.Errorf("写入配置失败: %w", err))
	}
	configWritten = true
	if err := ops.check(); err != nil {
		return rollback(err)
	}
	if err := ops.reload(); err != nil {
		return rollback(fmt.Errorf("Nginx 重载失败: %w", err))
	}
	dnsAttempted = true
	// 本地站点及恢复元数据已加载；远程写入可能成功后丢失响应，先保住可用现场。
	if err := ops.commitBoundary(); err != nil {
		dnsAttempted = false
		return rollback(err)
	}
	if err := change.apply(token); err != nil {
		return rollback(err)
	}
	meta.CFRecordID = change.After.ID
	if err := persistSiteMetadata(meta, path, ops); err != nil {
		return rollback(fmt.Errorf("保存 DNS 接管结果失败: %w", err))
	}
	if err := ops.commitBoundary(); err != nil {
		return meta, errors.Join(errSiteRetained, err)
	}
	return meta, nil
}

func removeManagedSite(meta SiteMeta, token, path string, staged bool, ops siteLifecycle) error {
	// DNS 操作先完成；失败时保留站点及原始解析，允许安全重试。
	if meta.DNS != nil && meta.DNS.Mode != "reused" {
		if token == "" {
			return errors.Join(errSiteRetained, fmt.Errorf("缺少站点所有者的 Cloudflare Token，无法恢复 DNS"))
		}
		if err := ops.commitBoundary(); err != nil {
			return errors.Join(errSiteRetained, err)
		}
		if err := meta.DNS.release(token); err != nil {
			return errors.Join(errSiteRetained, fmt.Errorf("DNS 清理失败，保留站点供重试: %w", err))
		}
	}
	backup := path + ".relay-delete.bak"
	if !staged {
		if err := ops.rename(path, backup); err != nil {
			return fmt.Errorf("移除配置失败: %w", err)
		}
	}
	if err := ops.check(); err != nil {
		if staged {
			return err
		}
		return errors.Join(err, restoreSitePath(backup, path, ops))
	}
	if err := ops.reload(); err != nil {
		if staged {
			return fmt.Errorf("Nginx 重载失败，删除恢复信息已保留: %w", err)
		}
		return errors.Join(fmt.Errorf("Nginx 重载失败: %w", err), restoreSitePath(backup, path, ops))
	}
	// 配置已隔离且重载成功；证书/入口机密一经删除便不能恢复原活动配置。
	if err := ops.commitBoundary(); err != nil {
		return err
	}
	if meta.CertificateOwned {
		if err := ops.cleanup(meta.Domain, token, meta.Owner); err != nil {
			// 证书可能已被部分清理，禁止恢复引用它的活动配置。
			return fmt.Errorf("本地证书清理失败，删除恢复信息已保留，请再次删除重试: %w", err)
		}
	}
	if meta.Reality != nil && ops.removeLink != nil {
		if err := ops.removeLink(meta.Domain); err != nil {
			return fmt.Errorf("入口已停止，清理链接失败，请再次删除重试: %w", err)
		}
	}
	// 非活动的重试标记最后原子删除；不可回头点之后不再为它创建恢复旧配置的日志。
	discard := ops.discardBackup
	if discard == nil {
		discard = ops.remove
	}
	if err := discard(backup); err != nil {
		return errors.Join(fmt.Errorf("清理配置备份失败: %w", err), ops.commitBoundary())
	}
	return ops.commitBoundary()
}

func resolveSiteDeletePath(base string) (string, bool, error) {
	for _, path := range []string{base, base + ".disabled"} {
		if _, err := os.Stat(path); err == nil {
			return path, false, nil
		} else if !os.IsNotExist(err) {
			return "", false, err
		}
	}
	for _, path := range []string{base, base + ".disabled"} {
		if _, err := os.Stat(path + ".relay-delete.bak"); err == nil {
			return path, true, nil
		} else if !os.IsNotExist(err) {
			return "", false, err
		}
	}
	return "", false, os.ErrNotExist
}

// 恢复活动文件后立即恢复派生路由，语法检查失败也不能留下过期映射。
func restoreSitePath(from, to string, ops siteLifecycle) error {
	if err := ops.rename(from, to); err != nil {
		return err
	}
	if ops.syncDerived != nil {
		if err := ops.syncDerived(); err != nil {
			return err
		}
	} else if err := ops.reload(); err != nil {
		return err
	}
	if ops.consistent != nil {
		ops.consistent()
	}
	return nil
}

// 同时保护当前进程及独立 CLI 进程中的配置事务。
func lockSiteRequest(w http.ResponseWriter) (func(), bool) {
	if err := ensureNoSNIMigration(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return nil, false
	}
	siteMutationMu.Lock()
	unlock, err := lockConfigDirectory(confDir)
	if err != nil {
		siteMutationMu.Unlock()
		if pendingErr := ensureNoSNIMigration(); pendingErr != nil {
			writeErr(w, http.StatusConflict, pendingErr.Error())
			return nil, false
		}
		writeErr(w, http.StatusServiceUnavailable, "配置正由其他进程修改，或无法锁定配置目录，请稍后重试")
		return nil, false
	}
	if err := ensureNoSNIMigration(); err != nil {
		unlock()
		siteMutationMu.Unlock()
		writeErr(w, http.StatusConflict, err.Error())
		return nil, false
	}
	if err := recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation); err != nil {
		unlock()
		siteMutationMu.Unlock()
		writeErr(w, 503, "证书事务尚未恢复，请稍后重试")
		return nil, false
	}
	if err := reconcileNginxWith(nginxPendingPath(), nginxReload); err != nil {
		unlock()
		siteMutationMu.Unlock()
		writeErr(w, 503, "上一配置事务尚未恢复，请稍后重试")
		return nil, false
	}
	op := startNginxOperation(false)
	return func() { op.close(); unlock(); siteMutationMu.Unlock() }, true
}

func prepareNginxMutation(w http.ResponseWriter) bool {
	if err := beginNginxMutation(); err != nil {
		writeErr(w, 500, "无法保存配置事务记录，未执行写操作")
		return false
	}
	return true
}

// 成功响应前显式确认；失败回滚由生命周期标记，统一解锁出口再清理日志。
func completeNginxRequest(w http.ResponseWriter) bool {
	markNginxConsistent()
	if op := activeNginxOperation.Load(); op != nil {
		if err := op.finish(); err != nil {
			// 防止解锁出口悄悄重试删除，调用方已经收到失败并应保留恢复日志。
			op.consistent.Store(false)
			log.Print("配置已一致，但操作日志清理失败")
			writeErr(w, 500, "配置操作日志清理失败，已保留恢复记录")
			return false
		}
	}
	return true
}
