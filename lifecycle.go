package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// 所有站点写操作串行，避免同域重复创建及 Nginx 全局检查相互干扰。
var siteMutationMu sync.Mutex

type siteLifecycle struct {
	issue             func(string, string, string) error
	cleanup           func(string, string, string) error
	certificateExists func(string, string) bool
	render            func(SiteMeta) ([]byte, error)
	write             func(string, []byte, os.FileMode) error
	remove            func(string) error
	rename            func(string, string) error
	check             func() error
	reload            func() error
}

func liveSiteLifecycle() siteLifecycle {
	return siteLifecycle{
		issue: acmeIssue, cleanup: acmeRemove, render: renderSite,
		write: atomicWrite, remove: os.Remove, rename: os.Rename,
		check: nginxSyntaxCheck, reload: nginxReload,
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

func writeManagedSite(meta SiteMeta, path string, ops siteLifecycle) error {
	rendered, err := ops.render(meta)
	if err != nil {
		return err
	}
	return ops.write(path, rendered, 0o644)
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
				persistErr := writeManagedSite(meta, path, ops)
				return meta, errors.Join(cause, fmt.Errorf("DNS 恢复失败，已保留站点供重试: %w", restoreErr), persistErr)
			}
		}
		if configWritten {
			if removeErr := ops.remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				return meta, errors.Join(cause, fmt.Errorf("清理配置失败: %w", removeErr))
			}
			if reloadErr := ops.reload(); reloadErr != nil {
				// 仍在使用证书的旧 worker 未退出时，不能清除其材料。
				persistErr := writeManagedSite(meta, path, ops)
				return meta, errors.Join(cause, fmt.Errorf("回滚重载失败，保留站点材料: %w", reloadErr), persistErr)
			}
		}
		if meta.CertificateOwned {
			cause = errors.Join(cause, ops.cleanup(meta.Domain, token, meta.Owner))
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
	if err := change.apply(token); err != nil {
		return rollback(err)
	}
	meta.CFRecordID = change.After.ID
	if err := writeManagedSite(meta, path, ops); err != nil {
		return rollback(fmt.Errorf("保存 DNS 接管结果失败: %w", err))
	}
	return meta, nil
}

func removeManagedSite(meta SiteMeta, token, path string, staged bool, ops siteLifecycle) error {
	// DNS 操作先完成；失败时保留站点及原始解析，允许安全重试。
	if meta.DNS != nil && meta.DNS.Mode != "reused" {
		if token == "" {
			return fmt.Errorf("缺少站点所有者的 Cloudflare Token，无法恢复 DNS")
		}
		if err := meta.DNS.release(token); err != nil {
			return fmt.Errorf("DNS 清理失败，保留站点供重试: %w", err)
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
		return errors.Join(err, ops.rename(backup, path))
	}
	if err := ops.reload(); err != nil {
		if staged {
			return fmt.Errorf("Nginx 重载失败，删除恢复信息已保留: %w", err)
		}
		return errors.Join(fmt.Errorf("Nginx 重载失败: %w", err), ops.rename(backup, path))
	}
	if meta.CertificateOwned {
		if err := ops.cleanup(meta.Domain, token, meta.Owner); err != nil {
			// 证书可能已被部分清理，禁止恢复引用它的活动配置。
			return fmt.Errorf("本地证书清理失败，删除恢复信息已保留，请再次删除重试: %w", err)
		}
	}
	if err := ops.remove(backup); err != nil {
		return fmt.Errorf("清理配置备份失败: %w", err)
	}
	return nil
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
