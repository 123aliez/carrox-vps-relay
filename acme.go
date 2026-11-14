// Wraps the container-internal /usr/local/bin/relay-acme shim for cert ops.
// Each user gets an isolated acme.sh home at /root/.acme.sh-{keyID}/.
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

const relayAcmePath = "/usr/local/bin/relay-acme"
const autoRenewInterval = 12 * time.Hour
const renewThresholdDays = 30

func acmeHome(keyID string) string {
	return fmt.Sprintf("/root/.acme.sh-%s", keyID)
}

func persistentAcmeHome(keyID string) string {
	return filepath.Join("/root/.acme.sh/users", keyID)
}

// ensureAcmeHome creates the per-user acme.sh home directory and symlinks
// the acme.sh script into it so that `--home` can discover the script.
func ensureAcmeHome(keyID string) error {
	home := acmeHome(keyID)
	if err := os.MkdirAll(persistentAcmeHome(keyID), 0o700); err != nil {
		return err
	}
	// 保留旧绝对路径，实际材料放入已挂载的 acme_data 卷。
	if _, err := os.Lstat(home); os.IsNotExist(err) {
		if err := os.Symlink(persistentAcmeHome(keyID), home); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	dst := filepath.Join(home, "acme.sh")
	if _, err := os.Lstat(dst); os.IsNotExist(err) {
		if err := os.Symlink("/root/.acme.sh/acme.sh", dst); err != nil {
			return err
		}
	}
	return nil
}

func acmeIssue(domain, cfTok, keyID string) error {
	return runAcme(domain, "issue", cfTok, keyID, 4*time.Minute)
}

// 仅清理本面板新建的本地材料，不吊销源站可能同时使用的证书。
func acmeRemove(domain, cfTok, keyID string) error {
	return runAcme(domain, "remove", cfTok, keyID, 60*time.Second)
}

func acmeRenew(domain, cfTok, keyID string) error {
	return runAcme(domain, "renew", cfTok, keyID, 4*time.Minute)
}

func runAcme(domain, action, cfTok, keyID string, timeout time.Duration) error {
	if err := ensureNoSNIMigration(); err != nil {
		return err
	}
	if err := ensureAcmeHome(keyID); err != nil {
		return err
	}
	cmd := exec.Command(relayAcmePath, domain, action)
	cmd.Env = append(cmd.Env,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"CF_API_TOKEN="+cfTok,
		"ACME_HOME="+acmeHome(keyID),
	)

	if err := runACMEProcess(cmd, timeout); err != nil {
		return fmt.Errorf("relay-acme %s %s: %w", domain, action, err)
	}
	return nil
}

// 同步启动独立进程组，超时杀死整棵受控进程树并等待退出后才归还调用方的锁。
func runACMEProcess(cmd *exec.Cmd, timeout time.Duration) error {
	inherited, err := duplicateConfigLock(confDir)
	if err != nil {
		return err
	}
	if inherited != nil {
		defer inherited.Close()
		cmd.ExtraFiles = []*os.File{inherited}
		cmd.Env = append(cmd.Environ(), "VPS_RELAY_CONFIG_LOCK_HELD=3")
	}
	configureACMEGroup(cmd)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		// 正常退出也清除可能遗留的后台任务，不让继承的锁逃出事务。
		killACMEGroup(cmd)
		waitACMEGroup(cmd.Process.Pid)
		if err != nil {
			return fmt.Errorf("命令失败: %v（输出 %d 字节，已脱敏）", err, output.Len())
		}
		return nil
	case <-timer.C:
		killACMEGroup(cmd)
		waitACMEGroup(cmd.Process.Pid)
		<-done
		return fmt.Errorf("超时（%s），受控进程组已结束", timeout)
	}
}

func autoRenewLoop() {
	// 容器频繁重启时 12h 定时器可能永远不触发，启动约 2 分钟后先检查一次。
	time.Sleep(2 * time.Minute)
	renewExpiringCerts()
	ticker := time.NewTicker(autoRenewInterval)
	defer ticker.Stop()
	for range ticker.C {
		renewExpiringCerts()
	}
}

func renewExpiringCerts() {
	if err := ensureNoSNIMigration(); err != nil {
		log.Printf("[auto-renew] 迁移未完成，跳过续期及重载：%v", err)
		return
	}
	sites, _, err := scanSites("", true)
	if err != nil {
		log.Printf("[auto-renew] scan sites: %v", err)
		return
	}
	for _, s := range sites {
		if s.DeletionPending || s.CertDaysLeft > renewThresholdDays {
			continue
		}
		owner := s.Owner
		if owner == "" {
			owner = "admin"
		}
		cfTok := cfTokenForKey(owner)
		if cfTok == "" {
			log.Printf("[auto-renew] %s: skip — no CF token for owner %q", s.Domain, owner)
			continue
		}
		log.Printf("[auto-renew] %s: %d days left, renewing…", s.Domain, s.CertDaysLeft)
		siteMutationMu.Lock()
		unlock, lockErr := lockConfigDirectory(confDir)
		if lockErr != nil {
			siteMutationMu.Unlock()
			log.Printf("[auto-renew] 配置正在迁移，延后续期")
			continue
		}
		if pendingErr := ensureNoSNIMigration(); pendingErr != nil {
			unlock()
			siteMutationMu.Unlock()
			log.Printf("[auto-renew] 迁移未完成，跳过续期及重载：%v", pendingErr)
			continue
		}
		_, deleting, pathErr := resolveSiteDeletePath(confPath(s.Domain))
		if pathErr != nil || deleting {
			unlock()
			siteMutationMu.Unlock()
			continue
		}
		err := recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation)
		if err == nil {
			err = reconcileNginxWith(nginxPendingPath(), nginxReload)
		}
		if err == nil {
			err = acmeRenew(s.Domain, cfTok, owner)
		}
		unlock()
		siteMutationMu.Unlock()
		if err != nil {
			log.Printf("[auto-renew] %s: renew failed: %v", s.Domain, err)
		} else {
			log.Printf("[auto-renew] %s: renewed OK", s.Domain)
		}
	}
	renewPanelCert()
}

// 面板不在 scanSites 的范围内，启用 HTTPS 后要单独续期。
var panelCertRE = regexp.MustCompile(`(?m)^[ \t]*ssl_certificate[ \t]+\S*/ssl/([^/\s]+)/fullchain\.pem[ \t]*;`)

func panelCertDomain(conf []byte) string {
	m := panelCertRE.FindSubmatch(conf)
	if m == nil {
		return ""
	}
	return string(m[1])
}

func renewPanelCert() {
	if err := ensureNoSNIMigration(); err != nil {
		log.Printf("[auto-renew] 迁移未完成，跳过续期及重载：%v", err)
		return
	}
	conf, err := os.ReadFile(filepath.Join(confDir, "relay-panel.conf"))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[auto-renew] panel conf: %v", err)
		}
		return
	}
	domain := panelCertDomain(conf)
	if domain == "" {
		return
	}
	_, days, err := certInfo(domain)
	if err != nil {
		log.Printf("[auto-renew] %s: read cert: %v", domain, err)
		return
	}
	if days > renewThresholdDays {
		return
	}
	cfTok := cfTokenForKey("admin")
	if cfTok == "" {
		log.Printf("[auto-renew] %s: skip — no CF token for admin", domain)
		return
	}
	log.Printf("[auto-renew] %s: %d days left, renewing…", domain, days)
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
	unlock, lockErr := lockConfigDirectory(confDir)
	if lockErr != nil {
		log.Printf("[auto-renew] 配置正在迁移，延后面板续期")
		return
	}
	defer unlock()
	if pendingErr := ensureNoSNIMigration(); pendingErr != nil {
		log.Printf("[auto-renew] 迁移未完成，跳过面板续期及重载：%v", pendingErr)
		return
	}
	err = recoverACMETransactions(sniBackupDir, nginxReload, beginNginxMutation)
	if err == nil {
		err = reconcileNginxWith(nginxPendingPath(), nginxReload)
	}
	if err == nil {
		err = acmeRenew(domain, cfTok, "admin")
	}
	if err != nil {
		log.Printf("[auto-renew] %s: renew failed: %v", domain, err)
		return
	}
	log.Printf("[auto-renew] %s: renewed OK", domain)
}
