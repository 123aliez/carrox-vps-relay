// Wraps the container-internal /usr/local/bin/relay-acme shim for cert ops.
// Each user gets an isolated acme.sh home at /root/.acme.sh-{keyID}/.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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

	done := make(chan error, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		if err != nil {
			done <- fmt.Errorf("relay-acme %s %s: %v\n%s", domain, action, err, string(out))
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("relay-acme %s %s: timed out after %s", domain, action, timeout)
	}
}

func autoRenewLoop() {
	ticker := time.NewTicker(autoRenewInterval)
	defer ticker.Stop()
	for range ticker.C {
		renewExpiringCerts()
	}
}

func renewExpiringCerts() {
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
		_, deleting, pathErr := resolveSiteDeletePath(confPath(s.Domain))
		if pathErr != nil || deleting {
			siteMutationMu.Unlock()
			continue
		}
		err := acmeRenew(s.Domain, cfTok, owner)
		siteMutationMu.Unlock()
		if err != nil {
			log.Printf("[auto-renew] %s: renew failed: %v", s.Domain, err)
		} else {
			log.Printf("[auto-renew] %s: renewed OK", s.Domain)
		}
	}
}
