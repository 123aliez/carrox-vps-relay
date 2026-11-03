package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestM15ACMEStrictModeStopsAfterEveryFailedStep(t *testing.T) {
	for _, panel := range []bool{false, true} {
		path := "manual"
		if panel {
			path = "panel"
		}
		for _, test := range []struct {
			action, fail string
			want         []string
			installed    bool
		}{
			{"issue", "set-default-ca", []string{"set-default-ca"}, false},
			{"issue", "issue", []string{"set-default-ca", "issue"}, false},
			{"issue", "install-cert", []string{"set-default-ca", "issue", "install", "install-cert"}, false},
			{"renew", "install-cert", []string{"install-cert"}, false},
			{"renew", "renew", []string{"install-cert", "renew"}, false},
			{"remove", "remove", []string{"remove"}, false},
		} {
			t.Run(path+"/"+test.action+"/"+test.fail, func(t *testing.T) {
				h := newACMEScriptHarness(t)
				fake := `#!/bin/sh
set -eu
[ "${VPS_RELAY_CONFIG_LOCK_HELD:-}" = 3 ]
[ -d /proc/self/fd/3 ]
for arg in "$@"; do
  case "$arg" in
    --set-default-ca|--issue|--install-cert|--renew|--remove) step="${arg#--}" ;;
  esac
done
echo "$step" >> "$M15_ACTIONS"
if [ "$step" = "$M15_FAIL_STEP" ]; then exit 42; fi
if [ "$step" = install-cert ]; then
  echo installed > "$VPS_RELAY_CERT_STAGE/fullchain.pem"
  echo key > "$VPS_RELAY_CERT_STAGE/key.pem"
fi
`
				if err := os.WriteFile(filepath.Join(h.root, "acme/acme.sh"), []byte(fake), 0700); err != nil {
					t.Fatal(err)
				}
				cmd := h.command(test.action)
				cmd.Env = append(cmd.Env, "M15_FAIL_STEP="+test.fail)
				var err error
				if panel {
					previous := confDir
					confDir = h.p.conf
					t.Cleanup(func() { confDir = previous })
					unlock, lockErr := lockConfigDirectory(confDir)
					if lockErr != nil {
						t.Fatal(lockErr)
					}
					defer unlock()
					err = runACMEProcess(cmd, 5*time.Second)
				} else {
					_, err = cmd.CombinedOutput()
				}
				if err == nil {
					t.Fatal("失败步骤必须让真实内层脚本返回非零")
				}
				steps := strings.Fields(string(readTestFile(t, h.actions)))
				if !reflect.DeepEqual(steps, test.want) {
					t.Fatal("失败后继续执行了后续步骤", steps, test.want)
				}
				certificate := []byte("原证书")
				if test.installed {
					certificate = []byte("installed\n")
				}
				requireBytes(t, readTestFile(t, h.cert), certificate)
			})
		}
	}
}

func TestM15RealityFingerprintWhitelist(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"} {
		link := strings.Replace(testLink, "fp=chrome", "fp="+fingerprint, 1)
		outbound, err := parseRealityOutbound(link)
		want := fingerprint
		if want == "" {
			want = "chrome"
		}
		if err != nil || outbound.Fingerprint != want {
			t.Fatal(fingerprint, err)
		}
	}
	for _, fingerprint := range []string{"invalid", "Chrome", "none", "unsafe-" + testUUID} {
		_, err := parseRealityOutbound(strings.Replace(testLink, "fp=chrome", "fp="+fingerprint, 1))
		if err == nil || strings.Contains(err.Error(), fingerprint) || strings.Contains(err.Error(), testUUID) {
			t.Fatal("非法指纹应安全拒绝", err)
		}
	}
}

func TestM15RealityValidationHealthMatchesEnabledConfiguration(t *testing.T) {
	p, xp, fs := tempSNIPaths(t), tempXrayPaths(t), liveRelayFS()
	putTestFile(t, p.marker(), []byte(sni443Config))
	if err := privateJSON(fs, xp.keys(), fixtureRealityKeys(t)); err != nil {
		t.Fatal(err)
	}
	good, bad, off := m15Reality(), m15Reality(), m15Reality()
	good.Domain, bad.Domain, off.Domain = "good.example.com", "bad.example.com", "off.example.com"
	for _, site := range []SiteMeta{good, bad, off} {
		suffix := ""
		if site.Domain == off.Domain {
			suffix = ".disabled"
		}
		putMeta(t, p, site, suffix)
		if err := saveRealityEntry(xp, site.Domain, fixtureRealityEntry(t), fs); err != nil {
			t.Fatal(err)
		}
	}
	check := func(path string) error {
		if bytes.Contains(readTestFile(t, path), []byte(bad.Domain)) {
			return errors.New("校验输出含机密 " + fixtureBackendUUID)
		}
		return nil
	}
	if err := syncRelayConfig(p, fs, xp, check); err != nil {
		t.Fatal(err)
	}
	requireBytes(t, readTestFile(t, p.derived()[0]), []byte("good.example.com 127.0.0.1:30001;\n"))
	sites := []Site{{SiteMeta: good, Enabled: true}, {SiteMeta: bad, Enabled: true}, {SiteMeta: off}}
	annotateRealityHealth(sites, xp, fs)
	if sites[0].RealityPaused || !sites[1].RealityPaused || sites[2].RealityPaused {
		t.Fatal("停用站点不能使启用入口的健康摘要失效", sites)
	}
	data, err := json.Marshal(sites)
	if err != nil || bytes.Contains(data, []byte(fixtureBackendUUID)) {
		t.Fatal("状态泄露校验器输出", err)
	}
	info, err := os.Stat(xp.health())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("健康状态文件权限错误", err)
	}
	if err := checkRealityEntryHealth(bad.Domain, p, xp, fs); err == nil || !strings.Contains(err.Error(), "暂停") {
		t.Fatal("创建入口不得把其他入口的已就绪配置当作自身成功", err)
	}
	// 健康状态文件不可注入任意文案，当前机密改变也不能继续显示陈旧原因。
	var health realityValidationHealth
	if err := json.Unmarshal(readTestFile(t, xp.health()), &health); err != nil {
		t.Fatal(err)
	}
	health.Errors[bad.Domain] = fixtureBackendUUID
	if err := saveRealityValidationHealth(health, xp, fs); err != nil {
		t.Fatal(err)
	}
	annotateRealityHealth(sites, xp, fs)
	if sites[1].RealityError != "" {
		t.Fatal("状态文件中的未知错误文本不应展示")
	}
	health.Errors[bad.Domain] = "入口 Xray 配置校验失败，入口已暂停"
	if err := saveRealityValidationHealth(health, xp, fs); err != nil {
		t.Fatal(err)
	}
	entry := fixtureRealityEntry(t)
	entry.Outbound.SpiderX = "/changed"
	if err := saveRealityEntry(xp, bad.Domain, entry, fs); err != nil {
		t.Fatal(err)
	}
	annotateRealityHealth(sites, xp, fs)
	if sites[1].RealityError != "" {
		t.Fatal("机密改变后不得显示旧配置的校验原因")
	}
	if err := syncRelayConfig(p, fs, xp, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	annotateRealityHealth(sites, xp, fs)
	if sites[1].RealityPaused || sites[1].RealityError != "" {
		t.Fatal("校验恢复后未清除暂停状态")
	}
	if _, err := os.Stat(xp.health()); !os.IsNotExist(err) {
		t.Fatal("有效完整配置应清除旧隔离记录")
	}
}
