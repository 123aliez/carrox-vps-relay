package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestM15DefaultSiteExcludedFromScans(t *testing.T) {
	p := tempSNIPaths(t)
	for _, suffix := range []string{"", ".disabled", tcpDeleteSuffix, ".disabled" + tcpDeleteSuffix} {
		putTestFile(t, p.defaultSite()+suffix, []byte(sniDefaultConfig))
	}
	previous := confDir
	confDir = p.conf
	t.Cleanup(func() { confDir = previous })
	sites, warnings, err := scanSites("admin", true)
	if err != nil || len(sites) != 0 || len(warnings) != 0 {
		t.Fatal(sites, warnings, err)
	}
	files, err := managedSNIFiles(p, liveRelayFS())
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	if bytes.Contains([]byte(sniDefaultConfig), []byte("relay-meta")) {
		t.Fatal("默认站点不得含业务元数据")
	}
}

func TestM15DefaultServerPreflightNoWrites(t *testing.T) {
	for _, name := range []string{"custom.conf", "custom-ipv6.conf", "custom-8443.conf", "relay-panel.conf", "relay-site.example.com.conf", "relay-off0.example.com.conf.disabled", "relay-off1.example.com.conf" + tcpDeleteSuffix} {
		t.Run(name, func(t *testing.T) {
			h := newMigrationHarness(t)
			path := filepath.Join(h.ops.paths.conf, name)
			data, err := os.ReadFile(path)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			address := "80"
			if strings.Contains(name, "ipv6") {
				address = "[::]:80"
			} else if strings.Contains(name, "8443") {
				address = "127.0.0.1:8443"
			}
			putTestFile(t, path, append(data, []byte("\nserver { listen \""+address+"\" default_server; }\n")...))
			before := configTree(t, h.ops.paths, true)
			err = migrateSNI443("enable", h.ops, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "default_server") {
				t.Fatal("必须提前拒绝默认站点冲突", err)
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, true)) || h.checks != 0 || h.reloads != 0 {
				t.Fatal("前置检查失败改动了文件或运行配置")
			}
		})
	}
	for _, data := range []string{
		"# listen 80 default_server;\nserver { listen 80; }",
		`server { listen 80; return 200 "default_server"; }`,
		`server { listen 80; set $hint "listen 80 default_server"; }`,
	} {
		if hasDefaultServer([]byte(data)) {
			t.Fatal("误把注释或其他指令当成默认监听", data)
		}
	}
}

func TestM15DefaultSiteRecovery(t *testing.T) {
	for _, action := range []string{"enable", "disable"} {
		t.Run(action, func(t *testing.T) {
			h := newMigrationHarness(t)
			path := h.ops.paths.defaultSite()
			if action == "disable" {
				if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
				putTestFile(t, path, append([]byte(sniDefaultConfig), []byte("# 保留原始字节\n")...))
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			}
			before := configTree(t, h.ops.paths, false)
			write, remove := h.ops.fs.write, h.ops.fs.remove
			h.ops.fs.write = func(p string, data []byte, mode os.FileMode) error {
				err := write(p, data, mode)
				if p == path && err == nil {
					panic("中断")
				}
				return err
			}
			h.ops.fs.remove = func(p string) error {
				err := remove(p)
				if p == path && err == nil {
					panic("中断")
				}
				return err
			}
			func() {
				defer func() {
					if recover() != "中断" {
						t.Fatal("未在默认站点变更后中断")
					}
				}()
				_ = migrateSNI443(action, h.ops, io.Discard)
			}()
			h.ops.fs.write, h.ops.fs.remove = write, remove
			pending, err := latestPendingMigration(h.ops.paths, h.ops.fs)
			if err != nil || pending == "" {
				t.Fatal(pending, err)
			}
			var record sniManifest
			if err := json.Unmarshal(readTestFile(t, filepath.Join(pending, "manifest.json")), &record); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, file := range record.Files {
				if file.Path == path {
					found = true
					if file.Existed != (action == "disable") {
						t.Fatal("默认站点备份状态不正确", file)
					}
				}
			}
			if !found {
				t.Fatal("备份清单缺少默认站点")
			}
			if err := migrateSNI443("recover", h.ops, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, false)) {
				t.Fatal("默认站点或其他配置未逐字节恢复")
			}
		})
	}
}

func TestM15DefaultTLSHandshakeVerification(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "site.example.com"}, DNSNames: []string{"site.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, domain string
		reject, deny bool
		wantErr      bool
	}{
		{"known", "site.example.com", false, false, false},
		{"wrong-certificate", "other.example.com", false, false, true},
		{"known-rejected", "site.example.com", false, true, true},
		{"no-sni-rejected", "", true, true, false},
		{"unknown-rejected", "unknown.invalid", true, true, false},
		{"no-sni-accepted", "", true, false, true},
		{"unknown-accepted", "unknown.invalid", true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			seen := make(chan string, 1)
			done := make(chan struct{})
			dial := func(time.Duration) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					defer close(done)
					defer server.Close()
					conn := tls.Server(server, &tls.Config{
						Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
						GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
							seen <- hello.ServerName
							if test.deny {
								return nil, errors.New("拒绝未知域名")
							}
							return nil, nil
						},
					})
					_ = conn.Handshake()
				}()
				return client, nil
			}
			if err := verifySNIHandshake(test.domain, test.reject, time.Second, dial); (err != nil) != test.wantErr {
				t.Fatal(err)
			}
			<-done
			if sni := <-seen; sni != test.domain {
				t.Fatal("实际 SNI 不符", sni)
			}
		})
	}
	t.Run("connection-failed", func(t *testing.T) {
		if err := verifySNIHandshake("", true, time.Second, func(time.Duration) (net.Conn, error) { return nil, errors.New("不可达") }); err == nil {
			t.Fatal("连接失败不能当作拒绝握手")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		if err := verifySNIHandshake("", true, 10*time.Millisecond, func(time.Duration) (net.Conn, error) { return client, nil }); err == nil {
			t.Fatal("超时不能当作拒绝握手")
		}
	})
}
