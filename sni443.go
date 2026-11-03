package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sni443Config = `# ====== vps-relay managed: DO NOT HAND EDIT ======
# 443 按 SNI 分流，Reality 入口统一交给本机 Xray。
map $ssl_preread_server_name $relay_443_backend {
    include /usr/local/nginx/conf/stream.d/relay-443/sni.map;
    default 127.0.0.1:8443;
}
server {
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $relay_443_backend;
    proxy_protocol on;
    proxy_connect_timeout 10s;
    proxy_timeout 1h;
}
`

const sniDefaultName = "relay-00-default.conf"

const sniDefaultConfig = `# ====== vps-relay managed: DO NOT HAND EDIT ======
# 未知域名的 HTTP 请求直接关闭，TLS 握手直接拒绝，避免泄露业务站点。
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
server {
    listen 127.0.0.1:8443 ssl proxy_protocol default_server;
    server_name _;
    ssl_reject_handshake on;
}
`

// 路径和文件系统操作集中注入，迁移测试无需触碰宿主配置。
type sniPaths struct{ conf, stream, backup, binary, nginxConf, templates string }

var sniBackupDir = "/etc/vps-relay/backup"

func liveSNIPaths() sniPaths {
	return sniPaths{confDir, streamDir, sniBackupDir, hostNginxPrefix + "/sbin/nginx", hostNginxConf, filepath.Dir(templatePath)}
}
func (p sniPaths) marker() string      { return filepath.Join(p.stream, "relay-443.conf") }
func (p sniPaths) defaultSite() string { return filepath.Join(p.conf, sniDefaultName) }
func (p sniPaths) derived() []string {
	return []string{filepath.Join(p.stream, "relay-443/sni.map")}
}

type relayFS struct {
	read    func(string) ([]byte, error)
	stat    func(string) (os.FileInfo, error)
	entries func(string) ([]os.DirEntry, error)
	mkdir   func(string, os.FileMode) error
	write   func(string, []byte, os.FileMode) error
	remove  func(string) error
	chmod   func(string, os.FileMode) error
}

func liveRelayFS() relayFS {
	return relayFS{read: os.ReadFile, stat: os.Stat, entries: os.ReadDir, mkdir: os.MkdirAll, write: atomicWrite, remove: os.Remove, chmod: os.Chmod}
}
func sniMode(p sniPaths, fs relayFS) (bool, error) {
	_, err := fs.stat(p.marker())
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func sni443Enabled() bool { on, _ := sniMode(liveSNIPaths(), liveRelayFS()); return on }

type managedSNIFile struct {
	path    string
	meta    SiteMeta
	enabled bool
}

func managedSNIFiles(p sniPaths, fs relayFS) ([]managedSNIFile, error) {
	entries, err := fs.entries(p.conf)
	if err != nil {
		return nil, err
	}
	var files []managedSNIFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "relay-") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(name, tcpDeleteSuffix), ".disabled")
		if !strings.HasSuffix(base, ".conf") || base == "relay-panel.conf" || base == sniDefaultName {
			continue
		}
		path := filepath.Join(p.conf, name)
		data, err := fs.read(path)
		if err != nil {
			return nil, err
		}
		match := metaRE.FindSubmatch(data)
		if match == nil {
			if bytes.Contains(data, []byte(relayHead)) {
				return nil, fmt.Errorf("托管配置缺少元数据: %s", name)
			}
			continue
		}
		var meta SiteMeta
		if json.Unmarshal(match[1], &meta) != nil || validateSNIDomain(meta.Domain) != nil {
			return nil, fmt.Errorf("托管配置元数据无效: %s", name)
		}
		files = append(files, managedSNIFile{path, meta, name == base})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func syncSNI443() error {
	fs := liveRelayFS()
	write := fs.write
	fs.write = func(path string, data []byte, mode os.FileMode) error {
		if path == liveSNIPaths().derived()[0] {
			if err := beginNginxMutation(); err != nil {
				return err
			}
		}
		return write(path, data, mode)
	}
	return syncRelayConfig(liveSNIPaths(), fs, liveXrayPaths(), testXrayConfig)
}

func syncRelayConfig(p sniPaths, fs relayFS, xpaths xrayPaths, check func(string) error) error {
	on, err := sniMode(p, fs)
	if err != nil || !on {
		return err
	}
	files, err := managedSNIFiles(p, fs)
	if err != nil {
		return err
	}
	material := loadRealityMaterial(enabledRealitySites(files), xpaths, fs)
	if err := syncXrayMaterial(&material, xpaths, fs, check); err != nil {
		// Xray 私有目录故障只暂停入口，不能阻断普通站点和证书的 Nginx 事务。
		material.Sites = nil
		for _, site := range enabledRealitySites(files) {
			material.Errors[site.Domain] = "Xray 私有材料不可用，入口已暂停"
		}
		_ = removeXrayFile(fs, xpaths.config())
		log.Print("Xray 私有材料不可用，已暂停 Reality 入口")
	}
	for _, file := range files {
		if message := material.Errors[file.meta.Domain]; message != "" {
			log.Printf("Reality 入口 %s：%s", file.meta.Domain, message)
		}
	}
	return syncSNIMap(material.Sites, p, fs)

}

func enabledRealitySites(files []managedSNIFile) []SiteMeta {
	sites := make([]SiteMeta, 0)
	for _, f := range files {
		if f.enabled && f.meta.Reality != nil {
			sites = append(sites, f.meta)
		}
	}
	return sites
}
func syncSNI443With(p sniPaths, fs relayFS) error {
	on, err := sniMode(p, fs)
	if err != nil {
		return err
	}
	if !on {
		return nil
	}
	files, err := managedSNIFiles(p, fs)
	if err != nil {
		return err
	}
	sites := make([]SiteMeta, 0, len(files))
	for _, f := range files {
		if f.enabled && f.meta.Reality != nil {
			sites = append(sites, f.meta)
		}
	}
	return syncSNIMap(sites, p, fs)
}
func syncSNIMap(sites []SiteMeta, p sniPaths, fs relayFS) error {
	data, err := renderSNIDerived(sites)
	if err != nil {
		return err
	}
	for i, path := range p.derived() {
		if err := writeSNIChanged(fs, path, data[i]); err != nil {
			return fmt.Errorf("同步 443 派生配置失败: %w", err)
		}
	}
	return nil
}
func writeSNIChanged(fs relayFS, path string, data []byte) error {
	old, err := fs.read(path)
	if err == nil && bytes.Equal(old, data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := fs.mkdir(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return fs.write(path, data, 0644)
}
func renderSNIDerived(sites []SiteMeta) ([1][]byte, error) {
	var out [1][]byte
	domains := map[string]bool{}
	for _, site := range sites {
		if site.Reality == nil {
			continue
		}
		if validateSNIDomain(site.Domain) != nil {
			return out, errors.New("Reality 元数据无效")
		}
		domains[site.Domain] = true
	}
	names := make([]string, 0, len(domains))
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)
	var sni strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sni, "%s 127.0.0.1:%d;\n", name, realityInboundPort)
	}
	out[0] = []byte(sni.String())
	return out, nil
}

// 调用前已恢复残留日志；本轮同步只有改动 Nginx 派生文件时才需要重载。
func syncSNI443Runtime() error {
	if err := syncSNI443(); err != nil {
		return err
	}
	if _, err := os.Stat(nginxPendingPath()); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := nginxReload(); err != nil {
		return err
	}
	return finishNginxMutation()
}
