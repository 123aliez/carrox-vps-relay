package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

const xrayDir = "/etc/vps-relay/xray"
const realityInboundPort = 30001

type xrayPaths struct{ root string }

func liveXrayPaths() xrayPaths     { return xrayPaths{xrayDir} }
func (p xrayPaths) keys() string   { return filepath.Join(p.root, "keys.json") }
func (p xrayPaths) config() string { return filepath.Join(p.root, "config.json") }
func (p xrayPaths) health() string { return filepath.Join(p.root, "health.json") }
func (p xrayPaths) entry(domain string) string {
	return filepath.Join(p.root, "entries", domain+".json")
}
func (p xrayPaths) socket() string { return filepath.Join(p.root, "control.sock") }

type realityKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}
type realityOutbound struct {
	UUID        string `json:"uuid"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Flow        string `json:"flow"`
	SNI         string `json:"sni"`
	Fingerprint string `json:"fp"`
	PublicKey   string `json:"pbk"`
	ShortID     string `json:"sid"`
	SpiderX     string `json:"spx"`
}
type realityEntry struct {
	FrontendUUID string          `json:"frontend_uuid"`
	Outbound     realityOutbound `json:"outbound"`
}

func generateRealityKeys() (realityKeys, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return realityKeys{}, errors.New("生成 Reality 密钥失败")
	}
	short := make([]byte, 8)
	if _, err := rand.Read(short); err != nil {
		return realityKeys{}, errors.New("生成 shortId 失败")
	}
	return realityKeys{base64.RawURLEncoding.EncodeToString(private.Bytes()), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), hex.EncodeToString(short)}, nil
}
func validateRealityKeys(keys realityKeys) error {
	raw, err := base64.RawURLEncoding.DecodeString(keys.PrivateKey)
	if err != nil || len(raw) != 32 {
		return errors.New("Reality 密钥文件无效")
	}
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != keys.PublicKey {
		return errors.New("Reality 密钥文件无效")
	}
	short, err := hex.DecodeString(keys.ShortID)
	if err != nil || len(short) != 8 {
		return errors.New("Reality shortId 无效")
	}
	return nil
}
func privateJSON(fs relayFS, path string, value any) error {
	if err := securePrivateDir(fs, filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("机密数据编码失败")
	}
	return fs.write(path, append(data, '\n'), 0600)
}
func loadOrCreateXrayKeys(p xrayPaths, fs relayFS) (realityKeys, error) {
	var keys realityKeys
	data, err := fs.read(p.keys())
	if err == nil {
		if json.Unmarshal(data, &keys) != nil || validateRealityKeys(keys) != nil {
			return keys, errors.New("Reality 密钥文件无效")
		}
		if err := securePrivateDir(fs, p.root); err != nil {
			return keys, errors.New("设置 Reality 密钥目录权限失败")
		}
		if err := fs.chmod(p.keys(), 0600); err != nil {
			return keys, errors.New("设置 Reality 密钥权限失败")
		}
		return keys, nil
	}
	if !os.IsNotExist(err) {
		return keys, errors.New("读取 Reality 密钥失败")
	}
	if entries, err := fs.entries(filepath.Join(p.root, "entries")); err == nil && len(entries) > 0 {
		return keys, errors.New("Reality 密钥缺失，请恢复原密钥或删除全部入口后重建")
	} else if err != nil && !os.IsNotExist(err) {
		return keys, errors.New("无法核对现有入口，已停止生成新密钥")
	}
	keys, err = generateRealityKeys()
	if err != nil {
		return keys, err
	}
	if err := privateJSON(fs, p.keys(), keys); err != nil {
		return keys, errors.New("保存 Reality 密钥失败")
	}
	return keys, nil
}
func newRealityUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("生成入口身份失败")
	}
	raw[6] = (raw[6] & 15) | 0x40
	raw[8] = (raw[8] & 63) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}
func parseRealityOutbound(raw string) (realityOutbound, error) {
	host, port, err := parseRealityLink(raw)
	if err != nil {
		return realityOutbound{}, err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return realityOutbound{}, errors.New("节点链接格式无效")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return realityOutbound{}, errors.New("节点查询参数无效")
	}
	if typ := q.Get("type"); typ != "" && typ != "tcp" {
		return realityOutbound{}, errors.New("后端仅支持 TCP Reality 链接")
	}
	flow := q.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return realityOutbound{}, errors.New("后端 flow 仅支持空或 xtls-rprx-vision")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	if !validRealityFingerprint(fp) {
		return realityOutbound{}, errors.New("后端 fp 不受支持")
	}
	return realityOutbound{u.User.Username(), host, port, flow, q.Get("sni"), fp, q.Get("pbk"), q.Get("sid"), q.Get("spx")}, nil
}

func validRealityFingerprint(fp string) bool {
	switch fp {
	case "", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn":
		return true
	}
	return false
}
func exportRealityLink(id, edge, domain, label string, keys realityKeys) string {
	if label == "" {
		label = domain
	}
	q := url.Values{"encryption": {"none"}, "flow": {"xtls-rprx-vision"}, "security": {"reality"}, "sni": {domain}, "fp": {"chrome"}, "pbk": {keys.PublicKey}, "sid": {keys.ShortID}, "type": {"tcp"}}
	u := url.URL{Scheme: "vless", User: url.User(id), Host: net.JoinHostPort(edge, "443"), RawQuery: q.Encode(), Fragment: label}
	return u.String()
}
func saveRealityEntry(p xrayPaths, domain string, entry realityEntry, fs relayFS) error {
	if err := securePrivateDir(fs, p.root); err != nil {
		return err
	}
	return privateJSON(fs, p.entry(domain), entry)
}
func removeRealityEntry(domain string) error {
	err := os.Remove(liveXrayPaths().entry(domain))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// 配置只从启用站点和受限机密文件生成，切片按域名排序使输出稳定。
func renderXrayConfig(sites []SiteMeta, keys realityKeys, entries map[string]realityEntry) ([]byte, error) {
	if len(sites) == 0 {
		return nil, nil
	}
	if err := validateRealityKeys(keys); err != nil {
		return nil, err
	}
	ordered := append([]SiteMeta{}, sites...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Domain < ordered[j].Domain })
	clients := []any{}
	names := []string{}
	outbounds := []any{}
	rules := []any{}
	seen := map[string]bool{}
	for _, site := range ordered {
		if site.Reality == nil {
			continue
		}
		if validateSNIDomain(site.Domain) != nil {
			return nil, errors.New("Reality 域名无效")
		}
		if seen[site.Domain] {
			continue
		}
		seen[site.Domain] = true
		entry, ok := entries[site.Domain]
		if !ok || entry.FrontendUUID == "" || entry.Outbound.UUID == "" {
			return nil, errors.New("缺少 Reality 入口机密")
		}
		backend := entry.Outbound
		if backend.Host != site.Reality.UpstreamHost || backend.Port != site.Reality.UpstreamPort {
			return nil, errors.New("Reality 路由与机密文件不一致")
		}
		if backend.Fingerprint == "" {
			backend.Fingerprint = "chrome"
		}
		names = append(names, site.Domain)
		clients = append(clients, map[string]any{"id": entry.FrontendUUID, "flow": "xtls-rprx-vision", "email": site.Domain})
		outbounds = append(outbounds, map[string]any{
			"tag": "to-" + site.Domain, "protocol": "vless",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": backend.Host, "port": backend.Port, "users": []any{map[string]any{"id": backend.UUID, "flow": backend.Flow, "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": backend.SNI, "fingerprint": backend.Fingerprint, "publicKey": backend.PublicKey, "shortId": backend.ShortID, "spiderX": backend.SpiderX}},
		})
		rules = append(rules, map[string]any{"type": "field", "user": []string{site.Domain}, "outboundTag": "to-" + site.Domain})
	}
	if len(names) == 0 {
		return nil, nil
	}
	outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})
	rules = append(rules, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"})
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{map[string]any{
			"tag": "reality-in", "listen": "127.0.0.1", "port": realityInboundPort, "protocol": "vless",
			"settings":       map[string]any{"decryption": "none", "clients": clients},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "sockopt": map[string]any{"acceptProxyProtocol": true}, "realitySettings": map[string]any{"dest": "127.0.0.1:8443", "xver": 1, "serverNames": names, "privateKey": keys.PrivateKey, "shortIds": []string{keys.ShortID}}},
		}},
		"outbounds": outbounds, "routing": map[string]any{"rules": rules},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("Xray 配置编码失败")
	}
	return append(data, '\n'), nil
}

// 完整配置失败时逐入口校验并隔离，普通业务不受 Xray 语义错误影响。
func syncXrayConfig(sites []SiteMeta, p xrayPaths, fs relayFS, check func(string) error) error {
	material := loadRealityMaterial(sites, p, fs)
	return syncXrayMaterial(&material, p, fs, check)
}
func syncXrayMaterial(material *realityMaterial, p xrayPaths, fs relayFS, check func(string) error) error {
	if len(material.Sites) == 0 {
		if err := removeXrayFile(fs, p.config()); err != nil {
			return err
		}
		return removeXrayFile(fs, p.health())
	}
	if err := securePrivateDir(fs, p.root); err != nil {
		return err
	}
	if err := fs.chmod(p.keys(), 0600); err != nil {
		return err
	}
	for _, site := range material.Sites {
		if err := securePrivateDir(fs, filepath.Dir(p.entry(site.Domain))); err != nil {
			return err
		}
		if err := fs.chmod(p.entry(site.Domain), 0600); err != nil {
			return err
		}
	}
	data, err := renderXrayConfig(material.Sites, material.Keys, material.Entries)
	if err != nil {
		return err
	}
	current, err := fs.read(p.config())
	if err == nil && bytes.Equal(current, data) {
		if err := fs.chmod(p.config(), 0600); err != nil {
			return err
		}
		return removeXrayFile(fs, p.health())
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := securePrivateDir(fs, p.root); err != nil {
		return err
	}
	candidate := p.config() + ".candidate"
	defer fs.remove(candidate)
	validate := func(data []byte) (bool, error) {
		if err := fs.write(candidate, data, 0600); err != nil {
			return false, err
		}
		// 校验器输出可能含凭据，绝不写入日志或健康状态。
		return check(candidate) == nil, nil
	}
	valid, err := validate(data)
	if err != nil {
		return err
	}
	if valid {
		if err := fs.write(p.config(), data, 0600); err != nil {
			return err
		}
		return removeXrayFile(fs, p.health())
	}
	original := data
	sites := material.Sites
	health := realityValidationHealth{Digest: xrayConfigDigest(original), Errors: map[string]string{}}
	usable := make([]SiteMeta, 0, len(sites))
	for _, site := range sites {
		single, renderErr := renderXrayConfig([]SiteMeta{site}, material.Keys, material.Entries)
		valid := false
		if renderErr == nil {
			valid, err = validate(single)
			if err != nil {
				return err
			}
		}
		if !valid {
			health.Errors[site.Domain] = "入口 Xray 配置校验失败，入口已暂停"
		} else {
			usable = append(usable, site)
		}
	}
	data = nil
	if len(usable) > 0 {
		data, err = renderXrayConfig(usable, material.Keys, material.Entries)
		valid := false
		if err == nil {
			valid, err = validate(data)
			if err != nil {
				return err
			}
		}
		if !valid {
			usable, data = nil, nil
			for _, site := range sites {
				health.Errors[site.Domain] = "共享 Xray 配置校验失败，所有入口已暂停"
			}
		}
	}
	material.Sites = usable
	for domain, message := range health.Errors {
		material.Errors[domain] = message
	}
	if err := saveRealityValidationHealth(health, p, fs); err != nil {
		return err
	}
	if len(data) == 0 {
		return removeXrayFile(fs, p.config())
	}
	return writePrivateConfig(fs, p.config(), data)
}

func removeXrayFile(fs relayFS, path string) error {
	if err := fs.remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// 状态记录关联完整候选配置的摘要；机密变化后旧暂停原因自动失效。
type realityValidationHealth struct {
	Digest string            `json:"digest"`
	Errors map[string]string `json:"errors"`
}

func xrayConfigDigest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func saveRealityValidationHealth(health realityValidationHealth, p xrayPaths, fs relayFS) error {
	data, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		return errors.New("编码 Reality 健康状态失败")
	}
	return writePrivateConfig(fs, p.health(), append(data, '\n'))
}

func annotateRealityValidation(material *realityMaterial, p xrayPaths, fs relayFS) {
	data, err := renderXrayConfig(material.Sites, material.Keys, material.Entries)
	if err != nil || len(data) == 0 {
		return
	}
	raw, err := fs.read(p.health())
	var health realityValidationHealth
	if err != nil || json.Unmarshal(raw, &health) != nil || health.Digest != xrayConfigDigest(data) {
		return
	}
	for _, site := range material.Sites {
		// 即使状态文件被改写，也不向 API 暴露任意原始字符串。
		switch health.Errors[site.Domain] {
		case "入口 Xray 配置校验失败，入口已暂停", "共享 Xray 配置校验失败，所有入口已暂停":
			material.Errors[site.Domain] = health.Errors[site.Domain]
		}
	}
}
func testXrayConfig(path string) error {
	ctx, cancel := contextWithTimeout(8 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/local/bin/xray", "run", "-test", "-c", path)
	// 命令输出可能含身份或密钥，错误仅报告校验结果。
	if err := cmd.Run(); err != nil {
		return errors.New("Xray 配置校验失败")
	}
	return nil
}

func writePrivateConfig(fs relayFS, path string, data []byte) error {
	if err := securePrivateDir(fs, filepath.Dir(path)); err != nil {
		return err
	}
	current, err := fs.read(path)
	if err == nil && bytes.Equal(current, data) {
		return fs.chmod(path, 0600)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return fs.write(path, data, 0600)
}

func securePrivateDir(fs relayFS, path string) error {
	if err := fs.mkdir(path, 0700); err != nil {
		return err
	}
	return fs.chmod(path, 0700)
}

// 读取故障只暂停受影响的入口；诊断只包含固定文案，不回显任何机密内容。
type realityMaterial struct {
	Sites   []SiteMeta
	Keys    realityKeys
	Entries map[string]realityEntry
	Errors  map[string]string
}

func loadRealityMaterial(sites []SiteMeta, p xrayPaths, fs relayFS) realityMaterial {
	material := realityMaterial{Entries: map[string]realityEntry{}, Errors: map[string]string{}}
	if len(sites) == 0 {
		return material
	}
	raw, err := fs.read(p.keys())
	if err != nil || json.Unmarshal(raw, &material.Keys) != nil || validateRealityKeys(material.Keys) != nil {
		for _, site := range sites {
			material.Errors[site.Domain] = "共享 Reality 密钥缺失、不可读或损坏，入口已暂停"
		}
		return material
	}
	ordered := append([]SiteMeta{}, sites...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Domain < ordered[j].Domain })
	for _, site := range ordered {
		var entry realityEntry
		raw, err := fs.read(p.entry(site.Domain))
		if err != nil || json.Unmarshal(raw, &entry) != nil || !validRealityEntry(site, entry) {
			material.Errors[site.Domain] = "入口机密缺失、不可读或损坏，入口已暂停"
			continue
		}
		material.Sites = append(material.Sites, site)
		material.Entries[site.Domain] = entry
	}
	return material
}
func validRealityEntry(site SiteMeta, entry realityEntry) bool {
	backend := entry.Outbound
	if site.Reality == nil || backend.Host != site.Reality.UpstreamHost || backend.Port != site.Reality.UpstreamPort {
		return false
	}
	if !validRealityUUID(entry.FrontendUUID) || !validRealityUUID(backend.UUID) || net.ParseIP(backend.Host) == nil || backend.Port < 1 || backend.Port > 65535 || backend.SNI == "" {
		return false
	}
	if backend.Flow != "" && backend.Flow != "xtls-rprx-vision" {
		return false
	}
	public, err := base64.RawURLEncoding.DecodeString(backend.PublicKey)
	if err != nil || len(public) != 32 {
		return false
	}
	short, err := hex.DecodeString(backend.ShortID)
	return err == nil && len(short) <= 8
}
func validRealityUUID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:])
	return err == nil
}
