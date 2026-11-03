package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	realityPortMin = 30000
	realityPortMax = 30999
	realityLinkDir = "/etc/vps-relay/reality-links"
	camouflageDir  = "/usr/local/nginx/html/relay-camouflage"
)

// RealityMeta 只保存路由信息，节点凭据单独写入受限文件。
type RealityMeta struct {
	UpstreamHost string `json:"upstream_host"`
	UpstreamPort int    `json:"upstream_port"`
	Label        string `json:"label"`
}

func realityLinkPath(domain string) string { return filepath.Join(realityLinkDir, domain+".link") }
func saveRealityLink(domain, link string) error {
	return saveRealityLinkAt(realityLinkDir, domain, link)
}

func saveRealityLinkAt(dir, domain, link string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, domain+".link"), []byte(link), 0600)
}
func removeRealityLink(domain string) error {
	err := os.Remove(realityLinkPath(domain))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func ensureCamouflage() error { return ensureCamouflageAt(camouflageDir) }

func ensureCamouflageAt(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "index.html")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWrite(path, []byte("<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><body><h1>Welcome</h1><p>Have a pleasant day.</p></body></html>\n"), 0644)
}
func realityStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	sites, warnings, err := scanSites(authKeyID(r), true)
	if err != nil {
		writeErr(w, 500, "读取 Reality 入口失败")
		return
	}
	entries := make([]Site, 0)
	for _, site := range sites {
		if site.Reality != nil {
			entries = append(entries, site)
		}
	}
	annotateRealityHealth(entries, liveXrayPaths(), liveRelayFS())
	annotateRealityRouting(entries, liveSNIPaths(), liveRelayFS())
	writeJSON(w, 200, map[string]any{"sni_mode": sni443Enabled(), "xray_running": xrayRunning(), "xray_error": xrayLastError(), "entries": entries, "warnings": warnings})
}
func realityCreate(w http.ResponseWriter, r *http.Request) {
	realityCreateWithMode(w, r, sni443Enabled)
}

func realityCreateWithMode(w http.ResponseWriter, r *http.Request, enabled func() bool) {
	if !requireAdmin(w, r) {
		return
	}
	if err := ensureNoSNIMigration(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if !enabled() {
		writeErr(w, http.StatusPreconditionFailed, "请先执行 docker exec vps-relay vps-relay sni443 enable 迁移命令")
		return
	}
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	if !enabled() {
		writeErr(w, 412, "请先执行 docker exec vps-relay vps-relay sni443 enable 迁移命令")
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Link   string `json:"link"`
		Label  string `json:"label"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
		writeErr(w, 400, "请求格式无效")
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	req.Link = strings.TrimSpace(req.Link)
	req.Label = strings.TrimSpace(req.Label)
	if validateSNIDomain(req.Domain) != nil {
		writeErr(w, 400, "域名无效")
		return
	}
	if len(req.Link) > tcpLinkMax {
		writeErr(w, 400, "节点链接过长")
		return
	}
	if err := validateTCPLabel(req.Label); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if existsAnyForm(req.Domain) {
		writeErr(w, 409, "站点已存在")
		return
	}
	if panel, err := os.ReadFile(filepath.Join(confDir, "relay-panel.conf")); err == nil && panelCertDomain(panel) == req.Domain {
		writeErr(w, 409, "域名已由面板使用")
		return
	}
	outbound, err := parseRealityOutbound(req.Link)
	host, port := outbound.Host, outbound.Port
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	edge := edgeIPv4()
	if ip := net.ParseIP(edge); ip == nil || ip.To4() == nil {
		writeErr(w, 500, "无法检测边缘 IPv4")
		return
	}
	if err = validateTCPUpstream(host, port, edge); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	host = net.ParseIP(host).String()
	outbound.Host = host
	token := cfTokenForKey(authKeyID(r))
	if token == "" {
		writeErr(w, 424, "请先配置 Cloudflare Token")
		return
	}
	if !xrayRunning() {
		if err := tcpPortAvailable(realityInboundPort); err != nil {
			writeErr(w, 409, "本机 Xray 保留端口 30001 已被占用，请先释放该端口并检查历史 stream 配置")
			return
		}
	}
	zone, err := cfPickZoneFor(token, req.Domain)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !prepareNginxMutation(w) {
		return
	}
	keys, err := loadOrCreateXrayKeys(liveXrayPaths(), liveRelayFS())
	if err != nil {
		writeErr(w, 500, "准备前端 Reality 密钥失败")
		return
	}
	frontendUUID, err := newRealityUUID()
	if err != nil {
		writeErr(w, 500, "生成入口身份失败")
		return
	}
	entry := realityEntry{FrontendUUID: frontendUUID, Outbound: outbound}
	link := exportRealityLink(frontendUUID, edge, req.Domain, req.Label, keys)
	if err = ensureCamouflage(); err != nil {
		writeErr(w, 500, "准备静态页面失败")
		return
	}
	if err = saveRealityEntry(liveXrayPaths(), req.Domain, entry, liveRelayFS()); err != nil {
		writeErr(w, 500, "保存入口机密失败")
		return
	}
	if err = saveRealityLink(req.Domain, link); err != nil {
		_ = removeRealityEntry(req.Domain)
		writeErr(w, 500, "保存链接失败")
		return
	}
	meta := SiteMeta{V: 2, Domain: req.Domain, Upstream: "https://" + net.JoinHostPort(host, strconv.Itoa(port)), Owner: authKeyID(r), Created: time.Now().UTC().Format(time.RFC3339), Reality: &RealityMeta{host, port, req.Label}}
	meta, err = provisionRealityWith(meta,
		func(meta SiteMeta) (SiteMeta, error) {
			return provisionSite(meta, token, edge, *zone, liveSiteLifecycle())
		},
		func() error { return confirmRealityRuntime(req.Domain) },
		func(meta SiteMeta) error {
			return removeManagedSite(meta, token, confPath(meta.Domain), false, liveSiteLifecycle())
		},
	)
	if err != nil {
		cleanupErr := cleanupRealityProvisionFailure(req.Domain, err, cleanupFailedReality)
		if cleanupErr != nil {
			err = errors.Join(err, errors.New("清理入口或恢复运行状态失败"))
		}
		writeErr(w, 502, err.Error())
		return
	}
	site := Site{SiteMeta: meta, Enabled: true}
	probeSite(&site)
	w.Header().Set("Cache-Control", "no-store")
	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, 200, map[string]any{"site": site, "link": link})
}

func cleanupRealityProvisionFailure(domain string, cause error, cleanup func(string) error) error {
	if errors.Is(cause, errSiteRetained) {
		return nil
	}
	return cleanup(domain)
}
func realityLink(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	domain := strings.ToLower(r.PathValue("domain"))
	if validateSNIDomain(domain) != nil {
		writeErr(w, 400, "域名无效")
		return
	}
	b, err := os.ReadFile(realityLinkPath(domain))
	if os.IsNotExist(err) {
		writeErr(w, 404, "该入口没有保存链接")
		return
	}
	if err != nil {
		writeErr(w, 500, "读取链接失败")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"link": string(b)})
}

func realityEditError(meta SiteMeta) error {
	if meta.Reality != nil {
		return errors.New("Reality 入口请删除重建")
	}
	return nil
}

// Nginx 的 map 键和 server_name 必须是纯 DNS 名称。
var sniDomainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

func validateSNIDomain(domain string) error {
	if validateDomain(domain) != nil || len(domain) > 253 {
		return errors.New("域名无效")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 || !sniDomainRE.MatchString(strings.ToLower(label)) {
			return errors.New("域名无效")
		}
	}
	return nil
}

func removeRealitySecrets(domain string) error {
	return errors.Join(removeRealityEntry(domain), removeRealityLink(domain))
}

func cleanupFailedReality(domain string) error {
	return cleanupFailedRealityWith(domain, resolveSiteDeletePath, renameNginxFile, removeRealitySecrets, restoreRelayRuntime)
}

func cleanupFailedRealityWith(domain string, resolve func(string) (string, bool, error), rename func(string, string) error, remove func(string) error, syncRuntime func() error) error {
	// 只有确认配置不再参与同步后才能删除凭据；隔离失败保留完整材料供重试。
	path, staged, err := resolve(confPath(domain))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !staged {
		if err := rename(path, path+tcpDeleteSuffix); err != nil {
			return fmt.Errorf("隔离入口失败，已保留机密: %w", err)
		}
	}
	// 先把隔离状态加载，再删除不可恢复的机密；失败时仍可恢复完整入口。
	if err := syncRuntime(); err != nil {
		return err
	}
	if err := commitNginxMutation(); err != nil {
		return err
	}
	cleanupErr := remove(domain)
	if cleanupErr == nil {
		markNginxConsistent()
	}
	return cleanupErr
}

// 仅新建 Reality 需要确认就绪；失败仍通过站点生命周期恢复 DNS 并撤下配置。
func provisionRealityWith(meta SiteMeta, provision func(SiteMeta) (SiteMeta, error), confirm func() error, rollback func(SiteMeta) error) (SiteMeta, error) {
	meta, err := provision(meta)
	if err != nil {
		return meta, err
	}
	if err := confirm(); err != nil {
		if op := activeNginxOperation.Load(); op != nil {
			op.consistent.Store(false)
		}
		return meta, errors.Join(errors.New("Xray 未就绪，入口创建失败"), rollback(meta))
	}
	return meta, nil
}

func annotateRealityHealth(sites []Site, p xrayPaths, fs relayFS) {
	metas := make([]SiteMeta, 0, len(sites))
	active := make([]SiteMeta, 0, len(sites))
	for _, site := range sites {
		metas = append(metas, site.SiteMeta)
		if site.Enabled {
			active = append(active, site.SiteMeta)
		}
	}
	material := loadRealityMaterial(metas, p, fs)
	validation := loadRealityMaterial(active, p, fs)
	annotateRealityValidation(&validation, p, fs)
	for i := range sites {
		sites[i].RealityError = material.Errors[sites[i].Domain]
		if message := validation.Errors[sites[i].Domain]; message != "" {
			sites[i].RealityError = message
		}
		sites[i].RealityPaused = sites[i].Enabled && sites[i].RealityError != ""
	}
}

func annotateRealityRouting(sites []Site, p sniPaths, fs relayFS) {
	on, err := sniMode(p, fs)
	if err != nil || !on {
		return
	}
	data, err := fs.read(p.derived()[0])
	if err != nil {
		data = nil
	}
	for i := range sites {
		if sites[i].Enabled && sites[i].RealityError == "" && !strings.Contains(string(data), sites[i].Domain+" 127.0.0.1:30001;") {
			sites[i].RealityPaused = true
			sites[i].RealityError = "Reality 路由未就绪，入口已暂停"
		}
	}
}
