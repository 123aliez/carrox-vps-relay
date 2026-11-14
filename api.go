// HTTP handlers + route registration for the Go 1.22 mux.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	edgeIPCache   string
	edgeIPCacheMu sync.Mutex
)

func registerAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/healthz", healthz)
	mux.HandleFunc("POST /api/login", loginHandler)
	mux.HandleFunc("POST /api/logout", logoutHandler)

	mux.HandleFunc("GET /api/whoami", auth(whoami))

	mux.HandleFunc("GET /api/cf-token/status", auth(cfTokenStatus))
	mux.HandleFunc("PUT /api/cf-token", auth(cfTokenSave))

	mux.HandleFunc("GET /api/zones", auth(zonesList))
	mux.HandleFunc("GET /api/edge", auth(edgeInfo))

	mux.HandleFunc("GET /api/sites", auth(sitesList))
	mux.HandleFunc("POST /api/sites", auth(sitesCreate))
	mux.HandleFunc("POST /api/sites/adopt", auth(sitesAdopt))
	mux.HandleFunc("PUT /api/sites/{domain}", auth(sitesEdit))
	mux.HandleFunc("POST /api/sites/{domain}/toggle", auth(sitesToggle))
	mux.HandleFunc("DELETE /api/sites/{domain}", auth(sitesDelete))

	// Reality 入口仅供管理员使用。
	mux.HandleFunc("GET /api/reality", auth(realityStatus))
	mux.HandleFunc("POST /api/reality", auth(realityCreate))
	mux.HandleFunc("GET /api/reality/{domain}/link", auth(realityLink))

	// Key management (admin only).
	mux.HandleFunc("GET /api/keys", auth(keysList))
	mux.HandleFunc("POST /api/keys", auth(keysCreate))
	mux.HandleFunc("DELETE /api/keys/{key_id}", auth(keysDelete))
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"role":   authRole(r),
		"key_id": authKeyID(r),
	})
}

// ---------------- CF Token ----------------

type cfTokenStatusResp struct {
	Configured bool   `json:"configured"`
	Masked     string `json:"masked"`
}

func cfTokenStatus(w http.ResponseWriter, r *http.Request) {
	tok := cfTokenForKey(authKeyID(r))
	writeJSON(w, http.StatusOK, cfTokenStatusResp{
		Configured: tok != "",
		Masked:     maskToken(tok),
	})
}

func cfTokenSave(w http.ResponseWriter, r *http.Request) {
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if body.Token == "" {
		writeErr(w, http.StatusBadRequest, "token required")
		return
	}
	if err := cfVerifyToken(body.Token); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "cloudflare 拒绝了此 Token: " + err.Error(),
		})
		return
	}
	keyID := authKeyID(r)
	if err := saveCfTokenForKey(keyID, body.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, "save config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"masked": maskToken(body.Token),
	})
}

// ---------------- Zones ----------------

func zonesList(w http.ResponseWriter, r *http.Request) {
	tok := cfTokenForKey(authKeyID(r))
	if tok == "" {
		writeErr(w, http.StatusFailedDependency, "请先配置 Cloudflare Token")
		return
	}
	zones, err := cfListZones(tok)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, zones)
}

// ---------------- Edge info ----------------

type edgeResp struct {
	IPv4 string `json:"ipv4"`
}

func edgeInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, edgeResp{IPv4: edgeIPv4()})
}

// validEdgeIPv4 仅接受合法 IPv4 文本，避免缓存 HTML 等垃圾输出。
func validEdgeIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}

func edgeIPv4() string {
	edgeIPCacheMu.Lock()
	defer edgeIPCacheMu.Unlock()
	if edgeIPCache != "" {
		return edgeIPCache
	}
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", "-sf", "-4", "--max-time", "3", "https://ifconfig.me")
	out, err := cmd.Output()
	if err == nil {
		ip := strings.TrimSpace(string(out))
		if validEdgeIPv4(ip) {
			edgeIPCache = ip
		}
	}
	return edgeIPCache
}

// ---------------- Sites ----------------

// writeNginxErr 只对普通用户隐藏 nginx -t 的原始输出（含宿主路径和其他站点文件名）；
// DNS、证书等用户可自行处理的错误照常返回。
func writeNginxErr(w http.ResponseWriter, r *http.Request, status int, err error) {
	if authIsAdmin(r) || !strings.Contains(err.Error(), "nginx -t failed") {
		writeErr(w, status, err.Error())
		return
	}
	log.Printf("nginx 操作失败: %v", err)
	writeErr(w, status, "配置校验或重载失败，请联系管理员查看日志")
}

func sitesList(w http.ResponseWriter, r *http.Request) {
	keyID := authKeyID(r)
	isAdmin := authIsAdmin(r)
	sites, warn, err := scanSites(keyID, isAdmin)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sites == nil {
		sites = []Site{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sites":    sites,
		"warnings": warn,
		"edge_ip":  edgeIPv4(),
	})
}

// --- create ---

type createReq struct {
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
}

func sitesCreate(w http.ResponseWriter, r *http.Request) {
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	req.Upstream = strings.TrimSpace(req.Upstream)
	if err := validateDomain(req.Domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, _, _, _, err := parseUpstream(req.Upstream); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if existsAnyForm(req.Domain) {
		writeErr(w, http.StatusConflict, "站点已存在: "+req.Domain)
		return
	}
	keyID := authKeyID(r)
	tok := cfTokenForKey(keyID)
	if tok == "" {
		writeErr(w, http.StatusFailedDependency, "请先配置 Cloudflare Token")
		return
	}
	edge := edgeIPv4()
	if edge == "" {
		writeErr(w, http.StatusInternalServerError, "无法检测边缘 IPv4")
		return
	}

	zone, err := cfPickZoneFor(tok, req.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validateRelayUpstream(req.Domain, req.Upstream, edge); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta := SiteMeta{
		V: 2, Domain: req.Domain, Upstream: req.Upstream,
		Owner: keyID, Created: time.Now().UTC().Format(time.RFC3339),
	}
	if !prepareNginxMutation(w) {
		return
	}
	meta, err = provisionSite(meta, tok, edge, *zone, liveSiteLifecycle())
	if err != nil {
		writeNginxErr(w, r, http.StatusBadGateway, err)
		return
	}
	target := confPath(req.Domain)

	site := Site{SiteMeta: meta, ConfPath: target, Enabled: true}
	probeSite(&site)
	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, http.StatusOK, site)
}

// --- edit upstream ---

type editReq struct {
	Upstream string `json:"upstream"`
}

func sitesEdit(w http.ResponseWriter, r *http.Request) {
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	domain := strings.ToLower(r.PathValue("domain"))
	if err := validateDomain(domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	keyID := authKeyID(r)
	isAdmin := authIsAdmin(r)

	cur := confPath(domain)
	var fromPath string
	if _, err := os.Stat(cur); err == nil {
		fromPath = cur
	} else if _, err := os.Stat(cur + ".disabled"); err == nil {
		fromPath = cur + ".disabled"
	} else {
		path, staged, pathErr := resolveSiteDeletePath(cur)
		if pathErr == nil && staged {
			pending, readErr := readSiteMeta(path + tcpDeleteSuffix)
			if readErr == nil && pending.Reality != nil {
				if !isAdmin {
					writeErr(w, 403, "无权操作此站点")
				} else {
					writeErr(w, 422, "Reality 入口请删除重建")
				}
				return
			}
		}
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	meta, err := readSiteMeta(fromPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取元数据失败: "+err.Error())
		return
	}
	if !isAdmin && (meta.Reality != nil || meta.Owner != keyID) {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}

	if err := realityEditError(meta); err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	if strings.HasSuffix(fromPath, ".disabled") {
		writeErr(w, 422, "站点已停用，请先启用再编辑")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req editReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Upstream = strings.TrimSpace(req.Upstream)
	if _, _, _, _, err := parseUpstream(req.Upstream); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRelayUpstream(domain, req.Upstream, edgeIPv4()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta.Upstream = req.Upstream
	rendered, err := renderSite(meta)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "渲染配置失败: "+err.Error())
		return
	}
	if !prepareNginxMutation(w) {
		return
	}
	if status, err := commitSiteEdit(fromPath, rendered, liveSiteEditOps()); err != nil {
		writeNginxErr(w, r, status, err)
		return
	}
	site := Site{SiteMeta: meta, ConfPath: fromPath, Enabled: true}
	probeSite(&site)
	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, http.StatusOK, site)
}

// --- toggle (enable/disable) ---

func sitesToggle(w http.ResponseWriter, r *http.Request) {
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	domain := strings.ToLower(r.PathValue("domain"))
	if err := validateDomain(domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	keyID := authKeyID(r)
	isAdmin := authIsAdmin(r)

	enabled := confPath(domain)
	disabled := enabled + ".disabled"
	var newPath, fromPath string
	if _, err := os.Stat(enabled); err == nil {
		fromPath, newPath = enabled, disabled
	} else if _, err := os.Stat(disabled); err == nil {
		fromPath, newPath = disabled, enabled
	} else {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	meta, err := readSiteMeta(fromPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取元数据失败: "+err.Error())
		return
	}
	if !isAdmin && (meta.Reality != nil || meta.Owner != keyID) {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}
	if !prepareNginxMutation(w) {
		return
	}
	if err := renameNginxFile(fromPath, newPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "重命名失败: "+err.Error())
		return
	}
	if err := nginxSyntaxCheck(); err != nil {
		restoreErr := renameNginxFile(newPath, fromPath)
		if restoreErr == nil {
			restoreErr = restoreRelayRuntime()
		}
		if restoreErr == nil {
			markNginxConsistent()
		}
		writeNginxErr(w, r, http.StatusUnprocessableEntity, errors.Join(err, restoreErr))
		return
	}
	if err := nginxReload(); err != nil {
		restoreErr := renameNginxFile(newPath, fromPath)
		if restoreErr == nil {
			restoreErr = restoreRelayRuntime()
		}
		if restoreErr == nil {
			markNginxConsistent()
		}
		writeNginxErr(w, r, http.StatusInternalServerError, errors.Join(err, restoreErr))
		return
	}
	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"enabled": !strings.HasSuffix(newPath, ".disabled"),
	})
}

// --- delete ---

func sitesDelete(w http.ResponseWriter, r *http.Request) {
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	domain := strings.ToLower(r.PathValue("domain"))
	if err := validateDomain(domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	keyID := authKeyID(r)
	isAdmin := authIsAdmin(r)

	path, staged, err := resolveSiteDeletePath(confPath(domain))
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "站点不存在")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	readPath := path
	if staged {
		readPath += ".relay-delete.bak"
	}
	meta, err := readSiteMeta(readPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取元数据失败: "+err.Error())
		return
	}
	if !isAdmin && (meta.Reality != nil || meta.Owner != keyID) {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}
	owner := meta.Owner
	if owner == "" {
		owner = "admin"
	}
	meta.Owner = owner
	if !prepareNginxMutation(w) {
		return
	}
	if err := removeManagedSite(meta, cfTokenForKey(owner), path, staged, liveSiteLifecycle()); err != nil {
		writeNginxErr(w, r, http.StatusBadGateway, err)
		return
	}

	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": domain})
}

// --- adopt: convert an existing hand-written vhost into a managed site ---

type adoptReq struct {
	ConfPath   string `json:"conf_path"`
	Domain     string `json:"domain"`
	Upstream   string `json:"upstream"`
	CFZone     string `json:"cf_zone"`
	CFRecordID string `json:"cf_record_id"`
}

func sitesAdopt(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req adoptReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if err := validateSNIDomain(req.Domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, _, _, _, err := parseUpstream(req.Upstream); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ConfPath == "" {
		writeErr(w, http.StatusBadRequest, "conf_path required")
		return
	}
	source, err := adoptSourcePath(req.ConfPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.ConfPath = source
	src, err := os.ReadFile(req.ConfPath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "读取源配置失败: "+err.Error())
		return
	}
	if filepath.Base(source) == "relay-panel.conf" || metaRE.Match(src) || bytes.Contains(src, []byte(relayHead)) {
		writeErr(w, 422, "已托管的站点或面板配置不能再次接管，请使用对应管理接口")
		return
	}
	target := confPath(req.Domain)
	if existsAnyForm(req.Domain) {
		writeErr(w, http.StatusConflict, "托管站点已存在: "+req.Domain)
		return
	}
	bak := req.ConfPath + ".pre-adopt.bak"
	if !prepareNginxMutation(w) {
		return
	}
	if err := writeNginxFile(bak, src, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "备份失败: "+err.Error())
		return
	}
	keyID := authKeyID(r)
	meta := SiteMeta{
		V: 1, Domain: req.Domain, Upstream: req.Upstream,
		Owner: keyID, CFZone: req.CFZone, CFRecordID: req.CFRecordID,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	header := fmt.Sprintf("%s\n# relay-meta: %s\n# =================================================\n",
		relayHead, mustJSON(meta))
	merged := []byte(header)
	merged = append(merged, src...)
	if err := writeNginxFile(target, merged, 0o644); err != nil {
		_ = removeNginxFile(bak)
		writeErr(w, http.StatusInternalServerError, "写入托管配置失败: "+err.Error())
		return
	}
	if req.ConfPath != target {
		_ = removeNginxFile(req.ConfPath)
	}
	if err := nginxSyntaxCheck(); err != nil {
		removeErr := removeNginxFile(target)
		restoreErr := writeNginxFile(req.ConfPath, src, 0o644)
		var reloadErr error
		if removeErr == nil && restoreErr == nil {
			reloadErr = nginxReload()
		}
		if removeErr == nil && restoreErr == nil && reloadErr == nil {
			markNginxConsistent()
		}
		writeErr(w, http.StatusUnprocessableEntity, errors.Join(err, removeErr, restoreErr, reloadErr).Error())
		return
	}
	if err := nginxReload(); err != nil {
		writeErr(w, http.StatusInternalServerError, "reload 失败: "+err.Error())
		return
	}
	site := Site{SiteMeta: meta, ConfPath: target, Enabled: true}
	probeSite(&site)
	if !completeNginxRequest(w) {
		return
	}
	writeJSON(w, http.StatusOK, site)
}

// ---------------- Key management (admin only) ----------------

func keysList(w http.ResponseWriter, r *http.Request) {
	if !authIsAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	writeJSON(w, http.StatusOK, listKeys())
}

func keysCreate(w http.ResponseWriter, r *http.Request) {
	if !authIsAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var body struct {
		ID   string `json:"id"`
		Role string `json:"role"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	body.ID = strings.TrimSpace(body.ID)
	body.Role = strings.TrimSpace(body.Role)
	entry, err := addKey(body.ID, body.Role, body.Note)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"id":   entry.ID,
		"key":  entry.Key,
		"role": entry.Role,
	})
}

func keysDelete(w http.ResponseWriter, r *http.Request) {
	if !authIsAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	unlock, ok := lockSiteRequest(w)
	if !ok {
		return
	}
	defer unlock()
	keyID := strings.TrimSpace(r.PathValue("key_id"))
	if keyID == "" {
		writeErr(w, http.StatusBadRequest, "key_id required")
		return
	}
	if err := deleteKey(keyID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": keyID})
}

// ---------------- helpers ----------------

func existsAnyForm(domain string) bool {
	_, _, err := resolveSiteDeletePath(confPath(domain))
	return !os.IsNotExist(err)
}

func validateDomain(d string) error {
	if d == "" {
		return errors.New("domain required")
	}
	if strings.ContainsAny(d, " /\\\t\n") {
		return errors.New("domain contains whitespace or slash")
	}
	u, err := url.Parse("http://" + d)
	if err != nil || u.Host != d || strings.IndexByte(d, '.') < 0 {
		return errors.New("invalid domain: " + d)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".relay-tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return atomicWrite(dst, b, info.Mode().Perm())
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// 接管只允许 conf.d 的普通配置文件，防止越界读取机密或通过重命名绕过站点权限。
func adoptSourcePath(path string) (string, error) {
	root, err := filepath.Abs(confDir)
	if err != nil {
		return "", errors.New("配置目录无效")
	}
	if !filepath.IsAbs(path) || filepath.Dir(filepath.Clean(path)) != root || filepath.Ext(path) != ".conf" {
		return "", errors.New("接管源必须是 conf.d 内的普通 .conf 文件")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("接管源不存在或不是普通配置文件")
	}
	return path, nil
}

// 编辑事务的文件及重载操作可注入，以核对磁盘与最后一次成功 HUP 的内容一致。
type siteEditOps struct {
	copy          func(string, string) error
	write         func(string, []byte, os.FileMode) error
	rename        func(string, string) error
	remove        func(string) error
	check, reload func() error
	consistent    func()
}

func liveSiteEditOps() siteEditOps {
	return siteEditOps{copy: copyNginxFile, write: writeNginxFile, rename: renameNginxFile, remove: removeNginxFile, check: nginxSyntaxCheck, reload: nginxReload, consistent: markNginxConsistent}
}
func commitSiteEdit(path string, data []byte, ops siteEditOps) (int, error) {
	backup := path + ".relay.bak"
	if err := ops.copy(path, backup); err != nil {
		return 500, fmt.Errorf("备份失败: %w", err)
	}
	rollback := func(cause error) error {
		if err := ops.rename(backup, path); err != nil {
			return errors.Join(cause, err)
		}
		if err := ops.reload(); err != nil {
			return errors.Join(cause, err)
		}
		if ops.consistent != nil {
			ops.consistent()
		}
		return cause
	}
	if err := ops.write(path, data, 0644); err != nil {
		return 500, rollback(err)
	}
	if err := ops.check(); err != nil {
		return 422, rollback(err)
	}
	if err := ops.reload(); err != nil {
		return 500, rollback(err)
	}
	if err := ops.remove(backup); err != nil {
		return 500, err
	}
	return 200, nil
}
