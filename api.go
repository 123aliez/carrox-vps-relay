// HTTP handlers + route registration for the Go 1.22 mux.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

	// TCP forwards (admin only).
	mux.HandleFunc("GET /api/tcp-forwards", auth(tcpForwardsList))
	mux.HandleFunc("POST /api/tcp-forwards", auth(tcpForwardsCreate))
	mux.HandleFunc("GET /api/tcp-forwards/{port}/link", auth(tcpForwardLink))
	mux.HandleFunc("DELETE /api/tcp-forwards/{port}", auth(tcpForwardsDelete))

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

func edgeIPv4() string {
	edgeIPCacheMu.Lock()
	defer edgeIPCacheMu.Unlock()
	if edgeIPCache != "" {
		return edgeIPCache
	}
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", "-s", "-4", "--max-time", "3", "https://ifconfig.me")
	out, err := cmd.Output()
	if err == nil {
		ip := strings.TrimSpace(string(out))
		if ip != "" {
			edgeIPCache = ip
		}
	}
	return edgeIPCache
}

// ---------------- Sites ----------------

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
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
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
	meta, err = provisionSite(meta, tok, edge, *zone, liveSiteLifecycle())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	target := confPath(req.Domain)

	site := Site{SiteMeta: meta, ConfPath: target, Enabled: true}
	probeSite(&site)
	writeJSON(w, http.StatusOK, site)
}

// --- edit upstream ---

type editReq struct {
	Upstream string `json:"upstream"`
}

func sitesEdit(w http.ResponseWriter, r *http.Request) {
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
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
		writeErr(w, http.StatusUnprocessableEntity, "站点已停用，请先启用再编辑")
		return
	} else {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	meta, err := readSiteMeta(fromPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取元数据失败: "+err.Error())
		return
	}
	if !isAdmin && meta.Owner != keyID {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}

	var req editReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
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
	// Backup → write new → syntax check → reload; on failure restore.
	bak := fromPath + ".relay.bak"
	if err := copyFile(fromPath, bak); err != nil {
		writeErr(w, http.StatusInternalServerError, "备份失败: "+err.Error())
		return
	}
	if err := atomicWrite(fromPath, rendered, 0o644); err != nil {
		_ = os.Rename(bak, fromPath)
		writeErr(w, http.StatusInternalServerError, "写入配置失败: "+err.Error())
		return
	}
	if err := nginxSyntaxCheck(); err != nil {
		_ = os.Rename(bak, fromPath)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := nginxReload(); err != nil {
		_ = os.Rename(bak, fromPath)
		writeErr(w, http.StatusInternalServerError, "reload 失败: "+err.Error())
		return
	}
	_ = os.Remove(bak)
	site := Site{SiteMeta: meta, ConfPath: fromPath, Enabled: true}
	probeSite(&site)
	writeJSON(w, http.StatusOK, site)
}

// --- toggle (enable/disable) ---

func sitesToggle(w http.ResponseWriter, r *http.Request) {
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
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
	if !isAdmin && meta.Owner != keyID {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}
	if err := os.Rename(fromPath, newPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "重命名失败: "+err.Error())
		return
	}
	if err := nginxSyntaxCheck(); err != nil {
		_ = os.Rename(newPath, fromPath)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := nginxReload(); err != nil {
		_ = os.Rename(newPath, fromPath)
		writeErr(w, http.StatusInternalServerError, "reload 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"enabled": !strings.HasSuffix(newPath, ".disabled"),
	})
}

// --- delete ---

func sitesDelete(w http.ResponseWriter, r *http.Request) {
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
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
	if !isAdmin && meta.Owner != keyID {
		writeErr(w, http.StatusForbidden, "无权操作此站点")
		return
	}
	owner := meta.Owner
	if owner == "" {
		owner = "admin"
	}
	meta.Owner = owner
	if err := removeManagedSite(meta, cfTokenForKey(owner), path, staged, liveSiteLifecycle()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
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
	siteMutationMu.Lock()
	defer siteMutationMu.Unlock()
	var req adoptReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := validateDomain(req.Domain); err != nil {
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
	if !strings.HasPrefix(req.ConfPath, confDir+"/") {
		writeErr(w, http.StatusBadRequest, "conf_path must live in "+confDir)
		return
	}
	src, err := os.ReadFile(req.ConfPath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "读取源配置失败: "+err.Error())
		return
	}
	target := confPath(req.Domain)
	if existsAnyForm(req.Domain) {
		writeErr(w, http.StatusConflict, "托管站点已存在: "+req.Domain)
		return
	}
	bak := req.ConfPath + ".pre-adopt.bak"
	if err := atomicWrite(bak, src, 0o644); err != nil {
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
	if err := atomicWrite(target, merged, 0o644); err != nil {
		_ = os.Remove(bak)
		writeErr(w, http.StatusInternalServerError, "写入托管配置失败: "+err.Error())
		return
	}
	if req.ConfPath != target {
		_ = os.Remove(req.ConfPath)
	}
	if err := nginxSyntaxCheck(); err != nil {
		_ = os.Remove(target)
		_ = atomicWrite(req.ConfPath, src, 0o644)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := nginxReload(); err != nil {
		writeErr(w, http.StatusInternalServerError, "reload 失败: "+err.Error())
		return
	}
	site := Site{SiteMeta: meta, ConfPath: target, Enabled: true}
	probeSite(&site)
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
	return atomicWrite(dst, b, 0o644)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
