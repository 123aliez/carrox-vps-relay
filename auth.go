// Key-table authentication + per-IP rate limiting for failed login.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	keysPath     = "/etc/vps-relay/keys.json"
	cookieName   = "vps-relay-auth"
	cookieMaxAge = 7 * 24 * time.Hour

	failWindow    = 5 * time.Minute
	failLimit     = 5
	blockDuration = 5 * time.Minute
)

type KeyEntry struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Role string `json:"role"`
	Note string `json:"note"`
}

type ctxKey string

const (
	ctxKeyID ctxKey = "key_id"
	ctxRole  ctxKey = "role"
)

var (
	keyTable   map[string]*KeyEntry // key -> entry
	keyTableMu sync.RWMutex

	fails   = make(map[string]*failEntry)
	failsMu sync.Mutex
)

type failEntry struct {
	count        int
	firstAt      time.Time
	blockedUntil time.Time
}

func loadKeyTable() {
	b, err := os.ReadFile(keysPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("read keys.json (%s): %v", keysPath, err)
		}
		if err := ensureNoSNIMigration(); err != nil {
			keyTableMu.Lock()
			keyTable = map[string]*KeyEntry{}
			keyTableMu.Unlock()
			log.Print("！！！迁移未完成，暂停初始化管理员密钥")
			return
		}
		// First start — auto-generate admin key.
		key := generateKey()
		entry := KeyEntry{ID: "admin", Key: key, Role: "admin", Note: "管理员"}
		keyTableMu.Lock()
		keyTable = map[string]*KeyEntry{key: &entry}
		keyTableMu.Unlock()
		if err := saveKeyTable(); err != nil {
			log.Fatalf("save initial keys.json: %v", err)
		}
		log.Printf("========================================")
		log.Printf("首次启动，已自动生成管理员密钥：")
		log.Printf("  %s", key)
		log.Printf("请妥善保管，用于登录面板。")
		log.Printf("========================================")
		return
	}
	var entries []KeyEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		log.Fatalf("parse keys.json: %v", err)
	}
	if len(entries) == 0 {
		log.Fatalf("keys.json is empty")
	}
	keyTableMu.Lock()
	keyTable = make(map[string]*KeyEntry, len(entries))
	for i := range entries {
		e := &entries[i]
		if e.ID == "" || e.Key == "" || e.Role == "" {
			log.Fatalf("keys.json entry %d: id/key/role required", i)
		}
		if len(e.Key) < 12 {
			log.Fatalf("keys.json entry %q: key too short (%d chars); expected ≥12", e.ID, len(e.Key))
		}
		if _, dup := keyTable[e.Key]; dup {
			log.Fatalf("keys.json: duplicate key for id %q", e.ID)
		}
		keyTable[e.Key] = e
	}
	keyTableMu.Unlock()
	log.Printf("loaded %d keys from %s", len(entries), keysPath)
}

func lookupKey(key string) *KeyEntry {
	keyTableMu.RLock()
	defer keyTableMu.RUnlock()
	return keyTable[key]
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if blocked, until := isBlocked(ip); blocked {
		retry := int(time.Until(until).Seconds())
		if retry < 0 {
			retry = 0
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               "登录失败次数过多，请稍后再试",
			"retry_after_seconds": retry,
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	entry := lookupKey(body.Token)
	if entry != nil && tokenEq(body.Token, entry.Key) {
		resetFails(ip)
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    entry.Key,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(cookieMaxAge),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"key_id": entry.ID,
			"role":   entry.Role,
		})
		return
	}
	recordFail(ip)
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "密码错误"})
}

// logoutHandler 清除 HttpOnly 登录 Cookie（前端 JS 无法自行清除）。
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := extractAuthToken(r)
		entry := lookupKey(tok)
		if entry != nil && tokenEq(tok, entry.Key) {
			ctx := context.WithValue(r.Context(), ctxKeyID, entry.ID)
			ctx = context.WithValue(ctx, ctxRole, entry.Role)
			next(w, r.WithContext(ctx))
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未授权访问"})
	}
}

func authKeyID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyID).(string); ok {
		return v
	}
	return ""
}

func authRole(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRole).(string); ok {
		return v
	}
	return ""
}

func authIsAdmin(r *http.Request) bool {
	return authRole(r) == "admin"
}

func extractAuthToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

func isBlocked(ip string) (bool, time.Time) {
	failsMu.Lock()
	defer failsMu.Unlock()
	e, ok := fails[ip]
	if !ok {
		return false, time.Time{}
	}
	if !e.blockedUntil.IsZero() && time.Now().Before(e.blockedUntil) {
		return true, e.blockedUntil
	}
	return false, time.Time{}
}

func recordFail(ip string) {
	failsMu.Lock()
	defer failsMu.Unlock()
	e := fails[ip]
	if e == nil && len(fails) > maxFailEntries {
		// 限制 map 大小：清理窗口和封禁都已过期的条目
		now := time.Now()
		for k, v := range fails {
			if now.Sub(v.firstAt) > failWindow && now.After(v.blockedUntil) {
				delete(fails, k)
			}
		}
	}
	if e == nil || time.Since(e.firstAt) > failWindow {
		fails[ip] = &failEntry{count: 1, firstAt: time.Now()}
		return
	}
	e.count++
	if e.count >= failLimit {
		e.blockedUntil = time.Now().Add(blockDuration)
	}
}

func resetFails(ip string) {
	failsMu.Lock()
	defer failsMu.Unlock()
	delete(fails, ip)
}

// clientIP 优先使用 X-Real-IP（nginx 模板设为 $remote_addr），不再信任客户端可控的 X-Forwarded-For。
func clientIP(r *http.Request) string {
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

const maxFailEntries = 10000

var keyIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

func validKeyID(id string) bool { return keyIDRE.MatchString(id) }

// maskKey 只显示前 4 位，其余用 • 代替（密钥仅 12 位，不泄露尾部）。
func maskKey(k string) string {
	if len(k) <= 4 {
		return strings.Repeat("•", len(k))
	}
	return k[:4] + strings.Repeat("•", 8)
}

func tokenEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// --- key management ---

const keyChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateKey() string {
	b := make([]byte, 12)
	n := big.NewInt(int64(len(keyChars)))
	for i := range b {
		idx, _ := rand.Int(rand.Reader, n)
		b[i] = keyChars[idx.Int64()]
	}
	return string(b)
}

func saveKeyTable() error {
	keyTableMu.RLock()
	defer keyTableMu.RUnlock()
	return saveKeyTableLocked()
}

func addKey(id, role, note string) (*KeyEntry, error) {
	if id == "" || role == "" {
		return nil, &keyErr{"id 和 role 不能为空"}
	}
	if role != "admin" && role != "user" {
		return nil, &keyErr{"role 必须是 admin 或 user"}
	}
	if !validKeyID(id) {
		return nil, &keyErr{"密钥 ID 只能包含字母、数字、- 和 _，最长 32 位"}
	}
	keyTableMu.Lock()
	defer keyTableMu.Unlock()
	// Check duplicate id.
	for _, e := range keyTable {
		if e.ID == id {
			return nil, &keyErr{"密钥 ID 已存在: " + id}
		}
	}
	key := generateKey()
	entry := &KeyEntry{ID: id, Key: key, Role: role, Note: note}
	keyTable[key] = entry
	if err := saveKeyTableLocked(); err != nil {
		delete(keyTable, key)
		return nil, err
	}
	return entry, nil
}

func deleteKey(id string) error {
	keyTableMu.Lock()
	defer keyTableMu.Unlock()
	var target string
	for k, e := range keyTable {
		if e.ID == id {
			target = k
			break
		}
	}
	if target == "" {
		return &keyErr{"密钥不存在: " + id}
	}
	// Prevent deleting the last admin.
	if keyTable[target].Role == "admin" {
		adminCount := 0
		for _, e := range keyTable {
			if e.Role == "admin" {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return &keyErr{"不能删除最后一个管理员密钥"}
		}
	}
	delete(keyTable, target)
	return saveKeyTableLocked()
}

func listKeys() []KeyEntry {
	keyTableMu.RLock()
	defer keyTableMu.RUnlock()
	out := make([]KeyEntry, 0, len(keyTable))
	for _, e := range keyTable {
		out = append(out, KeyEntry{
			ID:   e.ID,
			Key:  maskKey(e.Key),
			Role: e.Role,
			Note: e.Note,
		})
	}
	return out
}

// saveKeyTableLocked saves without acquiring the mutex (caller must hold it).
func saveKeyTableLocked() error {
	entries := make([]KeyEntry, 0, len(keyTable))
	for _, e := range keyTable {
		entries = append(entries, *e)
	}
	dir := filepath.Dir(keysPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keys.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, keysPath)
}

type keyErr struct{ msg string }

func (e *keyErr) Error() string { return e.msg }
