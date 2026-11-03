package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 检查、重载、核验、时间、渲染和全部文件操作均可替换。
type sniMigrationOps struct {
	fs            relayFS
	paths         sniPaths
	portFree      func(int) bool
	check, reload func() error
	commit        func() error
	verify        func(bool, []string) error
	now           func() time.Time
	renderSite    func(SiteMeta, bool) ([]byte, error)
	renderPanel   func(string, bool) ([]byte, error)
}

func liveSNIMigrationOps() sniMigrationOps {
	p := liveSNIPaths()
	return sniMigrationOps{
		fs: liveRelayFS(), paths: p, portFree: func(port int) bool {
			ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return false
			}
			_ = ln.Close()
			return true
		}, check: nginxSyntaxCheck, reload: nginxReload, commit: commitNginxMutation, verify: verifySNI443, now: time.Now,
		renderSite:  func(m SiteMeta, on bool) ([]byte, error) { return renderSiteMode(m, p.templates, on) },
		renderPanel: func(d string, on bool) ([]byte, error) { return renderPanel(d, p.templates, on) },
	}
}

// 只识别指令开头的 listen，正确跳过注释并保留引号内的 #。
func listensOn(conf []byte, port string) bool {
	tokens := nginxTokens(conf)
	start := true
	for i, token := range tokens {
		if token == ";" || token == "{" || token == "}" {
			start = true
			continue
		}
		if start && token == "listen" && i+1 < len(tokens) {
			address := tokens[i+1]
			if address == port || strings.HasSuffix(address, ":"+port) {
				return true
			}
		}
		start = false
	}
	return false
}

// 只检查 listen 的参数，避免注释或其他指令中的同名文本造成误报。
func hasDefaultServer(conf []byte) bool {
	start, listen := true, false
	for _, token := range nginxTokens(conf) {
		if token == ";" || token == "{" || token == "}" {
			start, listen = true, false
			continue
		}
		if start {
			listen = token == "listen"
		} else if listen && token == "default_server" {
			return true
		}
		start = false
	}
	return false
}

func reservedStreamListener(conf []byte) bool {
	tokens := nginxTokens(conf)
	start := true
	for i, token := range tokens {
		if token == ";" || token == "{" || token == "}" {
			start = true
			continue
		}
		if start && token == "listen" && i+1 < len(tokens) {
			address := tokens[i+1]
			if index := strings.LastIndex(address, ":"); index >= 0 {
				address = address[index+1:]
			}
			port, _ := strconv.Atoi(address)
			if port == 443 || port == 8443 || (port >= realityPortMin && port <= realityPortMax) {
				return true
			}
		}
		start = false
	}
	return false
}

func cleanupSNIMapDir(p sniPaths, fs relayFS) error {
	dir := filepath.Dir(p.derived()[0])
	entries, err := fs.entries(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fs.remove(dir)
	}
	return nil
}

func nginxTokens(conf []byte) []string {
	var tokens []string
	var token strings.Builder
	var quote byte
	flush := func() {
		if token.Len() > 0 {
			tokens = append(tokens, token.String())
			token.Reset()
		}
	}
	for i := 0; i < len(conf); i++ {
		ch := conf[i]
		if ch == '\\' && i+1 < len(conf) {
			i++
			token.WriteByte(conf[i])
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				token.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '#':
			flush()
			for i < len(conf) && conf[i] != '\n' {
				i++
			}
		case ' ', '\t', '\r', '\n':
			flush()
		case ';', '{', '}':
			flush()
			tokens = append(tokens, string(ch))
		default:
			token.WriteByte(ch)
		}
	}
	flush()
	return tokens
}

type sniSnapshot struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Mode    os.FileMode `json:"mode"`
	Data    []byte      `json:"-"`
}

func migrateSNI443(action string, ops sniMigrationOps, out io.Writer) error {
	pending, err := latestPendingMigration(ops.paths, ops.fs)
	if err != nil {
		return err
	}
	if action == "recover" {
		return recoverSNI443(pending, ops, out)
	}
	if pending != "" && action != "status" {
		return migrationRecoveryError()
	}
	on, err := sniMode(ops.paths, ops.fs)
	if err != nil {
		return err
	}
	if action == "status" && pending != "" {
		fmt.Fprintf(out, "警告：迁移尚未完成（%s），请先执行 vps-relay sni443 recover\n", pending)
	}
	if action == "enable" && on {
		fmt.Fprintln(out, "已处于目标模式，无需迁移")
		return nil
	}
	files, err := managedSNIFiles(ops.paths, ops.fs)
	if err != nil {
		return err
	}
	count := 0
	for _, f := range files {
		if f.meta.Reality != nil {
			count++
		}
	}
	if action == "status" {
		mode := "普通 HTTPS"
		if on {
			mode = "443 SNI 分流"
		}
		fmt.Fprintf(out, "当前模式：%s；Reality 入口：%d 个\n", mode, count)
		return nil
	}
	if action != "enable" && action != "disable" {
		return errors.New("用法：vps-relay sni443 enable|disable|status|recover")
	}
	target := action == "enable"
	if !target && count > 0 {
		return errors.New("存在 Reality 入口（含停用或待删除），请先全部删除")
	}
	if on == target {
		fmt.Fprintln(out, "已处于目标模式，无需迁移")
		return nil
	}
	if target {
		binary, err := ops.fs.read(ops.paths.binary)
		if err != nil {
			return fmt.Errorf("读取宿主 Nginx 失败: %w", err)
		}
		if !bytes.Contains(binary, []byte("ssl_preread")) {
			return errors.New("宿主 Nginx 缺少 ssl_preread，请先更换二进制")
		}
		conf, err := ops.fs.read(ops.paths.nginxConf)
		if err != nil {
			return err
		}
		if !streamEnabled(conf) {
			return errors.New("nginx.conf 尚未引入 stream.d/*.conf")
		}
		if !ops.portFree(8443) {
			return errors.New("127.0.0.1:8443 已被占用")
		}
		streamFiles, err := ops.fs.entries(ops.paths.stream)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, file := range streamFiles {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".conf") {
				continue
			}
			data, err := ops.fs.read(filepath.Join(ops.paths.stream, file.Name()))
			if err != nil {
				return err
			}
			if reservedStreamListener(data) {
				return fmt.Errorf("stream 配置 %s 占用 443 或内部保留端口，未改动任何文件", file.Name())
			}
		}
		entries, err := ops.fs.entries(ops.paths.conf)
		if err != nil {
			return err
		}
		managed := map[string]bool{}
		for _, f := range files {
			managed[f.path] = true
		}
		for _, e := range entries {
			path := filepath.Join(ops.paths.conf, e.Name())
			if e.IsDir() || (!strings.HasSuffix(e.Name(), ".conf") && !managed[path]) {
				continue
			}
			data, err := ops.fs.read(path)
			if err != nil {
				return err
			}
			if hasDefaultServer(data) {
				return fmt.Errorf("配置 %s 已有 default_server，未改动任何文件", e.Name())
			}
			if e.Name() == sniDefaultName {
				return errors.New("默认站点文件已存在，请先核对，未改动任何文件")
			}
			if managed[path] || e.Name() == "relay-panel.conf" {
				continue
			}
			if listensOn(data, "443") {
				return fmt.Errorf("非托管配置 %s 仍监听 443，未改动任何文件", e.Name())
			}
		}
	}
	// 先计算所有新内容，渲染失败时不产生备份或其他文件。
	changes := map[string][]byte{}
	modes := map[string]os.FileMode{}
	originals := map[string]sniSnapshot{}
	if !target {
		originals, err = originalSNIFiles(ops.paths, ops.fs)
		if err != nil {
			return err
		}
	}
	domains := map[string]bool{}
	for _, f := range files {
		data, err := ops.renderSite(f.meta, target)
		if err != nil {
			return err
		}
		changes[f.path] = data
		if !target {
			if original, ok := originals[f.path]; ok {
				var meta SiteMeta
				match := metaRE.FindSubmatch(original.Data)
				if len(match) > 1 && json.Unmarshal(match[1], &meta) == nil && mustJSON(meta) == mustJSON(f.meta) {
					changes[f.path], modes[f.path] = original.Data, original.Mode
				}
			}
		}
		if f.enabled {
			domains[f.meta.Domain] = true
		}
	}
	panelPath := filepath.Join(ops.paths.conf, "relay-panel.conf")
	panel, err := ops.fs.read(panelPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && ((target && listensOn(panel, "443")) || (!target && listensOn(panel, "8443"))) {
		domain := panelCertDomain(panel)
		if validateDomain(domain) != nil {
			return errors.New("无法从 HTTPS 面板配置读取证书域名")
		}
		data, err := ops.renderPanel(domain, target)
		if err != nil {
			return err
		}
		changes[panelPath] = data
		if !target {
			if original, ok := originals[panelPath]; ok && panelCertDomain(original.Data) == domain && listensOn(original.Data, "443") {
				changes[panelPath], modes[panelPath] = original.Data, original.Mode
			}
		}
		domains[domain] = true
	}
	if target {
		changes[ops.paths.defaultSite()] = []byte(sniDefaultConfig)
		changes[ops.paths.marker()] = []byte(sni443Config)
		data, err := renderSNIDerived(nil)
		if err != nil {
			return err
		}
		for i, path := range ops.paths.derived() {
			changes[path] = data[i]
		}
	} else {
		changes[ops.paths.defaultSite()] = nil
		changes[ops.paths.marker()] = nil
		for _, path := range ops.paths.derived() {
			changes[path] = nil
		}
	}
	paths := make([]string, 0, len(changes))
	for path := range changes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	// 开启时最后写模式标记，关闭时最先移除；中间状态由持久化记录封锁。
	marker := ops.paths.marker()
	ordered := make([]string, 0, len(paths))
	if !target {
		ordered = append(ordered, marker)
	}
	for _, path := range paths {
		if path != marker {
			ordered = append(ordered, path)
		}
	}
	if target {
		ordered = append(ordered, marker)
	}
	paths = ordered
	snapshots := make([]sniSnapshot, 0, len(paths))
	for _, path := range paths {
		s := sniSnapshot{Path: path}
		data, err := ops.fs.read(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			info, err := ops.fs.stat(path)
			if err != nil {
				return err
			}
			s.Existed = true
			s.Data = data
			s.Mode = info.Mode().Perm()
		}
		snapshots = append(snapshots, s)
	}
	backup := filepath.Join(ops.paths.backup, "sni443-"+ops.now().UTC().Format("20060102T150405.000000000Z"))
	if _, err := ops.fs.stat(backup); err == nil {
		return errors.New("备份目录已存在")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ops.fs.mkdir(backup, 0700); err != nil {
		return err
	}
	for _, s := range snapshots {
		if !s.Existed {
			continue
		}
		path := filepath.Join(backup, "files", strings.TrimPrefix(s.Path, string(filepath.Separator)))
		if err := ops.fs.mkdir(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := ops.fs.write(path, s.Data, 0600); err != nil {
			return err
		}
	}
	record := sniManifest{State: "in-progress", Direction: action, PreviousSNI: on, Files: snapshots}
	dir := sniDirectory{Path: filepath.Dir(ops.paths.derived()[0])}
	if info, err := ops.fs.stat(dir.Path); err == nil {
		dir.Existed, dir.Mode = true, info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	record.Directories = []sniDirectory{dir}
	for _, snapshot := range snapshots {
		if !snapshot.Existed {
			record.Created = append(record.Created, snapshot.Path)
		}
	}
	for domain := range domains {
		record.Domains = append(record.Domains, domain)
	}
	sort.Strings(record.Domains)
	if err := writeSNIManifest(backup, record, ops.fs); err != nil {
		return err
	}
	fmt.Fprintf(out, "备份：%s\n", backup)
	names := make([]string, 0, len(domains))
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)
	check := func() error {
		if err := syncSNI443With(ops.paths, ops.fs); err != nil {
			return err
		}
		return ops.check()
	}
	reload := func() error {
		if err := syncSNI443With(ops.paths, ops.fs); err != nil {
			return err
		}
		return ops.reload()
	}
	rollback := func(cause error) error {
		if restoreErr := recoverSNI443(backup, ops, out); restoreErr != nil {
			fmt.Fprintln(out, "迁移失败；旧配置恢复或核验失败，请先执行 recover")
			return errors.Join(cause, fmt.Errorf("回退失败: %w", restoreErr))
		}
		fmt.Fprintln(out, "迁移失败；已还原原文件并重载，旧模式核验通过")
		return cause
	}
	for _, path := range paths {
		data := changes[path]
		if data == nil {
			err := ops.fs.remove(path)
			if err != nil && !os.IsNotExist(err) {
				return rollback(err)
			}
		} else if mode, ok := modes[path]; ok {
			if err := ops.fs.write(path, data, mode); err != nil {
				return rollback(err)
			}
		} else if err := writeSNIChanged(ops.fs, path, data); err != nil {
			return rollback(err)
		}
	}
	if !target {
		if err := cleanupSNIMapDir(ops.paths, ops.fs); err != nil {
			return rollback(err)
		}
	}
	if err := check(); err != nil {
		return rollback(fmt.Errorf("配置检查失败: %w", err))
	}
	if err := reload(); err != nil {
		return rollback(fmt.Errorf("重载失败: %w", err))
	}
	if err := ops.verify(target, names); err != nil {
		return rollback(fmt.Errorf("核验失败: %w", err))
	}
	// 核验通过后先结束通用日志，再提交迁移清单，避免两份恢复记录相互撤销。
	if ops.commit != nil {
		if err := ops.commit(); err != nil {
			return rollback(err)
		}
	}
	record.State = "done"
	if err := writeSNIManifest(backup, record, ops.fs); err != nil {
		return rollback(err)
	}
	fmt.Fprintln(out, "迁移完成，配置检查、重载及 TLS 核验通过")
	return nil
}

// 未在 SNI 期间修改元数据的站点回退原始字节和权限；新建或编辑的站点保留当前数据。
func originalSNIFiles(p sniPaths, fs relayFS) (map[string]sniSnapshot, error) {
	out := map[string]sniSnapshot{}
	entries, err := fs.entries(p.backup)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() || !strings.HasPrefix(entries[i].Name(), "sni443-") {
			continue
		}
		root := filepath.Join(p.backup, entries[i].Name())
		data, err := fs.read(filepath.Join(root, "manifest.json"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var record sniManifest
		if json.Unmarshal(data, &record) != nil || record.State != "done" || record.Direction != "enable" {
			continue
		}
		for _, file := range record.Files {
			if !file.Existed {
				continue
			}
			file.Data, err = fs.read(filepath.Join(root, "files", strings.TrimPrefix(file.Path, "/")))
			if err != nil {
				return nil, err
			}
			out[file.Path] = file
		}
		break
	}
	return out, nil
}

// 核验叶子证书域名；不依赖本机 CA 链，但绝不省略 VerifyHostname。
func verifySNI443(on bool, domains []string) error {
	deadline := time.Now().Add(15 * time.Second)
	dial := func(timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("tcp", "127.0.0.1:443", timeout)
	}
	var last error
	for time.Now().Before(deadline) {
		last = nil
		if on && !tcpDial("127.0.0.1:8443", min(time.Second, time.Until(deadline))) {
			last = errors.New("本机 8443 不可达")
		}
		for _, domain := range domains {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				last = errors.New("TLS 核验超时")
				break
			}
			if err := verifySNIHandshake(domain, false, min(time.Second, remaining), dial); err != nil {
				last = err
				break
			}
		}
		if on && last == nil {
			for _, domain := range []string{"", "unknown.invalid"} {
				if err := verifySNIHandshake(domain, true, min(time.Second, time.Until(deadline)), dial); err != nil {
					last = err
					break
				}
			}
		}
		if last == nil {
			return nil
		}
		if remaining := time.Until(deadline); remaining > 0 {
			time.Sleep(min(200*time.Millisecond, remaining))
		}
	}
	return last
}

// 显式创建 TLS 客户端，空 ServerName 确保不带 SNI；连接失败或超时不算握手拒绝。
func verifySNIHandshake(domain string, reject bool, timeout time.Duration, dial func(time.Duration) (net.Conn, error)) error {
	if timeout <= 0 {
		return errors.New("TLS 核验超时")
	}
	deadline := time.Now().Add(timeout)
	raw, err := dial(timeout)
	if err != nil {
		return errors.New("本机 443 不可达，无法核验 TLS")
	}
	defer raw.Close()
	if err := raw.SetDeadline(deadline); err != nil {
		return err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
	err = conn.Handshake()
	if reject {
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			return fmt.Errorf("无 SNI 或未知域名 %q 的 TLS 握手未被拒绝", domain)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s 的 TLS 证书核验失败", domain)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 || certs[0].VerifyHostname(domain) != nil {
		return fmt.Errorf("%s 的 TLS 证书核验失败", domain)
	}
	return nil
}

// 备份写完后才发布进度记录，恢复只依赖记录及磁盘备份，不依赖当前混合配置。
type sniManifest struct {
	State       string         `json:"state"`
	Direction   string         `json:"direction"`
	PreviousSNI bool           `json:"previous_sni"`
	Files       []sniSnapshot  `json:"files"`
	Created     []string       `json:"created"`
	Domains     []string       `json:"domains"`
	Directories []sniDirectory `json:"directories,omitempty"`
}

type sniDirectory struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Mode    os.FileMode `json:"mode"`
}

func migrationRecoveryError() error {
	return errors.New("存在未完成的 443 迁移，请先执行 vps-relay sni443 recover")
}
func writeSNIManifest(backup string, record sniManifest, fs relayFS) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return fs.write(filepath.Join(backup, "manifest.json"), append(data, '\n'), 0600)
}
func latestPendingMigration(p sniPaths, fs relayFS) (string, error) {
	entries, err := fs.entries(p.backup)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var pending []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "sni443-") {
			continue
		}
		path := filepath.Join(p.backup, entry.Name())
		data, err := fs.read(filepath.Join(path, "manifest.json"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		var record sniManifest
		if json.Unmarshal(data, &record) != nil {
			return "", errors.New("迁移进度记录损坏，请检查备份")
		}
		if record.State == "in-progress" {
			pending = append(pending, path)
		}
	}
	sort.Strings(pending)
	if len(pending) == 0 {
		return "", nil
	}
	return pending[len(pending)-1], nil
}
func ensureNoSNIMigration() error {
	pending, err := latestPendingMigration(liveSNIPaths(), liveRelayFS())
	if err != nil {
		return err
	}
	if pending != "" {
		return migrationRecoveryError()
	}
	return nil
}
func recoverSNI443(backup string, ops sniMigrationOps, out io.Writer) error {
	if backup == "" {
		fmt.Fprintln(out, "没有待恢复的迁移")
		return nil
	}
	data, err := ops.fs.read(filepath.Join(backup, "manifest.json"))
	if err != nil {
		return err
	}
	var record sniManifest
	if json.Unmarshal(data, &record) != nil || record.State != "in-progress" {
		return errors.New("无效的迁移恢复记录")
	}
	// 先读齐所有原文件；备份缺失时绝不开始部分恢复。
	for i := range record.Files {
		snapshot := &record.Files[i]
		if snapshot.Existed {
			snapshot.Data, err = ops.fs.read(filepath.Join(backup, "files", strings.TrimPrefix(snapshot.Path, string(filepath.Separator))))
			if err != nil {
				return err
			}
		}
	}
	for _, dir := range record.Directories {
		if dir.Existed {
			if err := ops.fs.mkdir(dir.Path, dir.Mode); err != nil {
				return err
			}
			if err := ops.fs.chmod(dir.Path, dir.Mode); err != nil {
				return err
			}
		}
	}
	for _, snapshot := range record.Files {
		if snapshot.Existed {
			if err := ops.fs.mkdir(filepath.Dir(snapshot.Path), 0755); err != nil {
				return err
			}
			if err := ops.fs.write(snapshot.Path, snapshot.Data, snapshot.Mode); err != nil {
				return err
			}
		} else if err := ops.fs.remove(snapshot.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, dir := range record.Directories {
		if !dir.Existed {
			if err := cleanupSNIMapDir(ops.paths, ops.fs); err != nil {
				return err
			}
		}
	}
	if err := ops.check(); err != nil {
		return err
	}
	if err := ops.reload(); err != nil {
		return err
	}
	if err := ops.verify(record.PreviousSNI, record.Domains); err != nil {
		return err
	}
	if ops.commit != nil {
		if err := ops.commit(); err != nil {
			return err
		}
	}
	record.State = "recovered"
	if err := writeSNIManifest(backup, record, ops.fs); err != nil {
		return err
	}
	fmt.Fprintln(out, "已还原原文件并重载，旧模式核验通过，迁移记录已标记 recovered")
	return nil
}
