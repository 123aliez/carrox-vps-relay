package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// 日志覆盖持锁操作的当前可回退阶段；正常完成或越过不可回头点前显式结束。
// 边界之后的写入重新取安全快照，残留日志一律恢复当前阶段的快照。
type nginxPending struct {
	Restoring bool          `json:"restoring,omitempty"`
	Roots     []string      `json:"roots,omitempty"`
	Files     []nginxBefore `json:"files,omitempty"`
}

type nginxBefore struct {
	Path string      `json:"path"`
	Data []byte      `json:"data"`
	Mode os.FileMode `json:"mode"`
}

func nginxPendingPath() string {
	return filepath.Join(filepath.Dir(sniBackupDir), "nginx-pending.json")
}
func beginNginxMutation() error {
	if op := activeNginxOperation.Load(); op != nil {
		op.consistent.Store(false)
	}
	return beginNginxMutationAt(nginxPendingPath(), []string{confDir, streamDir})
}

func beginNginxMutationAt(path string, roots []string) error {
	if raw, err := os.ReadFile(path); err == nil {
		_, err := parseNginxPending(raw)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	files, err := nginxMutationFiles(roots)
	if err != nil {
		return err
	}
	record := nginxPending{Roots: roots}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		info, err := os.Stat(file)
		if err != nil {
			return err
		}
		record.Files = append(record.Files, nginxBefore{file, data, info.Mode().Perm()})
	}
	return saveNginxPending(path, record)
}

func nginxMutationFiles(roots []string) ([]string, error) {
	var files []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if strings.HasPrefix(e.Name(), ".") {
				if e.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if e.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".conf.disabled") || strings.HasSuffix(path, ".bak") || strings.HasSuffix(path, ".map") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func saveNginxPending(path string, record nginxPending) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}

// 空快照必须仍声明根目录；损坏记录不能被当成可恢复日志。
func parseNginxPending(raw []byte) (nginxPending, error) {
	var record nginxPending
	var fields map[string]json.RawMessage
	bad := func() (nginxPending, error) { return record, fmt.Errorf("配置事务记录损坏，已保留现场") }
	if json.Unmarshal(raw, &record) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return bad()
	}
	for key, value := range fields {
		if key != "restoring" && key != "roots" && key != "files" {
			return bad()
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad()
		}
	}
	if len(record.Roots) == 0 {
		return bad()
	}
	for _, root := range record.Roots {
		if !filepath.IsAbs(root) {
			return bad()
		}
	}
	for _, file := range record.Files {
		owned := false
		for _, root := range record.Roots {
			rel, err := filepath.Rel(root, file.Path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "." {
				owned = true
			}
		}
		if !filepath.IsAbs(file.Path) || !owned {
			return bad()
		}
	}
	return record, nil
}

// 同一操作的后续写入和备份清理沿用首次快照，不开启新的操作。
func mutateNginxFile(change func() error) error {
	if err := beginNginxMutation(); err != nil {
		return err
	}
	return change()
}
func writeNginxFile(path string, data []byte, mode os.FileMode) error {
	return mutateNginxFile(func() error { return atomicWrite(path, data, mode) })
}
func renameNginxFile(from, to string) error {
	return mutateNginxFile(func() error { return os.Rename(from, to) })
}
func removeNginxFile(path string) error {
	return mutateNginxFile(func() error { return os.Remove(path) })
}
func copyNginxFile(from, to string) error {
	return mutateNginxFile(func() error { return copyFile(from, to) })
}

func finishNginxMutation() error { return finishNginxMutationAt(nginxPendingPath()) }
func finishNginxMutationAt(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// 证书恢复始终执行；只有继承真实锁且父日志已存在时，才借用而不恢复父日志。
func recoverBeforeNginxOperation(inherited bool, reload, prepare func() error) (bool, error) {
	raw, err := os.ReadFile(nginxPendingPath())
	borrowed := inherited && err == nil
	if err == nil {
		if _, err := parseNginxPending(raw); err != nil {
			return false, err
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := recoverACMETransactions(sniBackupDir, reload, prepare); err != nil {
		return false, err
	}
	if !borrowed {
		if err := reconcileNginxWith(nginxPendingPath(), reload); err != nil {
			return false, err
		}
	}
	return borrowed, nil
}

// 一次持锁操作默认未完成；受控子进程可以借用父日志，但不能删除它。
type nginxOperation struct {
	consistent atomic.Bool
	borrowed   bool
}

var activeNginxOperation atomic.Pointer[nginxOperation]

func startNginxOperation(borrowed bool) *nginxOperation {
	op := &nginxOperation{borrowed: borrowed}
	activeNginxOperation.Store(op)
	return op
}
func markNginxConsistent() {
	if op := activeNginxOperation.Load(); op != nil {
		op.consistent.Store(true)
	}
}

// 不可回头的副作用发生前立即结束日志；失败则禁止继续执行副作用。
// 受控证书子事务也必须结束借用的父日志，避免证书提交后恢复旧活动配置。
// 后续配置写入会以此刻的安全现场重新取快照，不能复用越过边界前的日志。
func commitNginxMutation() error {
	markNginxConsistent()
	if err := finishNginxMutation(); err != nil {
		if op := activeNginxOperation.Load(); op != nil {
			op.consistent.Store(false)
		}
		return fmt.Errorf("无法结束配置操作日志，未继续执行不可回退操作: %w", err)
	}
	return nil
}

func (op *nginxOperation) finish() error {
	if !op.borrowed && op.consistent.Load() {
		return finishNginxMutation()
	}
	return nil
}
func (op *nginxOperation) close() {
	if err := op.finish(); err != nil {
		log.Print("配置操作日志清理失败，保留日志供恢复")
	}
	activeNginxOperation.CompareAndSwap(op, nil)
}

func reconcileNginxWith(path string, reload func() error) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	record, err := parseNginxPending(raw)
	if err != nil {
		return err
	}
	if !record.Restoring {
		record.Restoring = true
		if err := saveNginxPending(path, record); err != nil {
			return err
		}
	}
	if err := restoreNginxPending(record); err != nil {
		return err
	}
	if err := reload(); err != nil {
		return err
	}
	return finishNginxMutationAt(path)
}

func restoreNginxPending(record nginxPending) error {
	old := map[string]bool{}
	for _, file := range record.Files {
		old[file.Path] = true
	}
	current, err := nginxMutationFiles(record.Roots)
	if err != nil {
		return err
	}
	for _, path := range current {
		if !old[path] {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	for _, file := range record.Files {
		if err := os.MkdirAll(filepath.Dir(file.Path), 0755); err != nil {
			return err
		}
		if err := atomicWrite(file.Path, file.Data, file.Mode); err != nil {
			return err
		}
	}
	return nil
}
