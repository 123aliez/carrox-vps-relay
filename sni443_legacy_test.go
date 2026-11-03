package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSNIMigrationPreservesLegacyStreams(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable-disable", true: "recover"}[interrupt], func(t *testing.T) {
			h := newMigrationHarness(t)
			legacy := filepath.Join(h.ops.paths.stream, "relay-tcp-24443.conf")
			data := []byte("# 历史配置保持字节及权限\nserver { listen 24443; proxy_pass 198.51.100.7:443; }\n")
			for _, suffix := range []string{"", tcpDeleteSuffix} {
				putTestFile(t, legacy+suffix, data)
				if err := os.Chmod(legacy+suffix, 0640); err != nil {
					t.Fatal(err)
				}
			}
			assertLegacy := func() {
				t.Helper()
				for _, suffix := range []string{"", tcpDeleteSuffix} {
					requireBytes(t, readTestFile(t, legacy+suffix), data)
					if info, err := os.Stat(legacy + suffix); err != nil || info.Mode().Perm() != 0640 {
						t.Fatal("历史配置权限被修改", err)
					}
				}
			}
			if interrupt {
				write := h.ops.fs.write
				h.ops.fs.write = func(path string, data []byte, mode os.FileMode) error {
					if err := write(path, data, mode); err != nil {
						return err
					}
					if path == h.ops.paths.marker() {
						panic("模拟被杀")
					}
					return nil
				}
				sixthInterrupt(t, func() { _ = migrateSNI443("enable", h.ops, io.Discard) })
				h.ops.fs.write = write
				assertLegacy()
				if err := migrateSNI443("recover", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := migrateSNI443("enable", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
				assertLegacy()
				if err := migrateSNI443("disable", h.ops, io.Discard); err != nil {
					t.Fatal(err)
				}
			}
			assertLegacy()
		})
	}
}

func TestSNIMigrationRejectsLegacyReservedListenersWithoutWrites(t *testing.T) {
	for _, port := range []int{443, 8443, 30000, 30001, 30500, 30999} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			h := newMigrationHarness(t)
			path := filepath.Join(h.ops.paths.stream, fmt.Sprintf("relay-tcp-%d.conf", port))
			putTestFile(t, path, []byte(fmt.Sprintf("server { listen [::]:%d; proxy_pass 198.51.100.7:443; }\n", port)))
			before := configTree(t, h.ops.paths, true)
			var output bytes.Buffer
			if err := migrateSNI443("enable", h.ops, &output); err == nil || !strings.Contains(err.Error(), "保留端口") {
				t.Fatal("历史配置占用保留端口时应拒绝迁移", err)
			}
			if !reflect.DeepEqual(before, configTree(t, h.ops.paths, true)) || h.checks != 0 || h.reloads != 0 {
				t.Fatal("迁移前置检查失败不得改写文件或重载")
			}
		})
	}
}
