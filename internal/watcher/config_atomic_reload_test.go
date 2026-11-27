package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestCodexDeviceFingerprintConfigAtomicReload(t *testing.T) {
	for _, sharedDirectory := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-directory=%t", sharedDirectory), func(t *testing.T) {
			dir := t.TempDir()
			authDir := dir
			if !sharedDirectory {
				authDir = filepath.Join(dir, "auths")
				if errMkdir := os.Mkdir(authDir, 0o700); errMkdir != nil {
					t.Fatal(errMkdir)
				}
			}
			path := filepath.Join(dir, "config.yaml")
			writeConfig := func(mode string, atomic bool) {
				t.Helper()
				raw := fmt.Sprintf("server: {port: 8317, server-id: 11111111-2222-4333-8444-555555555555}\noauth:\n  auth-dir: %q\n  providers: {codex: {device-fingerprint-mode: %q}}\n", filepath.ToSlash(authDir), mode)
				target := path
				if atomic {
					target += ".next"
				}
				if errWrite := os.WriteFile(target, []byte(raw), 0o600); errWrite != nil {
					t.Fatal(errWrite)
				}
				if atomic {
					if errRename := os.Rename(target, path); errRename != nil {
						t.Fatal(errRename)
					}
				}
			}
			writeConfig("off", false)
			initial, errLoad := config.LoadConfig(path)
			if errLoad != nil {
				t.Fatal(errLoad)
			}
			reloaded := make(chan *config.Config, 16)
			w, errNew := NewWatcher(path, authDir, func(cfg *config.Config) { reloaded <- cfg })
			if errNew != nil {
				t.Fatal(errNew)
			}
			t.Cleanup(func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			})
			w.SetConfig(initial)
			if errStart := w.Start(t.Context()); errStart != nil {
				t.Fatal(errStart)
			}
			awaitMode := func(mode string) {
				t.Helper()
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				for {
					select {
					case cfg := <-reloaded:
						if cfg.Codex.DeviceFingerprintMode == mode {
							return
						}
					case <-deadline.C:
						t.Fatalf("fsnotify did not apply mode %q after config replacement", mode)
					}
				}
			}
			awaitMode("off")
			for _, mode := range []string{"device", "off", " DeViCe ", ""} {
				writeConfig(mode, true)
				awaitMode(mode)
			}
			// Changing an auth directory must not remove the shared config watch.
			if sharedDirectory {
				authDir = filepath.Join(dir, "next-auths")
				if errMkdir := os.Mkdir(authDir, 0o700); errMkdir != nil {
					t.Fatal(errMkdir)
				}
				writeConfig("off", true)
				awaitMode("off")
			}
			writeConfig("device", true)
			awaitMode("device")
			writeConfig("off", false)
			awaitMode("off")
		})
	}
}
