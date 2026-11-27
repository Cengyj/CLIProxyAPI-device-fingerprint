package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestConfigReloadDoesNotApplyAfterStop(t *testing.T) {
	for _, duringLoad := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-stop", true: "in-flight-load"}[duringLoad], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := fmt.Sprintf("oauth: {auth-dir: %q, providers: {codex: {device-fingerprint-mode: device}}}\n", filepath.ToSlash(dir))
			if errWrite := os.WriteFile(path, []byte(raw), 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			var callbacks atomic.Int32
			w, errNew := NewWatcher(path, dir, func(*config.Config) { callbacks.Add(1) })
			if errNew != nil {
				t.Fatal(errNew)
			}
			initial := &config.Config{AuthDir: dir}
			initial.Codex.DeviceFingerprintMode = "off"
			w.SetConfig(initial)
			stop := sync.OnceFunc(func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			})
			t.Cleanup(stop)

			if duringLoad {
				originalLoad := loadConfigFileFunc
				entered := make(chan struct{})
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				done := make(chan struct{})
				loadConfigFileFunc = func(string) (*config.Config, error) {
					close(entered)
					<-release
					updated := initial.CloneForRuntime()
					updated.Codex.DeviceFingerprintMode = "device"
					return updated, nil
				}
				t.Cleanup(func() {
					unblock()
					<-done
					loadConfigFileFunc = originalLoad
				})
				go func() {
					defer close(done)
					w.ReloadConfigIfChanged()
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("reload did not reach the blocked config loader")
				}
				stop()
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("stopped reload did not finish")
				}
			} else {
				stop()
				w.ReloadConfigIfChanged()
			}
			w.scheduleConfigReload()
			w.configReloadMu.Lock()
			hasTimer := w.configReloadTimer != nil
			w.configReloadMu.Unlock()
			if hasTimer {
				t.Error("stopped watcher accepted another config reload timer")
			}
			if callbacks.Load() != 0 {
				t.Errorf("stopped watcher applied %d config callbacks", callbacks.Load())
			}
			w.clientsMutex.RLock()
			mode := w.config.Codex.DeviceFingerprintMode
			hash := w.lastConfigHash
			w.clientsMutex.RUnlock()
			if mode != "off" || hash != "" {
				t.Errorf("stopped watcher committed a new policy: mode=%q, hash=%q", mode, hash)
			}
		})
	}
}

func TestConfigReloadSkipsStoppedRescanCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := fmt.Sprintf("oauth: {auth-dir: %q, providers: {codex: {device-fingerprint-mode: device}}}\n", filepath.ToSlash(dir))
	if errWrite := os.WriteFile(path, []byte(raw), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	authPath := filepath.Join(dir, "synthetic.json")
	if errWrite := os.WriteFile(authPath, []byte(`{"type":"codex","access_token":"synthetic-access"}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	parser := &blockingAuthDirSwitchParser{blockPath: authPath, entered: make(chan struct{}), release: make(chan struct{})}
	var callbacks atomic.Int32
	w, errNew := NewWatcher(path, dir, func(*config.Config) { callbacks.Add(1) })
	if errNew != nil {
		t.Fatal(errNew)
	}
	w.SetPluginAuthParser(parser)
	stop := sync.OnceFunc(func() {
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	})
	t.Cleanup(stop)
	done := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(parser.release) })
	t.Cleanup(func() {
		unblock()
		<-done
	})
	go func() {
		defer close(done)
		w.ReloadConfigIfChanged()
	}()
	select {
	case <-parser.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("config reload did not reach the auth rescan")
	}
	stop()
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stopped rescan did not return")
	}
	if callbacks.Load() != 0 {
		t.Errorf("stopped rescan applied %d config callbacks", callbacks.Load())
	}
	w.clientsMutex.RLock()
	hash := w.lastConfigHash
	w.clientsMutex.RUnlock()
	if hash != "" {
		t.Error("stopped rescan recorded a config that was never applied")
	}
}
