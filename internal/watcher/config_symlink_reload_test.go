//go:build unix

package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestCodexDeviceFingerprintConfigSymlinkAtomicReload(t *testing.T) {
	for _, sharedAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-auth=%t", sharedAuth), func(t *testing.T) {
			testConfigSymlinkAtomicReload(t, sharedAuth)
		})
	}
}

func testConfigSymlinkAtomicReload(t *testing.T, sharedAuth bool) {
	targetDir, aliasDir, authDir := t.TempDir(), t.TempDir(), t.TempDir()
	if sharedAuth {
		authDir = targetDir
	}
	target := filepath.Join(targetDir, "actual.yaml")
	alias := filepath.Join(aliasDir, "config.yaml")
	write := func(mode string) {
		t.Helper()
		raw := fmt.Sprintf("server: {port: 8317, server-id: 11111111-2222-4333-8444-555555555555}\noauth:\n  auth-dir: %q\n  providers: {codex: {device-fingerprint-mode: %q}}\n", filepath.ToSlash(authDir), mode)
		if errWrite := os.WriteFile(target+".next", []byte(raw), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		if errRename := os.Rename(target+".next", target); errRename != nil {
			t.Fatal(errRename)
		}
	}
	write("off")
	if errLink := os.Symlink(target, alias); errLink != nil {
		t.Fatal(errLink)
	}
	initial, errLoad := config.LoadConfig(alias)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	reloaded := make(chan string, 16)
	w, errNew := NewWatcher(alias, authDir, func(cfg *config.Config) { reloaded <- cfg.Codex.DeviceFingerprintMode })
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
	await := func(mode string) {
		t.Helper()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case actual := <-reloaded:
				if actual == mode {
					return
				}
			case <-timer.C:
				t.Fatalf("config symlink did not apply %q after target atomic replacement", mode)
			}
		}
	}
	await("off")
	for _, mode := range []string{"device", "off", "device"} {
		write(mode)
		await(mode)
	}
	// Move the alias to identical bytes: the content hash must not prevent
	// following the new directory, and old target directories must be released.
	oldDir := targetDir
	newDir := t.TempDir()
	raw, errRead := os.ReadFile(target)
	if errRead != nil {
		t.Fatal(errRead)
	}
	target = filepath.Join(newDir, "actual.yaml")
	if errWrite := os.WriteFile(target, raw, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errLink := os.Symlink(target, alias+".next"); errLink != nil {
		t.Fatal(errLink)
	}
	if errRename := os.Rename(alias+".next", alias); errRename != nil {
		t.Fatal(errRename)
	}
	// Synchronize the unchanged-content reload without depending on a timer.
	w.ReloadConfigIfChanged()
	oldTargetWatched := false
	for _, watched := range w.watcher.WatchList() {
		resolved, errResolve := filepath.EvalSymlinks(watched)
		oldResolved, errOld := filepath.EvalSymlinks(oldDir)
		if errResolve == nil && errOld == nil && resolved == oldResolved {
			oldTargetWatched = true
		}
	}
	if oldTargetWatched != sharedAuth {
		t.Fatalf("old target watch retained=%t, shared auth directory=%t", oldTargetWatched, sharedAuth)
	}
	write("off")
	await("off")
	write("device")
	await("device")
}

func TestCodexDeviceFingerprintConfigProjectedSymlinkReload(t *testing.T) {
	dir, authDir := t.TempDir(), t.TempDir()
	alias := filepath.Join(dir, "config.yaml")
	dataLink := filepath.Join(dir, "..data")
	writeVersion := func(version, mode string) string {
		t.Helper()
		targetDir := filepath.Join(dir, version)
		if errMkdir := os.Mkdir(targetDir, 0o700); errMkdir != nil {
			t.Fatal(errMkdir)
		}
		raw := fmt.Sprintf("server: {port: 8317, server-id: 11111111-2222-4333-8444-555555555555}\noauth:\n  auth-dir: %q\n  providers: {codex: {device-fingerprint-mode: %q}}\n", filepath.ToSlash(authDir), mode)
		if errWrite := os.WriteFile(filepath.Join(targetDir, "config.yaml"), []byte(raw), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		return targetDir
	}
	first := writeVersion("version-1", "off")
	if errLink := os.Symlink(first, dataLink); errLink != nil {
		t.Fatal(errLink)
	}
	if errLink := os.Symlink(filepath.Join("..data", "config.yaml"), alias); errLink != nil {
		t.Fatal(errLink)
	}
	initial, errLoad := config.LoadConfig(alias)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	reloaded := make(chan string, 16)
	w, errNew := NewWatcher(alias, authDir, func(cfg *config.Config) { reloaded <- cfg.Codex.DeviceFingerprintMode })
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
	if got := <-reloaded; got != "off" {
		t.Fatalf("initial mode = %q", got)
	}
	for i, mode := range []string{"device", "off", "device"} {
		next := writeVersion(fmt.Sprintf("version-%d", i+2), mode)
		if errLink := os.Symlink(next, dataLink+".next"); errLink != nil {
			t.Fatal(errLink)
		}
		if errRename := os.Rename(dataLink+".next", dataLink); errRename != nil {
			t.Fatal(errRename)
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case got := <-reloaded:
			timer.Stop()
			if got != mode {
				t.Fatalf("mode = %q, want %q", got, mode)
			}
		case <-timer.C:
			t.Fatalf("projected config symlink did not apply %q", mode)
		}
	}
}
