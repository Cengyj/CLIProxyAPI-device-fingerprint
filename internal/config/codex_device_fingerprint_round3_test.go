package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexDeviceFingerprintConfigClearModeOnSave(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		migrate bool
	}{
		{"legacy", "port: 8317\ncodex: {device-fingerprint-mode: device}\n", false},
		{"legacy-migrate", "port: 8317\ncodex: {device-fingerprint-mode: device}\n", true},
		{"v8", "server: {port: 8317}\noauth: {providers: {codex: {device-fingerprint-mode: device}}}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Codex.ResponseSteering = true
			for _, mode := range []string{"", "device", " ", " DeViCe ", "off", "device", "unknown", ""} {
				cfg.Codex.DeviceFingerprintMode = mode
				if err := SaveConfigPreserveComments(path, cfg, tc.migrate); err != nil {
					t.Fatal(err)
				}
				reloaded, err := LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				if reloaded.Codex.DeviceFingerprintMode != mode {
					t.Fatalf("saved mode = %q, want %q", reloaded.Codex.DeviceFingerprintMode, mode)
				}
				if !reloaded.Codex.ResponseSteering {
					t.Fatal("clearing device mode changed another Codex option")
				}
				cfg = reloaded
			}
		})
	}
}
