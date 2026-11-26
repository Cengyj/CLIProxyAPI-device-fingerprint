package diff

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestCodexDeviceFingerprintConfigDiff(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: " DeViCe ", DeviceFingerprintInjectMissing: new(false)}}
	changes := strings.Join(BuildConfigChangeDetails(oldCfg, newCfg), "\n")
	for _, want := range []string{
		"oauth.providers.codex.device-fingerprint-mode: off -> device",
		"oauth.providers.codex.device-fingerprint-inject-missing: inherit -> false",
	} {
		if !strings.Contains(changes, want) {
			t.Fatalf("missing %q in %q", want, changes)
		}
	}
	oldCfg = newCfg.CloneForRuntime()
	newCfg.Codex.DeviceFingerprintMode = "off"
	newCfg.Codex.DeviceFingerprintInjectMissing = new(true)
	changes = strings.Join(BuildConfigChangeDetails(oldCfg, newCfg), "\n")
	if !strings.Contains(changes, "device-fingerprint-mode: device -> off") || !strings.Contains(changes, "device-fingerprint-inject-missing: false -> true") {
		t.Fatalf("mode/injection reload changes missing: %q", changes)
	}
	if got := BuildConfigChangeDetails(newCfg, newCfg.CloneForRuntime()); len(got) != 0 {
		t.Fatalf("identical snapshot reported changes: %v", got)
	}
}

func TestCodexDeviceFingerprintConfigDiffRedactsUnknownMode(t *testing.T) {
	oldCfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	newCfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "secret-account-or-token\ninjected log"}}
	changes := strings.Join(BuildConfigChangeDetails(oldCfg, newCfg), "\n")
	if !strings.Contains(changes, "device-fingerprint-mode: device -> off (invalid)") || strings.Contains(changes, "secret-account") || strings.Contains(changes, "injected log") {
		t.Fatalf("unknown mode must be visible without logging its contents: %q", changes)
	}
}
