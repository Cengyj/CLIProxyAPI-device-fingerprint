package cliproxy

import (
	"fmt"
	"os"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintConfigFaultRecovery(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "device")
			h.loadAuth(serviceDeviceAuth())
			h.reload("device", true)
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
			current := h.service.currentConfig()
			executor, _ := h.service.coreManager.Executor("codex")
			last := h.run(ctx, body)
			assertServiceDevice(t, last, serviceDeviceID, serviceDeviceID)
			original, errRead := os.ReadFile(h.configPath)
			if errRead != nil {
				t.Fatal(errRead)
			}
			for _, fault := range []struct {
				name string
				raw  string
			}{
				{name: "empty"},
				{name: "truncated", raw: "oauth: {providers: {codex: {device-fingerprint-mode:"},
				{name: "wrong injection type", raw: "oauth: {providers: {codex: {device-fingerprint-mode: off, device-fingerprint-inject-missing: []}}}\n"},
				{name: "wrong mode type", raw: "oauth: {providers: {codex: {device-fingerprint-mode: []}}}\n"},
				{name: "missing"},
			} {
				t.Logf("config fault: %s", fault.name)
				if fault.name == "missing" {
					if errRemove := os.Remove(h.configPath); errRemove != nil {
						t.Fatal(errRemove)
					}
				} else if errWrite := os.WriteFile(h.configPath, []byte(fault.raw), 0o600); errWrite != nil {
					t.Fatal(errWrite)
				}
				h.watcher.ReloadConfigIfChanged()
				next, _ := h.service.coreManager.Executor("codex")
				if next != executor || h.service.currentConfig() != current {
					t.Fatal("incomplete or invalid config replaced the accepted runtime snapshot")
				}
				captured := h.run(ctx, body)
				assertServiceDevice(t, captured, serviceDeviceID, serviceDeviceID)
				if websocket && captured.connection != last.connection {
					t.Fatal("rejected config disturbed the accepted physical connection")
				}
				if errRestore := os.WriteFile(h.configPath, original, 0o600); errRestore != nil {
					t.Fatal(errRestore)
				}
				h.watcher.ReloadConfigIfChanged()
				if h.service.currentConfig() != current {
					t.Fatal("restoring identical accepted bytes caused a spurious config commit")
				}
			}
			h.reload("off", false)
			recovered := h.run(ctx, body)
			assertServiceDevice(t, recovered, "client-device", "client-device")
			if websocket && recovered.connection == last.connection {
				t.Fatal("valid recovery did not apply the disabled policy on a new handshake")
			}
			h.reload("device", true)
			assertServiceDevice(t, h.run(ctx, `{"input":[]}`), serviceDeviceID, serviceDeviceID)
		})
	}
}

func TestCodexDeviceFingerprintStoppedWatcherKeepsRuntime(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "device")
			h.loadAuth(serviceDeviceAuth())
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
			before := h.run(ctx, body)
			assertServiceDevice(t, before, serviceDeviceID, serviceDeviceID)
			current := h.service.currentConfig()
			executor, _ := h.service.coreManager.Executor("codex")
			if errStop := h.watcher.Stop(); errStop != nil {
				t.Fatal(errStop)
			}
			// The harness cleanup must not close the same fsnotify backend twice.
			h.watcher.stop = nil
			next := current.CloneForRuntime()
			next.Codex.DeviceFingerprintMode = "off"
			if errSave := internalconfig.SaveConfigPreserveComments(h.configPath, next, true); errSave != nil {
				t.Fatal(errSave)
			}
			h.watcher.ReloadConfigIfChanged()
			afterExecutor, _ := h.service.coreManager.Executor("codex")
			if current != h.service.currentConfig() || executor != afterExecutor {
				t.Fatal("stopped watcher rebuilt the active runtime")
			}
			after := h.run(ctx, body)
			assertServiceDevice(t, after, serviceDeviceID, serviceDeviceID)
			if websocket && before.connection != after.connection {
				t.Fatal("stopped watcher replaced the active physical connection")
			}
		})
	}
}
