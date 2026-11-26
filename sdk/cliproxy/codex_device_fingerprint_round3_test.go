package cliproxy

import (
	"fmt"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintServiceClearModeOnSave(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "device")
			auth := serviceDeviceAuth()
			h.loadAuth(auth)
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
			for _, mode := range []string{"", " ", "off", "unknown"} {
				before := h.run(ctx, body)
				assertServiceDevice(t, before, serviceDeviceID, serviceDeviceID)
				cfg := h.service.currentConfig().CloneForRuntime()
				cfg.Codex.DeviceFingerprintMode = mode
				if errSave := internalconfig.SaveConfigPreserveComments(h.configPath, cfg, true); errSave != nil {
					t.Fatal(errSave)
				}
				h.watcher.ReloadConfigIfChanged()
				after := h.run(ctx, body)
				assertServiceDevice(t, after, "client-device", "client-device")
				if websocket && before.connection == after.connection {
					t.Fatal("disabled mode retained an enabled physical handshake")
				}
				h.reload("device", false)
			}
			if errSet := auth.Set("codex_device_fingerprint", "off"); errSet != nil {
				t.Fatal(errSet)
			}
			h.loadAuth(auth)
			assertServiceDevice(t, h.run(ctx, body), "client-device", "client-device")
			h.reload("", false)
			if errSet := auth.Set("codex_device_fingerprint", "device"); errSet != nil {
				t.Fatal(errSet)
			}
			h.loadAuth(auth)
			assertServiceDevice(t, h.run(ctx, body), serviceDeviceID, serviceDeviceID)
		})
	}
}

func TestCodexDeviceFingerprintServiceRemoveAuthOverrides(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "off")
			auth := serviceDeviceAuth()
			if errSet := auth.Set("codex_device_fingerprint", "device"); errSet != nil {
				t.Fatal(errSet)
			}
			h.loadAuth(auth)
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
			assertServiceDevice(t, h.run(ctx, body), serviceDeviceID, serviceDeviceID)
			if errDelete := auth.Delete("codex_device_fingerprint"); errDelete != nil {
				t.Fatal(errDelete)
			}
			h.loadAuth(auth)
			assertServiceDevice(t, h.run(ctx, body), "client-device", "client-device")
			if errSet := auth.Set("codex_device_fingerprint", "device"); errSet != nil {
				t.Fatal(errSet)
			}
			if errDelete := auth.Delete("codex_installation_id"); errDelete != nil {
				t.Fatal(errDelete)
			}
			h.loadAuth(auth)
			const derivedID = "e1e46a26-def3-4e3e-9ee2-185e59ed0444"
			assertServiceDevice(t, h.run(ctx, body), derivedID, derivedID)
			if errDelete := auth.Delete("codex_device_fingerprint"); errDelete != nil {
				t.Fatal(errDelete)
			}
			h.loadAuth(auth)
			assertServiceDevice(t, h.run(ctx, body), "client-device", "client-device")
		})
	}
}
