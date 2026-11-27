package cliproxy

import (
	"fmt"
	"os"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"gopkg.in/yaml.v3"
)

func TestCodexDeviceFingerprintServiceInjectionRemoval(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "device")
			h.loadAuth(serviceDeviceAuth())
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			for _, inject := range []*bool{new(true), nil, new(false), new(true)} {
				before := h.service.currentConfig()
				previous, _ := h.service.coreManager.Executor("codex")
				cfg := before.CloneForRuntime()
				cfg.Codex.DeviceFingerprintInjectMissing = inject
				if errSave := internalconfig.SaveConfigPreserveComments(h.configPath, cfg, true); errSave != nil {
					t.Fatal(errSave)
				}
				h.watcher.ReloadConfigIfChanged()
				current := h.service.currentConfig()
				next, ok := h.service.coreManager.Executor("codex")
				if !ok || next == previous || current == before {
					t.Fatal("injection update did not replace the runtime configuration and executor")
				}
				assertInjection := func(label string, got *bool) {
					t.Helper()
					if (got == nil) != (inject == nil) || (got != nil && *got != *inject) {
						t.Fatalf("%s lost the optional injection value", label)
					}
				}
				assertInjection("runtime", current.Codex.DeviceFingerprintInjectMissing)
				saved, errRead := os.ReadFile(h.configPath)
				if errRead != nil {
					t.Fatal(errRead)
				}
				loaded, errParse := internalconfig.ParseConfigBytes(saved)
				if errParse != nil {
					t.Fatal(errParse)
				}
				assertInjection("disk", loaded.Codex.DeviceFingerprintInjectMissing)
				snapshot, errSnapshot := yaml.Marshal(current)
				if errSnapshot != nil {
					t.Fatal(errSnapshot)
				}
				restored, errRestore := internalconfig.ParseConfigBytes(snapshot)
				if errRestore != nil {
					t.Fatal(errRestore)
				}
				assertInjection("snapshot", restored.Codex.DeviceFingerprintInjectMissing)
				if apiConfig := current.ForAPIKey(); apiConfig.Codex.DeviceFingerprintMode != "" || apiConfig.Codex.DeviceFingerprintInjectMissing != nil {
					t.Fatal("injection update escaped the OAuth configuration scope")
				}
				want := ""
				if inject != nil && *inject {
					want = serviceDeviceID
				}
				assertServiceDevice(t, h.run(ctx, `{"input":[]}`), want, serviceDeviceID)
				assertServiceDevice(t, h.run(ctx, `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`), serviceDeviceID, serviceDeviceID)
			}
		})
	}
}
