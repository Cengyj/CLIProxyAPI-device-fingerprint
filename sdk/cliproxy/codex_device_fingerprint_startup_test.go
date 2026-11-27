package cliproxy

import (
	"fmt"
	"os"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintConfigChangeBeforeWatcherStart(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(fmt.Sprint(websocket), func(t *testing.T) {
			h := newServiceDeviceHarness(t, false, "off")
			h.loadAuth(serviceDeviceAuth())
			ctx := t.Context()
			if websocket {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
			assertServiceDevice(t, h.run(ctx, body), "client-device", "client-device")
			// Service.Run accepts HTTP before it starts the watcher. A valid
			// operator save in that interval produces no subscribed file event.
			next := h.service.currentConfig().CloneForRuntime()
			next.Codex.DeviceFingerprintMode = "device"
			if errSave := internalconfig.SaveConfigPreserveComments(h.configPath, next, true); errSave != nil {
				t.Fatal(errSave)
			}
			// Replace the inode as container config bind mounts commonly do.
			written, errRead := os.ReadFile(h.configPath)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if errWrite := os.WriteFile(h.configPath+".next", written, 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			if errRename := os.Rename(h.configPath+".next", h.configPath); errRename != nil {
				t.Fatal(errRename)
			}
			if errStart := h.watcher.Start(t.Context()); errStart != nil {
				t.Fatal(errStart)
			}
			if got := h.service.currentConfig().Codex.DeviceFingerprintMode; got != "device" {
				t.Errorf("watcher startup missed accepted file policy: %q", got)
			}
			assertServiceDevice(t, h.run(ctx, body), serviceDeviceID, serviceDeviceID)
		})
	}
}
