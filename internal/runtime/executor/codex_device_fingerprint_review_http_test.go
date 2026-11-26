package executor

import (
	"net/http"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintDirectImageInheritedAttempt(t *testing.T) {
	for _, siwc := range []bool{false, true} {
		name := "oauth"
		if siwc {
			name = "siwc"
		}
		t.Run(name, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			ctx := helps.WithCodexDevicePolicy(t.Context(), helps.CodexDevicePolicy{Enabled: true, ID: fingerprintHTTPID, SIWC: siwc})
			opts := codexOpenAIImageTestOptions(codexImagesGenerationsPath, false)
			opts.Headers = http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"direct-original","turn_id":"unchanged"}`}}
			req := core.Request{Model: "gpt-image-2", Payload: []byte(`{"model":"gpt-image-2","prompt":"draw"}`)}
			fingerprintRunHTTP(t, ctx, NewCodexExecutor(cfg), fingerprintHTTPAuth(server.URL), req, opts, false)
			got := <-captured
			if got.path != "/images/generations" {
				t.Fatalf("not a direct image route: %s", got.path)
			}
			if ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "direct-original" {
				t.Fatal("an inherited Responses policy changed the excluded direct-image headers")
			}
		})
	}
}
