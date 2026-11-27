package helps_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexSIWCRefreshReceiptKeepsCurrentDevice(t *testing.T) {
	const nextDevice = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	for _, file := range []bool{false, true} {
		name := "memory"
		if file {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, file, "2000-01-01T00:00:00Z", true)
			cfg.Home.Enabled = false
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			delete(base.Metadata, "refresh_token")
			var err error
			base, err = manager.Update(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			if file {
				if err = codexauth.WriteJSONFileAtomic(path, base.Metadata); err != nil {
					t.Fatal(err)
				}
			}
			var calls atomic.Int32
			grant := base.Metadata["siwc"].(map[string]any)["refresh_token"].(string)
			renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Get("refresh_token") != grant {
					t.Error("wrong grant submitted to local SIWC endpoint")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"receipt-access","refresh_token":"receipt-grant","expires_in":7200}`))
			}))
			t.Cleanup(renewal.Close)
			t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
			// A successful exchange was journaled before its result reached this
			// credential. The current file then received a newer device setting.
			first, err := codexauth.NewCodexAuth(cfg).RefreshSIWCTokens(t.Context(), grant, "oaiapp_test", homeExplicit)
			if err != nil || first.DeviceID != homeExplicit {
				t.Fatalf("initial exchange: %v", err)
			}
			current := base.Clone()
			current.Metadata["siwc"].(map[string]any)["device_id"] = nextDevice
			current, err = manager.Update(t.Context(), current)
			if err != nil {
				t.Fatal(err)
			}
			if file {
				if err = codexauth.WriteJSONFileAtomic(path, current.Metadata); err != nil {
					t.Fatal(err)
				}
			}
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), current)
			if err != nil {
				t.Fatal(err)
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, current, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				nested := candidate.Metadata["siwc"].(map[string]any)
				if nested["device_id"] != nextDevice {
					t.Errorf("%s recovered the first caller's device instead of the current setting", stage)
				}
				if nested["access_token"] != "receipt-access" || nested["refresh_token"] != "receipt-grant" {
					t.Errorf("%s lost recovered credentials", stage)
				}
			})
			server, frames, _ := homeWireServer(t)
			cold.Attributes["base_url"] = server.URL
			if _, err = executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}); err != nil {
				t.Fatal(err)
			}
			assertHomeWire(t, <-frames, nextDevice, "", "receipt-access")
			if calls.Load() != 1 || first.DeviceID != homeExplicit {
				t.Errorf("receipt recovery replayed or mutated original result: calls=%d", calls.Load())
			}
		})
	}
}
