package helps_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintHomeSparseOuter(t *testing.T) {
	const fallbackID = "a5d5c695-9e71-452f-8371-2003896e2146"
	const accountTwoID = "0e8bd008-02df-49ff-ab0e-f445c3c6e5b8"
	const oldExpiry = "2000-01-01T00:00:00Z"
	const newExpiry = "2099-01-01T00:00:00Z"
	tokenA := homeToken(t, "acc-team-1", "user-aaa", "team")
	tokenB := homeToken(t, "acc-team-1", "user-bbb", "team")
	for _, tc := range []struct {
		name, bearer, oldExpiryKey, newExpiryKey string
		fields                                   map[string]any
		account, token, member, plan, device     string
	}{
		{"omitted", "outer-A", "expired", "expired", nil, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"unchanged-account", "outer-A", "expired", "expired", map[string]any{"account_id": "acc-team-1"}, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"unchanged-token", "outer-A", "expired", "expired", map[string]any{"id_token": tokenA}, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"unchanged-member", "outer-A", "expired", "expired", map[string]any{"chatgpt_user_id": "user-aaa"}, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"unchanged-provenance", "outer-A", "expired", "expired", map[string]any{"plan_type_defaulted": false}, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"cleared", "outer-A", "expired", "expired", map[string]any{"account_id": nil, "id_token": "", "chatgpt_user_id": nil, "plan_type": nil}, "", "", "", "free", fallbackID},
		{"cleared-account", "outer-A", "expired", "expired", map[string]any{"account_id": nil}, "", "", "", "free", fallbackID},
		{"cleared-account-repeated-token", "outer-A", "expired", "expired", map[string]any{"account_id": nil, "id_token": tokenA}, "", "", "", "free", fallbackID},
		{"cleared-account-empty-repeated-token", "outer-A", "expired", "expired", map[string]any{"account_id": "", "id_token": tokenA}, "", "", "", "free", fallbackID},
		{"cleared-account-wrong-type-repeated-token", "outer-A", "expired", "expired", map[string]any{"account_id": true, "id_token": tokenA}, "", "", "", "free", fallbackID},
		{"changed-account", "outer-A", "expired", "expired", map[string]any{"account_id": "acc-team-2"}, "acc-team-2", "", "", "free", accountTwoID},
		{"changed-member", "outer-A", "expired", "expired", map[string]any{"id_token": tokenB}, "acc-team-1", tokenB, "user-bbb", "team", homeMemberB},
		{"changed-bearer-no-claims", "outer-B", "expired", "expired", nil, "", "", "", "free", fallbackID},
		{"rotated-on-disk", "disk-bearer", "expired", "expires_at", nil, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"new-expiry-alias", "outer-B", "expires_at", "expires_at", nil, "", "", "", "free", fallbackID},
		{"changed-expiry-spelling", "outer-B", "expired", "expires_at", nil, "", "", "", "free", fallbackID},
		{"canonical-replaces-alias", "outer-A", "expires_at", "expired", nil, "acc-team-1", tokenA, "user-aaa", "team", homeMemberA},
		{"expire-alias", "outer-B", "expired", "expire", nil, "", "", "", "free", fallbackID},
		{"camelcase-expiry-alias", "outer-B", "expired", "expiresAt", nil, "", "", "", "free", fallbackID},
		{"expiry-alias", "outer-B", "expired", "expiry", nil, "", "", "", "free", fallbackID},
		{"expires-alias", "outer-B", "expired", "expires", nil, "", "", "", "free", fallbackID},
	} {
		for _, mode := range []string{"off", "device"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				server, captures, _ := homeWireServer(t)
				cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
				initial := &cliproxyauth.Auth{ID: "sparse.json", FileName: "sparse.json", Provider: "codex",
					Metadata: map[string]any{"type": "codex", "access_token": "outer-A", "refresh_token": "refresh-A", "account_id": "acc-team-1",
						"id_token": tokenA, "chatgpt_user_id": "user-aaa", "chatgpt_plan_type": "team", "plan_type": "team", "plan_type_defaulted": false, tc.oldExpiryKey: oldExpiry}}
				manager := cliproxyauth.NewManager(nil, nil, nil)
				base, err := manager.Register(t.Context(), initial)
				if err != nil {
					t.Fatal(err)
				}
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				path, err := store.Save(t.Context(), base)
				if err != nil {
					t.Fatal(err)
				}
				reply := ojson.NewDocString(`{"auth":{"metadata":{}}}`)
				fields := map[string]any{"access_token": tc.bearer, tc.newExpiryKey: newExpiry}
				for k, v := range tc.fields {
					fields[k] = v
				}
				if err := reply.Set("auth.metadata", fields); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(tc.name, "cleared-account-") {
					stale := map[string]string{"account_id": "acc-team-1", "id_token": tokenA, "chatgpt_user_id": "user-aaa", "plan_type": "team", "chatgpt_plan_type": "team"}
					if errSet := reply.Set("auth.attributes", stale); errSet != nil {
						t.Fatal(errSet)
					}
				}
				if tc.name == "rotated-on-disk" {
					replacement := base.Clone()
					replacement.Metadata["access_token"] = tc.bearer
					delete(replacement.Metadata, tc.oldExpiryKey)
					replacement.Metadata[tc.newExpiryKey] = newExpiry
					if err := codexauth.WriteJSONFileAtomic(path, replacement.Metadata); err != nil {
						t.Fatal(err)
					}
				}
				helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) {
					if tc.name == "rotated-on-disk" {
						t.Fatal("refresh contacted Home after adopting a fresh credential from disk")
					}
					return reply.Bytes(), nil
				})
				check := func(stage string, a *cliproxyauth.Auth) {
					t.Helper()
					for key, want := range map[string]string{"access_token": tc.bearer, "account_id": tc.account, "id_token": tc.token, "chatgpt_user_id": tc.member, "plan_type": tc.plan, tc.newExpiryKey: newExpiry} {
						if got, _ := a.Metadata[key].(string); got != want {
							t.Errorf("%s: unexpected %s", stage, key)
						}
					}
					wantAlias := ""
					if tc.plan == "team" {
						wantAlias = "team"
					}
					if alias, _ := a.Metadata["chatgpt_plan_type"].(string); alias != wantAlias || a.Metadata["plan_type_defaulted"] != (tc.plan == "free") {
						t.Errorf("%s: incorrect plan alias or provenance", stage)
					}
					if tc.oldExpiryKey != tc.newExpiryKey {
						if _, stale := a.Metadata[tc.oldExpiryKey]; stale {
							t.Errorf("%s: stale expiry %s", stage, tc.oldExpiryKey)
						}
					}
					if _, exists, due := cliproxyauth.CodexOuterNeedsRefresh(a, time.Now()); !exists || due {
						t.Errorf("%s: renewed synthetic bearer still due", stage)
					}
				}
				warm := executor.NewCodexExecutor(cfg)
				base.Attributes["base_url"] = server.URL
				options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
				request := core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}
				if _, errExecute := warm.Execute(t.Context(), base, request, options); errExecute != nil {
					t.Fatal(errExecute)
				}
				<-captures
				refreshed, err := warm.Refresh(t.Context(), base.Clone())
				if err != nil {
					t.Fatal(err)
				}
				check("executor", refreshed)
				merged, err := manager.UpdateRefreshedAuth(t.Context(), base, refreshed)
				if err != nil {
					t.Fatal(err)
				}
				check("manager", merged)
				merged.Attributes["base_url"] = server.URL
				if _, errExecute := warm.Execute(t.Context(), merged, request, options); errExecute != nil {
					t.Fatal(errExecute)
				}
				warmWire := <-captures
				warmID := tc.device
				if mode == "off" {
					warmID = "client"
				}
				assertHomeWire(t, warmWire, warmID, tc.account, tc.bearer)
				if _, err := store.Save(t.Context(), merged); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var disk map[string]any
				if err := json.Unmarshal(raw, &disk); err != nil {
					t.Fatal(err)
				}
				check("file", &cliproxyauth.Auth{Metadata: disk})
				cold, err := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
				if err != nil || len(cold) != 1 {
					t.Fatalf("cold synthesis: %v, count %d", err, len(cold))
				}
				check("cold", cold[0])
				cold[0].Attributes["base_url"] = server.URL
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
				if _, err := executor.NewCodexAutoExecutor(cfg).Execute(t.Context(), cold[0], core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, opts); err != nil {
					t.Fatal(err)
				}
				wire := <-captures
				wantID := tc.device
				if mode == "off" {
					wantID = "client"
				}
				assertHomeWire(t, wire, wantID, tc.account, tc.bearer)
			})
		}
	}
}
