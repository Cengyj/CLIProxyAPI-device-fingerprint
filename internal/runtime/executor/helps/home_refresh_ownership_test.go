package helps_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintHomeRefreshRejectsForeignRecord(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		for _, tc := range []struct {
			name, id, provider, fileType string
			disabled                     bool
		}{
			{name: "record", id: "b.json", provider: "codex"},
			{name: "provider", id: "a.json", provider: "claude"},
			{name: "stored-provider", id: "a.json", fileType: "claude"},
			{name: "disabled-foreign-record", id: "b.json", provider: "codex", disabled: true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				server, received, _ := homeWireServer(t)
				cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
				auto := executor.NewCodexAutoExecutor(cfg)
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				manager := cliproxyauth.NewManager(store, nil, nil)
				manager.RegisterExecutor(auto)
				readFile := func(id string) []byte {
					t.Helper()
					raw, errRead := os.ReadFile(filepath.Join(cfg.AuthDir, id))
					if errRead != nil {
						t.Fatal(errRead)
					}
					return raw
				}
				register := func(name string) *cliproxyauth.Auth {
					t.Helper()
					id := name + ".json"
					auth, errRegister := manager.Register(t.Context(), &cliproxyauth.Auth{
						ID: id, Index: name, FileName: id, Provider: "codex",
						Metadata: map[string]any{
							"type": "codex", "account_id": "account-" + name, "access_token": "bearer-" + name,
							"refresh_token": "refresh-" + name, "expired": "2000-01-01T00:00:00Z",
							"siwc": map[string]any{"access_token": "siwc-" + name, "refresh_token": "nested-" + name,
								"client_id": "client", "device_id": homeExplicit, "expired": "2000-01-01T00:00:00Z"},
						},
					})
					if errRegister != nil {
						t.Fatal(errRegister)
					}
					return auth
				}
				a, b := register("a"), register("b")
				beforeA, beforeB := readFile(a.ID), readFile(b.ID)
				doc := ojson.NewDocString(`{"auth_index":"reassigned-index","auth":{"metadata":{"access_token":"other-bearer","refresh_token":"other-refresh","account_id":"other-account","siwc":{"access_token":"other-nested","refresh_token":"other-nested-refresh"}}}}`)
				if errSet := doc.Set("auth.id", tc.id); errSet != nil {
					t.Fatal(errSet)
				}
				if errSet := doc.Set("auth.provider", tc.provider); errSet != nil {
					t.Fatal(errSet)
				}
				if tc.fileType != "" {
					if errSet := doc.Set("auth.metadata.type", tc.fileType); errSet != nil {
						t.Fatal(errSet)
					}
				}
				if tc.disabled {
					if errSet := doc.Set("auth.disabled", true); errSet != nil {
						t.Fatal(errSet)
					}
				}
				var homeCalls, renewalCalls atomic.Int32
				helps.SetHomeRefreshForTest(t, func(_ context.Context, index, _ string) ([]byte, error) {
					homeCalls.Add(1)
					if index != a.Index {
						t.Error("Home request used a different record")
					}
					return doc.Bytes(), nil
				})
				renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					renewalCalls.Add(1)
					_, _ = w.Write([]byte(`{"access_token":"renewed","refresh_token":"renewed-refresh","expires_in":7200}`))
				}))
				t.Cleanup(renewal.Close)
				t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))

				assertRejected := func(updated *cliproxyauth.Auth, err error) {
					t.Helper()
					var status interface{ StatusCode() int }
					if updated != nil || !errors.As(err, &status) || status.StatusCode() != http.StatusBadGateway {
						t.Errorf("expected a nil result and HTTP 502 for foreign credentials, got result=%t err=%v", updated != nil, err)
					}
				}
				input := a.Clone()
				assertRejected(auto.Refresh(t.Context(), input))
				if !reflect.DeepEqual(input, a) {
					t.Error("foreign refresh changed the caller's auth")
				}
				assertRejected(manager.ForceRefreshAuth(t.Context(), a.ID))
				if homeCalls.Load() != 2 || renewalCalls.Load() != 0 {
					t.Errorf("Home calls=%d, SIWC renewals=%d", homeCalls.Load(), renewalCalls.Load())
				}
				for _, previous := range []*cliproxyauth.Auth{a, b} {
					current, exists := manager.GetByID(previous.ID)
					if !exists || current.Provider != previous.Provider || current.Index != previous.Index || !reflect.DeepEqual(current.Metadata, previous.Metadata) {
						t.Errorf("manager changed credentials for %s", previous.ID)
					}
					if previous == b && !reflect.DeepEqual(current, b) {
						t.Error("foreign refresh changed the other manager record")
					}
				}
				raw := readFile(a.ID)
				if !bytes.Equal(raw, beforeA) || !bytes.Equal(readFile(b.ID), beforeB) {
					t.Error("foreign refresh rewrote a credential file")
				}
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, filepath.Join(cfg.AuthDir, a.ID), raw)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("reload: %v, count=%d", errLoad, len(loaded))
				}
				cold := loaded[0]
				if cold.ID != a.ID || cold.Metadata["account_id"] != "account-a" || cold.Metadata["access_token"] != "bearer-a" || !reflect.DeepEqual(cold.Metadata["siwc"], a.Metadata["siwc"]) {
					t.Error("cold credentials differ from the original")
				}
				cold.Attributes["base_url"] = server.URL
				if _, errExecute := executor.NewCodexAutoExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}); errExecute != nil {
					t.Fatal(errExecute)
				}
				wire := <-received
				if wire.headers.Get("Authorization") != "Bearer bearer-a" || wire.headers.Get("ChatGPT-Account-ID") != "account-a" {
					t.Error("cold HTTP request sent foreign credentials")
				}
			})
		}
	}
}

func TestHomeRefreshClaudeRejectsUnknownAuth(t *testing.T) {
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	for _, tc := range []struct{ name, raw string }{
		{"only-index", `{"auth_index":"different"}`},
		{"only-diagnostic", `{"diagnostic":"no auth"}`},
		{"unknown-envelope", `{"auth":{"misspelled_credential":true}}`},
		{"empty-metadata", `{"auth":{"metadata":{},"attributes":{}}}`},
		{"nested-only-index", `{"auth":{"auth_index":"different"}}`},
		{"null-envelope-with-outer-auth-fields", `{"auth":null,"provider":"claude","metadata":{"access_token":"unexpected"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return []byte(tc.raw), nil })
			auth := &cliproxyauth.Auth{ID: "claude-a", Index: "requested", Provider: "claude", Metadata: map[string]any{"access_token": "original"}}
			updated, errRefresh := executor.NewClaudeExecutor(cfg).Refresh(t.Context(), auth)
			var status interface{ StatusCode() int }
			if updated != nil || !errors.As(errRefresh, &status) || status.StatusCode() != http.StatusBadGateway {
				t.Errorf("expected an invalid Home response, got result=%t err=%v", updated != nil, errRefresh)
			}
			if auth.Index != "requested" || auth.Metadata["access_token"] != "original" {
				t.Error("invalid Home response changed the input")
			}
		})
	}
}

func TestHomeRefreshClaudeResponseCompatibility(t *testing.T) {
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	for _, tc := range []struct {
		name, raw, wantIndex string
		status               int
	}{
		{name: "legacy", raw: `{"id":"claude-a","provider":"claude","metadata":{"access_token":"renewed"}}`, wantIndex: "requested"},
		{name: "envelope", raw: `{"auth":{"id":"claude-a","provider":"claude","metadata":{"access_token":"renewed"}},"auth_index":"updated"}`, wantIndex: "updated"},
		{name: "disabled", raw: `{"auth":{"disabled":true}}`, status: http.StatusUnauthorized},
		{name: "disabled-status", raw: `{"status":"disabled"}`, status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return []byte(tc.raw), nil })
			auth := &cliproxyauth.Auth{ID: "claude-a", Index: "requested", Provider: "claude", Metadata: map[string]any{"access_token": "original"}}
			updated, errRefresh := executor.NewClaudeExecutor(cfg).Refresh(t.Context(), auth)
			if tc.status != 0 {
				var status interface{ StatusCode() int }
				if updated != nil || !errors.As(errRefresh, &status) || status.StatusCode() != tc.status {
					t.Fatalf("disabled record result=%t err=%v", updated != nil, errRefresh)
				}
			} else if errRefresh != nil || updated == nil || updated.Metadata["access_token"] != "renewed" || updated.Index != tc.wantIndex || updated.ID != auth.ID || updated.Provider != auth.Provider {
				t.Fatalf("valid Claude response result=%t err=%v", updated != nil, errRefresh)
			}
			if auth.Index != "requested" || auth.Metadata["access_token"] != "original" {
				t.Error("Home response changed the original Claude credential")
			}
		})
	}
	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cancellation.Error(), func(t *testing.T) {
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return nil, cancellation })
			updated, errRefresh := executor.NewClaudeExecutor(cfg).Refresh(t.Context(), &cliproxyauth.Auth{ID: "claude-a", Index: "requested", Provider: "claude"})
			if updated != nil || !errors.Is(errRefresh, cancellation) {
				t.Fatalf("cancellation was not preserved: %v", errRefresh)
			}
		})
	}
	t.Run("upstream-error", func(t *testing.T) {
		const upstreamBody = "first line\r\nsecond line\n"
		doc := ojson.NewDocString(`{"error":{"type":"refresh_temporarily_unavailable","upstream":{"status":429}}}`)
		if errSet := doc.Set("error.upstream.body", base64.StdEncoding.EncodeToString([]byte(upstreamBody))); errSet != nil {
			t.Fatal(errSet)
		}
		helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return doc.Bytes(), nil })
		updated, errRefresh := executor.NewClaudeExecutor(cfg).Refresh(t.Context(), &cliproxyauth.Auth{ID: "claude-a", Index: "requested", Provider: "claude"})
		var direct interface {
			StatusCode() int
			DirectResponse() bool
			ResponseBody() []byte
		}
		if updated != nil || !errors.As(errRefresh, &direct) || direct.StatusCode() != http.StatusTooManyRequests || !direct.DirectResponse() || string(direct.ResponseBody()) != upstreamBody || errRefresh.Error() != upstreamBody {
			t.Fatalf("upstream error was not preserved: %v", errRefresh)
		}
	})
}

func TestHomeRefreshPluginCredentialFormats(t *testing.T) {
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	plugin := pluginhost.NewPluginRefreshCompatExecutor(executor.NewOpenAICompatExecutor("custom", cfg), nil, cfg)
	for _, tc := range []struct{ name, raw, wantIndex string }{
		{"legacy", `{"metadata":{"custom_lease":{"key":"renewed"}}}`, "old-index"},
		{"envelope", `{"auth":{"metadata":{"custom_lease":{"key":"renewed"}}},"auth_index":"new-index"}`, "new-index"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return []byte(tc.raw), nil })
			auth := &cliproxyauth.Auth{ID: "plugin-a", Index: "old-index", Provider: "custom"}
			updated, errRefresh := plugin.Refresh(t.Context(), auth)
			if errRefresh != nil || updated == nil {
				t.Fatalf("plugin refresh failed: %v", errRefresh)
			}
			lease, _ := updated.Metadata["custom_lease"].(map[string]any)
			if lease["key"] != "renewed" || updated.Index != tc.wantIndex {
				t.Error("plugin credential or returned index was lost")
			}
		})
	}
}
