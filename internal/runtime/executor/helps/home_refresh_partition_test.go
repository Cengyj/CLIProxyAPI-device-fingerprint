package helps_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintHomeRefreshPartitions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		raw         string
		siwc, outer bool
	}{
		{name: "empty-object", raw: `{}`},
		{name: "null", raw: `null`},
		{name: "null-envelope", raw: `{"auth":null}`},
		{name: "empty-envelope", raw: `{"auth":{}}`},
		{name: "identity-only", raw: `{"auth":{"metadata":{"account_id":"acc-other"}}}`},
		{name: "siwc-only", raw: `{"auth":{"metadata":{"siwc":{"access_token":"siwc-new","refresh_token":"siwc-refresh-new","client_id":"client","device_id":"11111111-2222-4333-8444-555555555555","expired":"2099-01-01T00:00:00Z"}}}}`, siwc: true},
		{name: "same-siwc-bearer-new-expiry", raw: `{"auth":{"metadata":{"siwc":{"access_token":"siwc-old","refresh_token":"siwc-refresh","client_id":"client","device_id":"11111111-2222-4333-8444-555555555555","expired":"2100-01-01T00:00:00Z"}}}}`, siwc: true},
		{name: "same-outer-bearer", outer: true},
	} {
		for _, mode := range []string{"off", "device"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				server, captures, _ := homeWireServer(t)
				cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
				auth := &cliproxyauth.Auth{ID: "partition.json", FileName: "partition.json", Index: "partition", Provider: "codex", Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{
					"type": "codex", "access_token": "outer-old", "refresh_token": "outer-refresh", "account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-aaa", "team"), "chatgpt_user_id": "user-aaa", "chatgpt_plan_type": "team", "plan_type": "team", "plan_type_defaulted": false, "expired": "2099-01-01T00:00:00Z", "operator_note": "keep",
					"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-refresh", "client_id": "client", "device_id": homeExplicit, "expired": "2099-01-01T00:00:00Z", "earliest_refresh_at": "2098-01-01T00:00:00Z"},
				}}
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				manager := cliproxyauth.NewManager(nil, nil, nil)
				registered, errRegister := manager.Register(t.Context(), auth)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				auth = registered
				path, errSave := store.Save(t.Context(), auth)
				if errSave != nil {
					t.Fatal(errSave)
				}
				before, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				raw := []byte(tc.raw)
				if tc.outer {
					doc := ojson.NewDocString(`{}`)
					returned := auth.Clone()
					delete(returned.Metadata, "siwc")
					returned.Metadata["expired"] = "2100-01-01T00:00:00Z"
					if errSet := doc.Set("auth", returned); errSet != nil {
						t.Fatal(errSet)
					}
					raw = doc.Bytes()
				}
				var calls atomic.Int32
				helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { calls.Add(1); return raw, nil })
				input := auth.Clone()
				updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), input)
				if calls.Load() != 1 {
					t.Fatal("refresh did not cross the Home boundary exactly once")
				}
				if !tc.siwc && !tc.outer {
					var status interface{ StatusCode() int }
					if errRefresh == nil || !errors.As(errRefresh, &status) || status.StatusCode() != http.StatusBadGateway {
						t.Errorf("invalid Home result must fail as 502, got %v", errRefresh)
					}
					if !reflect.DeepEqual(input.Metadata, auth.Metadata) {
						t.Error("rejected result changed the in-memory credential")
					}
					updated = auth
				} else {
					if errRefresh != nil || updated == nil {
						t.Fatalf("valid partition failed: %v", errRefresh)
					}
					patch := updated.CodexRefreshPatch
					if patch == nil || patch.RefreshedOuter() != tc.outer || patch.RefreshedSIWC() != tc.siwc {
						t.Error("refresh patch marked the wrong credential partition successful")
					}
					if tc.siwc && (patch == nil || patch.OuterError() == nil || patch.SIWCError() != nil) {
						t.Error("SIWC-only success lost the missing-outer partition error")
					}
					merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), auth, updated)
					if errMerge != nil {
						t.Fatal(errMerge)
					}
					updated = merged
					if _, errSave = store.Save(t.Context(), updated); errSave != nil {
						t.Fatal(errSave)
					}
				}
				disk, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if !tc.siwc && !tc.outer && string(disk) != string(before) {
					t.Error("rejected Home response rewrote the credential file")
				}
				var diskMap map[string]any
				if errDecode := json.Unmarshal(disk, &diskMap); errDecode != nil {
					t.Fatal(errDecode)
				}
				for _, key := range []string{"access_token", "refresh_token", "account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type", "plan_type", "plan_type_defaulted", "operator_note"} {
					if !reflect.DeepEqual(diskMap[key], auth.Metadata[key]) || !reflect.DeepEqual(updated.Metadata[key], auth.Metadata[key]) {
						t.Errorf("adopted credential changed preserved outer field %s", key)
					}
				}
				if tc.siwc {
					want := ojson.GetBytes(raw, "auth.metadata.siwc")
					for _, key := range []string{"access_token", "refresh_token", "expired"} {
						if ojson.GetBytes(disk, "siwc."+key).String() != want.Get(key).String() {
							t.Errorf("SIWC %s was not persisted", key)
						}
					}
				}
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, disk)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("synthesis: %v count=%d", errLoad, len(loaded))
				}
				loaded[0].Attributes["base_url"] = server.URL
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
				if _, errExecute := executor.NewCodexAutoExecutor(cfg).Execute(t.Context(), loaded[0], core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, opts); errExecute != nil {
					t.Fatal(errExecute)
				}
				wantID := "client"
				if mode == "device" {
					wantID = homeMemberA
				}
				assertHomeWire(t, <-captures, wantID, "acc-team-1", "outer-old")
			})
		}
	}
}

func TestRefreshAuthViaHomeResultStructure(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		status    int
	}{
		{"empty-object", `{}`, http.StatusBadGateway},
		{"null", `null`, http.StatusBadGateway},
		{"null-envelope", `{"auth":null}`, http.StatusBadGateway},
		{"empty-envelope", `{"auth":{}}`, http.StatusBadGateway},
		{"array", `[]`, http.StatusBadGateway},
		{"nested-array", `{"auth":[]}`, http.StatusBadGateway},
		{"scalar", `false`, http.StatusBadGateway},
		{"legacy-provider-result", `{"provider":"claude","metadata":{"custom_token":"opaque"}}`, 0},
		{"envelope-plugin-result", `{"auth":{"provider":"plugin","metadata":{"custom_token":"opaque"}},"auth_index":"new-index"}`, 0},
		{"disabled", `{"auth":{"disabled":true}}`, http.StatusUnauthorized},
		{"disabled-status", `{"status":"disabled"}`, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return []byte(tc.raw), nil })
			cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
			updated, handled, errRefresh := helps.RefreshAuthViaHome(t.Context(), cfg, &cliproxyauth.Auth{ID: "result", Index: "old-index", Provider: "plugin"})
			if !handled {
				t.Fatal("Home refresh was not handled")
			}
			if tc.status != 0 {
				var status interface{ StatusCode() int }
				if updated != nil || !errors.As(errRefresh, &status) || status.StatusCode() != tc.status {
					t.Fatalf("response status=%v, want %d", errRefresh, tc.status)
				}
				return
			}
			if errRefresh != nil || updated == nil || updated.Metadata["custom_token"] != "opaque" {
				t.Fatalf("provider-specific response rejected: %v", errRefresh)
			}
			wantIndex := "old-index"
			if tc.name == "envelope-plugin-result" {
				wantIndex = "new-index"
			}
			if updated.Index != wantIndex {
				t.Error("auth index was not preserved")
			}
		})
	}
}
