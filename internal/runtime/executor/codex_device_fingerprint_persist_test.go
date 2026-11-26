package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func codexDeviceRefreshPlanToken(t *testing.T, plan string) string {
	t.Helper()
	claims := ojson.NewDocString(`{"email":"synthetic@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa"}}`)
	if plan != "" {
		if errSet := claims.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", plan); errSet != nil {
			t.Fatal(errSet)
		}
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig"
}

func TestCodexDeviceFingerprintRefreshSaveReloadPlanProvenance(t *testing.T) {
	for _, initialPlan := range []string{"team", "business", "enterprise", "edu"} {
		for _, nextPlan := range []string{"", "free", initialPlan} {
			t.Run(initialPlan+"/next="+nextPlan, func(t *testing.T) {
				const target = "http://localhost/responses"
				tempDir := t.TempDir()
				cfg := &config.Config{AuthDir: tempDir}
				ctx := &synthesizer.SynthesisContext{Config: cfg, AuthDir: tempDir, IDGenerator: synthesizer.NewStableIDGenerator()}
				path := filepath.Join(tempDir, "account.json")
				synthesize := func(raw []byte) *cliproxyauth.Auth {
					auths, err := synthesizer.SynthesizeAuthFile(ctx, path, raw)
					if err != nil || len(auths) != 1 {
						t.Fatalf("synthesis failed: count=%d error=%v", len(auths), err)
					}
					return auths[0]
				}
				doc := ojson.NewDocString(`{"type":"codex","access_token":"synthetic-old","account_id":"acc-team-1","codex_device_fingerprint":"device","codex_installation_id":"","operator_note":"keep"}`)
				for key, value := range map[string]any{"refresh_token": "synthetic-" + t.Name(), "id_token": codexDeviceRefreshPlanToken(t, initialPlan)} {
					if errSet := doc.Set(key, value); errSet != nil {
						t.Fatal(errSet)
					}
				}
				var resolver helps.CodexDeviceResolver
				first := resolver.Resolve(cfg, synthesize(doc.Bytes()), false, target)
				if first.ID != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
					t.Fatal("complete Team identity did not match golden vector")
				}
				// Start from a saved missing-claim refresh so explicit plans must clear true.
				for key, value := range map[string]any{"id_token": codexDeviceRefreshPlanToken(t, ""), "plan_type": "free", "plan_type_defaulted": true} {
					if errSet := doc.Set(key, value); errSet != nil {
						t.Fatal(errSet)
					}
				}
				if errWrite := os.WriteFile(path, doc.Bytes(), 0600); errWrite != nil {
					t.Fatal(errWrite)
				}
				auth := synthesize(doc.Bytes())
				if got := resolver.Resolve(cfg, auth, false, target); got.ID != first.ID {
					t.Fatal("saved default-free value displaced cached Team identity")
				}
				proxyURL, teardown := startCodexMockOAuthServers(t, codexDeviceRefreshPlanToken(t, nextPlan))
				defer teardown()
				auth.ProxyURL = proxyURL
				refreshed, errRefresh := NewCodexExecutor(cfg).Refresh(context.Background(), auth)
				if errRefresh != nil {
					t.Fatal(errRefresh)
				}
				if refreshed.CodexRefreshPatch == nil {
					t.Fatal("actual OAuth refresh did not produce a scoped credential patch")
				}
				wantID := first.ID
				if nextPlan == "free" {
					wantID = "c2a63432-aabe-4908-8fe6-ec89af8327c9"
				}
				if got := resolver.Resolve(cfg, refreshed, false, target); got.ID != wantID {
					t.Fatal("in-memory refresh did not preserve explicit/default plan distinction")
				}
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(tempDir)
				if _, errSave := store.Save(context.Background(), refreshed); errSave != nil {
					t.Fatal(errSave)
				}
				saved, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if ojson.GetBytes(saved, "plan_type_defaulted").Bool() != (nextPlan == "") {
					t.Fatal("scoped refresh save lost plan provenance")
				}
				if ojson.GetBytes(saved, "codex_device_fingerprint").String() != "device" || ojson.GetBytes(saved, "operator_note").String() != "keep" || !ojson.GetBytes(saved, "codex_installation_id").Exists() {
					t.Fatal("refresh/save discarded custom account settings")
				}
				reloaded := synthesize(saved)
				wantPlan := nextPlan
				if wantPlan == "" {
					wantPlan = "free"
				}
				if reloaded.Attributes["plan_type"] != wantPlan || reloaded.Metadata["plan_type"] != wantPlan {
					t.Fatal("general plan behavior changed after save/reload")
				}
				if got := resolver.Resolve(cfg, reloaded, false, target); got.ID != wantID {
					t.Fatal("synthesized refreshed credential changed device identity")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintAdoptRotatedPlanProvenance(t *testing.T) {
	for _, source := range []string{"legacy-explicit-free", "explicit-free", "defaulted-free", "token-team"} {
		t.Run(source, func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "account.json")
			cfg := &config.Config{AuthDir: tempDir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			auth := &cliproxyauth.Auth{
				ID: "account.json", FileName: "account.json", Provider: "codex",
				Attributes: map[string]string{cliproxyauth.AttributePath: path},
				Metadata: map[string]any{
					"type": "codex", "account_id": "acc-team-1", "id_token": codexDeviceRefreshPlanToken(t, "team"),
					"access_token": "old-access", "refresh_token": "old-refresh", "expired": "2099-01-01T00:00:00Z",
				},
			}
			var resolver helps.CodexDeviceResolver
			first := resolver.Resolve(cfg, auth, false, "http://localhost/responses")
			auth.Attributes["plan_type"] = "free"
			auth.Attributes["plan_type_defaulted"] = "true"
			auth.Metadata["plan_type"] = "free"
			auth.Metadata["plan_type_defaulted"] = true
			auth.Metadata["id_token"] = codexDeviceRefreshPlanToken(t, "")
			disk := ojson.NewDocString(`{"type":"codex","account_id":"acc-team-1","access_token":"rotated-access","refresh_token":"rotated-refresh","expired":"2099-01-01T00:00:00Z","plan_type":"free"}`)
			if source == "token-team" {
				if errDelete := disk.Delete("plan_type"); errDelete != nil {
					t.Fatal(errDelete)
				}
				if errSet := disk.Set("id_token", codexDeviceRefreshPlanToken(t, "team")); errSet != nil {
					t.Fatal(errSet)
				}
			} else {
				if errSet := disk.Set("id_token", codexDeviceRefreshPlanToken(t, "")); errSet != nil {
					t.Fatal(errSet)
				}
				if source != "legacy-explicit-free" {
					if errSet := disk.Set("plan_type_defaulted", source == "defaulted-free"); errSet != nil {
						t.Fatal(errSet)
					}
				}
			}
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			refreshed, errRefresh := NewCodexExecutor(cfg).Refresh(context.Background(), auth)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			if refreshed.Metadata["access_token"] != "rotated-access" || refreshed.CodexRefreshPatch == nil {
				t.Fatal("rotated credential partition was not adopted")
			}
			wantID := "c2a63432-aabe-4908-8fe6-ec89af8327c9"
			if source == "defaulted-free" || source == "token-team" {
				wantID = first.ID
			}
			if got := resolver.Resolve(cfg, refreshed, false, "http://localhost/responses"); got.ID != wantID {
				t.Fatal("disk adoption retained stale plan provenance")
			}
			if source == "legacy-explicit-free" || source == "token-team" {
				if _, exists := refreshed.Metadata["plan_type_defaulted"]; exists {
					t.Fatal("absent replacement marker retained old metadata")
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintRefreshAndSavePreserveMetadata(t *testing.T) {
	const explicitID = "11111111-2222-4333-8444-555555555555"
	proxyURL, teardown := startCodexMockOAuthServers(t, makeTestCodexRefreshJWT("plus", "device-refresh-account"))
	defer teardown()
	tempDir := t.TempDir()
	auth := &cliproxyauth.Auth{
		ID: "device-refresh.json", FileName: "device-refresh.json", Provider: "codex", ProxyURL: proxyURL,
		Attributes: map[string]string{"codex_device_fingerprint": "device", "codex_installation_id": explicitID},
		Metadata: map[string]any{
			"type": "codex", "refresh_token": "synthetic-refresh-token", "account_id": "device-refresh-account",
			"codex_device_fingerprint": "device", "codex_installation_id": explicitID,
		},
	}
	executor := NewCodexExecutor(&config.Config{AuthDir: tempDir})
	refreshed, errRefresh := executor.Refresh(context.Background(), auth)
	if errRefresh != nil {
		t.Fatalf("synthetic OAuth refresh failed: %v", errRefresh)
	}
	if refreshed.Metadata["codex_device_fingerprint"] != "device" || refreshed.Metadata["codex_installation_id"] != explicitID || refreshed.Attributes["codex_device_fingerprint"] != "device" || refreshed.Attributes["codex_installation_id"] != explicitID {
		t.Fatal("refresh discarded custom device fields")
	}
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(tempDir)
	refreshed.Attributes[cliproxyauth.AttributePath] = filepath.Join(tempDir, "device-refresh.json")
	path, errSave := store.Save(context.Background(), refreshed)
	if errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if ojson.GetBytes(raw, "codex_device_fingerprint").String() != "device" || ojson.GetBytes(raw, "codex_installation_id").String() != explicitID || ojson.GetBytes(raw, "access_token").String() != "new-mock-access-token" {
		t.Fatal("saved refresh lost device fields or updated credentials")
	}
}

func TestCodexDeviceFingerprintRefreshPatchPreservesOperatorChanges(t *testing.T) {
	for _, withStorage := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "storage"}[withStorage], func(t *testing.T) {
			const oldID = "11111111-2222-4333-8444-555555555555"
			const newID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			before := &cliproxyauth.Auth{
				ID: "device.json", FileName: "device.json", Provider: "codex",
				Metadata: map[string]any{"type": "codex", "access_token": "old", "refresh_token": "old-refresh", "codex_device_fingerprint": "device", "codex_installation_id": oldID},
			}
			refreshed := before.Clone()
			refreshed.Metadata["access_token"] = "new"
			refreshed.Metadata["refresh_token"] = "new-refresh"
			refreshed.CodexRefreshPatch = codexauth.NewCredentialRefreshPatch(before.Metadata, refreshed.Metadata, true, false)
			if withStorage {
				refreshed.Storage = &codexauth.CodexTokenStorage{AccessToken: "stale-storage"}
			}
			disk := ojson.NewDocString(`{"type":"codex","access_token":"old","refresh_token":"old-refresh"}`)
			if errSet := disk.Set("codex_device_fingerprint", "off"); errSet != nil {
				t.Fatal(errSet)
			}
			if errSet := disk.Set("codex_installation_id", newID); errSet != nil {
				t.Fatal(errSet)
			}
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "device.json")
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(tempDir)
			if _, errSave := store.Save(context.Background(), refreshed); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "codex_device_fingerprint").String() != "off" || ojson.GetBytes(raw, "codex_installation_id").String() != newID || ojson.GetBytes(raw, "access_token").String() != "new" {
				t.Fatal("refresh patch overwrote operator device settings or lost refreshed credentials")
			}
		})
	}
}
