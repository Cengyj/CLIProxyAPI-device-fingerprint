package executor

import (
	"context"
	"net/http"
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
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
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

func TestCodexDeviceFingerprintSaveIgnoresForeignAccountPlan(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	dir := t.TempDir()
	path := filepath.Join(dir, "foreign.json")
	cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	auth := fingerprintHTTPAuth(server.URL)
	auth.ID, auth.FileName = "foreign.json", "foreign.json"
	auth.Metadata["account_id"] = "acc-test-1"
	auth.Metadata["id_token"] = codexDeviceRefreshPlanToken(t, "team")
	exec := NewCodexExecutor(cfg)
	request := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
	options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
	assertWire := func(candidate *cliproxyauth.Auth) {
		t.Helper()
		candidate.Attributes["base_url"] = server.URL
		fingerprintRunHTTP(t, t.Context(), exec, candidate, request, options, false)
		wire := <-captured
		if wire.headers.Get("ChatGPT-Account-ID") != "acc-test-1" || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" {
			t.Error("saving configuration adopted a foreign account's plan")
		}
	}
	assertWire(auth)
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(t.Context(), auth); errSave != nil {
		t.Fatal(errSave)
	}
	assertWire(auth)
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	loaded, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if errSynthesize != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v count=%d", errSynthesize, len(loaded))
	}
	assertWire(loaded[0])
}

func TestCodexDeviceFingerprintHomeIdentityPersistsToWire(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	dir := t.TempDir()
	path := filepath.Join(dir, "home.json")
	cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	auth := fingerprintHTTPAuth(server.URL)
	auth.ID, auth.FileName = "home.json", "home.json"
	auth.Metadata["account_id"] = "acc-team-1"
	auth.Metadata["chatgpt_user_id"] = "user-aaa"
	auth.Metadata["plan_type"] = "team"
	auth.Metadata["id_token"] = codexDeviceRefreshPlanToken(t, "team")
	auth.Metadata["operator_note"] = "keep"
	auth.Attributes["chatgpt_user_id"] = "user-aaa"
	before := auth.Clone()
	source := &cliproxyauth.Auth{Metadata: map[string]any{
		"account_id": "acc-team-1", "access_token": "home-access", "refresh_token": "home-refresh",
		"id_token": deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`)),
	}}
	for key, value := range source.Metadata {
		auth.Metadata[key] = value
	}
	helps.AdoptCodexHomeIdentity(auth, source)
	auth.CodexRefreshPatch = codexauth.NewCredentialRefreshPatch(before.Metadata, auth.Metadata, true, false)
	manager := cliproxyauth.NewManager(nil, nil, nil)
	if _, errRegister := manager.Register(t.Context(), before); errRegister != nil {
		t.Fatal(errRegister)
	}
	merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), before, auth)
	if errMerge != nil {
		t.Fatal(errMerge)
	}
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(t.Context(), merged); errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	loaded, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if errSynthesize != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v count=%d", errSynthesize, len(loaded))
	}
	loaded[0].Attributes["base_url"] = server.URL
	selected, errUpdate := manager.Update(t.Context(), loaded[0])
	if errUpdate != nil {
		t.Fatal(errUpdate)
	}
	fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), selected,
		core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)},
		core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}, false)
	wire := <-captured
	if wire.headers.Get("Authorization") != "Bearer home-access" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" ||
		ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" ||
		ojson.Get(wire.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" ||
		selected.Metadata["operator_note"] != "keep" {
		t.Fatal("Home identity adoption/merge/save/reload sent inconsistent credentials")
	}
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

func TestCodexDeviceFingerprintOrdinarySaveKeepsCredentialIdentity(t *testing.T) {
	for _, withStorage := range []bool{false, true} {
		sources := []string{"member-hint", "token-only", "account-change", "access-only"}
		for _, source := range sources {
			t.Run(map[bool]string{false: "metadata", true: "storage"}[withStorage]+"/"+source, func(t *testing.T) {
				server, captured := fingerprintHTTPServer(t, false)
				dir := t.TempDir()
				path := filepath.Join(dir, "member.json")
				cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				oldToken := codexDeviceRefreshPlanToken(t, "team")
				newToken := deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`))
				disk := ojson.NewDocString(`{"type":"codex","access_token":"disk-access","refresh_token":"disk-refresh","account_id":"acc-team-1","plan_type":"team","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team","operator_note":"before","remove_me":"old","expired":"2099-01-01T00:00:00Z"}`)
				wantID, wantAccount := "fd5de10e-f853-4dd0-92f4-ece041b115a9", "acc-team-1"
				wantAccess, wantRefresh := "disk-access", "disk-refresh"
				wantHint := "user-bbb"
				if source != "member-hint" {
					wantHint = ""
				}
				if source == "access-only" {
					_ = disk.Delete("refresh_token")
					wantRefresh = ""
					if !withStorage {
						// Legacy metadata-only records without refresh provenance
						// allow incoming credential replacement. Its identity must
						// follow that selected snapshot, not the displaced disk token.
						wantAccess, wantRefresh = "memory-access", "memory-refresh"
						wantID, wantHint = "2d1c341a-5607-4894-ae5e-6cf59c2e7dde", "user-aaa"
					}
				}
				if source == "account-change" {
					newToken = deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-test-2","chatgpt_plan_type":"free"}}`))
					wantID, wantAccount = "3216ba40-955f-42a6-aabf-a9ac6ae94a30", "acc-test-2"
					_ = disk.Set("account_id", wantAccount)
					_ = disk.Set("plan_type", "free")
				}
				if errSet := disk.Set("id_token", newToken); errSet != nil {
					t.Fatal(errSet)
				}
				if source != "member-hint" {
					_ = disk.Delete("chatgpt_user_id")
					_ = disk.Delete("chatgpt_plan_type")
				}
				if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
					t.Fatal(errWrite)
				}
				auth := fingerprintHTTPAuth(server.URL)
				auth.ID, auth.FileName = "member.json", "member.json"
				auth.Attributes[cliproxyauth.AttributePath] = path
				auth.Attributes["account_id"] = "acc-team-1"
				auth.Attributes["id_token"] = oldToken
				auth.Attributes["chatgpt_user_id"] = "user-aaa"
				auth.Attributes["chatgpt_plan_type"] = "team"
				originalAttributes := auth.Attributes
				for key, value := range map[string]any{
					"access_token": "memory-access", "refresh_token": "memory-refresh", "id_token": oldToken,
					"account_id": "acc-team-1", "plan_type": "team", "chatgpt_user_id": "user-aaa",
					"chatgpt_plan_type": "team", "codex_device_fingerprint": "device", "operator_note": "after",
					"expired": "2099-01-01T00:00:00Z",
				} {
					auth.Metadata[key] = value
				}
				var originalStorage *codexauth.CodexTokenStorage
				if withStorage {
					originalStorage = &codexauth.CodexTokenStorage{AccessToken: "memory-access", RefreshToken: "memory-refresh", IDToken: oldToken, AccountID: "acc-team-1", PlanType: "team"}
					auth.Storage = originalStorage
				}
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(dir)
				if _, errSave := store.Save(t.Context(), auth); errSave != nil {
					t.Fatal(errSave)
				}
				saved, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if ojson.GetBytes(saved, "access_token").String() != wantAccess || ojson.GetBytes(saved, "refresh_token").String() != wantRefresh || ojson.GetBytes(saved, "operator_note").String() != "after" || ojson.GetBytes(saved, "remove_me").Exists() {
					t.Error("ordinary save lost selected credentials or administrator changes/deletion")
				}
				if ojson.GetBytes(saved, "chatgpt_user_id").String() != wantHint || auth.Metadata["access_token"] != wantAccess {
					t.Error("ordinary save mixed an old member hint into preserved disk credentials")
				}
				if originalAttributes["chatgpt_user_id"] != "user-aaa" || originalAttributes["id_token"] != oldToken {
					t.Error("ordinary save mutated the caller's shared identity attributes")
				}
				if withStorage && (originalStorage.AccessToken != "memory-access" || originalStorage.Metadata != nil) {
					t.Error("ordinary save mutated the caller's shared storage snapshot")
				}
				if withStorage {
					savedStorage, ok := auth.Storage.(*codexauth.CodexTokenStorage)
					if !ok || savedStorage == originalStorage || savedStorage.AccessToken != "disk-access" || savedStorage.RefreshToken != wantRefresh || savedStorage.IDToken != newToken {
						t.Error("ordinary save retained an outdated runtime storage credential")
					}
				}
				request := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
				options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"keep"}`}}}
				exec := NewCodexExecutor(cfg)
				assertWire := func(candidate *cliproxyauth.Auth) {
					t.Helper()
					candidate.Attributes["base_url"] = server.URL
					manager := cliproxyauth.NewManager(nil, nil, nil)
					registered, errRegister := manager.Register(t.Context(), candidate)
					if errRegister != nil {
						t.Fatal(errRegister)
					}
					fingerprintRunHTTP(t, t.Context(), exec, registered, request, options, false)
					wire := <-captured
					if wire.headers.Get("Authorization") != "Bearer "+wantAccess || wire.headers.Get("ChatGPT-Account-ID") != wantAccount || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != wantID || ojson.Get(wire.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != wantID {
						t.Error("saved credential and member were inconsistent on the wire")
					}
				}
				assertWire(auth)
				synthesized, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, saved)
				if errSynthesize != nil || len(synthesized) != 1 {
					t.Fatalf("synthesis failed: %v count=%d", errSynthesize, len(synthesized))
				}
				assertWire(synthesized[0])
			})
		}
	}
}
