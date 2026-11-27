package helps_test

import (
	"context"
	"os"
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
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func homeExpirationLifecycle(t *testing.T, file bool, metadata, returned map[string]any, check func(string, *auth.Auth)) *auth.Auth {
	t.Helper()
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	manager := auth.NewManager(nil, nil, nil)
	base, errRegister := manager.Register(t.Context(), &auth.Auth{ID: "expiry.json", FileName: "expiry.json", Provider: "codex", Metadata: metadata})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	store := fileauth.NewFileTokenStore()
	var path string
	if file {
		cfg.AuthDir = t.TempDir()
		store.SetBaseDir(cfg.AuthDir)
		var errSave error
		path, errSave = store.Save(t.Context(), base)
		if errSave != nil {
			t.Fatal(errSave)
		}
	}
	doc := ojson.NewDocString(`{}`)
	if errSet := doc.Set("auth", &auth.Auth{Provider: "codex", Metadata: returned}); errSet != nil {
		t.Fatal(errSet)
	}
	helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return doc.Bytes(), nil })
	updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
	if errRefresh != nil {
		t.Fatal(errRefresh)
	}
	check("executor", updated)
	merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
	if errMerge != nil {
		t.Fatal(errMerge)
	}
	check("manager", merged)
	if !file {
		return merged
	}
	if _, errSave := store.Save(t.Context(), merged); errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var saved map[string]any
	if errDecode := json.Unmarshal(raw, &saved); errDecode != nil {
		t.Fatal(errDecode)
	}
	check("disk", &auth.Auth{Provider: "codex", Metadata: saved})
	loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if errLoad != nil || len(loaded) != 1 {
		t.Fatalf("cold load: %v, count=%d", errLoad, len(loaded))
	}
	check("cold", loaded[0])
	return loaded[0]
}

func assertHomeExpirationBearer(t *testing.T, candidate *auth.Auth, bearer string) {
	t.Helper()
	server, received, _ := homeWireServer(t)
	if candidate.Attributes == nil {
		candidate.Attributes = make(map[string]string)
	}
	candidate.Attributes["base_url"] = server.URL
	if _, errExecute := executor.NewCodexExecutor(&config.Config{}).Execute(t.Context(), candidate, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
		t.Fatal(errExecute)
	}
	if wire := <-received; wire.headers.Get("Authorization") != "Bearer "+bearer {
		t.Fatal("request used the previous bearer after expiry adoption")
	}
}

func TestCodexHomeSIWCExpirationLifecycle(t *testing.T) {
	const past = "2000-01-01T00:00:00Z"
	const future = "2099-01-01T00:00:00Z"
	want, _ := time.Parse(time.RFC3339, future)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, key := range []string{"expired", "expires_at", "expiresAt", "expire", "expiry", "expires", "relative", "relative-camel"} {
		for _, file := range []bool{false, true} {
			persistence := "memory"
			if file {
				persistence = "file"
			}
			t.Run(key+"/"+persistence, func(t *testing.T) {
				initial := map[string]any{
					"type": "codex", "access_token": "outer-old", "refresh_token": "outer-grant", "expired": past, "use_siwc": true,
					"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-grant", "client_id": "client", "expired": past, "expires_at": past},
				}
				nested := map[string]any{"access_token": "siwc-new", "refresh_token": "siwc-new-grant"}
				switch key {
				case "relative":
					nested["expires_in"], nested["last_refresh"] = 7200, want.Add(-2*time.Hour).Format(time.RFC3339)
				case "relative-camel":
					nested["expiresIn"], nested["lastRefresh"] = 7200, want.Add(-2*time.Hour).Format(time.RFC3339)
				default:
					nested[key] = future
				}
				check := func(stage string, candidate *auth.Auth) {
					t.Helper()
					if expiry, ok := candidate.SIWCRenewalExpirationTime(); !ok || !expiry.Equal(want) {
						t.Errorf("%s lost %s expiration: got=%v known=%t", stage, key, expiry, ok)
					}
					if due, has, needs := auth.CodexSIWCNeedsRefresh(candidate, now); !has || needs || !due.Equal(want.Add(-auth.CodexSIWCRefreshLead)) {
						t.Errorf("%s changed SIWC renewal lead: due=%v has=%t needs=%t", stage, due, has, needs)
					}
				}
				cold := homeExpirationLifecycle(t, file, initial, map[string]any{"access_token": "outer-new", "expired": future, "siwc": nested}, check)
				assertHomeExpirationBearer(t, cold, "siwc-new")
			})
		}
	}
}

func TestCodexHomeOuterExpirationLifecycle(t *testing.T) {
	oldExpiry, _ := time.Parse(time.RFC3339, "2000-01-01T01:00:00Z")
	for _, form := range []string{"relative", "relative-camel", "nested", "nested-camel"} {
		for _, sameBearer := range []bool{true, false} {
			for _, file := range []bool{false, true} {
				name := form + "/rotated/memory"
				if sameBearer {
					name = form + "/same/memory"
				}
				if file {
					name += "-file"
				}
				t.Run(name, func(t *testing.T) {
					initial := map[string]any{"type": "codex", "access_token": "opaque-old", "refresh_token": "outer-grant"}
					switch form {
					case "relative":
						initial["expires_in"], initial["timestamp"] = 3600, "2000-01-01T00:00:00Z"
					case "relative-camel":
						initial["expiresIn"], initial["issuedAt"] = 3600, "2000-01-01T00:00:00Z"
					case "nested":
						initial["token"] = map[string]any{"expires_at": oldExpiry.Format(time.RFC3339), "custom": "retain"}
					case "nested-camel":
						initial["Token"] = map[string]any{"Token": map[string]any{"expires_in": 3600, "issued_at": "2000-01-01T00:00:00Z", "custom": "retain"}, "custom": "retain"}
					}
					wantBearer := "opaque-new"
					if sameBearer {
						wantBearer = "opaque-old"
					}
					check := func(stage string, candidate *auth.Auth) {
						t.Helper()
						expiry, known := candidate.OuterExpirationTime()
						if known != sameBearer || (sameBearer && !expiry.Equal(oldExpiry)) {
							t.Errorf("%s inherited or lost %s expiry: got=%v known=%t same=%t", stage, form, expiry, known, sameBearer)
						}
						if form == "nested" && candidate.Metadata["token"].(map[string]any)["custom"] != "retain" {
							t.Errorf("%s erased custom token metadata", stage)
						}
					}
					cold := homeExpirationLifecycle(t, file, initial, map[string]any{"access_token": wantBearer}, check)
					assertHomeExpirationBearer(t, cold, wantBearer)
				})
			}
		}
	}
}

func TestCodexHomeExpirationIndependentPartitionCAS(t *testing.T) {
	const old = "2000-01-01T00:00:00Z"
	const currentTime = "2098-01-01T00:00:00Z"
	const siwcTime = "2099-01-01T00:00:00Z"
	for _, file := range []bool{false, true} {
		name := "memory"
		if file {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Home: config.HomeConfig{Enabled: true}, AuthDir: t.TempDir()}
			manager := auth.NewManager(nil, nil, nil)
			base, errRegister := manager.Register(t.Context(), &auth.Auth{ID: "independent.json", FileName: "independent.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "outer-old", "refresh_token": "outer-old-grant", "expires_in": 3600, "timestamp": old,
				"token": map[string]any{"expires_at": old, "custom": "base"}, "codex_device_fingerprint": "off",
				"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-old-grant", "client_id": "client", "expires_at": old},
			}})
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			var path string
			if file {
				var errSave error
				path, errSave = store.Save(t.Context(), base)
				if errSave != nil {
					t.Fatal(errSave)
				}
			}
			response := ojson.NewDocString(`{"auth":{"provider":"codex","metadata":{"access_token":"outer-obsolete","refresh_token":"outer-obsolete-grant","expiresIn":7200,"issuedAt":"2001-01-01T00:00:00Z","token":{"expires_at":"2001-01-01T02:00:00Z","custom":"home"},"siwc":{"access_token":"siwc-new","refresh_token":"siwc-new-grant","expiresAt":"2099-01-01T00:00:00Z"}}}}`)
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) {
				current := base.Clone()
				current.Metadata["access_token"], current.Metadata["refresh_token"] = "outer-current", "outer-current-grant"
				current.Metadata["expires_in"], current.Metadata["timestamp"] = 3600, currentTime
				current.Metadata["token"] = map[string]any{"expires_at": currentTime, "custom": "admin"}
				current.Metadata["codex_device_fingerprint"] = "device"
				current.Metadata["codex_installation_id"] = homeExplicit
				current.Metadata["headers"] = map[string]any{"X-Admin": "keep"}
				if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
					t.Fatal(errUpdate)
				}
				if file {
					if errWrite := codexauth.WriteJSONFileAtomic(path, current.Metadata); errWrite != nil {
						t.Fatal(errWrite)
					}
				}
				return response.Bytes(), nil
			})
			updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			check := func(stage string, candidate *auth.Auth) {
				t.Helper()
				if candidate.Metadata["access_token"] != "outer-current" || candidate.Metadata["timestamp"] != currentTime || candidate.Metadata["expiresIn"] != nil {
					t.Errorf("%s accepted an obsolete outer expiry snapshot", stage)
				}
				if nested, _ := candidate.Metadata["token"].(map[string]any); nested["expires_at"] != currentTime || nested["custom"] != "admin" {
					t.Errorf("%s lost nested current expiry or administrator metadata", stage)
				}
				if candidate.Metadata["codex_device_fingerprint"] != "device" || candidate.Metadata["codex_installation_id"] != homeExplicit {
					t.Errorf("%s lost administrator device settings", stage)
				}
				if nested, _ := candidate.Metadata["siwc"].(map[string]any); nested["access_token"] != "siwc-new" {
					t.Errorf("%s dropped independently applicable SIWC result", stage)
				}
				if expiry, ok := candidate.SIWCRenewalExpirationTime(); !ok || expiry.Format(time.RFC3339) != siwcTime {
					t.Errorf("%s lost independently applicable SIWC expiry", stage)
				}
			}
			if file {
				check("executor", updated)
			}
			merged, errUpdate := manager.UpdateRefreshedAuth(t.Context(), base, updated)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			check("manager", merged)
			if file {
				if _, errSave := store.Save(t.Context(), merged); errSave != nil {
					t.Fatal(errSave)
				}
				raw, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				var disk map[string]any
				if errDecode := json.Unmarshal(raw, &disk); errDecode != nil {
					t.Fatal(errDecode)
				}
				check("disk", &auth.Auth{Provider: "codex", Metadata: disk})
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("cold load: %v count=%d", errLoad, len(loaded))
				}
				merged = loaded[0]
				check("cold", merged)
			}
			assertHomeExpirationBearer(t, merged, "outer-current")
		})
	}
}

func TestCodexHomeOuterRefreshTimestampLifecycle(t *testing.T) {
	const past = "2000-01-01T00:00:00Z"
	const future = "2099-01-01T00:00:00Z"
	for _, field := range append(codexauth.RefreshTimeMetadataKeys(), "omitted", "cleared") {
		for _, sameBearer := range []bool{false, true} {
			for _, file := range []bool{false, true} {
				name := field + "/rotated/memory"
				if sameBearer {
					name = field + "/same/memory"
				}
				if file {
					name += "-file"
				}
				t.Run(name, func(t *testing.T) {
					metadata := map[string]any{"type": "codex", "access_token": "old", "refresh_token": "grant", "last_refresh": past}
					bearer := "new"
					if sameBearer {
						bearer = "old"
					}
					returned := map[string]any{"access_token": bearer}
					want := future
					switch field {
					case "omitted":
						want = ""
						if sameBearer {
							want = past
						}
					case "cleared":
						returned["lastRefresh"] = nil
						want = ""
					default:
						returned[field] = future
					}
					check := func(stage string, candidate *auth.Auth) {
						t.Helper()
						got, _ := candidate.Metadata["last_refresh"].(string)
						if got != want {
							t.Errorf("%s refresh timestamp=%q, want %q", stage, got, want)
						}
						for _, alias := range codexauth.RefreshTimeMetadataKeys()[1:] {
							if candidate.Metadata[alias] != nil || candidate.Attributes[alias] != "" {
								t.Errorf("%s retained duplicate refresh timestamp %s", stage, alias)
							}
						}
						now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
						if _, has, due := auth.CodexOuterNeedsRefresh(candidate, now); !has || due != (want != future) {
							t.Errorf("%s scheduled opaque outer bearer using a stale timestamp", stage)
						}
					}
					cold := homeExpirationLifecycle(t, file, metadata, returned, check)
					assertHomeExpirationBearer(t, cold, bearer)
				})
			}
		}
	}
}
