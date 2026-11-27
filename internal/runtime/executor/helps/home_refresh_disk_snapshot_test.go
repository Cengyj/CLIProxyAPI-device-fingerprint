package helps_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/json"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type codexDiskSnapshotTransport func(*http.Request) (*http.Response, error)

func (f codexDiskSnapshotTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCodexDiskReplacementDoesNotInheritPreviousGrant(t *testing.T) {
	cfg, manager, store, path, base := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", false)
	cfg.Home.Enabled = false
	delete(base.Metadata, "siwc")
	base.Metadata["refresh_token"] = "previous-account-grant-" + t.Name()
	var errUpdate error
	base, errUpdate = manager.Update(t.Context(), base)
	if errUpdate != nil {
		t.Fatal(errUpdate)
	}
	disk := map[string]any{
		"type": "codex", "access_token": "replacement-access", "account_id": "replacement-account",
		"expired": "2000-01-01T00:00:00Z", "last_refresh": "2000-01-01T00:00:00Z",
	}
	if errWrite := codexauth.WriteJSONFileAtomic(path, disk); errWrite != nil {
		t.Fatal(errWrite)
	}
	var calls atomic.Int32
	renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.PostFormValue("refresh_token"); got != base.Metadata["refresh_token"] {
			t.Error("unexpected refresh grant reached local token endpoint")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"old-account-renewed","refresh_token":"old-account-next","expires_in":7200}`))
	}))
	t.Cleanup(renewal.Close)
	endpoint, errURL := url.Parse(renewal.URL)
	if errURL != nil {
		t.Fatal(errURL)
	}
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	oldTransport := http.DefaultTransport
	http.DefaultTransport = codexDiskSnapshotTransport(func(r *http.Request) (*http.Response, error) {
		local := r.Clone(r.Context())
		local.URL.Scheme, local.URL.Host = endpoint.Scheme, endpoint.Host
		return transport.RoundTrip(local)
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(context.Background(), base)
	http.DefaultTransport = oldTransport
	if errRefresh != nil {
		t.Fatal(errRefresh)
	}
	if calls.Load() != 0 {
		t.Errorf("submitted a removed previous-account refresh grant %d times", calls.Load())
	}
	if updated.CodexRefreshPatch == nil || updated.CodexRefreshPatch.UpstreamRefreshed() {
		t.Error("disk replacement was misreported as a completed upstream renewal")
	}
	cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
		t.Helper()
		grant, _ := candidate.Metadata["refresh_token"].(string)
		if candidate.Metadata["access_token"] != "replacement-access" || candidate.Metadata["account_id"] != "replacement-account" || grant != "" {
			t.Errorf("%s mixed replacement credentials with the previous authorization", stage)
		}
	})
	assertHomeExpirationBearer(t, cold, "replacement-access")
}

func TestCodexDiskReplacementSurvivesConfigurationSave(t *testing.T) {
	for _, typedStorage := range []bool{false, true} {
		name := "metadata"
		if typedStorage {
			name = "token-storage"
		}
		t.Run(name, func(t *testing.T) {
			cfg, _, store, path, stale := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", false)
			disk := map[string]any{"type": "codex", "access_token": "replacement-access", "account_id": "replacement-account", "last_refresh": "2000-01-01T00:00:00Z"}
			if errWrite := codexauth.WriteJSONFileAtomic(path, disk); errWrite != nil {
				t.Fatal(errWrite)
			}
			stale.Metadata["notes"] = "admin-update"
			if typedStorage {
				stale.Storage = &codexauth.CodexTokenStorage{AccessToken: "outer-old", RefreshToken: "outer-grant", AccountID: "acc-team-1"}
			}
			if _, errSave := store.Save(t.Context(), stale); errSave != nil {
				t.Fatal(errSave)
			}
			check := func(stage string, candidate *auth.Auth) {
				t.Helper()
				if candidate.Metadata["access_token"] != "replacement-access" || candidate.Metadata["account_id"] != "replacement-account" || candidate.Metadata["notes"] != "admin-update" {
					t.Errorf("%s replaced disk credentials during an ordinary configuration save", stage)
				}
				if grant, _ := candidate.Metadata["refresh_token"].(string); grant != "" {
					t.Errorf("%s resurrected a previous account grant", stage)
				}
				if _, staleSIWC := candidate.Metadata["siwc"]; staleSIWC {
					t.Errorf("%s resurrected a SIWC partition removed from the complete disk snapshot", stage)
				}
			}
			check("saved-memory", stale)
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if errDecode := json.Unmarshal(raw, &disk); errDecode != nil {
				t.Fatal(errDecode)
			}
			check("disk", &auth.Auth{Metadata: disk})
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("cold load: %v count=%d", errLoad, len(loaded))
			}
			check("cold-file", loaded[0])
			assertHomeExpirationBearer(t, loaded[0], "replacement-access")
		})
	}
}

func TestCodexSIWCDiskReplacementDoesNotRestoreRemovedGrant(t *testing.T) {
	for _, removeRegistration := range []bool{false, true} {
		t.Run(map[bool]string{false: "registration-retained", true: "registration-removed"}[removeRegistration], func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2000-01-01T00:00:00Z", true)
			cfg.Home.Enabled = false
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			delete(base.Metadata, "refresh_token")
			base.Metadata["siwc"].(map[string]any)["scope"] = "old-scope"
			base.Metadata["siwc"].(map[string]any)["scopes"] = []any{"old-scope"}
			var errUpdate error
			base, errUpdate = manager.Update(t.Context(), base)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			disk := base.Clone()
			disk.Metadata["siwc"] = map[string]any{"access_token": "replacement-siwc", "expired": "2000-01-01T00:00:00Z", "client_id": "oaiapp_test", "device_id": homeExplicit}
			if removeRegistration {
				delete(disk.Metadata["siwc"].(map[string]any), "client_id")
				delete(disk.Metadata["siwc"].(map[string]any), "device_id")
			}
			if errWrite := codexauth.WriteJSONFileAtomic(path, disk.Metadata); errWrite != nil {
				t.Fatal(errWrite)
			}
			updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			if updated.CodexRefreshPatch == nil || updated.CodexRefreshPatch.UpstreamRefreshed() {
				t.Error("disk SIWC replacement was misreported as an upstream renewal")
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				nested := candidate.Metadata["siwc"].(map[string]any)
				if nested["access_token"] != "replacement-siwc" {
					t.Errorf("%s lost disk replacement bearer", stage)
				}
				if grant, _ := nested["refresh_token"].(string); grant != "" {
					t.Errorf("%s restored the removed previous SIWC grant", stage)
				}
				for _, key := range []string{"client_id", "device_id", "scope", "scopes"} {
					want, present := disk.Metadata["siwc"].(map[string]any)[key]
					if !present {
						want = ""
					}
					if value, exists := nested[key]; (present && !exists) || (exists && value != want) {
						t.Errorf("%s restored or changed SIWC %s", stage, key)
					}
				}
			})
			assertHomeExpirationBearer(t, cold, "replacement-siwc")
			var renewals atomic.Int32
			renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				renewals.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"unexpected-local-renewal","refresh_token":"unexpected-new-grant","expires_in":7200}`))
			}))
			t.Cleanup(renewal.Close)
			t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
			warm, _ := manager.GetByID(base.ID)
			if _, errNext := executor.NewCodexExecutor(cfg).Refresh(t.Context(), warm); errNext != nil {
				t.Fatal(errNext)
			}
			if renewals.Load() != 0 {
				t.Error("next Manager refresh submitted the removed SIWC grant")
			}

		})
	}
}

func TestCodexSIWCDiskSnapshotClearsRemovedIdentity(t *testing.T) {
	for _, removePartition := range []bool{false, true} {
		t.Run(map[bool]string{false: "grant-rotation", true: "partition-removed"}[removePartition], func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", true)
			cfg.Home.Enabled = false
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			delete(base.Metadata, "refresh_token")
			base.Metadata["siwc"].(map[string]any)["id_token"] = "old-member-id-token"
			var err error
			base, err = manager.Update(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			disk := base.Clone()
			if removePartition {
				delete(disk.Metadata, "siwc")
			} else {
				nested := disk.Metadata["siwc"].(map[string]any)
				nested["refresh_token"] = "replacement-grant"
				delete(nested, "id_token")
			}
			if err = codexauth.WriteJSONFileAtomic(path, disk.Metadata); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"resurrected","refresh_token":"resurrected-grant","expires_in":7200}`))
			}))
			t.Cleanup(renewal.Close)
			t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Error("submitted a grant from the removed disk partition")
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				raw, present := candidate.Metadata["siwc"]
				if removePartition {
					if present {
						t.Errorf("%s restored the removed SIWC partition", stage)
					}
					return
				}
				nested, _ := raw.(map[string]any)
				if token, _ := nested["id_token"].(string); token != "" {
					t.Errorf("%s restored the removed ID token", stage)
				}
				if nested["refresh_token"] != "replacement-grant" || nested["access_token"] != "nested" {
					t.Errorf("%s lost the disk grant rotation", stage)
				}
			})
			wantBearer := "nested"
			if removePartition {
				server, received, _ := homeWireServer(t)
				cold.Attributes["base_url"] = server.URL
				_, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse})
				if errExecute == nil {
					t.Error("missing selected SIWC credentials were accepted")
				}
				select {
				case <-received:
					t.Error("request used credentials from the removed partition")
				default:
				}
				// The administrator can explicitly route subsequent requests to outer OAuth.
				cold.Metadata["use_siwc"] = false
				wantBearer = "outer-old"
			}
			assertHomeExpirationBearer(t, cold, wantBearer)
		})
	}
}
