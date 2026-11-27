package helps_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexRefreshStorageFollowsAcceptedSnapshot(t *testing.T) {
	for _, source := range []string{"disk-sparse", "disk-siwc-removed", "home"} {
		t.Run(source, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", false)
			cfg.Home.Enabled = source == "home"
			useSIWC := false
			initialStorage := &codexauth.CodexTokenStorage{
				AccessToken: "outer-old", RefreshToken: "outer-grant", AccountID: "acc-team-1",
				IDToken: base.Metadata["id_token"].(string), Expire: "2000-01-01T00:00:00Z",
				UseSIWC: &useSIWC, SIWC: base.Clone().Metadata["siwc"].(map[string]any), Metadata: base.Clone().Metadata,
			}
			base.Storage = initialStorage
			accepted := base.Clone()
			accepted.Metadata["expired"] = "2099-01-01T00:00:00Z"
			delete(accepted.Metadata, "refresh_token")
			delete(accepted.Metadata, "id_token")
			if source == "disk-siwc-removed" {
				delete(accepted.Metadata, "siwc")
			} else {
				accepted.Metadata["siwc"].(map[string]any)["device_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			}
			if source == "home" {
				accepted.Metadata["access_token"] = "outer-new"
				accepted.Metadata["refresh_token"] = "outer-new-grant"
				homeGrantResponse(t, accepted)
			} else if err := codexauth.WriteJSONFileAtomic(path, accepted.Metadata); err != nil {
				t.Fatal(err)
			}
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			storage, ok := updated.Storage.(*codexauth.CodexTokenStorage)
			if !ok || storage == nil {
				t.Fatal("refresh lost the typed storage snapshot")
			}
			if storage == initialStorage || initialStorage.IDToken == "" || initialStorage.RefreshToken != "outer-grant" {
				t.Error("refresh mutated the caller's storage snapshot")
			}
			if storage.AccessToken != updated.Metadata["access_token"] || storage.Expire != updated.Metadata["expired"] {
				t.Error("typed storage retained a superseded bearer or expiry")
			}
			if source != "home" && (storage.RefreshToken != "" || storage.IDToken != "") {
				t.Error("typed storage restored cleared outer credentials")
			}
			if source == "disk-siwc-removed" && len(storage.SIWC) != 0 {
				t.Error("typed storage retained a removed SIWC partition")
			}
			newPath := filepath.Join(t.TempDir(), "copied.json")
			if err = storage.SaveTokenToFile(newPath); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(newPath)
			if err != nil {
				t.Fatal(err)
			}
			var copyMap map[string]any
			if err = json.Unmarshal(raw, &copyMap); err != nil {
				t.Fatal(err)
			}
			if copyMap["access_token"] != updated.Metadata["access_token"] || copyMap["expired"] != updated.Metadata["expired"] {
				t.Error("direct token storage save wrote the superseded credential")
			}
			if source != "home" {
				if grant, _ := copyMap["refresh_token"].(string); grant != "" {
					t.Error("direct token storage save restored a removed grant")
				}
			}
			if source == "disk-siwc-removed" {
				if nested, _ := copyMap["siwc"].(map[string]any); codexauth.SIWCAccessToken(nested) != "" {
					t.Error("direct token storage save restored a removed SIWC partition")
				}
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				if candidate.Metadata["access_token"] != updated.Metadata["access_token"] {
					t.Errorf("%s changed the accepted credential", stage)
				}
			})
			assertHomeExpirationBearer(t, cold, updated.Metadata["access_token"].(string))
		})
	}
}

func TestCodexHomeSameBearerMemberRejectsLatePatch(t *testing.T) {
	for _, file := range []bool{false, true} {
		name := "memory"
		if file {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, file, "2099-01-01T00:00:00Z", false)
			base.Metadata["chatgpt_user_id"] = "user-old"
			base.Storage = (&codexauth.CodexTokenStorage{}).WithMetadataSnapshot(base.Metadata)
			var err error
			base, err = manager.Register(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			if file {
				if err = codexauth.WriteJSONFileAtomic(path, base.Metadata); err != nil {
					t.Fatal(err)
				}
			}
			returned := base.Clone()
			returned.Metadata["chatgpt_user_id"] = "user-aaa"
			returned.Metadata["expired"] = "2099-01-01T00:00:00Z"
			returned.Metadata["siwc"].(map[string]any)["access_token"] = "nested-new"
			homeGrantResponse(t, returned)
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			current := base.Clone()
			current.Metadata["chatgpt_user_id"] = "user-bbb"
			current.Metadata["operator_note"] = "concurrent-admin"
			current.Storage = (&codexauth.CodexTokenStorage{}).WithMetadataSnapshot(current.Metadata)
			if _, err = manager.Update(t.Context(), current); err != nil {
				t.Fatal(err)
			}
			if file {
				if err = codexauth.WriteJSONFileAtomic(path, current.Metadata); err != nil {
					t.Fatal(err)
				}
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				if stage == "executor" {
					return
				}
				if candidate.Metadata["chatgpt_user_id"] != "user-bbb" || candidate.Metadata["operator_note"] != "concurrent-admin" {
					t.Errorf("%s replaced a newer same-bearer member or administrator edit", stage)
				}
				if candidate.Metadata["siwc"].(map[string]any)["access_token"] != "nested-new" {
					t.Errorf("%s rejected the independent SIWC renewal", stage)
				}
				if storage, ok := candidate.Storage.(*codexauth.CodexTokenStorage); ok && storage != nil {
					if storage.Metadata["chatgpt_user_id"] != "user-bbb" || codexauth.SIWCAccessToken(storage.SIWC) != "nested-new" {
						t.Errorf("%s storage disagrees with accepted partition versions", stage)
					}
				}
			})
			server, frames, _ := homeWireServer(t)
			cold.Attributes["base_url"] = server.URL
			options := core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
			if _, err = executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, options); err != nil {
				t.Fatal(err)
			}
			assertHomeWire(t, <-frames, homeMemberB, "acc-team-1", "outer-old")
		})
	}
}

func localCodexDiskRenewal(t *testing.T, calls *atomic.Int32) func() {
	t.Helper()
	renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"unexpected-renewal","refresh_token":"unexpected-grant","expires_in":7200}`))
	}))
	t.Cleanup(renewal.Close)
	endpoint, err := url.Parse(renewal.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	oldTransport := http.DefaultTransport
	http.DefaultTransport = codexDiskSnapshotTransport(func(r *http.Request) (*http.Response, error) {
		local := r.Clone(r.Context())
		local.URL.Scheme, local.URL.Host = endpoint.Scheme, endpoint.Host
		return transport.RoundTrip(local)
	})
	restore := func() { http.DefaultTransport = oldTransport }
	t.Cleanup(restore)
	return restore
}

func TestCodexOuterDiskSameBearerUpdate(t *testing.T) {
	for _, scenario := range []string{"grant-removed", "grant-empty", "grant-null", "expiry-only", "account-only", "member-only", "email-removed"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", false)
			cfg.Home.Enabled = false
			delete(base.Metadata, "siwc")
			base.Metadata["refresh_token"] = "old-grant-" + t.Name()
			if scenario == "account-only" || scenario == "member-only" || scenario == "email-removed" {
				base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			}
			if scenario == "email-removed" {
				base.Metadata["email"] = "synthetic@example.test"
			}
			var err error
			base, err = manager.Register(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			disk := base.Clone()
			switch scenario {
			case "grant-removed":
				delete(disk.Metadata, "refresh_token")
			case "grant-empty":
				disk.Metadata["refresh_token"] = ""
			case "grant-null":
				disk.Metadata["refresh_token"] = nil
			case "expiry-only":
				disk.Metadata["expired"] = "2099-01-01T00:00:00Z"
			case "account-only":
				disk.Metadata["account_id"] = "acc-team-2"
			case "member-only":
				disk.Metadata["chatgpt_user_id"] = "user-bbb"
			case "email-removed":
				delete(disk.Metadata, "email")
			}
			if err = codexauth.WriteJSONFileAtomic(path, disk.Metadata); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			restoreTransport := localCodexDiskRenewal(t, &calls)
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			restoreTransport()
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Errorf("disk-only adoption submitted the previous grant %d times", calls.Load())
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				if candidate.Metadata["access_token"] != "outer-old" {
					t.Errorf("%s did not retain disk bearer", stage)
				}
				switch scenario {
				case "grant-removed", "grant-empty", "grant-null":
					if grant, _ := candidate.Metadata["refresh_token"].(string); grant != "" {
						t.Errorf("%s restored a cleared outer grant", stage)
					}
				case "expiry-only":
					if expiry, ok := candidate.OuterExpirationTime(); !ok || expiry.Year() != 2099 {
						t.Errorf("%s lost renewed expiry", stage)
					}
				case "account-only":
					if candidate.Metadata["account_id"] != "acc-team-2" {
						t.Errorf("%s lost explicit account selection", stage)
					}
				case "member-only":
					if candidate.Metadata["chatgpt_user_id"] != "user-bbb" {
						t.Errorf("%s lost explicit member selection", stage)
					}
				case "email-removed":
					if email, _ := candidate.Metadata["email"].(string); email != "" {
						t.Errorf("%s restored removed credential email", stage)
					}
				}
			})
			server, received, _ := homeWireServer(t)
			cold.Attributes["base_url"] = server.URL
			options := core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
			if _, err = executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, options); err != nil {
				t.Fatal(err)
			}
			wire := <-received
			wantAccount := "acc-team-1"
			if scenario == "account-only" {
				wantAccount = "acc-team-2"
			}
			if wire.headers.Get("Authorization") != "Bearer outer-old" || wire.headers.Get("ChatGPT-Account-ID") != wantAccount {
				t.Error("cold HTTP request used stale credentials or account selection")
			}
			if scenario == "member-only" {
				assertHomeWire(t, wire, homeMemberB, wantAccount, "outer-old")
			}
		})
	}
}

func TestCodexDiskSnapshotUpdateKeepsRejectedGrant(t *testing.T) {
	for _, partition := range []string{"outer", "siwc"} {
		t.Run(partition, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2000-01-01T00:00:00Z", partition == "siwc")
			cfg.Home.Enabled = false
			base.RequiresSignIn = true
			base.RefreshError = &auth.Error{Code: "invalid_grant", Message: "refresh grant rejected", HTTPStatus: http.StatusUnauthorized}
			if partition == "siwc" {
				delete(base.Metadata, "refresh_token")
				base.Metadata["expired"] = "2099-01-01T00:00:00Z"
				base.RejectedSIWCRefreshToken = base.Metadata["siwc"].(map[string]any)["refresh_token"].(string)
			} else {
				delete(base.Metadata, "siwc")
				base.RejectedRefreshToken = base.Metadata["refresh_token"].(string)
			}
			var err error
			base, err = manager.Register(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			disk := base.Clone()
			if partition == "siwc" {
				disk.Metadata["siwc"].(map[string]any)["device_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			} else {
				disk.Metadata["chatgpt_user_id"] = "user-bbb"
			}
			if err = codexauth.WriteJSONFileAtomic(path, disk.Metadata); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			localCodexDiskRenewal(t, &calls)
			updated, err := executor.NewCodexExecutor(cfg).Refresh(auth.WithForceRefresh(t.Context()), base)
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Errorf("a metadata-only disk update retried the rejected grant %d times", calls.Load())
			}
			if updated.CodexRefreshPatch == nil || updated.CodexRefreshPatch.UpstreamRefreshed() {
				t.Error("metadata-only disk adoption reported an upstream renewal")
			}
			homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				if stage != "manager" {
					return
				}
				if !candidate.RequiresSignIn || candidate.RejectedRefreshToken != base.RejectedRefreshToken || candidate.RejectedSIWCRefreshToken != base.RejectedSIWCRefreshToken {
					t.Error("Manager lost the unchanged rejected-grant state")
				}
			})
		})
	}
}

func TestCodexHomeSameBearerExpiryRejectsLatePatch(t *testing.T) {
	for _, partition := range []string{"outer", "siwc"} {
		for _, file := range []bool{false, true} {
			persistence := "memory"
			if file {
				persistence = "file"
			}
			t.Run(partition+"/"+persistence, func(t *testing.T) {
				cfg, manager, store, path, base := homeGrantFixture(t, file, "2000-01-01T00:00:00Z", partition == "siwc")
				returned := base.Clone()
				returned.Metadata["expired"] = "2098-01-01T00:00:00Z"
				returned.Metadata["siwc"].(map[string]any)["expired"] = "2098-01-01T00:00:00Z"
				returned.Metadata["siwc"].(map[string]any)["expires_at"] = "2098-01-01T00:00:00Z"
				if partition == "outer" {
					returned.Metadata["siwc"].(map[string]any)["access_token"] = "nested-new"
				} else {
					returned.Metadata["access_token"] = "outer-new"
				}
				homeGrantResponse(t, returned)
				updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
				if err != nil {
					t.Fatal(err)
				}
				current := base.Clone()
				current.Metadata["operator_note"] = "concurrent-admin"
				if partition == "outer" {
					current.Metadata["expired"] = "2099-01-01T00:00:00Z"
				} else {
					current.Metadata["siwc"].(map[string]any)["expired"] = "2099-01-01T00:00:00Z"
					current.Metadata["siwc"].(map[string]any)["expires_at"] = "2099-01-01T00:00:00Z"
				}
				if _, err = manager.Update(t.Context(), current); err != nil {
					t.Fatal(err)
				}
				if file {
					if err = codexauth.WriteJSONFileAtomic(path, current.Metadata); err != nil {
						t.Fatal(err)
					}
				}
				cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
					t.Helper()
					if stage == "executor" {
						return
					}
					outerExpiry, outerOK := candidate.OuterExpirationTime()
					siwcExpiry, siwcOK := candidate.SIWCRenewalExpirationTime()
					wantOuter, wantSIWC := 2098, 2099
					if partition == "outer" {
						wantOuter, wantSIWC = 2099, 2098
						if candidate.Metadata["siwc"].(map[string]any)["access_token"] != "nested-new" {
							t.Errorf("%s rejected an independent SIWC renewal", stage)
						}
					} else if candidate.Metadata["access_token"] != "outer-new" {
						t.Errorf("%s rejected an independent outer renewal", stage)
					}
					if !outerOK || !siwcOK || outerExpiry.Year() != wantOuter || siwcExpiry.Year() != wantSIWC {
						t.Errorf("%s let a late patch overwrite a newer same-bearer expiry", stage)
					}
					if candidate.Metadata["operator_note"] != "concurrent-admin" {
						t.Errorf("%s lost an administrator edit", stage)
					}
				})
				wantBearer := "outer-old"
				if partition == "siwc" {
					wantBearer = "nested"
				}
				assertHomeExpirationBearer(t, cold, wantBearer)
			})
		}
	}
}

func TestCodexSIWCDiskSameBearerUpdate(t *testing.T) {
	for _, scenario := range []string{"grant-removed", "grant-empty", "grant-null", "partition-null", "partition-empty", "expiry-only", "device-only"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2000-01-01T00:00:00Z", true)
			cfg.Home.Enabled = false
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			delete(base.Metadata, "refresh_token")
			if scenario == "device-only" {
				base.Metadata["siwc"].(map[string]any)["expires_at"] = "2099-01-01T00:00:00Z"
				base.Metadata["siwc"].(map[string]any)["expired"] = "2099-01-01T00:00:00Z"
			}
			var err error
			base, err = manager.Update(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			disk := base.Clone()
			nested := disk.Metadata["siwc"].(map[string]any)
			switch scenario {
			case "grant-removed":
				delete(nested, "refresh_token")
			case "grant-empty":
				nested["refresh_token"] = ""
			case "grant-null":
				nested["refresh_token"] = nil
			case "partition-null":
				disk.Metadata["siwc"] = nil
			case "partition-empty":
				disk.Metadata["siwc"] = map[string]any{}
			case "expiry-only":
				nested["expires_at"] = "2099-01-01T00:00:00Z"
				nested["expired"] = "2099-01-01T00:00:00Z"
			case "device-only":
				nested["device_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			}
			if err = codexauth.WriteJSONFileAtomic(path, disk.Metadata); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"unexpected-renewal","refresh_token":"unexpected-grant","expires_in":7200}`))
			}))
			t.Cleanup(renewal.Close)
			t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
			updated, err := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Errorf("submitted stale disk snapshot grant %d times", calls.Load())
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				got, _ := candidate.Metadata["siwc"].(map[string]any)
				if scenario == "partition-null" || scenario == "partition-empty" {
					if codexauth.SIWCAccessToken(got) != "" {
						t.Errorf("%s restored an explicitly cleared SIWC partition", stage)
					}
					return
				}
				if codexauth.SIWCAccessToken(got) != "nested" {
					t.Errorf("%s did not retain disk bearer", stage)
				}
				switch scenario {
				case "grant-removed", "grant-empty", "grant-null":
					if grant, _ := got["refresh_token"].(string); grant != "" {
						t.Errorf("%s restored a cleared grant", stage)
					}
				case "expiry-only":
					if expiry, ok := candidate.SIWCRenewalExpirationTime(); !ok || expiry.Year() != 2099 {
						t.Errorf("%s lost disk expiry", stage)
					}
					if _, _, due := auth.CodexSIWCNeedsRefresh(candidate, time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)); due {
						t.Errorf("%s still schedules renewed bearer", stage)
					}
				case "device-only":
					if got["device_id"] != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
						t.Errorf("%s lost new disk device", stage)
					}
				}
			})
			if scenario == "partition-null" || scenario == "partition-empty" {
				server, received, _ := homeWireServer(t)
				cold.Attributes["base_url"] = server.URL
				_, err = executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse})
				if err == nil {
					t.Error("cleared SIWC partition was sent")
				}
				select {
				case <-received:
					t.Error("unexpected business request after SIWC clearing")
				default:
				}
			} else {
				assertHomeExpirationBearer(t, cold, "nested")
			}
		})
	}
}
