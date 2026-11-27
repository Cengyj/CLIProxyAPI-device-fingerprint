package helps_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
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

func homeGrantFixture(t *testing.T, file bool, nestedExpiry string, useSIWC bool) (*config.Config, *auth.Manager, *fileauth.FileTokenStore, string, *auth.Auth) {
	t.Helper()
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	initial := &auth.Auth{ID: "audit.json", FileName: "audit.json", Provider: "codex", Attributes: map[string]string{}, Metadata: map[string]any{
		"type": "codex", "access_token": "outer-old", "refresh_token": "outer-grant", "expired": "2000-01-01T00:00:00Z", "use_siwc": useSIWC,
		"account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-aaa", "team"), "plan_type": "team", "plan_type_defaulted": false,
		"siwc": map[string]any{"access_token": "nested", "refresh_token": "grant-old-" + t.Name(), "client_id": "oaiapp_test", "device_id": homeExplicit, "expired": nestedExpiry, "expires_at": nestedExpiry},
	}}
	manager := auth.NewManager(nil, nil, nil)
	base, err := manager.Register(t.Context(), initial)
	if err != nil {
		t.Fatal(err)
	}
	store := fileauth.NewFileTokenStore()
	path := ""
	if file {
		cfg.AuthDir = t.TempDir()
		store.SetBaseDir(cfg.AuthDir)
		path, err = store.Save(t.Context(), base)
		if err != nil {
			t.Fatal(err)
		}
	}
	return cfg, manager, store, path, base
}

func homeGrantResponse(t *testing.T, returned *auth.Auth) {
	t.Helper()
	doc := ojson.NewDocString(`{}`)
	if err := doc.Set("auth", returned); err != nil {
		t.Fatal(err)
	}
	helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return doc.Bytes(), nil })
}

func homeGrantPersist(t *testing.T, cfg *config.Config, manager *auth.Manager, store *fileauth.FileTokenStore, path string, base, updated *auth.Auth, check func(string, *auth.Auth)) *auth.Auth {
	t.Helper()
	check("executor", updated)
	merged, err := manager.UpdateRefreshedAuth(t.Context(), base, updated)
	if err != nil {
		t.Fatal(err)
	}
	check("manager", merged)
	if path == "" {
		return merged
	}
	if _, err = store.Save(t.Context(), merged); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]any
	if errDecode := json.Unmarshal(raw, &disk); errDecode != nil {
		t.Fatal(errDecode)
	}
	check("disk", &auth.Auth{Provider: "codex", Metadata: disk})
	loaded, err := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("cold load: %v count=%d", err, len(loaded))
	}
	check("cold-file", loaded[0])
	return loaded[0]
}

func TestCodexHomeSIWCRefreshGrantOnly(t *testing.T) {
	const past, future = "2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z"
	for _, tc := range []struct {
		name                                                                                string
		expired, rejectedBearer, rejectedGrant, earliest, rejectLocal, sparse, outerMissing bool
		calls                                                                               int32
	}{
		{name: "valid-bearer"},
		{name: "valid-sparse", sparse: true},
		{name: "grant-only-outer-error", outerMissing: true},
		{name: "both-fail-save-grant", expired: true, rejectLocal: true, outerMissing: true, calls: 1},
		{name: "expired-bearer", expired: true, calls: 1},
		{name: "rejected-bearer", rejectedBearer: true, calls: 1},
		{name: "previous-grant-rejected", expired: true, rejectedGrant: true, calls: 1},
		{name: "earliest-window", expired: true, earliest: true},
		{name: "new-grant-rejected", expired: true, rejectLocal: true, calls: 1},
	} {
		for _, file := range []bool{false, true} {
			persistence := "memory"
			if file {
				persistence = "file"
			}
			t.Run(tc.name+"/"+persistence, func(t *testing.T) {
				expiry := future
				if tc.expired {
					expiry = past
				}
				cfg, manager, store, path, base := homeGrantFixture(t, file, expiry, true)
				oldGrant := base.Metadata["siwc"].(map[string]any)["refresh_token"].(string)
				if tc.rejectedBearer {
					base.RejectedSIWCAccessToken = "nested"
				}
				if tc.rejectedGrant {
					base.RejectedSIWCRefreshToken = oldGrant
				}
				if tc.earliest {
					base.Metadata["siwc"].(map[string]any)["earliest_refresh_at"] = future
					var errUpdate error
					base, errUpdate = manager.Update(t.Context(), base)
					if errUpdate != nil {
						t.Fatal(errUpdate)
					}
				}
				if file {
					if errWrite := codexauth.WriteJSONFileAtomic(path, base.Metadata); errWrite != nil {
						t.Fatal(errWrite)
					}
				}
				homeGrant := "grant-home-" + t.Name()
				returned := base.Clone()
				returned.Metadata["access_token"], returned.Metadata["expired"] = "outer-new", future
				returned.Metadata["siwc"].(map[string]any)["refresh_token"] = homeGrant
				if tc.sparse {
					returned.Metadata["siwc"] = map[string]any{"access_token": "nested", "refresh_token": homeGrant}
				}
				if tc.outerMissing {
					delete(returned.Metadata, "access_token")
				}
				homeGrantResponse(t, returned)
				var calls atomic.Int32
				requests := make(chan string, 4)
				localGrant := "local-grant-" + t.Name()
				localReply := ojson.NewDocString(`{"access_token":"local-access","expires_in":7200}`)
				if errSet := localReply.Set("refresh_token", localGrant); errSet != nil {
					t.Fatal(errSet)
				}
				renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					requests <- r.PostFormValue("refresh_token")
					if r.PostFormValue("client_id") != "oaiapp_test" {
						t.Error("wrong SIWC client")
					}
					w.Header().Set("Content-Type", "application/json")
					if tc.rejectLocal {
						http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
						return
					}
					_, _ = w.Write(localReply.Bytes())
				}))
				t.Cleanup(renewal.Close)
				t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
				updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
				if errRefresh != nil {
					t.Fatal(errRefresh)
				}
				if calls.Load() != tc.calls {
					t.Fatalf("local renewals=%d want=%d", calls.Load(), tc.calls)
				}
				if tc.calls != 0 && <-requests != homeGrant {
					t.Error("immediate renewal submitted the superseded Home grant")
				}
				patch := updated.CodexRefreshPatch
				if patch == nil || patch.RefreshedOuter() == tc.outerMissing || !patch.RefreshedSIWC() {
					t.Fatal("missing adopted credential partition")
				}
				if (patch.OuterError() != nil) != tc.outerMissing {
					t.Error("incorrect outer partition error")
				}
				if tc.outerMissing && patch.UpstreamRefreshed() {
					t.Error("grant adoption misreported bearer renewal")
				}
				if (patch.SIWCError() != nil) != tc.rejectLocal {
					t.Error("incorrect SIWC partition error")
				}
				if tc.rejectLocal && patch.FailedSIWCRefreshToken() != homeGrant {
					t.Error("rejection is bound to the superseded grant")
				}
				wantGrant, wantAccess := homeGrant, "nested"
				if tc.calls != 0 && !tc.rejectLocal {
					wantGrant, wantAccess = localGrant, "local-access"
				}
				check := func(stage string, candidate *auth.Auth) {
					t.Helper()
					nested := candidate.Metadata["siwc"].(map[string]any)
					if nested["refresh_token"] != wantGrant || nested["access_token"] != wantAccess {
						t.Errorf("%s lost the adopted SIWC token pair", stage)
					}
					wantOuter := "outer-new"
					if tc.outerMissing {
						wantOuter = "outer-old"
					}
					if candidate.Metadata["access_token"] != wantOuter {
						t.Errorf("%s lost outer success", stage)
					}
					if _, _, due := auth.CodexSIWCNeedsRefresh(candidate, time.Now()); due != tc.rejectLocal {
						t.Errorf("%s incorrect SIWC renewal decision", stage)
					}
					if tc.earliest && nested["earliest_refresh_at"] != future {
						t.Errorf("%s lost earliest renewal window", stage)
					}
				}
				cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, check)
				merged, _ := manager.GetByID(base.ID)
				if tc.rejectLocal && merged.RejectedSIWCRefreshToken != homeGrant {
					t.Error("Manager did not retain the actually rejected Home grant")
				}
				upstream, frames, _ := homeWireServer(t)
				cold.Attributes["base_url"] = upstream.URL
				if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
					t.Fatal(errExecute)
				}
				if wire := <-frames; wire.headers.Get("Authorization") != "Bearer "+wantAccess {
					t.Error("cold request used superseded bearer")
				}
				if tc.rejectLocal || tc.outerMissing {
					return
				}
				// Advance the credential state to a deterministic due time without sleeping.
				next := cold.Clone()
				nested := next.Metadata["siwc"].(map[string]any)
				nested["expired"], nested["expires_at"] = past, past
				delete(nested, "earliest_refresh_at")
				if file {
					if errWrite := codexauth.WriteJSONFileAtomic(path, next.Metadata); errWrite != nil {
						t.Fatal(errWrite)
					}
				}
				localCfg := *cfg
				localCfg.Home.Enabled = false
				if _, errNext := executor.NewCodexExecutor(&localCfg).Refresh(t.Context(), next); errNext != nil {
					t.Fatal(errNext)
				}
				if calls.Load() != tc.calls+1 {
					t.Fatalf("next local renewal count=%d want=%d", calls.Load(), tc.calls+1)
				}
				if submitted := <-requests; submitted != wantGrant {
					t.Error("next local renewal did not use the persisted grant")
				}
			})
		}
	}
}

func TestCodexHomeSparsePlanOnly(t *testing.T) {
	for _, tc := range []struct {
		name                string
		fields              map[string]any
		attributes          map[string]string
		plan, alias, device string
		defaulted           bool
	}{
		{name: "explicit-free", fields: map[string]any{"plan_type": "free"}, plan: "free", device: homeAccount},
		{name: "claim-plan-free", fields: map[string]any{"chatgpt_plan_type": "free"}, plan: "free", alias: "free", device: homeAccount},
		{name: "attribute-plan-free", attributes: map[string]string{"plan_type": "free"}, plan: "free", device: homeAccount},
		{name: "canonical-plan-precedes-attribute", fields: map[string]any{"plan_type": "free"}, attributes: map[string]string{"plan_type": "team"}, plan: "free", device: homeAccount},
		{name: "canonical-plan-provenance", fields: map[string]any{"plan_type": "free"}, attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"}, plan: "free", device: homeAccount},
		{name: "repeated-team", fields: map[string]any{"plan_type": "team"}, plan: "team", device: homeMemberA},
		{name: "default-provenance", fields: map[string]any{"plan_type": "free", "plan_type_defaulted": true}, plan: "free", alias: "team", device: homeMemberA, defaulted: true},
		{name: "clear-plan", fields: map[string]any{"plan_type": nil}, plan: "free", device: homeAccount, defaulted: true},
		{name: "empty-plan", fields: map[string]any{"plan_type": ""}, plan: "free", device: homeAccount, defaulted: true},
		{name: "wrong-type-plan", fields: map[string]any{"plan_type": true}, plan: "free", device: homeAccount, defaulted: true},
		{name: "clear-claim-plan", fields: map[string]any{"chatgpt_plan_type": nil}, plan: "free", device: homeAccount, defaulted: true},
	} {
		for _, mode := range []string{"off", "device"} {
			for _, file := range []bool{false, true} {
				persistence := "memory"
				if file {
					persistence = "file"
				}
				t.Run(tc.name+"/"+mode+"/"+persistence, func(t *testing.T) {
					server, frames, _ := homeWireServer(t)
					cfg, manager, store, path, base := homeGrantFixture(t, file, "2099-01-01T00:00:00Z", false)
					cfg.Codex.DeviceFingerprintMode = mode
					returned := &auth.Auth{Provider: "codex", Attributes: tc.attributes, Metadata: map[string]any{"access_token": "outer-old", "expired": "2099-01-01T00:00:00Z"}}
					for key, value := range tc.fields {
						returned.Metadata[key] = value
					}
					homeGrantResponse(t, returned)
					exec := executor.NewCodexExecutor(cfg)
					options := core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
					request := core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}
					base.Attributes["base_url"] = server.URL
					if _, errExecute := exec.Execute(t.Context(), base, request, options); errExecute != nil {
						t.Fatal(errExecute)
					}
					<-frames
					updated, errRefresh := exec.Refresh(t.Context(), base)
					if errRefresh != nil {
						t.Fatal(errRefresh)
					}
					check := func(stage string, candidate *auth.Auth) {
						t.Helper()
						if candidate.Metadata["account_id"] != "acc-team-1" || candidate.Metadata["id_token"] != base.Metadata["id_token"] || candidate.Metadata["chatgpt_user_id"] != "user-aaa" {
							t.Errorf("%s cleared unchanged-bearer identity on a sparse plan update", stage)
						}
						if candidate.Metadata["plan_type"] != tc.plan || candidate.Metadata["plan_type_defaulted"] != tc.defaulted {
							t.Errorf("%s incorrect plan or provenance", stage)
						}
						if alias, _ := candidate.Metadata["chatgpt_plan_type"].(string); alias != tc.alias {
							t.Errorf("%s revived an inherited plan alias: got %s want %s", stage, alias, tc.alias)
						}
					}
					cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, check)
					warm, _ := manager.GetByID(base.ID)
					warm.Attributes["base_url"] = server.URL
					wantDevice := tc.device
					if mode == "off" {
						wantDevice = "client"
					}
					if _, errExecute := exec.Execute(t.Context(), warm, request, options); errExecute != nil {
						t.Fatal(errExecute)
					}
					assertHomeWire(t, <-frames, wantDevice, "acc-team-1", "outer-old")
					cold.Attributes["base_url"] = server.URL
					if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, request, options); errExecute != nil {
						t.Fatal(errExecute)
					}
					assertHomeWire(t, <-frames, wantDevice, "acc-team-1", "outer-old")
				})
			}
		}
	}
}

func TestCodexHomeGrantPartitionCAS(t *testing.T) {
	for _, replaced := range []string{"outer", "siwc", "siwc-after-rejection"} {
		for _, file := range []bool{false, true} {
			persistence := "memory"
			if file {
				persistence = "file"
			}
			t.Run(replaced+"/"+persistence, func(t *testing.T) {
				expiry := "2099-01-01T00:00:00Z"
				if replaced == "siwc-after-rejection" {
					expiry = "2000-01-01T00:00:00Z"
					renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.PostFormValue("refresh_token") != "home-grant-"+t.Name() {
							t.Error("rejection fixture received a different grant")
						}
						http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
					}))
					t.Cleanup(renewal.Close)
					t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
				}
				cfg, manager, store, path, base := homeGrantFixture(t, file, expiry, true)
				returned := base.Clone()
				returned.Metadata["access_token"], returned.Metadata["expired"] = "outer-home", "2099-01-01T00:00:00Z"
				returned.Metadata["siwc"].(map[string]any)["refresh_token"] = "home-grant-" + t.Name()
				homeGrantResponse(t, returned)
				updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
				if errRefresh != nil {
					t.Fatal(errRefresh)
				}
				current := base.Clone()
				current.Metadata["codex_device_fingerprint"] = "off"
				current.Metadata["codex_installation_id"] = homeExplicit
				current.Metadata["operator_note"] = "edited"
				current.ProxyURL = "http://127.0.0.1:29999"
				current.Attributes["header:X-Operator"] = "keep"
				wantOuter, wantAccess, wantGrant := "outer-home", "nested", "home-grant-"+t.Name()
				if replaced == "outer" {
					current.Metadata["access_token"], current.Metadata["refresh_token"] = "outer-concurrent", "outer-concurrent-grant"
					current.Metadata["account_id"] = "account-concurrent"
					wantOuter = "outer-concurrent"
				} else {
					sub := current.Metadata["siwc"].(map[string]any)
					sub["access_token"], sub["refresh_token"] = "nested-concurrent", "grant-concurrent"
					sub["expired"], sub["expires_at"] = "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"
					wantAccess, wantGrant = "nested-concurrent", "grant-concurrent"
				}
				if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
					t.Fatal(errUpdate)
				}
				if file {
					if errWrite := codexauth.WriteJSONFileAtomic(path, current.Metadata); errWrite != nil {
						t.Fatal(errWrite)
					}
				}
				merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
				if errMerge != nil {
					t.Fatal(errMerge)
				}
				check := func(stage string, candidate *auth.Auth) {
					t.Helper()
					sub := candidate.Metadata["siwc"].(map[string]any)
					if candidate.Metadata["access_token"] != wantOuter || sub["access_token"] != wantAccess || sub["refresh_token"] != wantGrant {
						t.Errorf("%s did not independently version the credential partitions", stage)
					}
					if candidate.Metadata["codex_device_fingerprint"] != "off" || candidate.Metadata["codex_installation_id"] != homeExplicit || candidate.Metadata["operator_note"] != "edited" {
						t.Errorf("%s overwrote concurrent administrator settings", stage)
					}
				}
				check("manager", merged)
				if merged.RejectedSIWCRefreshToken != "" || merged.RequiresSignIn || merged.ProxyURL != current.ProxyURL || merged.Attributes["header:X-Operator"] != "keep" {
					t.Error("stale rejection or settings crossed the partition merge")
				}
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
					check("disk", &auth.Auth{Metadata: disk})
					cold, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
					if errLoad != nil || len(cold) != 1 {
						t.Fatalf("cold load: %v count=%d", errLoad, len(cold))
					}
					merged = cold[0]
					check("cold", merged)
				}
				upstream, frames, _ := homeWireServer(t)
				merged.ProxyURL = ""
				delete(merged.Metadata, "proxy_url")
				merged.Attributes["base_url"] = upstream.URL
				if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), merged, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
					t.Fatal(errExecute)
				}
				if wire := <-frames; wire.headers.Get("Authorization") != "Bearer "+wantAccess {
					t.Error("request sent a superseded bearer after independent partition merge")
				}
			})
		}
	}
}

func TestCodexLocalSIWCIdentityLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, member string
		sameBearer   bool
	}{
		{name: "same-bearer", member: "member-a", sameBearer: true},
		{name: "rotated-same-subject", member: "member-a"},
		{name: "rotated-different-subject", member: "member-b"},
	} {
		for _, stream := range []bool{false, true} {
			for _, file := range []bool{false, true} {
				name := tc.name + "/execute"
				if stream {
					name = tc.name + "/stream"
				}
				if file {
					name += "/file"
				} else {
					name += "/memory"
				}
				t.Run(name, func(t *testing.T) {
					bearer := func(member string, issue int) string {
						doc := ojson.NewDocString(`{"iss":"https://local-issuer.invalid","aud":"siwc-client"}`)
						for key, value := range map[string]any{"sub": member, "iat": issue, "https://api\\.openai\\.com/auth.chatgpt_account_id": "workspace", "https://api\\.openai\\.com/auth.chatgpt_user_id": member} {
							if errSet := doc.Set(key, value); errSet != nil {
								t.Fatal(errSet)
							}
						}
						return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
					}
					oldBearer, newBearer := bearer("member-a", 1), bearer(tc.member, 2)
					if tc.sameBearer {
						newBearer = oldBearer
					}
					upstream, frames, connections := homeWireServer(t)
					cfg, manager, store, path, base := homeGrantFixture(t, file, "2000-01-01T00:00:00Z", true)
					cfg.Home.Enabled = false
					base.Metadata["expired"] = "2099-01-01T00:00:00Z"
					base.Metadata["websockets"] = true
					base.Attributes["websockets"] = "true"
					base.Attributes["base_url"] = upstream.URL
					sub := base.Metadata["siwc"].(map[string]any)
					sub["access_token"], sub["id_token"] = oldBearer, oldBearer
					sub["scope"], sub["scopes"], sub["custom_registration"] = "openid", []any{"openid"}, "keep"
					var errUpdate error
					base, errUpdate = manager.Update(t.Context(), base)
					if errUpdate != nil {
						t.Fatal(errUpdate)
					}
					if file {
						if errWrite := codexauth.WriteJSONFileAtomic(path, base.Metadata); errWrite != nil {
							t.Fatal(errWrite)
						}
					}
					exec := executor.NewCodexAutoExecutor(cfg)
					t.Cleanup(func() { exec.CloseExecutionSession(t.Name()) })
					options := core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"Session-Id": {t.Name()}, "X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}, Metadata: map[string]any{core.CallerScopeMetadataKey: "local-siwc", core.ExecutionSessionMetadataKey: t.Name()}}
					execute := func(candidate *auth.Auth, body []byte) error {
						ctx := core.WithDownstreamWebsocket(t.Context())
						req := core.Request{Model: "gpt-5.4", Payload: body}
						if !stream {
							_, errExecute := exec.Execute(ctx, candidate, req, options)
							return errExecute
						}
						result, errExecute := exec.ExecuteStream(ctx, candidate, req, options)
						if errExecute != nil {
							return errExecute
						}
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								return chunk.Err
							}
						}
						return nil
					}
					if errExecute := execute(base, []byte(homeBusinessBody)); errExecute != nil {
						t.Fatal(errExecute)
					}
					first := <-frames
					if first.connection != 1 || first.headers.Get("Authorization") != "Bearer "+oldBearer {
						t.Fatal("initial physical handshake used wrong credential")
					}
					response := ojson.NewDocString(`{"expires_in":7200}`)
					for key, value := range map[string]any{"access_token": newBearer, "refresh_token": "local-next-" + t.Name()} {
						if errSet := response.Set(key, value); errSet != nil {
							t.Fatal(errSet)
						}
					}
					var calls atomic.Int32
					renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						if r.PostFormValue("refresh_token") != sub["refresh_token"] {
							t.Error("local SIWC renewal submitted wrong grant")
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(response.Bytes())
					}))
					t.Cleanup(renewal.Close)
					t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
					updated, errRefresh := exec.Refresh(t.Context(), base)
					if errRefresh != nil || calls.Load() != 1 {
						t.Fatalf("local refresh: %v, calls=%d", errRefresh, calls.Load())
					}
					check := func(stage string, candidate *auth.Auth) {
						t.Helper()
						nested := candidate.Metadata["siwc"].(map[string]any)
						wantID := ""
						if tc.sameBearer {
							wantID = oldBearer
						}
						if id, _ := nested["id_token"].(string); id != wantID {
							t.Errorf("%s retained an ID token from a replaced bearer or lost unchanged identity", stage)
						}
						if nested["access_token"] != newBearer || nested["refresh_token"] != "local-next-"+t.Name() || nested["scope"] != "openid" || nested["custom_registration"] != "keep" {
							t.Errorf("%s lost accepted credential or registration data", stage)
						}
					}
					cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, check)
					cold.Attributes["base_url"] = upstream.URL
					continuation := ojson.NewDocString(homeBusinessBody)
					if errSet := continuation.Set("previous_response_id", "r0"); errSet != nil {
						t.Fatal(errSet)
					}
					errContinue := execute(cold, continuation.Bytes())
					if tc.member != "member-a" {
						if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
							t.Fatalf("changed subject continuation: %v", errContinue)
						}
						select {
						case frame := <-frames:
							t.Fatalf("changed-subject continuation reached physical connection %d", frame.connection)
						default:
						}
					} else {
						if errContinue != nil {
							t.Fatal(errContinue)
						}
						frame := <-frames
						if frame.connection != 1 || connections.Load() != 1 || frame.headers.Get("Authorization") != "Bearer "+oldBearer {
							t.Fatal("unchanged subject did not reuse its physical handshake")
						}
					}
					exec.CloseExecutionSession(t.Name())
					if errExecute := execute(cold, []byte(homeBusinessBody)); errExecute != nil {
						t.Fatal(errExecute)
					}
					frame := <-frames
					if frame.connection != 2 || connections.Load() != 2 || frame.headers.Get("Authorization") != "Bearer "+newBearer {
						t.Fatal("fresh physical handshake did not use renewed credential")
					}
					if _, errHTTP := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, options); errHTTP != nil {
						t.Fatal(errHTTP)
					}
					if frame := <-frames; frame.headers.Get("Authorization") != "Bearer "+newBearer {
						t.Error("HTTP request did not use renewed bearer")
					}
				})
			}
		}
	}
}

func TestCodexHomeSparsePlanDoesNotInventHeader(t *testing.T) {
	injectFalse := false
	for _, explicitFalse := range []bool{false, true} {
		name := "default"
		if explicitFalse {
			name = "explicit-false"
		}
		t.Run(name, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, true, "2099-01-01T00:00:00Z", false)
			if explicitFalse {
				cfg.Codex.DeviceFingerprintInjectMissing = &injectFalse
			}
			homeGrantResponse(t, &auth.Auth{Metadata: map[string]any{"access_token": "outer-old", "expired": "2099-01-01T00:00:00Z", "plan_type": "free"}})
			updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
				t.Helper()
				if candidate.Metadata["account_id"] != "acc-team-1" || candidate.Metadata["plan_type"] != "free" {
					t.Errorf("%s lost sparse plan identity", stage)
				}
			})
			upstream, frames, _ := homeWireServer(t)
			cold.Attributes["base_url"] = upstream.URL
			if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
				t.Fatal(errExecute)
			}
			wire := <-frames
			if wire.headers.Get("X-Codex-Turn-Metadata") != "" {
				t.Error("fingerprint invented a missing turn metadata header")
			}
			if wire.headers.Get("Authorization") != "Bearer outer-old" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != homeAccount {
				t.Error("missing optional header changed the selected identity or existing payload field")
			}
		})
	}
}
