package helps_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
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

func TestCodexHomeSIWCRenewal(t *testing.T) {
	const past = "2000-01-01T00:00:00Z"
	const future = "2099-01-01T00:00:00Z"
	for _, tc := range []struct {
		name, homeExpiry, access, legacyAccess  string
		outerMissing, rejectGrant, rejectBearer bool
		renewalCalls                            int32
		wantAccess, wantGrant                   string
	}{
		{name: "echo", renewalCalls: 1, wantAccess: "local-access", wantGrant: "local-grant"},
		{name: "echo-local-error", rejectGrant: true, renewalCalls: 1, wantAccess: "siwc-old", wantGrant: "grant-old"},
		{name: "echo-both-fail", outerMissing: true, rejectGrant: true, renewalCalls: 1, wantAccess: "siwc-old", wantGrant: "grant-old"},
		{name: "echo-outer-missing", outerMissing: true, renewalCalls: 1, wantAccess: "local-access", wantGrant: "local-grant"},
		{name: "same-bearer-extended-expiry", homeExpiry: future, wantAccess: "siwc-old", wantGrant: "grant-old"},
		{name: "extension-still-expired", homeExpiry: "2001-01-01T00:00:00Z", renewalCalls: 1, wantAccess: "local-access", wantGrant: "local-grant"},
		{name: "extension-of-rejected-bearer", homeExpiry: future, rejectBearer: true, renewalCalls: 1, wantAccess: "local-access", wantGrant: "local-grant"},
		{name: "canonical", access: "home-access", homeExpiry: future, wantAccess: "home-access", wantGrant: "home-grant"},
		{name: "legacy-only", legacyAccess: "home-access", homeExpiry: future, outerMissing: true, wantAccess: "home-access", wantGrant: "home-grant"},
		{name: "both-agree", access: "home-access", legacyAccess: "home-access", homeExpiry: future, wantAccess: "home-access", wantGrant: "home-grant"},
		{name: "canonical-precedes-conflicting-legacy", access: "home-access", legacyAccess: "stale-alias", homeExpiry: future, wantAccess: "home-access", wantGrant: "home-grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, received, _ := homeWireServer(t)
			cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			initial := &auth.Auth{ID: "siwc.json", FileName: "siwc.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "outer-old", "refresh_token": "outer-grant", "expired": past, "use_siwc": true,
				"siwc": map[string]any{"id_token": "old-nested-identity", "access_token": "siwc-old", "refresh_token": "grant-old", "client_id": "oaiapp_test", "device_id": homeExplicit, "expired": past, "expires_at": past, "earliest_refresh_at": past},
			}}
			if tc.rejectBearer {
				initial.RejectedSIWCAccessToken = "siwc-old"
			}
			manager := auth.NewManager(nil, nil, nil)
			base, errRegister := manager.Register(t.Context(), initial)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			path, errSave := store.Save(t.Context(), base)
			if errSave != nil {
				t.Fatal(errSave)
			}
			before, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			now := time.Now()
			if _, _, due := auth.CodexSIWCNeedsRefresh(base, now); !due {
				t.Fatal("fixture SIWC is not due")
			}
			if _, _, due := auth.CodexOuterNeedsRefresh(base, now); !due {
				t.Fatal("fixture outer OAuth is not due")
			}
			result := base.Clone()
			siwc := result.Metadata["siwc"].(map[string]any)
			if tc.homeExpiry != "" {
				siwc["expired"], siwc["expires_at"] = tc.homeExpiry, tc.homeExpiry
			}
			if tc.access != "" || tc.legacyAccess != "" {
				delete(siwc, "access_token")
				delete(siwc, "id_token")
				siwc["refresh_token"] = "home-grant"
				if tc.access != "" {
					siwc["access_token"] = tc.access
				}
				if tc.legacyAccess != "" {
					siwc["access"] = tc.legacyAccess
				}
			}
			result.Metadata["access_token"], result.Metadata["expired"] = "outer-new", future
			wantOuter := "outer-new"
			if tc.outerMissing {
				delete(result.Metadata, "access_token")
				wantOuter = "outer-old"
			}
			envelope := ojson.NewDocString(`{}`)
			if errSet := envelope.Set("auth", result); errSet != nil {
				t.Fatal(errSet)
			}
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) {
				return envelope.Bytes(), nil
			})
			var calls atomic.Int32
			renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.PostFormValue("refresh_token") != "grant-old" || r.PostFormValue("client_id") != "oaiapp_test" {
					t.Error("local SIWC renewal used the wrong grant or client")
				}
				w.Header().Set("Content-Type", "application/json")
				if tc.rejectGrant {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"local-access","refresh_token":"local-grant","expires_in":7200}`))
			}))
			t.Cleanup(renewal.Close)
			t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
			input := base.Clone()
			updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), input)
			if got := calls.Load(); got != tc.renewalCalls {
				t.Errorf("local SIWC renewals = %d, want %d", got, tc.renewalCalls)
			}
			bothFailed := tc.outerMissing && tc.rejectGrant
			var outerErr, siwcErr error
			if bothFailed {
				var partitionErr *codexauth.PartitionRefreshError
				if updated != nil || !errors.As(errRefresh, &partitionErr) || input.CodexRefreshPatch != nil {
					t.Fatalf("refresh did not return both failures: %v", errRefresh)
				}
				outerErr, siwcErr = partitionErr.OuterRefreshError(), partitionErr.SIWCRefreshError()
				updated = input
			} else {
				if errRefresh != nil || updated == nil {
					t.Fatalf("refresh: %v", errRefresh)
				}
				patch := updated.CodexRefreshPatch
				if patch == nil || !patch.UpstreamRefreshed() || patch.RefreshedOuter() != !tc.outerMissing || patch.RefreshedSIWC() != !tc.rejectGrant {
					t.Error("incorrect partition success flags")
				}
				outerErr, siwcErr = patch.OuterError(), patch.SIWCError()
				if tc.rejectGrant && patch.FailedSIWCRefreshToken() != "grant-old" {
					t.Error("SIWC failure lost the submitted refresh token")
				}
			}
			var outerStatus interface{ StatusCode() int }
			var grantErr *codexauth.SIWCRefreshError
			if (outerErr != nil) != tc.outerMissing || (tc.outerMissing && (!errors.As(outerErr, &outerStatus) || outerStatus.StatusCode() != http.StatusBadGateway)) {
				t.Errorf("incorrect outer refresh error: %v", outerErr)
			}
			if (siwcErr != nil) != tc.rejectGrant || (tc.rejectGrant && !errors.As(siwcErr, &grantErr)) {
				t.Errorf("incorrect SIWC refresh error: %v", siwcErr)
			}
			check := func(stage string, metadata map[string]any) {
				t.Helper()
				sub, _ := metadata["siwc"].(map[string]any)
				if metadata["access_token"] != wantOuter || sub["access_token"] != tc.wantAccess || sub["refresh_token"] != tc.wantGrant {
					t.Errorf("%s: wrong outer credential or mismatched SIWC access/refresh pair", stage)
				}
				if tc.wantGrant == "home-grant" && sub["id_token"] != nil {
					t.Errorf("%s: adopted Home bearer inherited an old SIWC identity token", stage)
				}
				if _, exists := sub["access"]; exists {
					t.Errorf("%s: unnormalized legacy access alias", stage)
				}
				snapshot := &auth.Auth{Provider: "codex", Metadata: metadata}
				exp, ok := snapshot.SIWCRealExpirationTime()
				if !ok || exp.After(now.Add(auth.CodexSIWCRefreshLead)) == tc.rejectGrant {
					t.Errorf("%s: incorrect SIWC expiry %v", stage, exp)
				}
				if _, has, due := auth.CodexSIWCNeedsRefresh(snapshot, now); !has || due != tc.rejectGrant {
					t.Errorf("%s: unexpected SIWC renewal decision: has=%t due=%t", stage, has, due)
				}
				if _, has, due := auth.CodexOuterNeedsRefresh(snapshot, now); !has || due != tc.outerMissing {
					t.Errorf("%s: unexpected outer renewal decision: has=%t due=%t", stage, has, due)
				}
			}
			check("executor", updated.Metadata)
			if !bothFailed {
				merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
				if errMerge != nil {
					t.Fatal(errMerge)
				}
				if tc.rejectGrant && merged.RejectedSIWCRefreshToken != "grant-old" {
					t.Error("manager lost SIWC grant rejection during outer-only success")
				}
				if _, errSave = store.Save(t.Context(), merged); errSave != nil {
					t.Fatal(errSave)
				}
			}
			stored, _ := manager.GetByID(base.ID)
			check("manager", stored.Metadata)
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if bothFailed && !bytes.Equal(before, raw) {
				t.Error("failed refresh rewrote the original credential file")
			}
			var saved map[string]any
			if errDecode := json.Unmarshal(raw, &saved); errDecode != nil {
				t.Fatal(errDecode)
			}
			check("disk", saved)
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("cold load: %v count=%d", errLoad, len(loaded))
			}
			cold := loaded[0]
			check("cold load", cold.Metadata)
			cold.Attributes["base_url"] = upstream.URL
			if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), cold, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
				t.Fatal(errExecute)
			}
			if wire := <-received; wire.headers.Get("Authorization") != "Bearer "+tc.wantAccess {
				t.Error("cold HTTP request sent the wrong SIWC bearer")
			}
		})
	}
}

func TestCodexHomeSIWCSparseSnapshot(t *testing.T) {
	for _, sameBearer := range []bool{true, false} {
		name := "rotated-via-alias"
		if sameBearer {
			name = "same-bearer-expiry-only"
		}
		for _, persistence := range []string{"memory", "file"} {
			t.Run(name+"/"+persistence, func(t *testing.T) {
				server, captures, _ := homeWireServer(t)
				cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
				base := &auth.Auth{ID: "home-only.json", FileName: "home-only.json", Index: "home-index", Provider: "codex", Metadata: map[string]any{
					"type": "codex", "access_token": "outer-old", "refresh_token": "outer-grant", "expired": "2000-01-01T00:00:00Z", "use_siwc": true,
					"siwc": map[string]any{"access_token": "old", "refresh_token": "grant", "client_id": "oaiapp_test", "device_id": homeExplicit, "id_token": "initial-member", "expires_at": "2000-01-01T00:00:00Z"},
				}}
				manager := auth.NewManager(nil, nil, nil)
				base, errRegister := manager.Register(t.Context(), base)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				store := fileauth.NewFileTokenStore()
				var path string
				if persistence == "file" {
					cfg.AuthDir = t.TempDir()
					store.SetBaseDir(cfg.AuthDir)
					var errSave error
					path, errSave = store.Save(t.Context(), base)
					if errSave != nil {
						t.Fatal(errSave)
					}
				}
				raw := `{"auth":{"metadata":{"access_token":"outer-new","siwc":{"access":"new","refresh_token":"next","expires_at":"2099-01-01T00:00:00Z"}}}}`
				wantAccess, wantGrant := "new", "next"
				if sameBearer {
					raw = `{"auth":{"metadata":{"access_token":"outer-new","siwc":{"access_token":"old","expired":"2099-01-01T00:00:00Z"}}}}`
					wantAccess, wantGrant = "old", "grant"
				}
				helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return []byte(raw), nil })
				got, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base.Clone())
				if errRefresh != nil || got == nil {
					t.Fatalf("refresh: %v", errRefresh)
				}
				check := func(stage string, candidate *auth.Auth) {
					t.Helper()
					sub, _ := candidate.Metadata["siwc"].(map[string]any)
					if sub["access_token"] != wantAccess || sub["refresh_token"] != wantGrant || sub["client_id"] != "oaiapp_test" || sub["device_id"] != homeExplicit || (sub["id_token"] == "initial-member") != sameBearer {
						t.Errorf("%s: credential snapshot lost its registration, recovered an old identity, or mismatched the token pair", stage)
					}
					if _, has, due := auth.CodexSIWCNeedsRefresh(candidate, time.Now()); !has || due {
						t.Errorf("%s: sparse snapshot cannot schedule the next renewal", stage)
					}
				}
				check("executor", got)
				merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, got)
				if errMerge != nil {
					t.Fatal(errMerge)
				}
				check("manager", merged)
				if path != "" {
					if _, errSave := store.Save(t.Context(), merged); errSave != nil {
						t.Fatal(errSave)
					}
					stored, errRead := os.ReadFile(path)
					if errRead != nil {
						t.Fatal(errRead)
					}
					var metadata map[string]any
					if errDecode := json.Unmarshal(stored, &metadata); errDecode != nil {
						t.Fatal(errDecode)
					}
					check("disk", &auth.Auth{Provider: "codex", Metadata: metadata})
					cold, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, stored)
					if errSynthesize != nil || len(cold) != 1 {
						t.Fatalf("cold synthesis: %v, count=%d", errSynthesize, len(cold))
					}
					merged = cold[0]
					check("cold", merged)
				}
				if merged.Attributes == nil {
					merged.Attributes = make(map[string]string)
				}
				merged.Attributes["base_url"] = server.URL
				if _, errExecute := executor.NewCodexExecutor(cfg).Execute(t.Context(), merged, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}); errExecute != nil {
					t.Fatal(errExecute)
				}
				if wire := <-captures; wire.headers.Get("Authorization") != "Bearer "+wantAccess {
					t.Error("next request used the wrong SIWC bearer")
				}
			})
		}
	}
}
