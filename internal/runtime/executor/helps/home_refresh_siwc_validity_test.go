package helps_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexHomeRotatedSIWCBearerStillDue(t *testing.T) {
	for _, scenario := range []string{"expired", "inside-renewal-window", "expired-jwt", "valid", "unknown-expiry"} {
		for _, file := range []bool{false, true} {
			persistence := "memory"
			if file {
				persistence = "file"
			}
			t.Run(scenario+"/"+persistence, func(t *testing.T) {
				cfg, manager, store, path, base := homeGrantFixture(t, file, "2000-01-01T00:00:00Z", true)
				homeBearer := "home-rotated"
				nested := map[string]any{"access_token": homeBearer, "refresh_token": "home-grant-" + t.Name()}
				renew := true
				switch scenario {
				case "expired":
					nested["expires_at"] = "2001-01-01T00:00:00Z"
				case "inside-renewal-window":
					nested["expires_at"] = time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
				case "expired-jwt":
					homeBearer = "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":946684800}`)) + ".sig"
					nested["access_token"] = homeBearer
					nested["expires_at"] = "2099-01-01T00:00:00Z"
				case "valid":
					nested["expires_at"] = "2099-01-01T00:00:00Z"
					renew = false
				case "unknown-expiry":
					renew = false
				}
				homeGrantResponse(t, &auth.Auth{Metadata: map[string]any{"access_token": "outer-new", "expired": "2099-01-01T00:00:00Z", "siwc": nested}})
				var calls atomic.Int32
				response := ojson.NewDocString(`{"access_token":"local-renewed","expires_in":7200}`)
				localGrant := "local-grant-" + t.Name()
				if errSet := response.Set("refresh_token", localGrant); errSet != nil {
					t.Fatal(errSet)
				}
				renewal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.PostFormValue("refresh_token") != nested["refresh_token"] || r.PostFormValue("client_id") != "oaiapp_test" {
						t.Error("SIWC renewal did not submit the adopted Home grant and registration")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(response.Bytes())
				}))
				t.Cleanup(renewal.Close)
				t.Cleanup(codexauth.OverrideSIWCTokenEndpointURLForTest(renewal.URL))
				updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
				if errRefresh != nil {
					t.Fatal(errRefresh)
				}
				wantCalls := int32(0)
				wantBearer, wantGrant := homeBearer, nested["refresh_token"]
				if renew {
					wantCalls, wantBearer, wantGrant = 1, "local-renewed", localGrant
				}
				if calls.Load() != wantCalls {
					t.Errorf("local SIWC renewals=%d want=%d; changed bytes do not prove a usable lifetime", calls.Load(), wantCalls)
				}
				patch := updated.CodexRefreshPatch
				if patch == nil || !patch.RefreshedOuter() || !patch.RefreshedSIWC() || patch.OuterError() != nil || patch.SIWCError() != nil {
					t.Fatal("incorrect partition result after Home adoption and local renewal")
				}
				cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
					t.Helper()
					got := candidate.Metadata["siwc"].(map[string]any)
					if got["access_token"] != wantBearer || got["refresh_token"] != wantGrant || candidate.Metadata["access_token"] != "outer-new" {
						t.Errorf("%s did not retain the completed credential partitions", stage)
					}
					if scenario != "unknown-expiry" {
						if _, has, due := auth.CodexSIWCNeedsRefresh(candidate, time.Now()); !has || due {
							t.Errorf("%s still needs SIWC renewal", stage)
						}
					}
				})
				assertHomeExpirationBearer(t, cold, wantBearer)
			})
		}
	}
}
