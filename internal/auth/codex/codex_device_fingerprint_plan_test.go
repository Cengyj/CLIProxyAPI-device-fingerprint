package codex

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
)

func fingerprintProvenanceJWT(t *testing.T, plan string) string {
	t.Helper()
	doc := ojson.NewDocString(`{"email":"synthetic@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa"}}`)
	if plan != "" {
		if err := doc.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", plan); err != nil {
			t.Fatal(err)
		}
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
}

func TestCodexDeviceFingerprintOAuthPlanProvenance(t *testing.T) {
	for _, plan := range []string{"", "free", "team", "business", "enterprise", "edu"} {
		t.Run("plan="+plan, func(t *testing.T) {
			token := fingerprintProvenanceJWT(t, plan)
			response := ojson.NewDocString(`{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600}`)
			if err := response.Set("id_token", token); err != nil {
				t.Fatal(err)
			}
			svc := &CodexAuth{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response.String())), Request: req}, nil
			})}}
			bundle, err := svc.ExchangeCodeForTokens(context.Background(), "synthetic-code", &PKCECodes{CodeVerifier: "synthetic-verifier"})
			if err != nil {
				t.Fatal(err)
			}
			wantPlan := plan
			if wantPlan == "" {
				wantPlan = "free"
			}
			if bundle.TokenData.PlanType != wantPlan || bundle.TokenData.PlanTypeDefaulted != (plan == "") {
				t.Fatal("exchange lost explicit/default plan distinction")
			}
			storage := svc.CreateTokenStorage(bundle)
			path := filepath.Join(t.TempDir(), "auth.json")
			if errSave := storage.SaveTokenToFile(path); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "plan_type").String() != wantPlan || ojson.GetBytes(raw, "plan_type_defaulted").Bool() != (plan == "") {
				t.Fatal("initial storage lost plan provenance")
			}
			refreshed, errRefresh := svc.RefreshTokens(context.Background(), "refresh-provenance-"+t.Name())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			if refreshed.PlanType != wantPlan || refreshed.PlanTypeDefaulted != (plan == "") {
				t.Fatal("refresh lost plan provenance")
			}
			receipt := ojson.NewDocString(`{}`)
			if errSet := receipt.Set("value", refreshed); errSet != nil {
				t.Fatal(errSet)
			}
			decoded, errDecode := decodeRefreshReceipt(receipt.Get("value"))
			if errDecode != nil {
				t.Fatal(errDecode)
			}
			if decoded.PlanTypeDefaulted != refreshed.PlanTypeDefaulted {
				t.Fatal("refresh journal lost plan provenance")
			}
			svc.UpdateTokenStorage(storage, refreshed)
			if storage.PlanTypeDefaulted != refreshed.PlanTypeDefaulted {
				t.Fatal("storage update lost plan provenance")
			}
		})
	}
}
