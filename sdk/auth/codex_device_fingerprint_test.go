package auth

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestCodexDeviceFingerprintLoginPlanProvenance(t *testing.T) {
	for _, plan := range []string{"", "free", "team", "business", "enterprise", "edu"} {
		t.Run("plan="+plan, func(t *testing.T) {
			claims := ojson.NewDocString(`{"email":"synthetic@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"account","chatgpt_user_id":"member"}}`)
			if plan != "" {
				if errSet := claims.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", plan); errSet != nil {
					t.Fatal(errSet)
				}
			}
			bundle := &codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
				IDToken:     "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig",
				AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", Email: "synthetic@example.test",
			}}
			auth, errBuild := NewCodexAuthenticator().buildAuthRecord(codex.NewCodexAuth(nil), bundle)
			if errBuild != nil {
				t.Fatal(errBuild)
			}
			wantPlan := plan
			if wantPlan == "" {
				wantPlan = "free"
			}
			if auth.Attributes["plan_type"] != wantPlan || auth.Metadata["plan_type"] != wantPlan {
				t.Fatal("login changed the general default-free behavior")
			}
			if auth.Attributes["plan_type_defaulted"] != strconv.FormatBool(plan == "") || auth.Metadata["plan_type_defaulted"] != (plan == "") {
				t.Fatal("login record lost explicit/default plan distinction")
			}
			storage := auth.Storage.(*codex.CodexTokenStorage)
			storage.SetMetadata(auth.Metadata)
			path := filepath.Join(t.TempDir(), "auth.json")
			if errSave := storage.SaveTokenToFile(path); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "plan_type_defaulted").Bool() != (plan == "") || ojson.GetBytes(raw, "plan_type").String() != wantPlan {
				t.Fatal("initial login save lost plan provenance")
			}
		})
	}
}
