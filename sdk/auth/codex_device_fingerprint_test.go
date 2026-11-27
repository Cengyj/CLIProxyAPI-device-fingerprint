package auth

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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

func TestCodexDeviceFingerprintLoginIgnoresForeignAccountClaims(t *testing.T) {
	bundle := &codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
		IDToken: makeTestCodexJWT("team", "acc-team-1"), AccountID: "acc-test-2",
		AccessToken: "new-access", RefreshToken: "new-refresh", Email: "synthetic@example.test", PlanType: "free",
	}}
	record, errBuild := NewCodexAuthenticator().buildAuthRecord(codex.NewCodexAuth(nil), bundle)
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	if record.Metadata["account_id"] != "acc-test-2" || record.Metadata["plan_type"] != "free" {
		t.Fatal("login mixed a foreign JWT plan with the adopted account")
	}
	if _, exists := record.Metadata["chatgpt_plan_type"]; exists {
		t.Fatal("login retained a foreign account plan hint")
	}
	var resolver helps.CodexDeviceResolver
	if resolver.Resolve(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}, record, false, "http://localhost/responses").ID != "3216ba40-955f-42a6-aabf-a9ac6ae94a30" {
		t.Fatal("login used a foreign account identity")
	}
}

func TestCodexDeviceFingerprintReloginReplacesCredentialIdentity(t *testing.T) {
	for _, scenario := range []struct {
		name, account, user, plan, want string
	}{
		{"member-change", "acc-team-1", "user-bbb", "team", "fd5de10e-f853-4dd0-92f4-ece041b115a9"},
		{"account-change", "acc-test-2", "", "free", "3216ba40-955f-42a6-aabf-a9ac6ae94a30"},
		{"missing-member", "acc-team-1", "", "team", "38c7c364-2427-4d06-b94e-823bb0ccb808"},
		{"missing-account-and-plan", "", "", "", "1318bcb2-1f7d-477a-8ab8-a399dca931c6"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			claims := ojson.NewDocString(`{"email":"synthetic@example.test","https://api.openai.com/auth":{}}`)
			for key, value := range map[string]string{
				"chatgpt_account_id": scenario.account, "chatgpt_user_id": scenario.user, "chatgpt_plan_type": scenario.plan,
			} {
				if value != "" {
					if errSet := claims.Set("https://api\\.openai\\.com/auth."+key, value); errSet != nil {
						t.Fatal(errSet)
					}
				}
			}
			bundle := &codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
				IDToken:     "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig",
				AccessToken: "new-access", RefreshToken: "new-refresh", AccountID: scenario.account,
				Email: "synthetic@example.test", PlanType: scenario.plan,
			}}
			record, errBuild := NewCodexAuthenticator().buildAuthRecord(codex.NewCodexAuth(nil), bundle)
			if errBuild != nil {
				t.Fatal(errBuild)
			}
			path := filepath.Join(dir, record.FileName)
			previous := ojson.NewDocString(`{"type":"codex","access_token":"old-access","refresh_token":"old-refresh","account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team","plan_type":"team","plan_type_defaulted":false,"codex_device_fingerprint":"device","operator_note":"keep","header":{"X-Operator":"keep"},"use_siwc":false,"siwc":{"access_token":"siwc-access","refresh_token":"siwc-refresh"}}`)
			if errSet := previous.Set("id_token", makeTestCodexJWT("team", "acc-team-1")); errSet != nil {
				t.Fatal(errSet)
			}
			if errWrite := os.WriteFile(path, previous.Bytes(), 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			store := NewFileTokenStore()
			manager := NewManager(store, &dummyAuthenticator{provider: "codex", record: record})
			cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			loggedIn, savedPath, errLogin := manager.Login(context.Background(), "codex", cfg, nil)
			if errLogin != nil {
				t.Fatal(errLogin)
			}
			if savedPath != path {
				t.Fatal("re-login did not replace the matching credential file")
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			disk := ojson.NewDoc(raw)
			if disk.Get("access_token").String() != "new-access" || disk.Get("refresh_token").String() != "new-refresh" || disk.Get("id_token").String() != bundle.TokenData.IDToken {
				t.Fatal("re-login did not adopt the new credential version")
			}
			if disk.Get("operator_note").String() != "keep" || disk.Get("header.X-Operator").String() != "keep" || disk.Get("codex_device_fingerprint").String() != "device" || disk.Get("siwc.access_token").String() != "siwc-access" || disk.Get("use_siwc").Bool() {
				t.Fatal("re-login lost administrator settings or independent SIWC credentials")
			}
			auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errSynthesize != nil || len(auths) != 1 {
				t.Fatalf("reload failed: %v count=%d", errSynthesize, len(auths))
			}
			for _, auth := range []*coreauth.Auth{loggedIn, auths[0]} {
				var resolver helps.CodexDeviceResolver
				id := resolver.Resolve(cfg, auth, false, "http://localhost/responses").ID
				if id != scenario.want {
					t.Errorf("new login used the prior credential identity, got %s", id)
				}
			}
			if got := disk.Get("chatgpt_user_id").String(); got != "" && got != scenario.user {
				t.Error("persisted login retained a stale member hint")
			}
		})
	}
}

// BuildCodexAuthRecordForTest exposes the real login-record builder to external
// integration tests without adding an executor dependency to the auth package.
func BuildCodexAuthRecordForTest(bundle *codex.CodexAuthBundle) (*coreauth.Auth, error) {
	return NewCodexAuthenticator().buildAuthRecord(codex.NewCodexAuth(nil), bundle)
}
