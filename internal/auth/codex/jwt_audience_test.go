package codex

import (
	"reflect"
	"testing"
)

func TestParseJWTTokenAudienceForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		audience any
		want     []string
		invalid  bool
	}{
		{name: "string", audience: "codex-client", want: []string{"codex-client"}},
		{name: "list", audience: []string{"codex-client", "other"}, want: []string{"codex-client", "other"}},
		{name: "empty-list", audience: []string{}, want: []string{}},
		{name: "null"},
		{name: "missing"},
		{name: "number", audience: 12, invalid: true},
		{name: "object", audience: map[string]string{"name": "client"}, invalid: true},
		{name: "mixed-list", audience: []any{"client", 12}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"aud": tc.audience, "exp": 4070908800, "email": "member@example.invalid", "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "account", "chatgpt_user_id": "member", "chatgpt_plan_type": "team"}}
			if tc.name == "missing" {
				delete(payload, "aud")
			}
			claims, errParse := ParseJWTToken(makeTestJWT(payload))
			if tc.invalid {
				if errParse == nil || claims != nil {
					t.Fatal("unsupported audience type was accepted")
				}
				return
			}
			if errParse != nil {
				t.Fatal(errParse)
			}
			if !reflect.DeepEqual(claims.Aud, tc.want) || claims.Exp != 4070908800 || claims.GetAccountID() != "account" || claims.CodexAuthInfo.ChatgptUserID != "member" || claims.GetPlanType() != "team" || claims.GetUserEmail() != "member@example.invalid" {
				t.Fatal("audience normalization changed unrelated claims")
			}
		})
	}
	if _, errParse := ParseJWTToken(makeTestJWT(map[string]any{"aud": "client", "exp": "invalid"})); errParse == nil {
		t.Fatal("string audience weakened validation of another claim")
	}
}
