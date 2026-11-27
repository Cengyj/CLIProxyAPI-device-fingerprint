package helps

import "testing"

func TestCodexDeviceFingerprintExplicitMemberClear(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"empty", ""},
		{"null", nil},
		{"wrong-type", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := codexDeviceTestAuth("codex-a.json", "acc-team-1")
			auth.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team")
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Attributes["chatgpt_user_id"] = "user-aaa"
			var warm CodexDeviceResolver
			if got := warm.Resolve(codexDeviceTestConfig(), auth, false, codexDeviceTestURL).ID; got != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatal("initial Team member did not establish the fixed-vector identity")
			}
			auth.Metadata["chatgpt_user_id"] = tc.value
			var cold CodexDeviceResolver
			for _, resolver := range []*CodexDeviceResolver{&warm, &cold} {
				if got := resolver.Resolve(codexDeviceTestConfig(), auth, false, codexDeviceTestURL).ID; got != "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a" {
					t.Error("explicit member clear was replaced by an old attribute, token claim or cached hint")
				}
			}
			delete(auth.Metadata, "chatgpt_user_id")
			delete(auth.Attributes, "chatgpt_user_id")
			delete(auth.Metadata, "id_token")
			auth.Metadata["plan_type"] = "team"
			if got := warm.Resolve(codexDeviceTestConfig(), auth, false, codexDeviceTestURL).ID; got != "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a" {
				t.Fatal("later omitted hints restored the explicitly cleared cached member")
			}
		})
	}
}
