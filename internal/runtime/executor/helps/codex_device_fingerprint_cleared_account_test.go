package helps

import "testing"

func TestCodexDeviceFingerprintClearedCanonicalIdentityIgnoresAttributes(t *testing.T) {
	for _, attribute := range []string{"account_id", "id_token"} {
		for _, tc := range []struct {
			name  string
			value any
		}{
			{"empty", ""},
			{"null", nil},
			{"wrong-type", true},
		} {
			t.Run(attribute+"/"+tc.name, func(t *testing.T) {
				auth := codexDeviceTestAuth("codex-a.json", "acc-test-1")
				auth.Metadata["id_token"] = ""
				auth.Attributes[attribute] = "acc-test-1"
				if attribute == "id_token" {
					auth.Attributes[attribute] = codexDeviceTestToken(t, "acc-test-1", "", "free")
				}
				var warm CodexDeviceResolver
				if got := warm.Resolve(codexDeviceTestConfig(), auth, false, codexDeviceTestURL).ID; got != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" {
					t.Fatal("initial account did not establish its fixed-vector identity")
				}
				cleared := auth.Clone()
				cleared.Metadata["account_id"] = tc.value
				cleared.Metadata["id_token"] = tc.value
				cleared.Metadata["access_token"] = "replacement-without-claims"
				var cold CodexDeviceResolver
				for _, resolver := range []*CodexDeviceResolver{&warm, &cold} {
					if got := resolver.Resolve(codexDeviceTestConfig(), cleared, false, codexDeviceTestURL).ID; got != "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a" {
						t.Error("canonical account/token clear restored an old attribute or cached identity")
					}
				}
				delete(cleared.Metadata, "account_id")
				delete(cleared.Metadata, "id_token")
				var legacy CodexDeviceResolver
				if got := legacy.Resolve(codexDeviceTestConfig(), cleared, false, codexDeviceTestURL).ID; got != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" {
					t.Fatal("omitted canonical fields blocked supported legacy attributes")
				}
			})
		}
	}
}
