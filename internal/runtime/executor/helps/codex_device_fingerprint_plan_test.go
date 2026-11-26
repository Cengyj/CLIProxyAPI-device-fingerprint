package helps

import (
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestCodexDeviceFingerprintPlanProvenancePrecedence(t *testing.T) {
	for _, source := range []string{"attributes", "metadata"} {
		for _, defaulted := range []bool{false, true} {
			t.Run(source+map[bool]string{false: "/explicit-free", true: "/defaulted-free"}[defaulted], func(t *testing.T) {
				cfg := codexDeviceTestConfig()
				var resolver CodexDeviceResolver
				initial := codexDeviceTestAuth("team-file", "acc-team-1")
				initial.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team")
				first := resolver.Resolve(cfg, initial, false, codexDeviceTestURL)
				current := codexDeviceTestAuth(initial.ID, "acc-team-1")
				current.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "")
				// A stale storage marker must never overrule an explicit source value.
				current.Storage = &codexauth.CodexTokenStorage{PlanType: "free", PlanTypeDefaulted: true}
				current.Metadata["plan_type"] = "free"
				current.Metadata["plan_type_defaulted"] = defaulted
				if source == "attributes" {
					current.Metadata["plan_type_defaulted"] = true
					current.Attributes["plan_type"] = "free"
					if defaulted {
						current.Attributes["plan_type_defaulted"] = "true"
					}
				}
				want := codexDeviceUUID("account\x00acc-team-1")
				if defaulted {
					want = first.ID
				}
				if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL); got.ID != want {
					t.Fatal("plan provenance escaped its source or lost explicit free")
				}
			})
		}
	}
}
