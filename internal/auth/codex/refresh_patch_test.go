package codex

import "testing"

func TestCodexDeviceFingerprintRefreshPatchKeepsIdentityWithCredentialVersion(t *testing.T) {
	before := map[string]any{
		"access_token": "old-access", "refresh_token": "old-refresh", "id_token": "same-identity-token", "account_id": "same-account",
		"chatgpt_user_id": "same-member", "plan_type": "team", "plan_type_defaulted": false,
	}
	after := cloneStringAnyMap(before)
	after["access_token"], after["refresh_token"] = "new-access", "new-refresh"
	disk := cloneStringAnyMap(before)
	disk["chatgpt_user_id"] = "stale-member"
	disk["chatgpt_plan_type"] = "free"
	disk["plan_type"], disk["plan_type_defaulted"] = "free", true
	disk["operator_note"] = "concurrent-admin"
	got := NewCredentialRefreshPatch(before, after, true, false).Apply(disk)
	if got["access_token"] != "new-access" || got["chatgpt_user_id"] != "same-member" || got["plan_type"] != "team" || got["plan_type_defaulted"] != false {
		t.Fatal("accepted token rotation retained identity hints from a different snapshot")
	}
	if _, exists := got["chatgpt_plan_type"]; exists {
		t.Fatal("accepted token rotation retained a hint absent from the adopted snapshot")
	}
	if got["operator_note"] != "concurrent-admin" {
		t.Fatal("credential identity synchronization lost administrator settings")
	}
}

func TestCodexDeviceFingerprintRefreshPatchIdentityDeletion(t *testing.T) {
	before := map[string]any{
		"access_token": "old", "refresh_token": "old-refresh", "id_token": "old-id", "account_id": "old-account",
		"chatgpt_user_id": "old-member", "chatgpt_plan_type": "team", "plan_type": "team", "plan_type_defaulted": false,
		"siwc": map[string]any{"access_token": "old-siwc", "refresh_token": "old-siwc-refresh"},
	}
	after := cloneStringAnyMap(before)
	after["access_token"], after["refresh_token"] = "new", "new-refresh"
	after["account_id"], after["id_token"] = "", ""
	delete(after, "chatgpt_user_id")
	delete(after, "chatgpt_plan_type")
	after["siwc"].(map[string]any)["access_token"] = "new-siwc"
	patch := NewCredentialRefreshPatch(before, after, true, true)
	for _, superseded := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "superseded-outer"}[superseded], func(t *testing.T) {
			disk := cloneStringAnyMap(before)
			disk["operator_note"] = "concurrent-admin"
			if superseded {
				disk["access_token"], disk["refresh_token"] = "latest", "latest-refresh"
				disk["chatgpt_user_id"] = "latest-member"
			}
			got := patch.Apply(disk)
			if superseded {
				if got["access_token"] != "latest" || got["chatgpt_user_id"] != "latest-member" {
					t.Fatal("superseded refresh changed current outer identity")
				}
			} else {
				if got["access_token"] != "new" || got["account_id"] != "" || got["id_token"] != "" {
					t.Fatal("identity deletion prevented matching credential adoption")
				}
				for _, key := range []string{"chatgpt_user_id", "chatgpt_plan_type"} {
					if _, exists := got[key]; exists {
						t.Fatalf("removed identity field %s returned during refresh application", key)
					}
				}
			}
			if got["siwc"].(map[string]any)["access_token"] != "new-siwc" || got["operator_note"] != "concurrent-admin" {
				t.Fatal("identity cleanup lost independent SIWC refresh or administrator edit")
			}
		})
	}
}

func TestCredentialRefreshPatchChecksPartitionsIndependently(t *testing.T) {
	for _, rotated := range []string{"outer", "siwc"} {
		t.Run(rotated, func(t *testing.T) {
			before := map[string]any{
				"access_token": "outer-old", "refresh_token": "outer-ref-old", "last_refresh": "2026-10-12T12:00:00Z",
				"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-ref-old", "last_refresh": "2026-10-12T12:00:00Z"},
			}
			after := cloneStringAnyMap(before)
			after["access_token"], after["refresh_token"] = "outer-new", "outer-ref-new"
			after["siwc"].(map[string]any)["access_token"] = "siwc-new"
			after["siwc"].(map[string]any)["refresh_token"] = "siwc-ref-new"
			patch := NewCredentialRefreshPatch(before, after, true, true)
			disk := cloneStringAnyMap(before)
			wantOuter, wantSIWC := "outer-ref-new", "siwc-ref-new"
			if rotated == "outer" {
				disk["access_token"], disk["refresh_token"] = "outer-bound", "outer-ref-bound"
				wantOuter = "outer-ref-bound"
			} else {
				disk["siwc"].(map[string]any)["access_token"] = "siwc-bound"
				disk["siwc"].(map[string]any)["refresh_token"] = "siwc-ref-bound"
				wantSIWC = "siwc-ref-bound"
			}
			// Changing source/result maps later must not mutate the immutable patch.
			before["refresh_token"] = "mutated-before"
			after["refresh_token"] = "mutated-after"
			saved := patch.Apply(disk)
			if saved["refresh_token"] != wantOuter || saved["siwc"].(map[string]any)["refresh_token"] != wantSIWC {
				t.Fatalf("partition version check lost a valid refresh or overwrote a bind: %#v", saved)
			}
		})
	}
}
