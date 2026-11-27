package codex

import (
	"testing"

	"github.com/MoeForge/moego/json"
)

func TestCredentialDiskSnapshotComparisonIgnoresRepresentationAndSettings(t *testing.T) {
	before := map[string]any{
		"access_token": "outer", "refresh_token": "outer-grant", "expires_in": int64(7200),
		"timestamp": int64(1795747200), "token": map[string]any{"expires_at": int64(1795754400), "custom": "old"},
		"codex_device_fingerprint": "off", "codex_installation_id": "old-override",
		"siwc": map[string]any{"access_token": "nested", "refresh_token": "nested-grant", "expires_in": int64(7200), "scopes": []string{"openid"}},
	}
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]any
	if err = json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	disk["codex_device_fingerprint"], disk["codex_installation_id"] = "device", "new-override"
	disk["token"].(map[string]any)["custom"] = "new"
	nested := disk["siwc"].(map[string]any)
	nested["access"] = nested["access_token"]
	delete(nested, "access_token")
	nested["operator_note"] = "edited"
	if !SameOuterCredentialSnapshot(before, disk) || !SameSIWCCredentialSnapshot(before["siwc"].(map[string]any), nested) {
		t.Fatal("a JSON round trip, access alias or administrator edit invented a credential rotation")
	}
	disk["token"].(map[string]any)["expires_at"] = float64(1795758000)
	if SameOuterCredentialSnapshot(before, disk) {
		t.Fatal("a nested outer expiry update was ignored")
	}
	nested["scopes"] = []any{"openid", "offline_access"}
	if SameSIWCCredentialSnapshot(before["siwc"].(map[string]any), nested) {
		t.Fatal("a SIWC registration update was ignored")
	}
}

func TestCredentialRefreshPatchSIWCRemovalKeepsConcurrentRotation(t *testing.T) {
	before := map[string]any{
		"access_token": "outer-old", "refresh_token": "outer-grant",
		"siwc": map[string]any{"access_token": "nested-old", "refresh_token": "nested-grant", "device_id": "old-device"},
	}
	after := map[string]any{"access_token": "outer-new", "refresh_token": "outer-new-grant"}
	patch := NewCredentialRefreshPatchWithDiskBaseline(before, after, after, true, true)
	for _, currentState := range []string{"matching", "already-removed", "rebound"} {
		t.Run(currentState, func(t *testing.T) {
			current := cloneStringAnyMap(before)
			current["operator_note"] = "keep"
			switch currentState {
			case "already-removed":
				delete(current, "siwc")
			case "rebound":
				current["siwc"] = map[string]any{"access_token": "new-binding", "refresh_token": "new-binding-grant", "device_id": "new-device"}
			}
			got := patch.Apply(current)
			if got["access_token"] != "outer-new" || got["operator_note"] != "keep" {
				t.Fatal("SIWC removal prevented independent outer adoption or lost administrator metadata")
			}
			if currentState == "rebound" {
				if got["siwc"].(map[string]any)["access_token"] != "new-binding" {
					t.Fatal("old partition removal deleted a newer SIWC binding")
				}
			} else if _, present := got["siwc"]; present {
				t.Fatal("matched removal restored a SIWC partition")
			}
		})
	}
}

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

func TestCredentialRefreshPatchSIWCLegacyAccess(t *testing.T) {
	record := func(key, bearer string) map[string]any {
		return map[string]any{"siwc": map[string]any{key: bearer, "refresh_token": "same-grant"}}
	}
	before := record("access", "old")
	patch := NewCredentialRefreshPatch(before, record("access", "new"), false, true)
	for _, key := range []string{"access_token", "access"} {
		t.Run(key, func(t *testing.T) {
			matching := record(key, "old")
			if !patch.CanApplyTo(matching) {
				t.Fatal("patch rejected a matching baseline encoded with the other spelling")
			}
			sub := patch.Apply(matching)["siwc"].(map[string]any)
			if _, legacy := sub["access"]; legacy || sub["access_token"] != "new" || sub["refresh_token"] != "same-grant" {
				t.Fatal("matching baseline did not receive the canonical SIWC pair")
			}
			newer := record(key, "newer")
			if patch.CanApplyTo(newer) || patch.Apply(newer)["siwc"].(map[string]any)[key] != "newer" {
				t.Fatal("stale refresh overwrote a newer bearer with the same grant")
			}
		})
	}
}
