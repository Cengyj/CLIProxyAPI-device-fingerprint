package helps

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
)

func TestCodexDeviceFingerprintFrozenSubjectWithExplicitID(t *testing.T) {
	for _, siwc := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "siwc"}[siwc], func(t *testing.T) {
			cfg := codexDeviceTestConfig()
			original := codexDeviceTestAuth("same-file", "account-a")
			original.Metadata["codex_installation_id"] = codexDeviceTestID
			original.Metadata["siwc"] = map[string]any{"device_id": codexDeviceTestID}
			var resolver CodexDeviceResolver
			policy := resolver.Resolve(cfg, original, siwc, codexDeviceTestURL)
			changed := codexDeviceTestAuth(original.ID, "account-b")
			changed.Metadata["codex_installation_id"] = codexDeviceTestID
			changed.Metadata["siwc"] = map[string]any{"device_id": codexDeviceTestID}
			if resolver.CompatibleFrozenAuth(policy, changed, siwc, codexDeviceTestURL) {
				t.Fatal("same explicit device allowed a different subject on the existing authenticated socket")
			}
			// Administrator IDs still take precedence and may intentionally be shared.
			other := resolver.Resolve(cfg, changed, siwc, codexDeviceTestURL)
			if other.ID != policy.ID {
				t.Fatal("subject guard changed administrator's public installation ID")
			}
			if policy.Identity(nil, nil).Compatible(other.Identity(nil, nil)) {
				t.Fatal("ordinary connection identity ignored changed authenticated subject")
			}
		})
	}
}

func TestCodexDeviceFingerprintFrozenTeamMemberAndRefresh(t *testing.T) {
	cfg := codexDeviceTestConfig()
	original := codexDeviceTestAuth("same-file", "workspace")
	original.Metadata["plan_type"] = "team"
	original.Metadata["chatgpt_user_id"] = "member-a"
	original.Metadata["codex_installation_id"] = codexDeviceTestID
	var resolver CodexDeviceResolver
	policy := resolver.Resolve(cfg, original, false, codexDeviceTestURL)
	refreshed := codexDeviceTestAuth(original.ID, "workspace")
	refreshed.Metadata["codex_installation_id"] = codexDeviceTestID
	refreshed.Metadata["codex_device_fingerprint"] = "off"
	refreshed.Attributes["codex_device_fingerprint"] = "off"
	before := refreshed.Clone()
	if !resolver.CompatibleFrozenAuth(policy, refreshed, false, codexDeviceTestURL) {
		t.Fatal("missing-field refresh or mode update disrupted frozen policy")
	}
	if !reflect.DeepEqual(refreshed.Attributes, before.Attributes) || !reflect.DeepEqual(refreshed.Metadata, before.Metadata) {
		t.Fatal("frozen check mutated caller credentials")
	}
	refreshed.Metadata["plan_type"] = "team"
	refreshed.Metadata["chatgpt_user_id"] = "member-b"
	if resolver.CompatibleFrozenAuth(policy, refreshed, false, codexDeviceTestURL) {
		t.Fatal("different Team member reused explicit device on old socket")
	}
}

func TestCodexDeviceFingerprintFrozenSIWCSubject(t *testing.T) {
	oidc := func(subject string, issuedAt int, changes ...map[string]any) string {
		doc := ojson.NewDocString(`{"iss":"https://issuer.invalid","aud":"siwc-client","https://api.openai.com/auth":{"chatgpt_account_id":"workspace"}}`)
		if errSet := doc.Set("https://api\\.openai\\.com/auth.chatgpt_user_id", subject); errSet != nil {
			t.Fatal(errSet)
		}
		if errSet := doc.Set("sub", subject); errSet != nil {
			t.Fatal(errSet)
		}
		if errSet := doc.Set("iat", issuedAt); errSet != nil {
			t.Fatal(errSet)
		}
		for _, fields := range changes {
			for field, value := range fields {
				if errSet := doc.Set(field, value); errSet != nil {
					t.Fatal(errSet)
				}
			}
		}
		return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
	}
	memberA := codexDeviceTestToken(t, "workspace", "a", "team")
	memberB := codexDeviceTestToken(t, "workspace", "b", "team")
	for _, tc := range []struct {
		name, oldBearer, oldID, bearer, id string
		reuse                              bool
	}{
		{"member-rotates-bearer", "old", memberA, "new", memberA, true},
		{"member-changes", "old", memberA, "new", memberB, false},
		{"oidc-only-subject-changes", "old", oidc("a", 1, map[string]any{"https://api\\.openai\\.com/auth": nil}), "new", oidc("b", 2, map[string]any{"https://api\\.openai\\.com/auth": nil}), false},
		{"oidc-only-token-reissued", "old", oidc("a", 1, map[string]any{"https://api\\.openai\\.com/auth": nil}), "new", oidc("a", 2, map[string]any{"https://api\\.openai\\.com/auth": nil}), true},
		{"oidc-subject-changes", "old", oidc("a", 1), "new", oidc("b", 2), false},
		{"oidc-token-reissued", "old", oidc("a", 1), "new", oidc("a", 2), true},
		{"bearer-same-member-without-id", oidc("a", 1), memberA, oidc("a", 2), "", true},
		{"bearer-new-member-without-id", oidc("a", 1), memberA, oidc("b", 2), "", false},
		{"bearer-new-issuer-without-id", oidc("a", 1), memberA, oidc("a", 2, map[string]any{"iss": "https://other.invalid"}), "", false},
		{"bearer-new-account-without-id", oidc("a", 1), memberA, oidc("a", 2, map[string]any{"https://api\\.openai\\.com/auth.chatgpt_account_id": "other"}), "", false},
		{"bearer-new-subject-without-id", oidc("a", 1), memberA, oidc("a", 2, map[string]any{"sub": "other"}), "", false},
		{"bearer-new-user-without-id", oidc("a", 1), memberA, oidc("a", 2, map[string]any{"https://api\\.openai\\.com/auth.chatgpt_user_id": "other"}), "", false},
		{"conflicting-id-member", oidc("a", 1), memberA, oidc("a", 2), memberB, false},
		{"conflicting-id-issuer", oidc("a", 1), oidc("a", 1), oidc("a", 2), oidc("a", 2, map[string]any{"iss": "https://other.invalid"}), false},
		{"incomplete-bearer-needs-id", oidc("a", 1, map[string]any{"https://api\\.openai\\.com/auth.chatgpt_user_id": ""}), memberA, oidc("a", 2, map[string]any{"https://api\\.openai\\.com/auth.chatgpt_user_id": ""}), "", false},
		{"bearer-identifies-new-member", memberA, memberA, memberB, memberA, false},
		{"opaque-workspace-changes", "same", codexDeviceTestToken(t, "one", "", "team"), "same", codexDeviceTestToken(t, "two", "", "team"), false},
		{"workspace-only-cannot-identify-member", "old", codexDeviceTestToken(t, "one", "", "team"), "new", codexDeviceTestToken(t, "one", "", "team"), false},
		{"same-opaque-bearer", "old", "", "old", "", true},
		{"unidentifiable-rotated-bearer", "old", "", "new", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := codexDeviceTestConfig()
			original := codexDeviceTestAuth("same-record", "outer-account")
			original.Metadata["siwc"] = map[string]any{"device_id": codexDeviceTestID, "access_token": tc.oldBearer, "id_token": tc.oldID}
			next := original.Clone()
			next.Metadata["siwc"] = map[string]any{"device_id": codexDeviceTestID, "access_token": tc.bearer, "id_token": tc.id}
			var resolver CodexDeviceResolver
			bound := resolver.Resolve(cfg, original, true, codexDeviceTestURL)
			candidate := resolver.Resolve(cfg, next, true, codexDeviceTestURL)
			if bound.ID != codexDeviceTestID || candidate.ID != bound.ID {
				t.Fatal("selected SIWC device ID changed")
			}
			if got := resolver.CompatibleFrozenAuth(bound, next, true, codexDeviceTestURL); got != tc.reuse {
				t.Errorf("frozen subject compatible = %t, want %t", got, tc.reuse)
			}
			if got := bound.Identity(nil, nil).CompatibleHandshake(candidate.Identity(nil, nil)); got != tc.reuse {
				t.Errorf("handshake compatible = %t, want %t", got, tc.reuse)
			}
			if resolver.CompatibleFrozenAuth(bound, next, false, codexDeviceTestURL) {
				t.Error("selected credential partition change reused frozen SIWC policy")
			}
			// With SIWC selected, a change confined to the outer credential
			// must not displace the socket authenticated by the nested bearer.
			next = original.Clone()
			next.Metadata["account_id"] = "other-outer-account"
			if !resolver.CompatibleFrozenAuth(bound, next, true, codexDeviceTestURL) {
				t.Error("outer account change invalidated the selected SIWC credential")
			}
		})
	}
}

func TestCodexDeviceFingerprintEscapedTargetsAndOriginalDoc(t *testing.T) {
	p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	raw := []byte(`{"client_metadata":{"x-codex-installation-id":"one","x-codex-installation-\u0069d":"two","x-codex-turn-metadata":"{\"installation_id\":\"one\",\"installation_\\u0069d\":\"two\",\"other\":900719925474099312345}"},"input":[]}`)
	doc := ojson.NewDoc(raw)
	if errSet := doc.Set("model", "gpt-test"); errSet != nil {
		t.Fatal(errSet)
	}
	if errSet := doc.Set("client_metadata.cpa_session_instructions", "reuse"); errSet != nil {
		t.Fatal(errSet)
	}
	if errApply := p.ApplyDoc(doc, false, raw); errApply != nil {
		t.Fatal(errApply)
	}
	if doc.Get("model").String() != "gpt-test" || doc.Get("client_metadata.cpa_session_instructions").String() != "reuse" {
		t.Fatal("pending built-ins lost")
	}
	count := 0
	doc.Get("client_metadata").ForEach(func(key, value ojson.Result) bool {
		if key.String() == codexDeviceInstallation {
			count++
			if value.String() != codexDeviceTestID {
				t.Fatal("escaped old ID survived")
			}
		}
		return true
	})
	if count != 1 {
		t.Fatal("escaped duplicate not normalized")
	}
	inner := ojson.Parse(doc.Get("client_metadata." + codexDeviceTurnMetadata).String())
	count = 0
	inner.ForEach(func(key, value ojson.Result) bool {
		if key.String() == "installation_id" {
			count++
			if value.String() != codexDeviceTestID {
				t.Fatal("escaped nested old ID survived")
			}
		}
		return true
	})
	if count != 1 || inner.Get("other").Raw != "900719925474099312345" {
		t.Fatal("nested normalization lost precision")
	}
	duplicate := []byte(`{"client_metadata":{"cpa_session_instructions":"reuse"},"client_\u006detadata":{"x-codex-installation-id":"old"}}`)
	if errValidate := p.ValidateInput(duplicate); errValidate == nil {
		t.Fatal("duplicate metadata with instruction marker accepted")
	}
}

func TestCodexDeviceFingerprintUsesCurrentMetadataToken(t *testing.T) {
	cfg := codexDeviceTestConfig()
	auth := codexDeviceTestAuth("team-current", "workspace-current")
	auth.Metadata["plan_type"] = "team"
	auth.Metadata["id_token"] = codexDeviceTestToken(t, "workspace-current", "member-current", "team")
	auth.Attributes["id_token"] = codexDeviceTestToken(t, "workspace-stale", "member-stale", "team")
	var resolver CodexDeviceResolver
	if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL).ID; got != codexDeviceUUID("account-user\x00workspace-current\x00member-current") {
		t.Fatal("stale token attribute displaced refreshed credential metadata")
	}
}

func TestCodexDeviceFingerprintHandshakeCompatibility(t *testing.T) {
	policy := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	body := ojson.NewDocString(`{"client_metadata":{"x-codex-installation-id":"` + codexDeviceTestID + `"}}`)
	standalone := http.Header{"X-Codex-Installation-Id": {codexDeviceTestID}}
	turn := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"` + codexDeviceTestID + `","turn_id":"one"}`}}
	empty := policy.Identity(nil, nil)
	bodyOnly := policy.Identity(body, nil)
	headerOnly := policy.Identity(nil, standalone)
	turnOnly := policy.Identity(nil, turn)
	for _, tc := range []struct {
		name             string
		bound, candidate CodexDeviceIdentity
		compatible       bool
	}{
		{"new standalone header", empty, headerOnly, false},
		{"new turn metadata header", empty, turnOnly, false},
		{"absent candidate header", headerOnly, empty, true},
		{"same device moved from body to header", bodyOnly, headerOnly, false},
		{"body first appears", empty, bodyOnly, true},
		{"body disappears", bodyOnly, empty, true},
		{"body added with established handshake device", headerOnly, bodyOnly, true},
		{"same standalone header", headerOnly, headerOnly, true},
		{"same turn metadata header", turnOnly, turnOnly, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.bound.CompatibleHandshake(tc.candidate); got != tc.compatible {
				t.Fatalf("CompatibleHandshake=%v want %v", got, tc.compatible)
			}
		})
	}
	changedTurn := http.Header{"X-CODEX-TURN-METADATA": {`{"turn_id":"two","installation_id":"` + codexDeviceTestID + `"}`}}
	if !turnOnly.CompatibleHandshake(policy.Identity(nil, changedTurn)) {
		t.Fatal("non-device turn change required handshake")
	}
	other := http.Header{"X-Codex-Installation-Id": {codexDeviceOtherID}}
	if headerOnly.CompatibleHandshake(policy.Identity(nil, other)) {
		t.Fatal("changed handshake device reused socket")
	}
	var off CodexDevicePolicy
	if !off.Identity(body, standalone).CompatibleHandshake(off.Identity(nil, other)) {
		t.Fatal("off inspected device fields")
	}
	if empty.CompatibleHandshake(off.Identity(nil, nil)) {
		t.Fatal("mode change did not require new socket")
	}
}

func TestCodexDeviceFingerprintConflictingMemberInvalidatesHints(t *testing.T) {
	cfg := codexDeviceTestConfig()
	auth := codexDeviceTestAuth("reused-file", "workspace-a")
	auth.Metadata["plan_type"] = "team"
	auth.Metadata["chatgpt_user_id"] = "member-a"
	var resolver CodexDeviceResolver
	first := resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
	partial := codexDeviceTestAuth(auth.ID, "")
	partial.Metadata["chatgpt_user_id"] = "member-b"
	partial.Metadata["plan_type"] = "team"
	fallback := codexDeviceUUID("auth-id\x00" + auth.ID)
	if got := resolver.Resolve(cfg, partial, false, codexDeviceTestURL); got.ID != fallback {
		t.Fatal("partial new member borrowed old workspace")
	}
	empty := codexDeviceTestAuth(auth.ID, "")
	if got := resolver.Resolve(cfg, empty, false, codexDeviceTestURL); got.ID != fallback || got.ID == first.ID {
		t.Fatal("missing-field refresh resurrected a disproved member identity")
	}
	if len(resolver.entries) != 0 || resolver.recent.Len() != 0 {
		t.Fatal("invalidated entry remained in bounded cache")
	}
	complete := codexDeviceTestAuth(auth.ID, "workspace-b")
	complete.Metadata["plan_type"] = "team"
	complete.Metadata["chatgpt_user_id"] = "member-b"
	want := codexDeviceUUID("account-user\x00workspace-b\x00member-b")
	if got := resolver.Resolve(cfg, complete, false, codexDeviceTestURL); got.ID != want {
		t.Fatal("full replacement identity was not established")
	}
	if got := resolver.Resolve(cfg, empty, false, codexDeviceTestURL); got.ID != want {
		t.Fatal("new confirmed identity was not retained")
	}
}

func TestCodexDeviceFingerprintClearedIdentityInvalidatesHints(t *testing.T) {
	cfg := codexDeviceTestConfig()
	auth := codexDeviceTestAuth("cleared-record", "workspace")
	auth.Metadata["id_token"] = codexDeviceTestToken(t, "workspace", "member", "team")
	var resolver CodexDeviceResolver
	previous := resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
	cleared := codexDeviceTestAuth(auth.ID, "")
	cleared.Metadata["id_token"] = ""
	cleared.Metadata["access_token"] = "replacement-without-claims"
	want := codexDeviceUUID("auth-id\x00" + auth.ID)
	if got := resolver.Resolve(cfg, cleared, false, codexDeviceTestURL); got.ID != want || got.ID == previous.ID {
		t.Fatal("explicitly cleared credential reused the cached member")
	}
	delete(cleared.Metadata, "id_token")
	delete(cleared.Metadata, "account_id")
	if got := resolver.Resolve(cfg, cleared, false, codexDeviceTestURL); got.ID != want {
		t.Fatal("later missing fields resurrected the cleared member")
	}
	if len(resolver.entries) != 0 || resolver.recent.Len() != 0 {
		t.Fatal("cleared identity remained in the cache")
	}
}
