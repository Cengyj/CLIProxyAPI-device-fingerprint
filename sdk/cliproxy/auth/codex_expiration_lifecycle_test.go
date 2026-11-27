package auth

import (
	"reflect"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestCodexOuterExpirationSnapshot(t *testing.T) {
	old := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	next := old.Add(24 * time.Hour)
	for _, tc := range []struct {
		name       string
		source     map[string]any
		sameBearer bool
		want       time.Time
		known      bool
	}{
		{"same omitted", nil, true, old, true},
		{"changed omitted", nil, false, time.Time{}, false},
		{"same cleared", map[string]any{"expires_at": nil}, true, time.Time{}, false},
		{"same mistyped", map[string]any{"expires_at": []any{1}}, true, time.Time{}, false},
		{"same relative cleared", map[string]any{"expires_in": nil}, true, time.Time{}, false},
		{"same container cleared", map[string]any{"token": nil}, true, time.Time{}, false},
		{"same new relative", map[string]any{"expiresIn": 3600, "issuedAt": next.Add(-time.Hour).Format(time.RFC3339)}, true, next, true},
		{"changed new relative", map[string]any{"expires_in": 3600, "timestamp": next.Add(-time.Hour).Format(time.RFC3339)}, false, next, true},
		{"changed relative without base", map[string]any{"expires_in": 3600}, false, time.Time{}, false},
		{"changed new nested", map[string]any{"Token": map[string]any{"expires_at": next.Format(time.RFC3339), "custom_new": "kept"}}, false, next, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]any{
				"access_token": "opaque", "expires_in": 3600, "timestamp": old.Add(-time.Hour).Format(time.RFC3339),
				"token": map[string]any{"expires_at": old.Format(time.RFC3339), "custom": "kept"},
			}
			ReplaceCodexOuterExpiration(metadata, tc.source, tc.sameBearer)
			expiry, known := (&Auth{Metadata: metadata}).OuterExpirationTime()
			if known != tc.known || (known && !expiry.Equal(tc.want)) {
				t.Fatalf("expiry=%v known=%t, want %v known=%t", expiry, known, tc.want, tc.known)
			}
			if nested, _ := metadata["token"].(map[string]any); nested["custom"] != "kept" {
				t.Fatal("expiry replacement erased custom legacy container data")
			}
			if tc.name == "changed new nested" {
				if nested, _ := metadata["Token"].(map[string]any); nested["custom_new"] != "kept" {
					t.Fatal("expiry replacement dropped new custom nested data")
				}
			}
		})
	}
}

func TestCodexSIWCExpirationSnapshot(t *testing.T) {
	real := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	legacy := real.Add(-codex.SIWCExpiryMargin)
	initial := map[string]any{
		"access_token": "opaque-old", "expired": legacy.Format(time.RFC3339), "expires_at": real.Format(time.RFC3339),
		"expires_in": 3600, "last_refresh": real.Add(-time.Hour).Format(time.RFC3339),
	}
	for _, tc := range []struct {
		name, bearer string
		source       map[string]any
		sameBearer   bool
		wantReal     time.Time
		wantLegacy   time.Time
		knownReal    bool
		knownLegacy  bool
	}{
		{name: "same omitted", bearer: "opaque-old", source: map[string]any{}, sameBearer: true, wantReal: real, wantLegacy: legacy, knownReal: true, knownLegacy: true},
		{name: "changed omitted", bearer: "opaque-new", source: map[string]any{}},
		{name: "same explicit clear", bearer: "opaque-old", source: map[string]any{"expires_at": nil}, sameBearer: true},
		{name: "legacy only", bearer: "opaque-new", source: map[string]any{"expired": legacy.Format(time.RFC3339)}, wantLegacy: legacy, knownLegacy: true},
		{name: "relative", bearer: "opaque-new", source: map[string]any{"expires_in": 3600, "last_refresh": real.Add(-time.Hour).Format(time.RFC3339)}, wantReal: real, wantLegacy: real, knownReal: true, knownLegacy: true},
		{name: "relative without base", bearer: "opaque-new", source: map[string]any{"expires_in": 3600}},
		{name: "distinct buffered and real", bearer: "opaque-new", source: map[string]any{"expires_at": real.Format(time.RFC3339), "expired": legacy.Format(time.RFC3339)}, wantReal: real, wantLegacy: legacy, knownReal: true, knownLegacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := (&Auth{Metadata: initial}).Clone().Metadata
			source := (&Auth{Metadata: tc.source}).Clone().Metadata
			source["access_token"] = tc.bearer
			ReplaceCodexSIWCExpiration(target, initial, source, tc.sameBearer)
			target["access_token"] = tc.bearer
			candidate := &Auth{Metadata: map[string]any{"siwc": target}}
			gotReal, knownReal := candidate.SIWCRealExpirationTime()
			gotLegacy, knownLegacy := candidate.SIWCExpirationTime()
			if knownReal != tc.knownReal || knownLegacy != tc.knownLegacy || (knownReal && !gotReal.Equal(tc.wantReal)) || (knownLegacy && !gotLegacy.Equal(tc.wantLegacy)) {
				t.Fatalf("real=%v (%t), fallback=%v (%t)", gotReal, knownReal, gotLegacy, knownLegacy)
			}
		})
	}
}

func TestCodexSIWCRelativeLifetimeKeepsOriginalBase(t *testing.T) {
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := map[string]any{"access_token": "same", "expires_in": 3600, "last_refresh": issued.Format(time.RFC3339)}
	returned := map[string]any{"access_token": "same", "last_refresh": issued.Add(time.Minute).Format(time.RFC3339), "refresh_token": "rotated"}
	ReplaceCodexSIWCExpiration(returned, current, returned, true)
	a := &Auth{Metadata: map[string]any{"siwc": returned}}
	if expiry, known := a.SIWCRenewalExpirationTime(); !known || !expiry.Equal(issued.Add(time.Hour)) {
		t.Fatalf("sparse renewal moved the original relative lifetime: %v (%t)", expiry, known)
	}
}

func TestCodexExpirationJWTPrecedence(t *testing.T) {
	want := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	claims, errMarshal := json.Marshal(map[string]any{"exp": want.Unix()})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	token := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	source := map[string]any{"access_token": token, "expires_at": "2000-01-01T00:00:00Z", "expired": "1999-12-31T23:57:00Z"}
	outer := &Auth{Metadata: source}
	if expiry, ok := outer.OuterExpirationTime(); !ok || !expiry.Equal(want) {
		t.Fatal("outer metadata overrode real JWT lifetime")
	}
	nested := &Auth{Metadata: map[string]any{"use_siwc": true, "siwc": source}}
	if expiry, ok := nested.SIWCRenewalExpirationTime(); !ok || !expiry.Equal(want) {
		t.Fatal("SIWC metadata overrode real JWT lifetime")
	}
	adopted := map[string]any{"access_token": token}
	ReplaceCodexSIWCExpiration(adopted, nil, source, false)
	nested.Metadata["siwc"] = adopted
	if expiry, ok := nested.AccessTokenExpirationTime(); !ok || !expiry.Equal(want) {
		t.Fatal("SIWC normalization changed JWT lifetime")
	}
}

func TestCodexExpirationPartitionCAS(t *testing.T) {
	base := &Auth{Provider: "codex", Metadata: map[string]any{
		"access_token": "outer-old", "refresh_token": "outer-grant", "expires_in": 3600, "timestamp": "2000-01-01T00:00:00Z",
		"Token": map[string]any{"expires_at": "2000-01-01T01:00:00Z", "custom": "base"},
		"siwc":  map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-grant", "expired": "2000-01-01T00:00:00Z"},
	}}
	updated := base.Clone()
	updated.Metadata["access_token"] = "outer-obsolete"
	ReplaceCodexOuterExpiration(updated.Metadata, map[string]any{"expires_at": "2001-01-01T00:00:00Z"}, false)
	updated.Metadata["siwc"] = map[string]any{"access_token": "siwc-new", "refresh_token": "siwc-new-grant", "expiresAt": "2099-01-01T00:00:00Z"}
	updated.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.Metadata, updated.Metadata, true, true)
	current := base.Clone()
	current.Metadata["access_token"] = "outer-current"
	current.Metadata["expires_in"], current.Metadata["timestamp"] = 7200, "2098-01-01T00:00:00Z"
	current.Metadata["Token"] = map[string]any{"expires_at": "2098-01-01T02:00:00Z", "custom": "admin"}
	merged := MergeRefreshedAuth(base, current, updated)
	if merged.Metadata["access_token"] != "outer-current" || merged.Metadata["expires_in"] != 7200 || merged.Metadata["timestamp"] != "2098-01-01T00:00:00Z" || !reflect.DeepEqual(merged.Metadata["Token"], current.Metadata["Token"]) {
		t.Fatal("stale outer refresh bypassed partition CAS through expiry metadata")
	}
	if siwc, _ := merged.Metadata["siwc"].(map[string]any); siwc["access_token"] != "siwc-new" || siwc["expiresAt"] != "2099-01-01T00:00:00Z" {
		t.Fatal("stale outer refresh prevented independent SIWC adoption")
	}
}

func TestCodexOuterRefreshTimestampCAS(t *testing.T) {
	for _, field := range codex.RefreshTimeMetadataKeys() {
		t.Run(field, func(t *testing.T) {
			base := &Auth{Provider: "codex", Attributes: map[string]string{field: "2000-01-01T00:00:00Z"}, Metadata: map[string]any{
				"access_token": "base", "refresh_token": "base-grant", field: "2000-01-01T00:00:00Z",
				"siwc": map[string]any{"access_token": "siwc-base", "refresh_token": "siwc-grant"},
			}}
			updated := base.Clone()
			updated.Metadata["access_token"] = "obsolete-result"
			updated.Metadata[field] = "2099-01-01T00:00:00Z"
			updated.Attributes[field] = "2099-01-01T00:00:00Z"
			updated.Metadata["siwc"].(map[string]any)["access_token"] = "siwc-updated"
			updated.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.Metadata, updated.Metadata, true, true)
			current := base.Clone()
			current.Metadata["access_token"], current.Metadata["refresh_token"] = "current", "current-grant"
			merged := MergeRefreshedAuth(base, current, updated)
			if merged.Metadata[field] != "2000-01-01T00:00:00Z" || merged.Attributes[field] != "2000-01-01T00:00:00Z" {
				t.Fatal("obsolete outer result bypassed CAS through a refresh timestamp")
			}
			if merged.Metadata["siwc"].(map[string]any)["access_token"] != "siwc-updated" {
				t.Fatal("independent SIWC patch was lost")
			}
		})
	}
}

func TestCodexOuterRefreshTimestampPresence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source *Auth
		want   string
	}{
		{"attributes", &Auth{Attributes: map[string]string{"lastRefresh": "2099-01-01T00:00:00Z"}}, "2099-01-01T00:00:00Z"},
		{"explicit clear blocks attributes", &Auth{Metadata: map[string]any{"last_refresh": nil}, Attributes: map[string]string{"lastRefresh": "2099-01-01T00:00:00Z"}}, ""},
		{"mistyped blocks attributes", &Auth{Metadata: map[string]any{"last_refresh": []string{"wrong"}}, Attributes: map[string]string{"lastRefresh": "2099-01-01T00:00:00Z"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &Auth{Metadata: map[string]any{"last_refresh": "2000-01-01T00:00:00Z"}, Attributes: map[string]string{"lastRefreshedAt": "2000-01-01T00:00:00Z"}, LastRefreshedAt: time.Now()}
			ReplaceCodexOuterRefreshTime(target, tc.source, true)
			got, _ := target.Metadata["last_refresh"].(string)
			if got != tc.want || !target.LastRefreshedAt.IsZero() || target.Attributes["lastRefreshedAt"] != "" {
				t.Fatal("refresh timestamp retained a conflicting source")
			}
		})
	}
	t.Run("same bearer inherits attributes", func(t *testing.T) {
		target := &Auth{Metadata: map[string]any{}, Attributes: map[string]string{"lastRefresh": "2099-01-01T00:00:00Z"}}
		ReplaceCodexOuterRefreshTime(target, &Auth{}, true)
		if target.Metadata["last_refresh"] != "2099-01-01T00:00:00Z" || target.Attributes["lastRefresh"] != "" {
			t.Fatal("sparse same-bearer renewal lost its legacy refresh timestamp")
		}
	})
}
