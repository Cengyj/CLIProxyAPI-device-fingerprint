package helps

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const codexDeviceTestURL = "http://127.0.0.1:1234/custom/responses"
const codexDeviceTestID = "11111111-2222-4333-8444-555555555555"
const codexDeviceOtherID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func codexDeviceTestConfig() *config.Config {
	return &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
}

func codexDeviceTestAuth(id, account string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: id, Provider: "codex", Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth}, Metadata: map[string]any{"account_id": account}}
}

func codexDeviceTestToken(t *testing.T, account, user, plan string) string {
	t.Helper()
	doc := ojson.NewDocString(`{}`)
	for path, value := range map[string]string{"https://api\\.openai\\.com/auth.chatgpt_account_id": account, "https://api\\.openai\\.com/auth.chatgpt_user_id": user, "https://api\\.openai\\.com/auth.chatgpt_plan_type": plan} {
		if value != "" {
			if errSet := doc.Set(path, value); errSet != nil {
				t.Fatal(errSet)
			}
		}
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
}

func TestCodexDeviceFingerprintModesAndScope(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		enabled    bool
	}{
		{"omitted", "", false}, {"off", "off", false}, {"mixed off", " OFF ", false}, {"device", "device", true}, {"mixed device", " Device \t", true}, {"unknown", "full", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := codexDeviceTestConfig()
			cfg.Codex.DeviceFingerprintMode = test.mode
			var resolver CodexDeviceResolver
			got := resolver.Resolve(cfg, codexDeviceTestAuth("a", "account"), false, codexDeviceTestURL)
			if got.Enabled != test.enabled {
				t.Fatalf("enabled=%v want %v", got.Enabled, test.enabled)
			}
		})
	}
	var resolver CodexDeviceResolver
	if resolver.Resolve(nil, nil, false, codexDeviceTestURL).Enabled {
		t.Fatal("nil enabled")
	}
	if resolver.Resolve(nil, codexDeviceTestAuth("a", "account"), false, codexDeviceTestURL).Enabled {
		t.Fatal("nil config enabled")
	}
	cfg := codexDeviceTestConfig()
	for _, route := range []string{"https://example.test/responses", "http://localhost/v1/responses/", "wss://example.test/backend-api/codex/responses", "https://example.test/responses/compact"} {
		if !resolver.Resolve(cfg, codexDeviceTestAuth("a", "account"), false, route).Enabled {
			t.Errorf("target excluded: %s", route)
		}
	}
	for _, route := range []string{"https://example.test/images/generations", "https://example.test/alpha/search", "https://example.test/live", "https://example.test/responses/extra", "%bad"} {
		if resolver.Resolve(cfg, codexDeviceTestAuth("a", "account"), false, route).Enabled {
			t.Errorf("target included: %s", route)
		}
	}
	for _, kind := range []string{"attribute-kind", "metadata-kind", "key", "key-and-siwc", "other-provider"} {
		auth := codexDeviceTestAuth("a", "account")
		auth.Metadata["codex_device_fingerprint"] = "device"
		switch kind {
		case "attribute-kind":
			auth.Attributes[cliproxyauth.AttributeAuthKind] = cliproxyauth.AuthKindAPIKey
		case "metadata-kind":
			delete(auth.Attributes, cliproxyauth.AttributeAuthKind)
			auth.Metadata[cliproxyauth.AttributeAuthKind] = cliproxyauth.AuthKindAPIKey
		case "key":
			auth.Attributes["api_key"] = "secret"
		case "key-and-siwc":
			auth.Attributes["api_key"] = "secret"
			auth.Metadata["use_siwc"] = true
		case "other-provider":
			auth.Provider = "claude"
		}
		if resolver.Resolve(cfg, auth, true, codexDeviceTestURL).Enabled {
			t.Errorf("enabled for %s", kind)
		}
	}
}

func TestCodexDeviceFingerprintPrecedenceAndInjection(t *testing.T) {
	cfg := codexDeviceTestConfig()
	auth := codexDeviceTestAuth("a", "account")
	var resolver CodexDeviceResolver
	auth.Metadata["codex_device_fingerprint"] = " off "
	if resolver.Resolve(cfg, auth, false, codexDeviceTestURL).Enabled {
		t.Fatal("metadata off did not override global")
	}
	auth.Attributes["codex_device_fingerprint"] = " DEVICE "
	if !resolver.Resolve(cfg, auth, false, codexDeviceTestURL).Enabled {
		t.Fatal("attributes did not override metadata")
	}
	auth.Attributes["codex_device_fingerprint"] = "unknown"
	if resolver.Resolve(cfg, auth, false, codexDeviceTestURL).Enabled {
		t.Fatal("unknown attributes fell through")
	}
	auth.Attributes["codex_device_fingerprint"] = " "
	if resolver.Resolve(cfg, auth, false, codexDeviceTestURL).Enabled {
		t.Fatal("blank attribute did not defer to metadata off")
	}
	delete(auth.Metadata, "codex_device_fingerprint")
	auth.Metadata["codex_installation_id"] = codexDeviceTestID
	auth.Attributes["codex_installation_id"] = codexDeviceOtherID
	if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL).ID; got != codexDeviceOtherID {
		t.Fatalf("attribute override=%s", got)
	}
	auth.Attributes["codex_installation_id"] = "bad"
	if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL).ID; got != codexDeviceTestID {
		t.Fatalf("invalid attribute did not fallback=%s", got)
	}
	cfg.Codex.DeviceFingerprintMode = "off"
	if resolver.Resolve(cfg, auth, false, codexDeviceTestURL).Enabled {
		t.Fatal("explicit ID implicitly enabled")
	}
	cfg.Codex.DeviceFingerprintMode = "device"
	no, yes := false, true
	for _, value := range []*bool{nil, &no, &yes} {
		cfg.Codex.DeviceFingerprintInjectMissing = value
		p := resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
		if p.InjectMissing != (value != nil && *value) {
			t.Fatal("wrong injection")
		}
		if resolver.Resolve(cfg, auth, true, codexDeviceTestURL).InjectMissing {
			t.Fatal("SIWC injection")
		}
	}
}

func TestCodexDeviceFingerprintUUIDAndGoldenVectors(t *testing.T) {
	for _, raw := range []string{codexDeviceTestID, strings.ToUpper(codexDeviceOtherID), " " + codexDeviceTestID + " "} {
		id, valid := codexDeviceValidUUID(raw)
		if !valid || id != strings.ToLower(strings.TrimSpace(raw)) {
			t.Fatalf("valid UUID rejected: %q", raw)
		}
	}
	for _, raw := range []string{"", "00000000-0000-0000-0000-000000000000", "11111111-2222-1333-8444-555555555555", "11111111-2222-4333-7444-555555555555", "urn:uuid:" + codexDeviceTestID, "{" + codexDeviceTestID + "}", strings.ReplaceAll(codexDeviceTestID, "-", "")} {
		if _, valid := codexDeviceValidUUID(raw); valid {
			t.Errorf("invalid UUID accepted: %q", raw)
		}
	}
	for _, test := range []struct{ seed, want string }{
		{"account\x00acc-test-1", "e1e46a26-def3-4e3e-9ee2-185e59ed0444"},
		{"account\x00acc-test-2", "3216ba40-955f-42a6-aabf-a9ac6ae94a30"},
		{"account-user\x00acc-team-1\x00user-aaa", "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"},
		{"account-user\x00acc-team-1\x00user-bbb", "fd5de10e-f853-4dd0-92f4-ece041b115a9"},
		{"auth-id\x00codex-a.json", "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a"},
	} {
		if got := codexDeviceUUID(test.seed); got != test.want {
			t.Fatalf("golden got=%s want=%s", got, test.want)
		}
	}
}

func TestCodexDeviceFingerprintAccountStability(t *testing.T) {
	cfg := codexDeviceTestConfig()
	var resolver CodexDeviceResolver
	auth := codexDeviceTestAuth("first.json", "")
	auth.Metadata["id_token"] = codexDeviceTestToken(t, "acc-test-1", "user-1", "")
	first := resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
	if first.ID != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" {
		t.Fatalf("JWT account=%s", first.ID)
	}
	auth.Metadata["account_id"] = "acc-test-1"
	auth.Metadata["access_token"] = "new-access"
	auth.Metadata["refresh_token"] = "new-refresh"
	auth.Metadata["email"] = ""
	if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL); got != first {
		t.Fatal("token refresh changed identity")
	}
	rebuilt := codexDeviceTestAuth("renamed.json", "acc-test-1")
	var restarted CodexDeviceResolver
	// Public account UUIDs survive missing claims, but a socket authenticated
	// for a known member cannot treat an unknown member as the same subject.
	for _, current := range []*CodexDeviceResolver{&resolver, &restarted} {
		got := current.Resolve(cfg, rebuilt, false, codexDeviceTestURL)
		if got.ID != first.ID || got.Enabled != first.Enabled || got.InjectMissing != first.InjectMissing || got.SIWC != first.SIWC {
			t.Fatal("renamed or restarted credential changed public account device policy")
		}
		if first.Identity(nil, nil).CompatibleHandshake(got.Identity(nil, nil)) {
			t.Fatal("missing member was assumed to own an existing authenticated socket")
		}
	}
	knownMember := rebuilt.Clone()
	knownMember.Metadata["chatgpt_user_id"] = "user-1"
	if got := restarted.Resolve(cfg, knownMember, false, codexDeviceTestURL); got != first {
		t.Fatal("same known member changed identity after restart")
	}
	if resolver.Resolve(cfg, codexDeviceTestAuth("second", "acc-test-2"), false, codexDeviceTestURL).ID == first.ID {
		t.Fatal("different account shared identity")
	}
	if resolver.Resolve(cfg, codexDeviceTestAuth("", ""), false, codexDeviceTestURL).Enabled {
		t.Fatal("unknown accounts shared fallback")
	}
}

func TestCodexDeviceFingerprintTeamAndStickyState(t *testing.T) {
	cfg := codexDeviceTestConfig()
	var resolver CodexDeviceResolver
	auth := codexDeviceTestAuth("team.json", "acc-team-1")
	auth.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team")
	first := resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
	if first.ID != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
		t.Fatalf("team claim=%s", first.ID)
	}
	empty := codexDeviceTestAuth(auth.ID, "")
	if got := resolver.Resolve(cfg, empty, false, codexDeviceTestURL); got != first {
		t.Fatal("transient empty fields lost identity")
	}
	// A token with an absent plan must not overwrite the last explicit team plan with free.
	empty.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "")
	if got := resolver.Resolve(cfg, empty, false, codexDeviceTestURL); got != first {
		t.Fatal("missing plan became free")
	}
	other := codexDeviceTestAuth("member-b", "acc-team-1")
	other.Metadata["plan_type"] = "business"
	other.Metadata["chatgpt_user_id"] = "user-bbb"
	if got := resolver.Resolve(cfg, other, false, codexDeviceTestURL).ID; got != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
		t.Fatalf("second member=%s", got)
	}
	for _, plan := range []string{"team", "business", "enterprise", "edu"} {
		missing := codexDeviceTestAuth("missing-"+plan, "acc-team-1")
		missing.Metadata["plan_type"] = plan
		if got := resolver.Resolve(cfg, missing, false, codexDeviceTestURL).ID; got != codexDeviceUUID("auth-id\x00"+missing.ID) {
			t.Fatalf("missing team user merged: %s", plan)
		}
		missing.ID = ""
		if resolver.Resolve(cfg, missing, false, codexDeviceTestURL).Enabled {
			t.Fatal("missing team user and auth ID enabled")
		}
	}
	changed := codexDeviceTestAuth(auth.ID, "acc-team-2")
	changed.Metadata["plan_type"] = "team"
	changed.Metadata["id_token"] = auth.Metadata["id_token"]
	if got := resolver.Resolve(cfg, changed, false, codexDeviceTestURL).ID; got != codexDeviceUUID("auth-id\x00"+auth.ID) {
		t.Fatal("new account borrowed cached/old-token user")
	}
	changed.Metadata["codex_installation_id"] = codexDeviceTestID
	if got := resolver.Resolve(cfg, changed, false, codexDeviceTestURL).ID; got != codexDeviceTestID {
		t.Fatal("cache displaced explicit ID")
	}
	// A changed account with no plan must not inherit the old team plan.
	delete(changed.Metadata, "codex_installation_id")
	delete(changed.Metadata, "plan_type")
	delete(changed.Metadata, "id_token")
	changed.Metadata["account_id"] = "new-personal"
	if got := resolver.Resolve(cfg, changed, false, codexDeviceTestURL).ID; got != codexDeviceUUID("account\x00new-personal") {
		t.Fatal("new account borrowed plan")
	}
	// With no account, a new user cannot be combined with a remembered workspace.
	partial := codexDeviceTestAuth(auth.ID, "")
	partial.Metadata["chatgpt_user_id"] = "unknown-workspace-member"
	partial.Metadata["plan_type"] = "team"
	if got := resolver.Resolve(cfg, partial, false, codexDeviceTestURL).ID; got != codexDeviceUUID("auth-id\x00"+auth.ID) {
		t.Fatal("unknown account borrowed cached workspace")
	}
}

func TestCodexDeviceFingerprintCacheBoundAndConcurrency(t *testing.T) {
	cfg := codexDeviceTestConfig()
	var resolver CodexDeviceResolver
	for i := 0; i < codexDeviceCacheLimit+20; i++ {
		resolver.Resolve(cfg, codexDeviceTestAuth(fmt.Sprintf("auth-%d", i), fmt.Sprintf("account-%d", i)), false, codexDeviceTestURL)
	}
	if len(resolver.entries) != codexDeviceCacheLimit || resolver.recent.Len() != codexDeviceCacheLimit {
		t.Fatal("cache exceeded bound")
	}
	if resolver.entries[codexDeviceCacheKey{id: "auth-0"}] != nil {
		t.Fatal("oldest entry was not evicted")
	}
	cfg.Codex.DeviceFingerprintMode = "off"
	before := len(resolver.entries)
	for i := 0; i < 10; i++ {
		resolver.Resolve(cfg, codexDeviceTestAuth(fmt.Sprintf("off-%d", i), "off"), false, codexDeviceTestURL)
	}
	if len(resolver.entries) != before {
		t.Fatal("off mutated cache")
	}
	cfg.Codex.DeviceFingerprintMode = "device"
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				auth := codexDeviceTestAuth(fmt.Sprintf("parallel-%d", i), "acc-test-1")
				if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL).ID; got != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" {
					t.Errorf("concurrent identity=%s", got)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestCodexDeviceFingerprintSIWCRequestSelection(t *testing.T) {
	cfg := codexDeviceTestConfig()
	yes := true
	cfg.Codex.DeviceFingerprintInjectMissing = &yes
	auth := codexDeviceTestAuth("a", "acc-test-1")
	auth.Metadata["siwc"] = map[string]any{"device_id": strings.ToUpper(codexDeviceOtherID)}
	auth.Metadata["codex_installation_id"] = codexDeviceTestID
	var resolver CodexDeviceResolver
	if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL); got.ID != codexDeviceTestID || !got.InjectMissing || got.SIWC {
		t.Fatal("unused SIWC affected route")
	}
	if got := resolver.Resolve(cfg, auth, true, codexDeviceTestURL); got.ID != codexDeviceOtherID || got.InjectMissing || !got.SIWC {
		t.Fatal("active SIWC did not dominate")
	}
	auth.Metadata["siwc"] = map[string]any{"device_id": "invalid"}
	if got := resolver.Resolve(cfg, auth, true, codexDeviceTestURL); got.ID != codexDeviceTestID || got.InjectMissing {
		t.Fatal("SIWC fallback wrong")
	}
	delete(auth.Metadata, "siwc")
	delete(auth.Metadata, "codex_installation_id")
	if got := resolver.Resolve(cfg, auth, true, codexDeviceTestURL); got.ID != "e1e46a26-def3-4e3e-9ee2-185e59ed0444" || got.InjectMissing {
		t.Fatal("SIWC missing device fallback wrong")
	}
}

func TestCodexDeviceFingerprintDocPrecisionDuplicatesAndIdempotence(t *testing.T) {
	p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	doc := ojson.NewDocString(`{"client_metadata":{"x-codex-installation-id":"old","x-codex-installation-id":"older","x-codex-turn-metadata":"{\"installation_id\":\"old\",\"installation_id\":\"older\",\"turn_id\":\"round\",\"number\":900719925474099312345,\"text\":\"雪 \\\\ \\\" 🚀\",\"unknown\":{\"installation_id\":\"nested\"}}","unknown":1,"unknown":2,"thread_id":"thread","window_id":"window"},"prompt_cache_key":"cache","previous_response_id":"previous","response_id":"response","input":[{"text":"keep"}],"n":900719925474099312345}`)
	if err := p.ApplyDoc(doc, false); err != nil {
		t.Fatal(err)
	}
	metadata := doc.Get("client_metadata")
	counts := map[string]int{}
	metadata.ForEach(func(key, value ojson.Result) bool { counts[key.String()]++; return true })
	if counts[codexDeviceInstallation] != 1 || counts["unknown"] != 2 {
		t.Fatalf("duplicate normalization=%v", counts)
	}
	if got := metadata.Get(codexDeviceInstallation).String(); got != p.ID {
		t.Fatalf("ID=%s", got)
	}
	inner := ojson.Parse(metadata.Get(codexDeviceTurnMetadata).String())
	if inner.Get("installation_id").String() != p.ID || inner.Get("unknown.installation_id").String() != "nested" || inner.Get("number").Raw != "900719925474099312345" {
		t.Fatal("inner rewrite lost data")
	}
	if inner.Get("turn_id").String() != "round" || inner.Get("text").String() != "雪 \\ \" 🚀" {
		t.Fatalf("escaped data changed: %s", inner.Raw)
	}
	for path, want := range map[string]string{"client_metadata.thread_id": "thread", "client_metadata.window_id": "window", "prompt_cache_key": "cache", "previous_response_id": "previous", "response_id": "response", "input.0.text": "keep", "n": "900719925474099312345"} {
		if doc.Get(path).String() != want {
			t.Errorf("non-target changed %s", path)
		}
	}
	first := doc.String()
	if err := p.ApplyDoc(doc, false); err != nil {
		t.Fatal(err)
	}
	if doc.String() != first {
		t.Fatal("not idempotent")
	}
	for _, raw := range []string{`{"client_metadata":{},"client_metadata":{}}`, `{"client_metadata":{},"client_\u006detadata":{}}`} {
		if err := p.ValidateInput([]byte(raw)); err == nil {
			t.Fatal("ambiguous original accepted")
		}
		if err := p.ApplyDoc(ojson.NewDocString(raw), false); err == nil {
			t.Fatal("ambiguous final built-in accepted")
		}
	}
}

func TestCodexDeviceFingerprintDocShapesAndControl(t *testing.T) {
	for _, raw := range []string{`[]`, `null`, `42`, `"text"`, `{"client_metadata":null}`, `{"client_metadata":[]}`, `{"client_metadata":"text"}`, `{"client_metadata":false}`, `{"client_metadata":{broken}`} {
		doc := ojson.NewDocString(raw)
		p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID, InjectMissing: true}
		if err := p.ApplyDoc(doc, false); err != nil {
			t.Fatal(err)
		}
		if doc.String() != raw {
			t.Errorf("malformed shape changed: %s", raw)
		}
	}
	for _, control := range []bool{false, true} {
		for _, siwc := range []bool{false, true} {
			for _, inject := range []bool{false, true} {
				p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID, InjectMissing: inject, SIWC: siwc}
				for _, raw := range []string{`{}`, `{"client_metadata":{}}`} {
					doc := ojson.NewDocString(raw)
					if err := p.ApplyDoc(doc, control); err != nil {
						t.Fatal(err)
					}
					if doc.Get("client_metadata."+codexDeviceInstallation).Exists() != (inject && !siwc && !control) {
						t.Fatal("wrong injection scope")
					}
				}
			}
		}
	}
	p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	for _, value := range []string{`null`, `{}`, `"not json"`, `"[]"`, `"null"`, `"42"`} {
		doc := ojson.NewDocString(`{"client_metadata":{"x-codex-turn-metadata":` + value + `,"keep":true}}`)
		if err := p.ApplyDoc(doc, false); err != nil {
			t.Fatal(err)
		}
		if doc.Get("client_metadata."+codexDeviceTurnMetadata).Exists() || !doc.Get("client_metadata.keep").Bool() {
			t.Fatalf("invalid turn not removed: %s", doc.String())
		}
	}
	doc := ojson.NewDocString(`{"client_metadata":{"x-codex-turn-metadata":"{\"turn_id\":\"t\"}"}}`)
	if err := p.ApplyDoc(doc, false); err != nil {
		t.Fatal(err)
	}
	if ojson.Parse(doc.Get("client_metadata." + codexDeviceTurnMetadata).String()).Get("installation_id").Exists() {
		t.Fatal("injected missing inner ID")
	}
	// Duplicate target fields normalize to the last value, preserving every unrelated member.
	doc = ojson.NewDocString(`{"client_metadata":{"x-codex-turn-metadata":"invalid","x-codex-turn-metadata":"{\"installation_id\":\"old\",\"keep\":true}"}}`)
	if err := p.ApplyDoc(doc, true); err != nil {
		t.Fatal(err)
	}
	if strings.Count(doc.String(), `x-codex-turn-metadata`) != 1 || !ojson.Parse(doc.Get("client_metadata."+codexDeviceTurnMetadata).String()).Get("keep").Bool() {
		t.Fatal("duplicate turn normalization")
	}
}

func TestCodexDeviceFingerprintHeadersAndOffNoop(t *testing.T) {
	shared := []string{`{"installation_id":"old","turn_id":"t","n":900719925474099312345}`, `invalid`, `{"session_id":"s"}`, `[]`}
	headers := http.Header{"x-codex-turn-metadata": shared, "X-CODEX-TURN-METADATA": {`{"installation_id":"other"}`}, "X-Codex-Installation-Id": {"old"}, "x-codex-installation-id": {"older"}, "X-Client-Request-Id": {"client"}, "X-Codex-Turn-State": {"state"}}
	p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	p.ApplyHeaders(headers)
	if len(headers["x-codex-turn-metadata"]) != 2 {
		t.Fatal("header values not filtered individually")
	}
	for key, values := range headers {
		if strings.EqualFold(key, "X-Codex-Installation-Id") {
			t.Fatal("independent header survived")
		}
		if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
			for _, value := range values {
				parsed := ojson.Parse(value)
				if id := parsed.Get("installation_id"); id.Exists() && id.String() != p.ID {
					t.Fatal("header not converged")
				}
			}
		}
	}
	if shared[0] != `{"installation_id":"old","turn_id":"t","n":900719925474099312345}` || len(shared) != 4 {
		t.Fatal("shared header slice mutated")
	}
	if headers.Get("X-Client-Request-Id") != "client" || headers.Get("X-Codex-Turn-State") != "state" {
		t.Fatal("non-device header changed")
	}
	first := headers.Clone()
	p.ApplyHeaders(headers)
	if !reflect.DeepEqual(first, headers) {
		t.Fatal("header processing not idempotent")
	}
	var off CodexDevicePolicy
	raw := ` { "client_metadata": {"x-codex-installation-id":"old","x-codex-turn-metadata": false},"client_metadata":{} } `
	doc := ojson.NewDocString(raw)
	if err := off.ApplyDoc(doc, false); err != nil {
		t.Fatal(err)
	}
	if err := off.ValidateInput([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	untouched := http.Header{"x-codex-installation-id": {"old"}, "X-CODEX-TURN-METADATA": {"invalid"}}
	copyHeaders := untouched.Clone()
	off.ApplyHeaders(untouched)
	if doc.String() != raw || !reflect.DeepEqual(untouched, copyHeaders) {
		t.Fatal("off changed body or headers")
	}
}

func TestCodexDeviceFingerprintAttemptContextAndFinalIdentity(t *testing.T) {
	p := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	ctx := WithCodexDevicePolicy(context.Background(), p)
	p.ID = codexDeviceOtherID
	if got, ok := CodexDevicePolicyFromContext(ctx); !ok || got.ID != codexDeviceTestID {
		t.Fatal("context snapshot changed")
	}
	ctx = WithCodexDevicePolicy(ctx, p)
	if got, _ := CodexDevicePolicyFromContext(ctx); got.ID != codexDeviceOtherID {
		t.Fatal("attempt did not replace policy")
	}
	body := func(id string) *ojson.Doc {
		doc := ojson.NewDocString(`{}`)
		if id != "" {
			if err := doc.Set("client_metadata."+codexDeviceInstallation, id); err != nil {
				t.Fatal(err)
			}
		}
		return doc
	}
	a := p.Identity(body(codexDeviceTestID), nil)
	b := p.Identity(body(codexDeviceOtherID), nil)
	if id, ok := a.EffectiveID(); !ok || id != codexDeviceTestID {
		t.Fatal("effective final device ID unavailable")
	}
	if a.Compatible(b) {
		t.Fatal("different final override reused")
	}
	missing := p.Identity(body(""), nil)
	if !a.Compatible(missing) || !missing.Compatible(a) {
		t.Fatal("missing treated as new device")
	}
	if !missing.Merge(a).Compatible(a) || missing.Merge(a).Compatible(b) {
		t.Fatal("merge forgot established identity")
	}
	if a.Compatible((CodexDevicePolicy{}).Identity(body(codexDeviceTestID), nil)) {
		t.Fatal("mode transition compatible")
	}
	if a.Compatible((CodexDevicePolicy{Enabled: true, SIWC: true}).Identity(body(codexDeviceTestID), nil)) {
		t.Fatal("SIWC transition compatible")
	}
	header := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"` + codexDeviceTestID + `","turn_id":"one"}`}}
	h := p.Identity(body(""), header)
	if h.Compatible(b) {
		t.Fatal("new frame ID conflicts with existing handshake")
	}
	header["X-Codex-Turn-Metadata"] = []string{`{"installation_id":"` + codexDeviceTestID + `","turn_id":"two"}`}
	if !h.Compatible(p.Identity(body(""), header)) {
		t.Fatal("turn ID leaked into compatibility")
	}
	// A changed derived ID is irrelevant when all final configured values agree.
	q := p
	q.ID = codexDeviceTestID
	if !a.Compatible(q.Identity(body(codexDeviceTestID), nil)) {
		t.Fatal("derived identity overruled final values")
	}
	conflict := p.Identity(body(codexDeviceOtherID), header)
	if _, ok := conflict.EffectiveID(); ok {
		t.Fatal("conflicting administrator values appeared unambiguous")
	}
	if !conflict.Compatible(p.Identity(body(codexDeviceOtherID), header)) {
		t.Fatal("same explicit conflict was unstable")
	}
	if conflict.Compatible(p.Identity(body(codexDeviceTestID), header)) {
		t.Fatal("changed explicit conflict reused a device")
	}
	third := ojson.NewDocString(`{"client_metadata":{"x-codex-turn-metadata":"{\"installation_id\":\"99999999-9999-4999-8999-999999999999\"}"}}`)
	if conflict.Compatible(p.Identity(third, header)) {
		t.Fatal("new location introduced a third device into a conflicting connection")
	}
}
