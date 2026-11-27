package helps

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexDeviceFingerprintHomeRefreshIdentity(t *testing.T) {
	const memberA = "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"
	const memberB = "fd5de10e-f853-4dd0-92f4-ece041b115a9"
	for _, test := range []struct {
		name                    string
		metadata                map[string]any
		attributes              map[string]string
		account, user, plan, id string
		defaulted               bool
	}{
		{
			name:       "metadata free does not inherit auxiliary default provenance",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", ""), "plan_type": "free"},
			attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"},
			account:    "acc-team-1", user: "user-aaa", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "metadata false clears auxiliary default provenance",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", ""), "plan_type": "free", "plan_type_defaulted": false},
			attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"},
			account:    "acc-team-1", user: "user-aaa", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "null metadata provenance is not auxiliary provenance",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", ""), "plan_type": "free", "plan_type_defaulted": nil},
			attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"},
			account:    "acc-team-1", user: "user-aaa", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "invalid metadata provenance is not auxiliary provenance",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", ""), "plan_type": "free", "plan_type_defaulted": "true"},
			attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"},
			account:    "acc-team-1", user: "user-aaa", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "foreign auxiliary member cannot shadow adopted token",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			attributes: map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"},
			account:    "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:       "same account auxiliary member cannot shadow adopted token",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			attributes: map[string]string{"account_id": "acc-team-1", "chatgpt_user_id": "user-aaa", "plan_type": "team"},
			account:    "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:       "canonical token supplies missing account before auxiliary account",
			metadata:   map[string]any{"id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			attributes: map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"},
			account:    "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:       "foreign auxiliary plan cannot supply missing claim",
			metadata:   map[string]any{"account_id": "acc-test-1", "id_token": codexDeviceTestToken(t, "acc-test-1", "", "")},
			attributes: map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"},
			account:    "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:     "new member",
			metadata: map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			account:  "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:     "new account missing member",
			metadata: map[string]any{"account_id": "acc-team-2", "id_token": codexDeviceTestToken(t, "acc-team-2", "", "team")},
			account:  "acc-team-2", plan: "team", id: "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a",
		},
		{
			name:     "same subject missing claims",
			metadata: map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "", "")},
			account:  "acc-team-1", plan: "free", defaulted: true, id: memberA,
		},
		{
			name:     "same subject token rotation",
			metadata: map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team")},
			account:  "acc-team-1", user: "user-aaa", plan: "team", id: memberA,
		},
		{
			name:       "source attribute hints",
			attributes: map[string]string{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team"), "chatgpt_user_id": "user-bbb", "plan_type": "team"},
			account:    "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:       "canonical metadata beats auxiliary attributes",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			attributes: map[string]string{"account_id": "acc-team-2", "id_token": codexDeviceTestToken(t, "acc-team-2", "user-aaa", "free")},
			account:    "acc-team-1", user: "user-bbb", plan: "team", id: memberB,
		},
		{
			name:       "explicit absence clears auxiliary account and token",
			metadata:   map[string]any{"account_id": "", "id_token": ""},
			attributes: map[string]string{"account_id": "acc-team-2", "id_token": codexDeviceTestToken(t, "acc-team-2", "user-bbb", "team")},
			plan:       "free", defaulted: true, id: memberA,
		},
		{
			name:     "explicit free",
			metadata: map[string]any{"account_id": "acc-test-1", "id_token": codexDeviceTestToken(t, "acc-test-1", "", ""), "plan_type": "free", "plan_type_defaulted": false},
			account:  "acc-test-1", plan: "free", id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:     "defaulted free missing plan",
			metadata: map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", ""), "plan_type": "free", "plan_type_defaulted": true},
			account:  "acc-team-1", user: "user-bbb", plan: "free", defaulted: true, id: memberB,
		},
		{
			name:     "foreign account claims",
			metadata: map[string]any{"account_id": "acc-test-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-bbb", "team")},
			account:  "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:    "all identity absent",
			account: "", plan: "free", defaulted: true, id: memberA,
		},
		{
			name:       "auxiliary token belongs to another account",
			metadata:   map[string]any{"account_id": "acc-test-1"},
			attributes: map[string]string{"id_token": codexDeviceTestToken(t, "acc-team-2", "user-bbb", "team"), "chatgpt_user_id": "user-bbb", "plan_type": "team"},
			account:    "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:       "cleared canonical token blocks auxiliary member",
			metadata:   map[string]any{"account_id": "acc-test-1", "id_token": nil},
			attributes: map[string]string{"account_id": "acc-test-1", "id_token": codexDeviceTestToken(t, "acc-test-1", "user-bbb", "team"), "chatgpt_user_id": "user-bbb", "plan_type": "team"},
			account:    "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:       "null canonical member blocks auxiliary member",
			metadata:   map[string]any{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "", "team"), "chatgpt_user_id": nil},
			attributes: map[string]string{"account_id": "acc-team-1", "chatgpt_user_id": "user-bbb"},
			account:    "acc-team-1", plan: "team", id: memberA,
		},
		{
			name:       "cleared canonical plan blocks auxiliary plan",
			metadata:   map[string]any{"account_id": "acc-test-1", "id_token": codexDeviceTestToken(t, "acc-test-1", "", ""), "plan_type": nil, "chatgpt_plan_type": nil},
			attributes: map[string]string{"account_id": "acc-test-1", "plan_type": "team", "chatgpt_plan_type": "team"},
			account:    "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
		{
			name:       "legacy auxiliary explicit free retains source provenance",
			attributes: map[string]string{"account_id": "acc-team-1", "id_token": codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team"), "chatgpt_plan_type": "team", "plan_type": "free", "plan_type_defaulted": "false"},
			account:    "acc-team-1", user: "user-aaa", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "empty default marker remains explicit free",
			metadata:   map[string]any{"account_id": "acc-team-1", "plan_type": "free", "plan_type_defaulted": ""},
			attributes: map[string]string{"plan_type": "free", "plan_type_defaulted": "true"},
			account:    "acc-team-1", plan: "free", id: "c2a63432-aabe-4908-8fe6-ec89af8327c9",
		},
		{
			name:       "malformed canonical identity blocks auxiliary recovery",
			metadata:   map[string]any{"account_id": 12, "id_token": false, "chatgpt_user_id": []any{}, "chatgpt_plan_type": nil, "plan_type": nil},
			attributes: map[string]string{"account_id": "acc-team-2", "id_token": codexDeviceTestToken(t, "acc-team-2", "user-bbb", "team"), "chatgpt_user_id": "user-bbb", "plan_type": "team"},
			plan:       "free", defaulted: true, id: memberA,
		},
		{
			name:       "empty member and plan do not inherit auxiliary fields",
			metadata:   map[string]any{"account_id": "acc-test-1", "id_token": "", "chatgpt_user_id": "", "chatgpt_plan_type": "", "plan_type": ""},
			attributes: map[string]string{"account_id": "acc-test-1", "chatgpt_user_id": "user-bbb", "chatgpt_plan_type": "team", "plan_type": "team"},
			account:    "acc-test-1", plan: "free", defaulted: true, id: "e1e46a26-def3-4e3e-9ee2-185e59ed0444",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := codexDeviceTestConfig()
			cfg.Home.Enabled = true
			old := codexDeviceTestAuth("codex-a.json", "acc-team-1")
			old.Index = "home-auth"
			old.Metadata["id_token"] = codexDeviceTestToken(t, "acc-team-1", "user-aaa", "team")
			old.Metadata["chatgpt_user_id"] = "user-aaa"
			old.Metadata["chatgpt_plan_type"] = "team"
			old.Metadata["plan_type"] = "team"
			old.Metadata["plan_type_defaulted"] = false
			old.Metadata["codex_device_fingerprint"] = "device"
			old.Metadata["operator_note"] = "keep"
			old.Metadata["siwc"] = map[string]any{"access_token": "siwc-keep"}
			old.Metadata["use_siwc"] = true
			for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type", "plan_type"} {
				old.Attributes[key], _ = old.Metadata[key].(string)
			}
			old.Attributes["plan_type_defaulted"] = "false"
			old.Attributes["header:X-Operator"] = "keep"
			originalAttributes := make(map[string]string, len(old.Attributes))
			for key, value := range old.Attributes {
				originalAttributes[key] = value
			}
			var resolver CodexDeviceResolver
			if got := resolver.Resolve(cfg, old, false, codexDeviceTestURL).ID; got != memberA {
				t.Fatal("initial member golden mismatch")
			}
			returned := &cliproxyauth.Auth{Provider: "codex", Metadata: test.metadata, Attributes: test.attributes}
			raw := ojson.NewDocString(`{}`)
			if errSet := raw.Set("auth", returned); errSet != nil {
				t.Fatal(errSet)
			}
			client := &fakeHomeRefreshClient{raw: raw.Bytes()}
			oldClient := currentHomeRefreshClient
			currentHomeRefreshClient = func() homeRefreshClient { return client }
			t.Cleanup(func() { currentHomeRefreshClient = oldClient })
			updated, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, old)
			if errRefresh != nil || !handled || updated == nil {
				t.Fatalf("refresh result = %v, %v", handled, errRefresh)
			}
			adopted := old.Clone()
			for key, value := range updated.Metadata {
				adopted.Metadata[key] = value
			}
			for key, value := range updated.Attributes {
				adopted.Attributes[key] = value
			}
			AdoptCodexHomeIdentity(adopted, updated)
			if got := adopted.Metadata["account_id"]; got != test.account {
				t.Fatalf("adopted account mismatch")
			}
			if got, _ := adopted.Metadata["chatgpt_user_id"].(string); got != test.user {
				t.Fatalf("adopted member mismatch")
			}
			if got := adopted.Metadata["plan_type"]; got != test.plan {
				t.Fatalf("plan = %v, want %v", got, test.plan)
			}
			if got := adopted.Metadata["plan_type_defaulted"]; got != test.defaulted {
				t.Fatalf("default provenance = %v, want %v", got, test.defaulted)
			}
			for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type"} {
				if _, exists := adopted.Attributes[key]; exists {
					t.Fatalf("stale attribute remains: %s", key)
				}
			}
			if adopted.Metadata["operator_note"] != "keep" || adopted.Metadata["use_siwc"] != true || adopted.Metadata["siwc"].(map[string]any)["access_token"] != "siwc-keep" || adopted.Attributes["header:X-Operator"] != "keep" {
				t.Fatal("administrator or SIWC metadata changed")
			}
			if !reflect.DeepEqual(old.Attributes, originalAttributes) || !reflect.DeepEqual(updated.Attributes, test.attributes) {
				t.Fatal("input attribute map changed")
			}
			policy := resolver.Resolve(cfg, adopted, false, codexDeviceTestURL)
			if policy.ID != test.id {
				t.Fatal("adopted identity differs from golden")
			}
			body := ojson.NewDocString(`{"client_metadata":{"x-codex-installation-id":"old","x-codex-turn-metadata":"{\"installation_id\":\"old\",\"turn\":\"keep\"}"}}`)
			if errApply := policy.ApplyDoc(body, false); errApply != nil {
				t.Fatal(errApply)
			}
			headers := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"old","turn":"keep"}`}}
			policy.ApplyHeaders(headers)
			if body.Get("client_metadata.x-codex-installation-id").String() != test.id || ojson.NewDocString(headers.Get("X-Codex-Turn-Metadata")).Get("installation_id").String() != test.id {
				t.Fatal("body/header identity differs from adopted credential")
			}
		})
	}
}

func TestStatusFromHomeErrorCodeMapsAuthenticationErrorToUnauthorized(t *testing.T) {
	if got := statusFromHomeErrorCode("authentication_error"); got != http.StatusUnauthorized {
		t.Fatalf("statusFromHomeErrorCode(authentication_error) = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := statusFromHomeErrorCode("unauthorized"); got != http.StatusUnauthorized {
		t.Fatalf("statusFromHomeErrorCode(unauthorized) = %d, want %d", got, http.StatusUnauthorized)
	}
	for _, code := range []string{"auth_not_found", "auth_unavailable", "refresh_temporarily_unavailable", "refresh_unsupported"} {
		if got := statusFromHomeErrorCode(code); got != http.StatusServiceUnavailable {
			t.Fatalf("statusFromHomeErrorCode(%s) = %d, want %d", code, got, http.StatusServiceUnavailable)
		}
	}
}

type fakeHomeRefreshClient struct {
	calls           atomic.Int32
	authIndex       string
	accessTokenHash string
	raw             []byte
	err             error
}

func (c *fakeHomeRefreshClient) HeartbeatOK() bool {
	return true
}

func (c *fakeHomeRefreshClient) GetRefreshAuth(_ context.Context, authIndex string, accessTokenHash string) ([]byte, error) {
	c.calls.Add(1)
	c.authIndex = authIndex
	c.accessTokenHash = accessTokenHash
	return c.raw, c.err
}

func TestRefreshAuthViaHomePreservesContextErrors(t *testing.T) {
	client := &fakeHomeRefreshClient{err: context.DeadlineExceeded}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return client }
	t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "codex"}
	_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
	if !handled || !errors.Is(errRefresh, context.DeadlineExceeded) {
		t.Fatalf("RefreshAuthViaHome() = handled %v err %v, want true/context.DeadlineExceeded", handled, errRefresh)
	}
}

func TestHomeStatusErrLogDiagnosticSanitizesUpstreamFallback(t *testing.T) {
	errRefresh := homeStatusErr{
		code:     http.StatusBadGateway,
		msg:      "upstream EOF access_token=provider-secret",
		upstream: true,
	}
	diagnostic := errRefresh.LogDiagnostic()
	if diagnostic != "Home refresh upstream response: status=502" || strings.Contains(diagnostic, "provider-secret") {
		t.Fatalf("LogDiagnostic() = %q, want safe upstream fallback", diagnostic)
	}
	if errRefresh.Error() != "upstream EOF access_token=provider-secret" {
		t.Fatalf("Error() = %q, want exact upstream response", errRefresh.Error())
	}
}

func TestRefreshAuthViaHomeMapsTransportFailureToGeneric503(t *testing.T) {
	client := &fakeHomeRefreshClient{err: errors.New("dial failed with provider-secret")}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return client }
	t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "codex"}
	_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
	statusErr, okStatus := errRefresh.(interface{ StatusCode() int })
	if !handled || !okStatus || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("RefreshAuthViaHome() = handled %v err %v, want generic 503", handled, errRefresh)
	}
	if strings.Contains(errRefresh.Error(), "provider-secret") {
		t.Fatalf("refresh error included transport detail: %v", errRefresh)
	}
	direct, okDirect := errRefresh.(interface {
		DirectResponse() bool
		ResponseBody() []byte
	})
	if !okDirect || direct.DirectResponse() {
		t.Fatalf("transport error direct response = %v/%v, want false", okDirect, direct)
	}
	diagnosticErr, okDiagnostic := errRefresh.(interface{ LogDiagnostic() string })
	if !okDiagnostic || !strings.Contains(diagnosticErr.LogDiagnostic(), "dial_failed") {
		t.Fatalf("transport log diagnostic = %T/%v, want allowlisted transport cause", errRefresh, errRefresh)
	}
	if strings.Contains(diagnosticErr.LogDiagnostic(), "provider-secret") {
		t.Fatalf("transport log diagnostic leaked provider detail: %q", diagnosticErr.LogDiagnostic())
	}
}

func TestRefreshAuthViaHomeUsesGenericMessageForLegacyErrorEnvelope(t *testing.T) {
	client := &fakeHomeRefreshClient{raw: []byte(`{"error":{"type":"error","message":"provider response: refresh_token=provider-secret"}}`)}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return client }
	t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "codex"}
	_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
	statusErr, okStatus := errRefresh.(interface{ StatusCode() int })
	if !handled || !okStatus || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("RefreshAuthViaHome() = handled %v err %v, want generic 503", handled, errRefresh)
	}
	if strings.Contains(errRefresh.Error(), "provider-secret") {
		t.Fatalf("refresh error included legacy Home detail: %v", errRefresh)
	}
	if diagnosticErr, ok := errRefresh.(interface{ LogDiagnostic() string }); !ok || diagnosticErr.LogDiagnostic() != "Home refresh failed: type=error" {
		t.Fatalf("legacy Home error type log diagnostic = %T/%v", errRefresh, errRefresh)
	}
}

func TestRefreshAuthViaHomeUsesDedicatedDiagnosticOnlyForLogs(t *testing.T) {
	const diagnostic = "antigravity refresh failed: stage=transport err=EOF"
	client := &fakeHomeRefreshClient{raw: []byte(`{"error":{"type":"refresh_temporarily_unavailable","message":"untrusted provider-secret","diagnostic":"` + diagnostic + `"}}`)}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return client }
	t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "antigravity"}
	_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
	if !handled || errRefresh == nil || errRefresh.Error() != "credential refresh temporarily unavailable" {
		t.Fatalf("RefreshAuthViaHome() = handled %v err %v, want generic client error", handled, errRefresh)
	}
	diagnosticErr, ok := errRefresh.(interface{ LogDiagnostic() string })
	if !ok || diagnosticErr.LogDiagnostic() != diagnostic {
		t.Fatalf("log diagnostic = %T/%v, want %q", errRefresh, errRefresh, diagnostic)
	}
	if strings.Contains(errRefresh.Error(), diagnostic) || strings.Contains(errRefresh.Error(), "provider-secret") {
		t.Fatalf("client error exposed internal detail: %v", errRefresh)
	}
}

func TestRefreshAuthViaHomePreservesUpstreamStatusAndBodyExactly(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "json", status: http.StatusBadRequest, body: []byte(`{"error":"invalid_request"}`)},
		{name: "access token expired", status: http.StatusUnauthorized, body: []byte(`{"error":{"message":"access token expired"}}`)},
		{name: "text", status: http.StatusBadGateway, body: []byte("provider unavailable")},
		{name: "multiline", status: http.StatusTooManyRequests, body: []byte("first line\r\nsecond line\n")},
		{name: "empty", status: http.StatusUnauthorized, body: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, errMarshal := json.Marshal(homeErrorEnvelope{Error: &homeErrorDetail{
				Type:       "refresh_temporarily_unavailable",
				Message:    "credential refresh temporarily unavailable",
				Diagnostic: "antigravity refresh failed: stage=upstream_response status=400",
				Upstream: &homeUpstreamResponse{
					Status: tt.status,
					Body:   tt.body,
				},
			}})
			if errMarshal != nil {
				t.Fatalf("marshal Home error envelope: %v", errMarshal)
			}
			client := &fakeHomeRefreshClient{raw: raw}
			oldCurrentHomeRefreshClient := currentHomeRefreshClient
			currentHomeRefreshClient = func() homeRefreshClient { return client }
			t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

			cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
			auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "codex"}
			_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
			statusErr, okStatus := errRefresh.(interface{ StatusCode() int })
			if !handled || !okStatus || statusErr.StatusCode() != tt.status {
				t.Fatalf("RefreshAuthViaHome() = handled %v err %v status %v, want true/%d", handled, errRefresh, okStatus, tt.status)
			}
			if got := []byte(errRefresh.Error()); !bytes.Equal(got, tt.body) {
				t.Fatalf("refresh body = %q, want exact body %q", got, tt.body)
			}
			direct, okDirect := errRefresh.(interface {
				DirectResponse() bool
				ResponseBody() []byte
			})
			if !okDirect || !direct.DirectResponse() {
				t.Fatalf("upstream error direct response = %v/%v, want true", okDirect, direct)
			}
			if got := direct.ResponseBody(); !bytes.Equal(got, tt.body) {
				t.Fatalf("direct response body = %q, want exact body %q", got, tt.body)
			}
			diagnosticErr, okDiagnostic := errRefresh.(interface{ LogDiagnostic() string })
			if !okDiagnostic || !strings.Contains(diagnosticErr.LogDiagnostic(), "stage=upstream_response") {
				t.Fatalf("upstream log diagnostic = %T/%v", errRefresh, errRefresh)
			}
		})
	}
}

func TestRefreshAuthViaHomeUsesGenericMessageForLegacyProviderDiagnostics(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		raw        []byte
		wantStatus int
		wantError  string
		wantLog    string
	}{
		{
			name:       "transient transport diagnostic",
			provider:   "antigravity",
			raw:        []byte(`{"error":{"type":"refresh_temporarily_unavailable","message":"antigravity refresh: Post https://oauth.example/token?access_token=provider-secret: connection refused"}}`),
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "credential refresh temporarily unavailable",
			wantLog:    "Home refresh failed: type=refresh_temporarily_unavailable",
		},
		{
			name:       "terminal legacy diagnostic",
			provider:   "codex",
			raw:        []byte(`{"error":{"type":"authentication_error","message":"codex refresh: invalid_grant refresh_token=provider-secret"}}`),
			wantStatus: http.StatusUnauthorized,
			wantError:  "credential unauthorized",
			wantLog:    "Home refresh failed: type=authentication_error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeHomeRefreshClient{raw: tt.raw}
			oldCurrentHomeRefreshClient := currentHomeRefreshClient
			currentHomeRefreshClient = func() homeRefreshClient { return client }
			t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

			cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
			auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: tt.provider}
			_, handled, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
			statusErr, okStatus := errRefresh.(interface{ StatusCode() int })
			if !handled || !okStatus || statusErr.StatusCode() != tt.wantStatus {
				t.Fatalf("RefreshAuthViaHome() = handled %v err %v, want status %d", handled, errRefresh, tt.wantStatus)
			}
			if got := errRefresh.Error(); got != tt.wantError {
				t.Fatalf("client refresh error = %q, want %q", got, tt.wantError)
			}
			if strings.Contains(errRefresh.Error(), "provider-secret") {
				t.Fatalf("legacy refresh error leaked provider detail: %v", errRefresh)
			}
			diagnosticErr, okDiagnostic := errRefresh.(interface{ LogDiagnostic() string })
			if !okDiagnostic {
				t.Fatalf("legacy refresh log diagnostic type = %T, want LogDiagnostic", errRefresh)
			}
			if got := diagnosticErr.LogDiagnostic(); got != tt.wantLog {
				t.Fatalf("legacy refresh log diagnostic = %q, want %q", got, tt.wantLog)
			}
			if strings.Contains(diagnosticErr.LogDiagnostic(), "provider-secret") {
				t.Fatalf("legacy refresh log diagnostic leaked provider detail: %q", diagnosticErr.LogDiagnostic())
			}
		})
	}
}

func TestRefreshAuthViaHomeRejectsUnmarkedRefreshMessage(t *testing.T) {
	client := &fakeHomeRefreshClient{raw: []byte(`{"error":{"type":"refresh_temporarily_unavailable","message":"database unavailable: provider-secret"}}`)}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return client }
	t.Cleanup(func() { currentHomeRefreshClient = oldCurrentHomeRefreshClient })

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{ID: "home-auth", Index: "home-auth", Provider: "antigravity"}
	_, _, errRefresh := RefreshAuthViaHome(context.Background(), cfg, auth)
	if got, want := errRefresh.Error(), "credential refresh temporarily unavailable"; got != want {
		t.Fatalf("refresh error = %q, want %q", got, want)
	}
}

func TestAuthAccessTokenSHA256SupportsKnownMetadataShapes(t *testing.T) {
	want := authAccessTokenSHA256(&cliproxyauth.Auth{Metadata: map[string]any{"access_token": "same-token"}})
	cases := map[string]*cliproxyauth.Auth{
		"camel case":        {Metadata: map[string]any{"accessToken": "same-token"}},
		"nested any map":    {Metadata: map[string]any{"token": map[string]any{"access_token": "same-token"}}},
		"nested string map": {Metadata: map[string]any{"Token": map[string]string{"accessToken": "same-token"}}},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			if got := authAccessTokenSHA256(auth); got == "" || got != want {
				t.Fatalf("token hash = %q, want %q", got, want)
			}
		})
	}
}

func TestRefreshAuthViaHomeAcceptsAuthEnvelope(t *testing.T) {
	raw, errMarshal := json.Marshal(struct {
		Auth      cliproxyauth.Auth `json:"auth"`
		AuthIndex string            `json:"auth_index"`
	}{
		Auth: cliproxyauth.Auth{
			ID:       "home-auth-1",
			Provider: "antigravity",
			Metadata: map[string]any{
				"access_token": "new-access-token",
			},
		},
		AuthIndex: "home-index-1",
	})
	if errMarshal != nil {
		t.Fatalf("marshal home envelope: %v", errMarshal)
	}

	client := &fakeHomeRefreshClient{raw: raw}
	oldCurrentHomeRefreshClient := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient {
		return client
	}
	t.Cleanup(func() {
		currentHomeRefreshClient = oldCurrentHomeRefreshClient
	})

	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	auth := &cliproxyauth.Auth{
		ID:       "home-auth-1",
		Provider: "antigravity",
		Index:    "home-index-1",
		Metadata: map[string]any{
			"access_token":  "old-access-token",
			"refresh_token": "refresh-token",
		},
	}

	updated, handled, err := RefreshAuthViaHome(context.Background(), cfg, auth)
	if err != nil {
		t.Fatalf("RefreshAuthViaHome error: %v", err)
	}
	if !handled {
		t.Fatal("RefreshAuthViaHome handled = false, want true")
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("home refresh calls = %d, want 1", got)
	}
	if client.authIndex != "home-index-1" {
		t.Fatalf("home refresh auth_index = %q, want home-index-1", client.authIndex)
	}
	if client.accessTokenHash != authAccessTokenSHA256(auth) {
		t.Fatalf("home refresh access token hash = %q, want %q", client.accessTokenHash, authAccessTokenSHA256(auth))
	}
	if updated == nil {
		t.Fatal("updated auth = nil")
	}
	if got := updated.Metadata["access_token"]; got != "new-access-token" {
		t.Fatalf("updated access_token = %q, want new-access-token", got)
	}
	if updated.Index != "home-index-1" {
		t.Fatalf("updated auth_index = %q, want home-index-1", updated.Index)
	}
}
