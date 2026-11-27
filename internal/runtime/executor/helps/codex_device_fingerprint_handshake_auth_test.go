package helps

import (
	"net/http"
	"reflect"
	"testing"
)

func TestCodexDeviceFingerprintFinalHandshakeHeaderSemantics(t *testing.T) {
	policy := CodexDevicePolicy{Enabled: true, ID: codexDeviceTestID}
	original := http.Header{"Authorization": {"Bearer custom-a"}, "ChatGPT-Account-ID": {"workspace"}}
	before := original.Clone()
	first := policy.IdentityForHandshake(nil, original, "selected")
	for _, tc := range []struct {
		name       string
		headers    http.Header
		compatible bool
	}{
		{"case-only", http.Header{"authorization": {"Bearer custom-a"}, "CHATGPT-ACCOUNT-ID": {"workspace"}}, true},
		{"unrelated-header", http.Header{"Authorization": {"Bearer custom-a"}, "ChatGPT-Account-ID": {"workspace"}, "Session-Id": {"different"}}, true},
		{"changed-token", http.Header{"Authorization": {"Bearer custom-b"}, "ChatGPT-Account-ID": {"workspace"}}, false},
		{"changed-account", http.Header{"Authorization": {"Bearer custom-a"}, "ChatGPT-Account-ID": {"other"}}, false},
		{"removed-account", http.Header{"Authorization": {"Bearer custom-a"}}, false},
		{"removed-authorization", http.Header{"ChatGPT-Account-ID": {"workspace"}}, false},
		{"empty-handshake", http.Header{}, false},
		{"control-no-handshake", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := policy.IdentityForHandshake(nil, tc.headers, "selected")
			if first.CompatibleHandshake(next) != tc.compatible {
				t.Fatal("final authentication compatibility did not match the header change")
			}
		})
	}
	if !reflect.DeepEqual(original, before) {
		t.Fatal("read-only handshake identity mutated final headers")
	}
	control := first.Merge(policy.Identity(nil, nil))
	if control != first {
		t.Fatal("control frame discarded the physical handshake identity")
	}
}
