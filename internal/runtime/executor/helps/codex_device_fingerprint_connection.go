package helps

import (
	"crypto/sha256"
	"net/http"
	"slices"
	"strings"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// IdentityForHandshake binds final authentication headers after administrator
// overrides. Controls have no handshake and continue to use Identity. Only
// digests are retained; normal selected-token renewal uses the subject guard,
// while opaque custom credentials cannot claim that same renewal contract.
func (p CodexDevicePolicy) IdentityForHandshake(doc *ojson.Doc, headers http.Header, selectedBearer string) CodexDeviceIdentity {
	identity := p.Identity(doc, headers)
	if !p.Enabled || headers == nil {
		return identity
	}
	var keys []string
	for key := range headers {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "ChatGPT-Account-ID") {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	type authHeaderValue struct {
		Name  string
		Value [32]byte
	}
	var values []authHeaderValue
	for _, key := range keys {
		for _, value := range headers[key] {
			value = strings.TrimSpace(value)
			kind := strings.ToLower(key)
			var digest [32]byte
			if strings.EqualFold(key, "Authorization") && len(value) >= len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
				bearer := strings.TrimSpace(value[len("Bearer "):])
				if subject, known := codexauth.ParseJWTSubject(bearer); known {
					encoded, _ := json.Marshal(subject)
					digest = sha256.Sum256(encoded)
					kind += ":subject"
				} else if bearer == strings.TrimSpace(selectedBearer) {
					digest = p.credentialSubject
					kind += ":selected"
				} else {
					digest = sha256.Sum256([]byte(value))
				}
			} else {
				digest = sha256.Sum256([]byte(value))
			}
			values = append(values, authHeaderValue{Name: kind, Value: digest})
		}
	}
	// Header-name casing cannot change authentication. Preserve the actual
	// value order within one header, but normalize order across header names.
	slices.SortStableFunc(values, func(a, b authHeaderValue) int {
		return strings.Compare(a.Name, b.Name)
	})
	encoded, _ := json.Marshal(values)
	identity.handshakeAuth = sha256.Sum256(encoded)
	identity.hasHandshakeAuth = true
	return identity
}

// CompatibleHandshake checks a candidate handshake against the headers actually
// sent on a retained socket. A newly requested device header needs a new socket;
// it cannot be learned from a business frame that never transmits those headers.
// Missing candidate fields impose no new identity requirement.
func (i CodexDeviceIdentity) CompatibleHandshake(other CodexDeviceIdentity) bool {
	if !i.Compatible(other) {
		return false
	}
	for field := 2; field < len(i.values); field++ {
		if other.values[field] != "" && i.values[field] != other.values[field] {
			return false
		}
	}
	return true
}

// ApplyHeadersFromSource preserves every caller turn-metadata value before the
// built-in rewrite. Other headers keep the executor's existing forwarding rules.
// Neither the caller map nor its slices are mutated. Administrator overrides
// must run after this method.
func (p CodexDevicePolicy) ApplyHeadersFromSource(target, source http.Header) {
	if !p.Enabled || target == nil {
		return
	}
	var keys []string
	for key := range source {
		if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
			keys = append(keys, key)
		}
	}
	if len(keys) > 0 {
		// Preserve each key's value order and make case-variant merging stable
		// across retries that rebuild headers from the same caller snapshot.
		slices.Sort(keys)
		var values []string
		for _, key := range keys {
			values = append(values, source[key]...)
		}
		for key := range target {
			if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
				delete(target, key)
			}
		}
		target["X-Codex-Turn-Metadata"] = values
	}
	p.ApplyHeaders(target)
}

// CompatibleFrozenAuth checks identity only. Global/per-auth mode and injection
// updates cannot change an active duplex, but a different credential subject or
// explicit installation ID cannot be sent on its already authenticated socket.
// Auth is a dispatcher-owned immutable snapshot; a temporary copy prevents this
// check from mutating its metadata or attributes.
func (r *CodexDeviceResolver) CompatibleFrozenAuth(policy CodexDevicePolicy, auth *cliproxyauth.Auth, useSIWC bool, targetURL string) bool {
	if !policy.Enabled {
		return true
	}
	if auth == nil || useSIWC != policy.SIWC {
		return false
	}
	copyAuth := *auth
	copyAuth.Attributes = make(map[string]string, len(auth.Attributes)+1)
	for key, value := range auth.Attributes {
		copyAuth.Attributes[key] = value
	}
	copyAuth.Attributes["codex_device_fingerprint"] = "device"
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &policy.InjectMissing}}
	current := r.Resolve(cfg, &copyAuth, useSIWC, targetURL)
	return current.Enabled && current.ID == policy.ID && current.SIWC == policy.SIWC && current.credentialSubject == policy.credentialSubject
}
