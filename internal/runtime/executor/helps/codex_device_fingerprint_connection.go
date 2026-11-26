package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ApplyHeadersFromSource preserves every caller turn-metadata value before the
// built-in rewrite. Other headers keep the executor's existing forwarding rules.
// Neither the caller map nor its slices are mutated. Administrator overrides
// must run after this method.
func (p CodexDevicePolicy) ApplyHeadersFromSource(target, source http.Header) {
	if !p.Enabled || target == nil {
		return
	}
	var values []string
	found := false
	for key, list := range source {
		if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
			found = true
			values = append(values, list...)
		}
	}
	if found {
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
	return current.Enabled && current.ID == policy.ID && current.SIWC == policy.SIWC
}
