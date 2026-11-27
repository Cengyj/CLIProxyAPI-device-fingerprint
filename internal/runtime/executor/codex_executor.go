package executor

import (
	"context"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// CodexExecutor executes Codex requests and retains bounded device identity hints.
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type CodexExecutor struct {
	cfg            *config.Config
	deviceResolver *helps.CodexDeviceResolver
}

func NewCodexExecutor(cfg *config.Config) *CodexExecutor {
	return &CodexExecutor{cfg: cfg, deviceResolver: &helps.CodexDeviceResolver{}}
}

func (e *CodexExecutor) Identifier() string { return "codex" }

// ShouldPrepareRequestAuth limits Home identity adoption to OAuth snapshots.
func (e *CodexExecutor) ShouldPrepareRequestAuth(auth *cliproxyauth.Auth) bool {
	return e != nil && e.cfg != nil && e.cfg.Home.Enabled && auth != nil &&
		(auth.Provider == "" || strings.EqualFold(strings.TrimSpace(auth.Provider), "codex")) &&
		auth.AuthKind() != cliproxyauth.AuthKindAPIKey && strings.TrimSpace(auth.Attributes["api_key"]) == ""
}

// PrepareRequestAuth applies the same identity source rules to first Home
// dispatch and refresh before a transport resolves its immutable device policy.
func (e *CodexExecutor) PrepareRequestAuth(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if ctx != nil {
		if errContext := ctx.Err(); errContext != nil {
			return nil, errContext
		}
	}
	if !e.ShouldPrepareRequestAuth(auth) {
		return auth, nil
	}
	prepared := auth.Clone()
	helps.AdoptCodexHomeIdentity(prepared, auth)
	return prepared, nil
}

func (e *CodexExecutor) modelLevelCooling() bool {
	return e != nil && e.cfg != nil && e.cfg.Codex.ModelLevelCooling
}

// SupportsApplyPatch reports the actual executor contract, independent of its provider name.
func (e *CodexExecutor) SupportsApplyPatch() bool { return e != nil }
