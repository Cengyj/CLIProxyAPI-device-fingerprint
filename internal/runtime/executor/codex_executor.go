package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
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

func (e *CodexExecutor) modelLevelCooling() bool {
	return e != nil && e.cfg != nil && e.cfg.Codex.ModelLevelCooling
}

// SupportsApplyPatch reports the actual executor contract, independent of its provider name.
func (e *CodexExecutor) SupportsApplyPatch() bool { return e != nil }
