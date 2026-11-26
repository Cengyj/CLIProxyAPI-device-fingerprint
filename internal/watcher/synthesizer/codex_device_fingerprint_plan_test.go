package synthesizer

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func fingerprintPlanFile(t *testing.T, plan string) []byte {
	t.Helper()
	claims := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa"}}`)
	if plan != "" {
		if err := claims.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", plan); err != nil {
			t.Fatal(err)
		}
	}
	token := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig"
	doc := ojson.NewDocString(`{"type":"codex","access_token":"synthetic","codex_device_fingerprint":"device"}`)
	if err := doc.Set("id_token", token); err != nil {
		t.Fatal(err)
	}
	return doc.Bytes()
}

func fingerprintSynthesizePlan(t *testing.T, ctx *SynthesisContext, path string, raw []byte) *coreauth.Auth {
	t.Helper()
	auths, err := SynthesizeAuthFile(ctx, path, raw)
	if err != nil || len(auths) != 1 {
		t.Fatalf("SynthesizeAuthFile count=%d err=%v", len(auths), err)
	}
	return auths[0]
}

func TestCodexDeviceFingerprintSynthesizedMissingPlan(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	ctx := &SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: NewStableIDGenerator()}
	path := filepath.Join(dir, "account.json")
	var resolver helps.CodexDeviceResolver
	for _, plan := range []string{"team", "business", "enterprise", "edu"} {
		t.Run(plan, func(t *testing.T) {
			original := fingerprintSynthesizePlan(t, ctx, path, fingerprintPlanFile(t, plan))
			first := resolver.Resolve(cfg, original, false, "http://localhost/responses")
			if first.ID != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatalf("wrong complete Team vector %s", first.ID)
			}
			missing := fingerprintSynthesizePlan(t, ctx, path, fingerprintPlanFile(t, ""))
			if missing.Attributes["plan_type"] != "free" {
				t.Fatal("general default-free behavior changed")
			}
			if got := resolver.Resolve(cfg, missing, false, "http://localhost/responses"); got.ID != first.ID {
				t.Fatalf("synthesized missing plan changed Team device: got %s want %s", got.ID, first.ID)
			}
		})
	}
}

func TestCodexDeviceFingerprintSynthesizedPlanTransitions(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	ctx := &SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: NewStableIDGenerator()}
	path := filepath.Join(dir, "account.json")
	const target = "http://localhost/responses"
	var resolver helps.CodexDeviceResolver
	initial := fingerprintSynthesizePlan(t, ctx, path, fingerprintPlanFile(t, "team"))
	first := resolver.Resolve(cfg, initial, false, target)
	missingRaw := fingerprintPlanFile(t, "")
	missing := fingerprintSynthesizePlan(t, ctx, path, missingRaw)
	if resolver.Resolve(cfg, missing, false, target).ID != first.ID {
		t.Fatal("reconstructed credential lost recent Team plan")
	}
	// Explicit free is an intentional transition, even when the JWT omits its plan.
	explicit := ojson.NewDoc(missingRaw)
	if errSet := explicit.Set("plan_type", "free"); errSet != nil {
		t.Fatal(errSet)
	}
	if got := resolver.Resolve(cfg, fingerprintSynthesizePlan(t, ctx, path, explicit.Bytes()), false, target); got.ID != "c2a63432-aabe-4908-8fe6-ec89af8327c9" {
		t.Fatal("explicit free failed to replace Team plan")
	}
	resolver.Resolve(cfg, initial, false, target)
	// A new account never receives a prior workspace's plan or member hints.
	changed := ojson.NewDoc(missingRaw)
	if errSet := changed.Set("account_id", "acc-test-2"); errSet != nil {
		t.Fatal(errSet)
	}
	if got := resolver.Resolve(cfg, fingerprintSynthesizePlan(t, ctx, path, changed.Bytes()), false, target); got.ID != "3216ba40-955f-42a6-aabf-a9ac6ae94a30" {
		t.Fatal("changed account borrowed old Team claims")
	}
	resolver.Resolve(cfg, initial, false, target)
	// Missing-field recovery is bounded and deliberately does not survive restart.
	for i := 0; i < 513; i++ {
		other := fingerprintSynthesizePlan(t, ctx, filepath.Join(dir, fmt.Sprintf("other-%d.json", i)), fingerprintPlanFile(t, "team"))
		resolver.Resolve(cfg, other, false, target)
	}
	if got := resolver.Resolve(cfg, missing, false, target); got.ID != "c2a63432-aabe-4908-8fe6-ec89af8327c9" {
		t.Fatal("evicted identity retained unbounded Team state")
	}
	var restarted helps.CodexDeviceResolver
	if got := restarted.Resolve(cfg, missing, false, target); got.ID != "c2a63432-aabe-4908-8fe6-ec89af8327c9" {
		t.Fatal("restart fabricated an unavailable Team plan")
	}
}
