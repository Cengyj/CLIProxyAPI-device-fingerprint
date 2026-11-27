package helps_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexHomeRefreshPreservesLocalSource(t *testing.T) {
	for _, scenario := range []struct {
		mode string
		file bool
	}{{"off", false}, {"off", true}, {"device", false}, {"device", true}} {
		file := scenario.file
		name := "memory"
		if file {
			name = "file"
		}
		t.Run(scenario.mode+"/"+name, func(t *testing.T) {
			cfg, manager, store, path, base := homeGrantFixture(t, file, "2099-01-01T00:00:00Z", false)
			cfg.Codex.DeviceFingerprintMode = scenario.mode
			dir := cfg.AuthDir
			if dir == "" {
				dir = t.TempDir()
				store.SetBaseDir(dir)
				path = filepath.Join(dir, base.FileName)
			}
			var errUpdate error
			base, errUpdate = manager.Update(t.Context(), base)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			other, errRegister := manager.Register(t.Context(), &auth.Auth{ID: "other.json", FileName: "other.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "other-access", "refresh_token": "other-grant", "account_id": "other-account", "expired": "2099-01-01T00:00:00Z",
			}})
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			otherPath, errSaveOther := store.Save(t.Context(), other)
			if errSaveOther != nil {
				t.Fatal(errSaveOther)
			}
			beforeOther, errReadOther := os.ReadFile(otherPath)
			if errReadOther != nil {
				t.Fatal(errReadOther)
			}
			homeGrantResponse(t, &auth.Auth{ID: base.ID, Provider: "codex", Attributes: map[string]string{
				auth.AttributePath: otherPath, auth.AttributeSource: otherPath,
				auth.AttributeSourceBackend: auth.AuthSourcePostgres, auth.AttributeRuntimeOnly: "true",
				"header:X-Home-Setting": "keep",
			}, Metadata: map[string]any{"access_token": "home-access", "refresh_token": "home-grant", "expired": "2099-01-01T00:00:00Z"}})
			updated, errRefresh := executor.NewCodexExecutor(cfg).Refresh(t.Context(), base)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			checkSource := func(stage string, candidate *auth.Auth) {
				t.Helper()
				for _, key := range []string{auth.AttributePath, auth.AttributeSource, auth.AttributeSourceBackend, auth.AttributeRuntimeOnly} {
					got, gotSet := candidate.Attributes[key]
					want, wantSet := base.Attributes[key]
					if gotSet != wantSet || got != want {
						t.Errorf("%s: Home changed local %s provenance", stage, key)
					}
				}
				if candidate.Metadata["access_token"] != "home-access" || candidate.ID != base.ID {
					t.Errorf("%s: result no longer belongs to the requested record", stage)
				}
				if candidate.Attributes["header:X-Home-Setting"] != "keep" {
					t.Errorf("%s: unrelated Home setting was dropped", stage)
				}
			}
			checkSource("executor", updated)
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			checkSource("manager", merged)
			savedPath, errSave := store.Save(t.Context(), merged)
			if errSave != nil {
				t.Fatal(errSave)
			}
			if savedPath != path || merged.Metadata["access_token"] != "home-access" {
				t.Error("save followed a remote path or adopted another record's credentials")
			}
			assertHomeExpirationBearer(t, merged, "home-access")
			afterOther, errReadOther := os.ReadFile(otherPath)
			if errReadOther != nil || !bytes.Equal(beforeOther, afterOther) {
				t.Error("refresh changed the unrelated credential file")
			}
			if current, ok := manager.GetByID(other.ID); !ok || current.Metadata["access_token"] != "other-access" {
				t.Error("refresh changed the unrelated Manager record")
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			var disk map[string]any
			if errDecode := json.Unmarshal(raw, &disk); errDecode != nil {
				t.Fatal(errDecode)
			}
			if disk["access_token"] != "home-access" {
				t.Error("requested credential file did not retain Home refresh")
			}
			cold, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(cold) != 1 {
				t.Fatalf("cold load: %v count=%d", errLoad, len(cold))
			}
			assertHomeExpirationBearer(t, cold[0], "home-access")
		})
	}
}
