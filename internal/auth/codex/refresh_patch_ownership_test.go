package codex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/json"
)

func TestCredentialRefreshPatchOwnsAppliedScopes(t *testing.T) {
	for _, typed := range []bool{false, true} {
		name := "json"
		var scopes any = []any{"openid", "chatgpt.tokens.use.direct"}
		if typed {
			name = "typed"
			scopes = []string{"openid", "chatgpt.tokens.use.direct"}
		}
		t.Run(name, func(t *testing.T) {
			before := map[string]any{"siwc": map[string]any{"access_token": "old", "refresh_token": "old-grant"}}
			after := map[string]any{"siwc": map[string]any{"access_token": "new", "refresh_token": "new-grant", "scopes": scopes}}
			patch := NewCredentialRefreshPatch(before, after, false, true)
			first := patch.Apply(before)
			switch current := first["siwc"].(map[string]any)["scopes"].(type) {
			case []any:
				current[0] = "caller-edit"
			case []string:
				current[0] = "caller-edit"
			}
			second := patch.Apply(before)
			var actual string
			switch current := second["siwc"].(map[string]any)["scopes"].(type) {
			case []any:
				actual, _ = current[0].(string)
			case []string:
				actual = current[0]
			}
			if actual != "openid" {
				t.Fatal("editing an applied snapshot changed the immutable refresh receipt")
			}
			if patch.CanApplySIWCTo(first) {
				t.Fatal("edited snapshot was incorrectly accepted as the original applied receipt")
			}
			path := filepath.Join(t.TempDir(), "credential.json")
			if err := WriteJSONFileAtomic(path, before); err != nil {
				t.Fatal(err)
			}
			storage := &CodexTokenStorage{RefreshPatch: patch}
			if err := storage.SaveTokenToFile(path); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]any
			if err = json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			if saved["siwc"].(map[string]any)["scopes"].([]any)[0] != "openid" {
				t.Fatal("persisting the patch inherited a caller edit from an earlier application")
			}
		})
	}
}
