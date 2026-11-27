package codex

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MoeForge/moego/json"
)

func TestCodexExpirationStoragePreservesPartition(t *testing.T) {
	disk := map[string]any{
		"type": "codex", "access_token": "current", "refresh_token": "current-grant", "expiresIn": 3600, "issuedAt": "2099-01-01T00:00:00Z",
		"token": map[string]any{"expires_at": "2099-01-01T01:00:00Z", "note": "base"},
	}
	incoming := map[string]any{
		"type": "codex", "access_token": "stale", "refresh_token": "stale-grant", "expires_in": 5, "timestamp": "2000-01-01T00:00:00Z",
		"token": map[string]any{"expires_at": "2000-01-01T00:00:05Z", "note": "administrator"},
	}
	for _, merge := range []struct {
		name string
		fn   func(map[string]any, map[string]any) map[string]any
	}{{"snapshot", MergeWithDiskMap}, {"configuration", MergeCodexCredentialsFromDisk}} {
		t.Run(merge.name, func(t *testing.T) {
			got := merge.fn(disk, incoming)
			if !reflect.DeepEqual(ExpirationFields(got), ExpirationFields(disk)) || got["access_token"] != "current" {
				t.Fatal("configuration save replaced current credential expiry")
			}
			if nested, _ := got["token"].(map[string]any); nested["note"] != "administrator" {
				t.Fatal("configuration save erased non-expiry administrator metadata")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "credential.json")
	if errWrite := WriteJSONFileAtomic(path, disk); errWrite != nil {
		t.Fatal(errWrite)
	}
	storage := &CodexTokenStorage{AccessToken: "replacement", RefreshToken: "replacement-grant", ReplaceCredentials: true}
	storage.SetMetadata(map[string]any{"token": map[string]any{"note": "replacement"}})
	if errSave := storage.SaveTokenToFile(path); errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var saved map[string]any
	if errDecode := json.Unmarshal(raw, &saved); errDecode != nil {
		t.Fatal(errDecode)
	}
	if saved["access_token"] != "replacement" || saved["expiresIn"] != nil || saved["issuedAt"] != nil {
		t.Fatal("explicit re-login retained a previous relative expiry")
	}
	if nested, _ := saved["token"].(map[string]any); nested["expires_at"] != nil || nested["note"] != "replacement" {
		t.Fatal("explicit re-login retained nested expiry or discarded new custom data")
	}
}

func TestCodexExpirationPatchDoesNotReviveOldSIWCRefreshTime(t *testing.T) {
	before := map[string]any{"siwc": map[string]any{"access_token": "old", "refresh_token": "grant", "expired": "2000-01-01T00:00:00Z", "expires_in": 3600, "last_refresh": "2099-01-01T00:00:00Z", "lastRefresh": "2099-01-01T00:00:00Z"}}
	after := map[string]any{"siwc": map[string]any{"access_token": "new", "refresh_token": "new-grant"}}
	got := NewCredentialRefreshPatch(before, after, false, true).Apply(before)
	nested, _ := got["siwc"].(map[string]any)
	for _, key := range []string{"expired", "expires_in", "last_refresh", "lastRefresh"} {
		if _, exists := nested[key]; exists {
			t.Fatalf("new opaque bearer inherited old lifecycle field %s", key)
		}
	}
}
