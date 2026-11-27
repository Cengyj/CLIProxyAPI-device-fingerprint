package executor

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexRefreshDoesNotRecreateRemovedSource(t *testing.T) {
	for _, timing := range []string{"before-refresh", "after-refresh"} {
		t.Run(timing, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "removed.json")
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(dir)
			cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			exec := NewCodexExecutor(cfg)
			manager := auth.NewManager(store, nil, nil)
			manager.RegisterExecutor(exec)
			base, errRegister := manager.Register(auth.WithAuthCreationIntent(t.Context()), &auth.Auth{
				ID: "removed.json", FileName: "removed.json", Provider: "codex", Status: auth.StatusActive,
				Metadata: map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "grant-" + timing,
					"account_id": "old-account", "expired": "2000-01-01T00:00:00Z", "codex_device_fingerprint": "device"},
			})
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			calls := 0
			original := http.DefaultTransport
			http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
					Body: io.NopCloser(strings.NewReader(`{"access_token":"new-access","refresh_token":"new-grant","expires_in":7200}`))}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = original })
			if timing == "before-refresh" {
				if errRemove := os.Remove(path); errRemove != nil {
					t.Fatal(errRemove)
				}
				if _, errRefresh := manager.ForceRefreshAuth(t.Context(), base.ID); errRefresh == nil {
					t.Error("refresh of a removed source reported success")
				}
				if calls != 0 {
					t.Errorf("removed source submitted %d token exchanges, want 0", calls)
				}
				current, exists := manager.GetByID(base.ID)
				if !exists || current.Metadata["access_token"] != "old-access" {
					t.Error("removed source adopted a new credential before watcher removal")
				}
			} else {
				updated, errRefresh := exec.Refresh(t.Context(), base)
				if errRefresh != nil || updated == nil || updated.CodexRefreshPatch == nil {
					t.Fatalf("refresh before removal: %v", errRefresh)
				}
				if calls != 1 {
					t.Fatalf("refresh calls=%d, want 1", calls)
				}
				// An accepted refresh may be copied to a different destination.
				copyPath := filepath.Join(t.TempDir(), "copy.json")
				copyStorage := (&codex.CodexTokenStorage{}).WithMetadataSnapshot(updated.Metadata)
				copyStorage.RefreshPatch = updated.CodexRefreshPatch
				if errSave := copyStorage.SaveTokenToFile(copyPath); errSave != nil {
					t.Fatalf("copying accepted refresh to a new file: %v", errSave)
				}
				if errRemove := os.Remove(path); errRemove != nil {
					t.Fatal(errRemove)
				}
				if _, errSave := store.Save(t.Context(), updated); errSave == nil {
					t.Error("late refresh save recreated a removed credential")
				}
				if updated.CodexRefreshPatch == nil {
					t.Error("failed save discarded the recoverable refresh patch")
				}
				// A new explicit login remains the supported way to recreate it.
				login := base.Clone()
				login.CodexRefreshPatch = nil
				login.Metadata["access_token"] = "explicit-login"
				if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
					t.Error("late refresh save restored the deleted file")
				}
				if _, errSave := store.Save(auth.WithAuthCreationIntent(t.Context()), login); errSave != nil {
					t.Fatal(errSave)
				}
				loaded, errList := store.List(t.Context())
				if errList != nil || len(loaded) != 1 || loaded[0].Metadata["access_token"] != "explicit-login" {
					t.Fatal("explicit login did not recreate the intended credential")
				}
				return
			}
			if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
				t.Errorf("removed credential reappeared: %v", errStat)
			}
			loaded, errList := store.List(t.Context())
			if errList != nil || len(loaded) != 0 {
				t.Fatalf("cold store resurrected removed credential: records=%d err=%v", len(loaded), errList)
			}
		})
	}
}

func TestCodexStorageRefreshDoesNotRecreateRemovedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "removed.json")
	before := map[string]any{"access_token": "old", "refresh_token": "old-grant"}
	after := map[string]any{"access_token": "new", "refresh_token": "new-grant"}
	storage := (&codex.CodexTokenStorage{}).WithMetadataSnapshot(after)
	storage.RefreshPatch = codex.NewCredentialRefreshPatchWithDiskBaseline(before, before, after, true, false)
	if errSave := storage.SaveTokenToFile(path); errSave == nil {
		t.Error("direct storage refresh recreated a source missing from its baseline")
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Error("direct storage refresh restored the removed file")
	}
	// A memory-only refresh has no removed source and may be persisted initially.
	storage.RefreshPatch = codex.NewCredentialRefreshPatch(before, after, true, false)
	if errSave := storage.SaveTokenToFile(path); errSave != nil {
		t.Fatalf("initial persistence of a memory credential failed: %v", errSave)
	}
}
