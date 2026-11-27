package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFileTokenStoreCodexOrdinarySaveDoesNotRecreateRemovedSource(t *testing.T) {
	for _, withStorage := range []bool{false, true} {
		name := "metadata"
		if withStorage {
			name = "storage"
		}
		t.Run(name, func(t *testing.T) {
			store := NewFileTokenStore()
			store.SetBaseDir(t.TempDir())
			auth := &coreauth.Auth{ID: "removed.json", FileName: "removed.json", Provider: "codex",
				Metadata: map[string]any{"type": "codex", "access_token": "valid-access", "expired": "2099-01-01T00:00:00Z",
					"codex_device_fingerprint": "device", "account_id": "account"}}
			if withStorage {
				auth.Storage = (&codex.CodexTokenStorage{}).WithMetadataSnapshot(auth.Metadata)
			}
			// Initial creation is allowed without an established file source.
			path, errSave := store.Save(t.Context(), auth)
			if errSave != nil {
				t.Fatal(errSave)
			}
			if withStorage {
				copiedPath := filepath.Join(t.TempDir(), "copied.json")
				if errCopy := auth.Storage.SaveTokenToFile(copiedPath); errCopy != nil {
					t.Fatalf("copying saved storage: %v", errCopy)
				}
			}
			if errRemove := os.Remove(path); errRemove != nil {
				t.Fatal(errRemove)
			}
			if _, errSave = store.Save(t.Context(), auth.Clone()); !errors.Is(errSave, os.ErrNotExist) {
				t.Errorf("ordinary save error = %v, want removed source", errSave)
			}
			if withStorage {
				if errSave = auth.Storage.SaveTokenToFile(path); !errors.Is(errSave, os.ErrNotExist) {
					t.Errorf("direct storage save error=%v, want removed original source", errSave)
				}
			}
			if _, errStat := os.Stat(path); !errors.Is(errStat, os.ErrNotExist) {
				t.Error("ordinary runtime save recreated the deleted credential")
			}
			loaded, errList := store.List(t.Context())
			if errList != nil || len(loaded) != 0 {
				t.Error("cold load restored a deleted credential")
			}
			// A deliberate login can recreate a previously established path.
			if _, errSave = store.Save(coreauth.WithAuthCreationIntent(t.Context()), auth.Clone()); errSave != nil {
				t.Fatal(errSave)
			}
			if _, errStat := os.Stat(path); errStat != nil {
				t.Fatal(errStat)
			}
		})
	}
}

type codexBlockedSaveMetadata struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (v *codexBlockedSaveMetadata) MarshalJSON() ([]byte, error) {
	v.once.Do(func() { close(v.entered) })
	<-v.release
	return []byte(`"operator-note"`), nil
}

func TestFileTokenStoreCodexDeleteWaitsForActiveSave(t *testing.T) {
	for _, separateStore := range []bool{false, true} {
		name := "same-store"
		if separateStore {
			name = "separate-store"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			deleter := store
			if separateStore {
				deleter = NewFileTokenStore()
				deleter.SetBaseDir(dir)
			}
			auth := &coreauth.Auth{ID: "remove-active.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "synthetic", "codex_device_fingerprint": "device",
			}}
			path, errSave := store.Save(t.Context(), auth)
			if errSave != nil {
				t.Fatal(errSave)
			}
			blocked := &codexBlockedSaveMetadata{entered: make(chan struct{}), release: make(chan struct{})}
			auth.Metadata["note"] = blocked
			saved := make(chan error, 1)
			go func() {
				_, err := store.Save(t.Context(), auth)
				saved <- err
			}()
			<-blocked.entered
			deleted := make(chan error, 1)
			go func() { deleted <- deleter.Delete(t.Context(), auth.ID) }()
			// A deliberately blocked save has already read its baseline. Deletion
			// must wait for that transaction, then remove its final replacement.
			select {
			case errDelete := <-deleted:
				close(blocked.release)
				<-saved
				t.Fatalf("Delete overtook an active save: %v", errDelete)
			case <-time.After(100 * time.Millisecond):
				close(blocked.release)
			}
			if errSave = <-saved; errSave != nil {
				t.Fatal(errSave)
			}
			if errDelete := <-deleted; errDelete != nil {
				t.Fatal(errDelete)
			}
			if _, errStat := os.Stat(path); !errors.Is(errStat, os.ErrNotExist) {
				t.Fatal("the completed save recreated the deleted source")
			}
		})
	}
}

func TestFileTokenStoreCodexOrdinarySavePreservesInvalidSource(t *testing.T) {
	for _, source := range []string{"", `{"interrupted":`, `null`, `{}`} {
		for _, withStorage := range []bool{false, true} {
			name := "metadata"
			if withStorage {
				name = "storage"
			}
			t.Run(name+"/"+source, func(t *testing.T) {
				store := NewFileTokenStore()
				store.SetBaseDir(t.TempDir())
				auth := &coreauth.Auth{ID: "interrupted.json", FileName: "interrupted.json", Provider: "codex",
					Metadata: map[string]any{"type": "codex", "access_token": "old-access", "codex_device_fingerprint": "device"}}
				if withStorage {
					auth.Storage = (&codex.CodexTokenStorage{}).WithMetadataSnapshot(auth.Metadata)
				}
				path, errSave := store.Save(t.Context(), auth)
				if errSave != nil {
					t.Fatal(errSave)
				}
				if errWrite := os.WriteFile(path, []byte(source), 0o600); errWrite != nil {
					t.Fatal(errWrite)
				}
				if _, errSave = store.Save(t.Context(), auth); errSave == nil {
					t.Error("ordinary runtime save replaced an invalid current source")
				}
				if raw, errRead := os.ReadFile(path); errRead != nil || !bytes.Equal(raw, []byte(source)) {
					t.Error("ordinary runtime save lost the operator's current file")
				}
			})
		}
	}
}
