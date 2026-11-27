package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v6"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexRefreshStoresDoNotRecreateRemovedSource(t *testing.T) {
	for _, backend := range []string{"file", "git", "postgres", "object"} {
		t.Run(backend, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "work", "auths")
			published := 0
			var store auth.Store
			var remote *git.Repository
			switch backend {
			case "file":
				local := fileauth.NewFileTokenStore()
				local.SetBaseDir(dir)
				store = local
			case "git":
				remotePath := filepath.Join(root, "remote.git")
				var errInit error
				remote, errInit = git.PlainInit(remotePath, true)
				if errInit != nil {
					t.Fatal(errInit)
				}
				local := NewGitTokenStore(remotePath, "", "", "")
				local.SetBaseDir(dir)
				store = local
			case "postgres":
				store = &PostgresStore{authDir: dir, persistAuthFn: func(context.Context, string, []byte) error {
					published++
					return nil
				}}
			case "object":
				store = &ObjectTokenStore{authDir: dir, putObjectFn: func(context.Context, string, []byte, string) error {
					published++
					return nil
				}}
			}
			before := &auth.Auth{ID: "removed.json", FileName: "removed.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "old", "refresh_token": "old-grant", "account_id": "account",
				"codex_device_fingerprint": "device", "codex_installation_id": "11111111-2222-4333-8444-555555555555",
			}}
			path, errSave := store.Save(auth.WithAuthCreationIntent(t.Context()), before)
			if errSave != nil {
				t.Fatal(errSave)
			}
			updated := before.Clone()
			updated.Metadata["access_token"], updated.Metadata["refresh_token"] = "new", "new-grant"
			updated.CodexRefreshPatch = codex.NewCredentialRefreshPatchWithDiskBaseline(before.Metadata, before.Metadata, updated.Metadata, true, false)
			var oldHead string
			if remote != nil {
				head, errHead := remote.Head()
				if errHead != nil {
					t.Fatal(errHead)
				}
				oldHead = head.Hash().String()
			}
			published = 0
			if errRemove := os.Remove(path); errRemove != nil {
				t.Fatal(errRemove)
			}
			if _, errSave = store.Save(t.Context(), updated); !errors.Is(errSave, os.ErrNotExist) {
				t.Fatalf("late refresh save error = %v, want missing source", errSave)
			}
			for _, withStorage := range []bool{false, true} {
				ordinary := before.Clone()
				if withStorage {
					ordinary.Storage = (&codex.CodexTokenStorage{}).WithMetadataSnapshot(ordinary.Metadata)
				}
				if _, errSave = store.Save(t.Context(), ordinary); !errors.Is(errSave, os.ErrNotExist) {
					t.Errorf("ordinary save with storage=%t: error=%v, want missing source", withStorage, errSave)
				}
			}
			if _, errStat := os.Stat(path); !errors.Is(errStat, os.ErrNotExist) {
				t.Fatal("late refresh save recreated the removed file")
			}
			if published != 0 || updated.CodexRefreshPatch == nil {
				t.Fatal("failed local save published remotely or discarded its refresh patch")
			}
			if remote != nil {
				head, errHead := remote.Head()
				if errHead != nil || head.Hash().String() != oldHead {
					t.Fatal("failed local save changed the Git remote")
				}
			}
		})
	}
}
