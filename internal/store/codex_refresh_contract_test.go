package store

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/go-git/go-git/v6"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Every backend must publish the locked, partition-merged file, including when
// a concurrent outer rotation invalidates only half of a refresh result.
func TestCodexRefreshPartitionStoreContract(t *testing.T) {
	for _, backend := range []string{"file", "git", "postgres", "object"} {
		t.Run(backend, func(t *testing.T) {
			root := t.TempDir()
			authDir := filepath.Join(root, "work", "auths")
			var tokenStore coreauth.Store
			var published []byte
			var remote *git.Repository
			switch backend {
			case "file":
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(authDir)
				tokenStore = store
			case "git":
				remoteDir := filepath.Join(root, "remote.git")
				var errInit error
				remote, errInit = git.PlainInit(remoteDir, true)
				if errInit != nil {
					t.Fatal(errInit)
				}
				store := NewGitTokenStore(remoteDir, "", "", "")
				store.SetBaseDir(authDir)
				if errEnsure := store.EnsureRepository(); errEnsure != nil {
					t.Fatal(errEnsure)
				}
				tokenStore = store
			case "postgres":
				tokenStore = &PostgresStore{authDir: authDir, persistAuthFn: func(_ context.Context, id string, data []byte) error {
					if id != "codex-contract.json" {
						t.Errorf("database record = %q", id)
					}
					published = bytes.Clone(data)
					return nil
				}}
			case "object":
				tokenStore = &ObjectTokenStore{authDir: authDir, putObjectFn: func(_ context.Context, key string, data []byte, _ string) error {
					if key != "auths/codex-contract.json" {
						t.Errorf("object key = %q", key)
					}
					published = bytes.Clone(data)
					return nil
				}}
			}
			before := &coreauth.Auth{ID: "codex-contract.json", FileName: "codex-contract.json", Provider: "codex", Metadata: map[string]any{
				"type": "codex", "access_token": "outer-before", "refresh_token": "outer-grant-before", "account_id": "account-before",
				"expires_in": 60, "timestamp": "2020-01-01T00:00:00Z", "codex_device_fingerprint": "device", "use_siwc": true,
				"siwc": map[string]any{"access_token": "siwc-before", "refresh_token": "siwc-grant-before", "expired": "2020-01-01T00:00:00Z", "client_id": "registration", "device_id": "11111111-2222-4333-8444-555555555555"},
			}}
			if _, errSave := tokenStore.Save(coreauth.WithAuthCreationIntent(t.Context()), before); errSave != nil {
				t.Fatal(errSave)
			}
			updated := before.Clone()
			updated.Metadata["access_token"] = "outer-result"
			updated.Metadata["refresh_token"] = "outer-grant-result"
			updated.Metadata["account_id"] = "account-result"
			delete(updated.Metadata, "expires_in")
			delete(updated.Metadata, "timestamp")
			updated.Metadata["expires_at"] = "2098-01-01T00:00:00Z"
			siwc := updated.Metadata["siwc"].(map[string]any)
			siwc["access_token"] = "siwc-result"
			siwc["refresh_token"] = "siwc-grant-result"
			delete(siwc, "expired")
			siwc["expiresAt"] = "2099-01-01T00:00:00Z"
			updated.CodexRefreshPatch = codexauth.NewCredentialRefreshPatch(before.Metadata, updated.Metadata, true, true)

			// A newer outer login and administrator edits arrive before persistence.
			current := before.Clone()
			current.Metadata["access_token"] = "outer-concurrent"
			current.Metadata["refresh_token"] = "outer-grant-concurrent"
			current.Metadata["account_id"] = "account-concurrent"
			delete(current.Metadata, "expires_in")
			delete(current.Metadata, "timestamp")
			current.Metadata["expiry"] = "2100-01-01T00:00:00Z"
			current.Metadata["codex_device_fingerprint"] = "off"
			current.Metadata["codex_installation_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			current.Metadata["proxy_url"] = "http://127.0.0.1:9876"
			current.Metadata["headers"] = map[string]any{"X-Operator": "keep"}
			current.Metadata["operator_note"] = "preserve"
			if _, errSave := tokenStore.Save(coreauth.WithAuthCreationIntent(t.Context()), current); errSave != nil {
				t.Fatal(errSave)
			}
			merged := coreauth.MergeRefreshedAuth(before, current, updated)
			assertCodexStoreContract(t, merged)
			path, errSave := tokenStore.Save(t.Context(), merged)
			if errSave != nil {
				t.Fatal(errSave)
			}
			assertCodexStoreContract(t, merged)
			data, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			var disk map[string]any
			if errDecode := json.Unmarshal(data, &disk); errDecode != nil {
				t.Fatal(errDecode)
			}
			assertCodexStoreContract(t, &coreauth.Auth{Provider: "codex", Metadata: disk})
			if remote != nil {
				head, errHead := remote.Head()
				if errHead != nil {
					t.Fatal(errHead)
				}
				commit, errCommit := remote.CommitObject(head.Hash())
				if errCommit != nil {
					t.Fatal(errCommit)
				}
				file, errFile := commit.File("auths/codex-contract.json")
				if errFile != nil {
					t.Fatal(errFile)
				}
				content, errContent := file.Contents()
				if errContent != nil {
					t.Fatal(errContent)
				}
				published = []byte(content)
			}
			if backend != "file" && !bytes.Equal(data, published) {
				t.Fatal("backend published a snapshot different from the merged credential file")
			}
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: &config.Config{}, AuthDir: authDir, Now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}, path, data)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("cold load count=%d error=%v", len(loaded), errLoad)
			}
			assertCodexStoreContract(t, loaded[0])
			// The cold snapshot must select the adopted SIWC bearer on the next
			// request, even though the administrator disabled fingerprint rewriting.
			received := make(chan http.Header, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				received <- r.Header.Clone()
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r0\",\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			t.Cleanup(upstream.Close)
			wireAuth := loaded[0].Clone()
			// Use the local upstream directly; proxy preservation was checked above.
			wireAuth.ProxyURL = ""
			wireAuth.Attributes["base_url"] = upstream.URL
			_, errExecute := executor.NewCodexExecutor(&config.Config{}).Execute(t.Context(), wireAuth, core.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":[]}`)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			if header := <-received; header.Get("Authorization") != "Bearer siwc-result" || header.Get("X-Operator") != "keep" {
				t.Error("cold request did not send the selected SIWC credential and administrator headers")
			}
		})
	}
}

func assertCodexStoreContract(t *testing.T, auth *coreauth.Auth) {
	t.Helper()
	for key, want := range map[string]string{"access_token": "outer-concurrent", "refresh_token": "outer-grant-concurrent", "account_id": "account-concurrent", "codex_device_fingerprint": "off", "codex_installation_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "proxy_url": "http://127.0.0.1:9876", "operator_note": "preserve"} {
		if auth.Metadata[key] != want {
			t.Errorf("%s did not preserve the current partition/configuration", key)
		}
	}
	siwc, _ := auth.Metadata["siwc"].(map[string]any)
	for key, want := range map[string]string{"access_token": "siwc-result", "refresh_token": "siwc-grant-result", "client_id": "registration", "device_id": "11111111-2222-4333-8444-555555555555"} {
		if siwc[key] != want {
			t.Errorf("SIWC %s did not adopt the valid partition", key)
		}
	}
	if headers, _ := auth.Metadata["headers"].(map[string]any); headers["X-Operator"] != "keep" {
		t.Error("administrator headers were lost")
	}
	if expiry, ok := auth.OuterExpirationTime(); !ok || expiry.Year() != 2100 {
		t.Errorf("outer expiry = %v, %v", expiry, ok)
	}
	if expiry, ok := auth.SIWCRenewalExpirationTime(); !ok || expiry.Year() != 2099 {
		t.Errorf("SIWC expiry = %v, %v", expiry, ok)
	}
}
