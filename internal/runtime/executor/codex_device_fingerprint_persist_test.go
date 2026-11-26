package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexDeviceFingerprintRefreshAndSavePreserveMetadata(t *testing.T) {
	const explicitID = "11111111-2222-4333-8444-555555555555"
	proxyURL, teardown := startCodexMockOAuthServers(t, makeTestCodexRefreshJWT("plus", "device-refresh-account"))
	defer teardown()
	tempDir := t.TempDir()
	auth := &cliproxyauth.Auth{
		ID: "device-refresh.json", FileName: "device-refresh.json", Provider: "codex", ProxyURL: proxyURL,
		Attributes: map[string]string{"codex_device_fingerprint": "device", "codex_installation_id": explicitID},
		Metadata: map[string]any{
			"type": "codex", "refresh_token": "synthetic-refresh-token", "account_id": "device-refresh-account",
			"codex_device_fingerprint": "device", "codex_installation_id": explicitID,
		},
	}
	executor := NewCodexExecutor(&config.Config{AuthDir: tempDir})
	refreshed, errRefresh := executor.Refresh(context.Background(), auth)
	if errRefresh != nil {
		t.Fatalf("synthetic OAuth refresh failed: %v", errRefresh)
	}
	if refreshed.Metadata["codex_device_fingerprint"] != "device" || refreshed.Metadata["codex_installation_id"] != explicitID || refreshed.Attributes["codex_device_fingerprint"] != "device" || refreshed.Attributes["codex_installation_id"] != explicitID {
		t.Fatal("refresh discarded custom device fields")
	}
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(tempDir)
	refreshed.Attributes[cliproxyauth.AttributePath] = filepath.Join(tempDir, "device-refresh.json")
	path, errSave := store.Save(context.Background(), refreshed)
	if errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if ojson.GetBytes(raw, "codex_device_fingerprint").String() != "device" || ojson.GetBytes(raw, "codex_installation_id").String() != explicitID || ojson.GetBytes(raw, "access_token").String() != "new-mock-access-token" {
		t.Fatal("saved refresh lost device fields or updated credentials")
	}
}

func TestCodexDeviceFingerprintRefreshPatchPreservesOperatorChanges(t *testing.T) {
	for _, withStorage := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "storage"}[withStorage], func(t *testing.T) {
			const oldID = "11111111-2222-4333-8444-555555555555"
			const newID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			before := &cliproxyauth.Auth{
				ID: "device.json", FileName: "device.json", Provider: "codex",
				Metadata: map[string]any{"type": "codex", "access_token": "old", "refresh_token": "old-refresh", "codex_device_fingerprint": "device", "codex_installation_id": oldID},
			}
			refreshed := before.Clone()
			refreshed.Metadata["access_token"] = "new"
			refreshed.Metadata["refresh_token"] = "new-refresh"
			refreshed.CodexRefreshPatch = codexauth.NewCredentialRefreshPatch(before.Metadata, refreshed.Metadata, true, false)
			if withStorage {
				refreshed.Storage = &codexauth.CodexTokenStorage{AccessToken: "stale-storage"}
			}
			disk := ojson.NewDocString(`{"type":"codex","access_token":"old","refresh_token":"old-refresh"}`)
			if errSet := disk.Set("codex_device_fingerprint", "off"); errSet != nil {
				t.Fatal(errSet)
			}
			if errSet := disk.Set("codex_installation_id", newID); errSet != nil {
				t.Fatal(errSet)
			}
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "device.json")
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(tempDir)
			if _, errSave := store.Save(context.Background(), refreshed); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "codex_device_fingerprint").String() != "off" || ojson.GetBytes(raw, "codex_installation_id").String() != newID || ojson.GetBytes(raw, "access_token").String() != "new" {
				t.Fatal("refresh patch overwrote operator device settings or lost refreshed credentials")
			}
		})
	}
}
