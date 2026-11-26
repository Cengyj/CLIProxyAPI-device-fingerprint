package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintRotatedDiskIdentityManagerMerge(t *testing.T) {
	for _, field := range []string{"id_token", "account_id"} {
		t.Run(field, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			dir := t.TempDir()
			path := filepath.Join(dir, "rotated.json")
			exec := NewCodexExecutor(&config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			base := fingerprintHTTPAuth(server.URL)
			base.ID, base.FileName = "rotated.json", "rotated.json"
			base.Attributes[cliproxyauth.AttributePath] = path
			base.Metadata["access_token"] = "old-access"
			base.Metadata["refresh_token"] = "old-refresh"
			base.Metadata["account_id"] = "acc-team-1"
			base.Metadata["chatgpt_user_id"] = "user-aaa"
			base.Metadata["plan_type"] = "team"
			base.Metadata["id_token"] = deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team"}}`))
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), base)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			base = registered
			disk := ojson.NewDocString(`{"type":"codex","account_id":"acc-team-1","chatgpt_user_id":"user-bbb","plan_type":"team","access_token":"rotated-access","refresh_token":"rotated-refresh","expired":"2099-01-01T00:00:00Z"}`)
			if field == "account_id" {
				_ = disk.Delete("account_id")
				_ = disk.Set("id_token", deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`)))
			}
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			updated, errRefresh := exec.Refresh(t.Context(), base.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			current := base.Clone()
			current.Metadata["codex_device_fingerprint"] = "device"
			current.Attributes["header:X-Operator-Note"] = "concurrent-admin"
			if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			request := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
			fingerprintRunHTTP(t, t.Context(), exec, merged, request, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
			wire := <-captured
			if wire.headers.Get("Authorization") != "Bearer rotated-access" {
				t.Error("Manager merge retained the previous bearer credential after disk identity deletion")
			}
			if ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
				t.Error("Manager merge did not preserve the replacement member identity")
			}
			if wire.headers.Get("X-Operator-Note") != "concurrent-admin" || merged.Metadata["codex_device_fingerprint"] != "device" {
				t.Fatal("refresh merge discarded concurrent administrator settings")
			}
		})
	}
}

func TestCodexDeviceFingerprintRotatedDiskPreservesNewerSubject(t *testing.T) {
	for _, identitySource := range []string{"token", "attributes"} {
		t.Run(identitySource, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			dir := t.TempDir()
			path := filepath.Join(dir, "rotated.json")
			exec := NewCodexExecutor(&config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			base := fingerprintHTTPAuth(server.URL)
			base.ID, base.FileName = "rotated.json", "rotated.json"
			base.Attributes[cliproxyauth.AttributePath] = path
			base.Metadata["access_token"] = "old-access"
			base.Metadata["refresh_token"] = "old-refresh"
			base.Metadata["account_id"] = "old-account"
			base.Metadata["chatgpt_user_id"] = "old-member"
			base.Metadata["plan_type"] = "team"
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			base.Metadata["siwc"] = map[string]any{"access_token": "old-siwc", "refresh_token": "old-siwc-refresh", "client_id": "local-client", "expired": "2099-01-01T00:00:00Z"}
			base.Attributes["account_id"] = "old-account"
			base.Attributes["chatgpt_user_id"] = "old-member"
			base.Attributes["chatgpt_plan_type"] = "team"
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), base)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			base = registered
			disk := ojson.NewDocString(`{"type":"codex","account_id":"disk-account","chatgpt_user_id":"disk-member","chatgpt_plan_type":"free","plan_type":"free","access_token":"disk-access","refresh_token":"disk-refresh","expired":"2099-01-01T00:00:00Z","siwc":{"access_token":"rotated-siwc","refresh_token":"rotated-siwc-refresh","client_id":"local-client","expired":"2099-01-01T00:00:00Z"}}`)
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			updated, errRefresh := exec.Refresh(t.Context(), base.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			current := base.Clone()
			current.Metadata["access_token"] = "latest-access"
			current.Metadata["refresh_token"] = "latest-refresh"
			current.Metadata["account_id"] = "acc-team-1"
			delete(current.Metadata, "chatgpt_user_id")
			delete(current.Metadata, "plan_type")
			for _, key := range []string{"account_id", "chatgpt_user_id", "chatgpt_plan_type"} {
				delete(current.Attributes, key)
			}
			if identitySource == "token" {
				current.Metadata["id_token"] = deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`))
			} else {
				current.Attributes["chatgpt_user_id"] = "user-bbb"
				current.Attributes["chatgpt_plan_type"] = "team"
			}
			current.Metadata["codex_device_fingerprint"] = "device"
			current.Attributes["header:X-Operator-Note"] = "latest-admin"
			if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			request := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
			options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			fingerprintRunHTTP(t, t.Context(), exec, merged, request, options, false)
			wire := <-captured
			if wire.headers.Get("Authorization") != "Bearer latest-access" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
				t.Fatal("partial refresh mixed disk identity with the newer account/member credential")
			}
			if wire.headers.Get("X-Operator-Note") != "latest-admin" || merged.Metadata["codex_device_fingerprint"] != "device" {
				t.Fatal("partial refresh lost current administrator settings")
			}
			siwc := merged.Clone()
			siwc.Metadata["use_siwc"] = true
			fingerprintRunHTTP(t, t.Context(), exec, siwc, request, options, false)
			if wire := <-captured; wire.headers.Get("Authorization") != "Bearer rotated-siwc" {
				t.Fatal("new outer identity prevented the compatible SIWC partition from applying")
			}
		})
	}
}
