package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintRotatedDiskMemberReachesWire(t *testing.T) {
	for _, source := range []string{"explicit-disk-member", "token-disk-member", "token-disk-account"} {
		t.Run(source, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			dir := t.TempDir()
			path := filepath.Join(dir, "member.json")
			cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			executor := NewCodexExecutor(cfg)
			auth := fingerprintHTTPAuth(server.URL)
			auth.FileName, auth.ID = "member.json", "member.json"
			auth.Attributes[cliproxyauth.AttributePath] = path
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			auth.Attributes["chatgpt_user_id"] = "user-aaa"
			auth.Attributes["account_id"] = "acc-team-1"
			auth.Attributes["chatgpt_plan_type"] = "team"
			auth.Attributes["id_token"] = codexDeviceRefreshPlanToken(t, "team")
			auth.Metadata["access_token"] = "old-access"
			auth.Metadata["refresh_token"] = "old-refresh"
			auth.Metadata["expired"] = "2099-01-01T00:00:00Z"
			staleStorage := &codexauth.CodexTokenStorage{
				IDToken: auth.Attributes["id_token"], AccessToken: "old-access", RefreshToken: "old-refresh",
				AccountID: "acc-team-1", PlanType: "team", Expire: "2099-01-01T00:00:00Z",
			}
			auth.Storage = staleStorage
			request := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
			options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			fingerprintRunHTTP(t, t.Context(), executor, auth, request, options, false)
			if first := <-captured; ojson.GetBytes(first.body, "client_metadata.x-codex-installation-id").String() != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatal("original member did not reach upstream")
			}
			disk := ojson.NewDocString(`{"type":"codex","account_id":"acc-team-1","chatgpt_user_id":"user-bbb","plan_type":"team","access_token":"rotated-access","refresh_token":"rotated-refresh","expired":"2099-01-01T00:00:00Z"}`)
			wantID := "fd5de10e-f853-4dd0-92f4-ece041b115a9"
			if source != "explicit-disk-member" {
				if errDelete := disk.Delete("chatgpt_user_id"); errDelete != nil {
					t.Fatal(errDelete)
				}
				claims := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`)
				if source == "token-disk-account" {
					wantID = "3216ba40-955f-42a6-aabf-a9ac6ae94a30"
					_ = disk.Delete("account_id")
					_ = disk.Delete("plan_type")
					_ = claims.Set("https://api\\.openai\\.com/auth.chatgpt_account_id", "acc-test-2")
					_ = claims.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", "free")
				}
				if errSet := disk.Set("id_token", deviceRound3Token(claims)); errSet != nil {
					t.Fatal(errSet)
				}
			}
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			refreshed, errRefresh := executor.Refresh(t.Context(), auth)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			fingerprintRunHTTP(t, t.Context(), executor, refreshed, request, options, false)
			got := <-captured
			if got.headers.Get("Authorization") != "Bearer rotated-access" {
				t.Fatal("did not adopt rotated credential")
			}
			wantAccountHeader := "acc-team-1"
			if source == "token-disk-account" {
				wantAccountHeader = ""
			}
			if got.headers.Get("ChatGPT-Account-ID") != wantAccountHeader {
				t.Fatal("rotated credential retained the previous account header")
			}
			if ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != wantID {
				t.Fatal("rotated credential used the previous member identity")
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(dir)
			if _, errSave := store.Save(t.Context(), refreshed); errSave != nil {
				t.Fatal(errSave)
			}
			if refreshed.Storage != nil || staleStorage.RefreshPatch != nil || staleStorage.AccessToken != "old-access" {
				t.Fatal("save retained stale storage or mutated the caller's storage snapshot")
			}
			saved, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, saved)
			if errSynthesize != nil || len(auths) != 1 {
				t.Fatalf("reload: %v count=%d", errSynthesize, len(auths))
			}
			auths[0].Attributes["base_url"] = server.URL
			fingerprintRunHTTP(t, t.Context(), executor, auths[0], request, options, false)
			again := <-captured
			if ojson.GetBytes(again.body, "client_metadata.x-codex-installation-id").String() != wantID {
				t.Fatal("adoption save/reload changed new subject")
			}
			if again.headers.Get("Authorization") != "Bearer rotated-access" || again.headers.Get("ChatGPT-Account-ID") != wantAccountHeader {
				t.Fatal("save/reload restored previous credential headers")
			}
		})
	}
}

func deviceRound3Token(claims *ojson.Doc) string {
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig"
}

func TestCodexDeviceFingerprintRotatedDiskMemberWebsocket(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "member.json")
			cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			executor := NewCodexWebsocketsExecutor(cfg)
			executor.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer executor.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.ID, auth.FileName = "member.json", "member.json"
			auth.Attributes[cliproxyauth.AttributePath] = path
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			auth.Metadata["access_token"] = "old-access"
			auth.Metadata["refresh_token"] = "old-refresh"
			auth.Metadata["expired"] = "2099-01-01T00:00:00Z"
			auth.Metadata["codex_installation_id"] = codexDeviceTestA
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if err := runCodexDeviceWSTurn(t, executor, t.Context(), auth, opts, body, stream); err != nil {
				t.Fatal(err)
			}
			<-frames
			disk := ojson.NewDocString(`{"type":"codex","account_id":"acc-team-1","chatgpt_user_id":"user-bbb","plan_type":"team","access_token":"rotated-access","refresh_token":"rotated-refresh","expired":"2099-01-01T00:00:00Z"}`)
			_ = disk.Set("codex_installation_id", codexDeviceTestA)
			if err := os.WriteFile(path, disk.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			refreshed, err := executor.Refresh(t.Context(), auth)
			if err != nil {
				t.Fatal(err)
			}
			err = runCodexDeviceWSTurn(t, executor, t.Context(), refreshed, opts, `{"input":[],"previous_response_id":"r0"}`, stream)
			if !core.IsUpstreamWebsocketReplayRequired(err) {
				t.Fatalf("changed member with same explicit ID reused continuation: %v", err)
			}
			if err = runCodexDeviceWSTurn(t, executor, t.Context(), refreshed, opts, body, stream); err != nil {
				t.Fatal(err)
			}
			frame := <-frames
			if connections.Load() != 2 || frame.headers.Get("Authorization") != "Bearer rotated-access" || ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("replacement member did not establish its own physical handshake")
			}
		})
	}
}

func TestCodexDeviceFingerprintRotatedDiskConcurrentCredential(t *testing.T) {
	for _, rotateSIWC := range []bool{false, true} {
		t.Run(map[bool]string{false: "outer-only", true: "dual-partition"}[rotateSIWC], func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			dir := t.TempDir()
			path := filepath.Join(dir, "member.json")
			executor := NewCodexExecutor(&config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			base := fingerprintHTTPAuth(server.URL)
			base.ID, base.FileName = "member.json", "member.json"
			base.Attributes[cliproxyauth.AttributePath] = path
			base.Metadata["account_id"] = "acc-team-1"
			base.Metadata["plan_type"] = "team"
			base.Metadata["access_token"] = "old-access"
			base.Metadata["refresh_token"] = "old-refresh"
			base.Metadata["id_token"] = deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team"}}`))
			base.Metadata["expired"] = "2099-01-01T00:00:00Z"
			base.Attributes["account_id"] = "acc-team-1"
			base.Attributes["chatgpt_user_id"] = "user-aaa"
			base.Attributes["chatgpt_plan_type"] = "team"
			base.Attributes["id_token"] = base.Metadata["id_token"].(string)
			if rotateSIWC {
				base.Metadata["siwc"] = map[string]any{"access_token": "old-siwc", "refresh_token": "old-siwc-refresh", "client_id": "local-client", "expired": "2099-01-01T00:00:00Z"}
			}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), base)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			base = registered
			disk := ojson.NewDocString(`{"type":"codex","account_id":"acc-team-1","chatgpt_user_id":"user-bbb","plan_type":"team","access_token":"rotated-access","refresh_token":"rotated-refresh","expired":"2099-01-01T00:00:00Z"}`)
			if rotateSIWC {
				if errSet := disk.Set("siwc", map[string]any{"access_token": "rotated-siwc", "refresh_token": "rotated-siwc-refresh", "client_id": "local-client", "expired": "2099-01-01T00:00:00Z"}); errSet != nil {
					t.Fatal(errSet)
				}
			}
			if errWrite := os.WriteFile(path, disk.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			updated, errRefresh := executor.Refresh(t.Context(), base.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			current := base.Clone()
			current.Metadata["access_token"] = "latest-access"
			current.Metadata["refresh_token"] = "latest-refresh"
			current.Attributes["header:X-Operator-Note"] = "latest-admin"
			if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, updated)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			request := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
			fingerprintRunHTTP(t, t.Context(), executor, merged, request, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
			wire := <-captured
			if wire.headers.Get("Authorization") != "Bearer latest-access" || wire.headers.Get("X-Operator-Note") != "latest-admin" {
				t.Fatal("stale refresh displaced the newer credential or administrator settings")
			}
			if ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatal("stale refresh mixed its member with the newer credential")
			}
			if rotateSIWC {
				siwc := merged.Clone()
				siwc.Metadata["use_siwc"] = true
				fingerprintRunHTTP(t, t.Context(), executor, siwc, request, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
				if siwcWire := <-captured; siwcWire.headers.Get("Authorization") != "Bearer rotated-siwc" {
					t.Fatal("rejecting the stale outer partition lost the valid SIWC refresh")
				}
			}
		})
	}
}
