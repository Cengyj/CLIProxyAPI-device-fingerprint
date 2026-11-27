package executor

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
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

func TestCodexDeviceFingerprintRefreshReceiptIdentityReachesWire(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "current-receipt", true: "legacy-receipt"}[legacy], func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			var oauthCalls atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				oauthCalls.Add(1)
				w.WriteHeader(http.StatusBadGateway)
			}))
			defer proxy.Close()
			cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			executor := NewCodexExecutor(cfg)
			auth := fingerprintHTTPAuth(server.URL)
			auth.ID, auth.FileName = "codex-a.json", "codex-a.json"
			path := filepath.Join(cfg.AuthDir, auth.FileName)
			auth.Attributes[cliproxyauth.AttributePath] = path
			auth.Attributes["header:X-Operator-Note"] = "keep"
			for key, value := range map[string]string{
				"account_id":        "acc-team-1",
				"chatgpt_user_id":   "user-aaa",
				"chatgpt_plan_type": "team",
				"plan_type":         "team",
				"id_token":          codexDeviceRefreshPlanToken(t, "team"),
			} {
				auth.Metadata[key] = value
				auth.Attributes[key] = value
			}
			grant := "receipt-identity-" + t.Name()
			auth.Metadata["refresh_token"] = grant
			auth.Metadata["expired"] = "2000-01-01T00:00:00Z"
			auth.Metadata["operator_note"] = "keep"
			initial := ojson.NewDocString(`{}`)
			for key, value := range auth.Metadata {
				if errSet := initial.Set(key, value); errSet != nil {
					t.Fatal(errSet)
				}
			}
			if errWrite := os.WriteFile(path, initial.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			auth = registered
			claims := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`)
			receipt := ojson.NewDocString(`{"value":{"account_id":"acc-team-1","access_token":"receipt-access","refresh_token":"receipt-next","expired":"2099-01-01T00:00:00Z","plan_type":"team"}}`)
			if errSet := receipt.Set("value.id_token", deviceRound3Token(claims)); errSet != nil {
				t.Fatal(errSet)
			}
			if !legacy {
				if errSet := receipt.Set("value.plan_type_defaulted", false); errSet != nil {
					t.Fatal(errSet)
				}
			}
			journal := &codexauth.FileRefreshJournal{Dir: t.TempDir()}
			key := fmt.Sprintf("%x", sha256.Sum256([]byte(codexauth.ClientID+"\x00"+grant)))
			if claimed, errClaim := journal.RefreshClaim(t.Context(), key); errClaim != nil || !claimed {
				t.Fatalf("preload receipt claim: claimed=%v err=%v", claimed, errClaim)
			}
			if errComplete := journal.RefreshComplete(t.Context(), key, receipt.Bytes()); errComplete != nil {
				t.Fatal(errComplete)
			}
			auth.ProxyURL = proxy.URL
			refreshed, errRefresh := executor.Refresh(codexauth.WithRefreshJournal(t.Context(), journal), auth.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			if oauthCalls.Load() != 0 {
				t.Fatal("receipt recovery consumed another OAuth refresh")
			}
			refreshed.ProxyURL = ""
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), auth, refreshed)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			if _, errSave := store.Save(t.Context(), merged); errSave != nil {
				t.Fatal(errSave)
			}
			saved, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(saved, "chatgpt_user_id").String() != "user-bbb" || ojson.GetBytes(saved, "operator_note").String() != "keep" {
				t.Fatal("receipt recovery lost adopted member or administrator metadata")
			}
			auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, saved)
			if errSynthesize != nil || len(auths) != 1 {
				t.Fatalf("reload: %v count=%d", errSynthesize, len(auths))
			}
			reloaded := auths[0]
			reloaded.Attributes["base_url"] = server.URL
			reloaded.ProxyURL = ""
			selected, errUpdate := manager.Update(t.Context(), reloaded)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			request := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
			options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"keep"}`}}}
			fingerprintRunHTTP(t, t.Context(), executor, selected, request, options, false)
			wire := <-captured
			if wire.headers.Get("Authorization") != "Bearer receipt-access" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" ||
				ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" ||
				ojson.Get(wire.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
				t.Fatal("receipt/Manager/save/reload sent inconsistent credentials and member identity")
			}
			retained, errReceipt := journal.RefreshRead(t.Context(), key)
			if errReceipt != nil || string(retained) != receipt.String() {
				t.Fatal("receipt recovery changed the successful immutable receipt")
			}
		})
	}
}

func TestCodexDeviceFingerprintOAuthRefreshIdentityReachesWire(t *testing.T) {
	for _, scenario := range []struct {
		name, account, user, plan, wantID string
	}{
		{"same-subject", "acc-team-1", "user-aaa", "team", "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"},
		{"new-member", "acc-team-1", "user-bbb", "team", "fd5de10e-f853-4dd0-92f4-ece041b115a9"},
		{"new-account", "acc-team-2", "user-bbb", "team", "e7586ede-1b70-4428-9407-367a6aa12ea6"},
		{"new-account-missing-member", "acc-team-2", "", "team", "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a"},
		{"missing-account-new-member", "", "user-bbb", "team", "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a"},
		{"missing-member-plan", "acc-team-1", "", "", "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			executor := NewCodexExecutor(cfg)
			auth := fingerprintHTTPAuth(server.URL)
			auth.ID, auth.FileName = "codex-a.json", "codex-a.json"
			path := filepath.Join(cfg.AuthDir, auth.FileName)
			auth.Attributes[cliproxyauth.AttributePath] = path
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["chatgpt_plan_type"] = "team"
			auth.Metadata["plan_type"] = "team"
			auth.Metadata["id_token"] = codexDeviceRefreshPlanToken(t, "team")
			auth.Metadata["refresh_token"] = "refresh-identity-" + t.Name()
			for _, key := range []string{"account_id", "chatgpt_user_id", "chatgpt_plan_type", "plan_type", "id_token"} {
				auth.Attributes[key], _ = auth.Metadata[key].(string)
			}
			initial := ojson.NewDocString(`{}`)
			for key, value := range auth.Metadata {
				if errSet := initial.Set(key, value); errSet != nil {
					t.Fatal(errSet)
				}
			}
			if errWrite := os.WriteFile(path, initial.Bytes(), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), auth.Clone())
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			auth = registered
			request := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
			options := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"keep"}`}}}
			fingerprintRunHTTP(t, t.Context(), executor, auth, request, options, false)
			if first := <-captured; ojson.GetBytes(first.body, "client_metadata.x-codex-installation-id").String() != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatal("original member did not reach upstream")
			}
			claims := ojson.NewDocString(`{"https://api.openai.com/auth":{}}`)
			for key, value := range map[string]string{"chatgpt_account_id": scenario.account, "chatgpt_user_id": scenario.user, "chatgpt_plan_type": scenario.plan} {
				if value != "" {
					if errSet := claims.Set("https://api\\.openai\\.com/auth."+key, value); errSet != nil {
						t.Fatal(errSet)
					}
				}
			}
			proxy, teardown := startCodexMockOAuthServers(t, deviceRound3Token(claims))
			defer teardown()
			auth.ProxyURL = proxy
			refreshed, errRefresh := executor.Refresh(t.Context(), auth.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			refreshed.ProxyURL = ""
			fingerprintRunHTTP(t, t.Context(), executor, refreshed, request, options, false)
			got := <-captured
			if got.headers.Get("Authorization") != "Bearer new-mock-access-token" || got.headers.Get("ChatGPT-Account-ID") != scenario.account {
				t.Fatal("refreshed credential and account header disagree")
			}
			if ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != scenario.wantID || ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != scenario.wantID {
				t.Fatal("actual OAuth refresh retained the previous member or plan")
			}
			if scenario.user != "" && refreshed.Metadata["chatgpt_user_id"] != scenario.user {
				t.Fatal("adopted credential retained stale persisted member hint")
			}
			if refreshed.Attributes["id_token"] != "" || refreshed.Attributes["chatgpt_user_id"] == "user-aaa" && scenario.user != "user-aaa" {
				t.Fatal("adopted credential retained stale auxiliary identity")
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), auth, refreshed)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			if _, errSave := store.Save(t.Context(), merged); errSave != nil {
				t.Fatal(errSave)
			}
			saved, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if scenario.user == "" && ojson.GetBytes(saved, "chatgpt_user_id").Exists() {
				t.Fatal("missing refreshed member claim retained a stale disk hint")
			}
			if scenario.plan == "" && (ojson.GetBytes(saved, "chatgpt_plan_type").Exists() || !ojson.GetBytes(saved, "plan_type_defaulted").Bool()) {
				t.Fatal("missing refreshed plan claim lost its provenance")
			}
			auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, saved)
			if errSynthesize != nil || len(auths) != 1 {
				t.Fatalf("reload: %v count=%d", errSynthesize, len(auths))
			}
			reloaded := auths[0]
			reloaded.Attributes["base_url"] = server.URL
			reloaded.ProxyURL = ""
			if _, errUpdate := manager.Update(t.Context(), reloaded); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			fingerprintRunHTTP(t, t.Context(), executor, reloaded, request, options, false)
			reloadedWire := <-captured
			if ojson.GetBytes(reloadedWire.body, "client_metadata.x-codex-installation-id").String() != scenario.wantID || reloadedWire.headers.Get("Authorization") != "Bearer new-mock-access-token" || reloadedWire.headers.Get("ChatGPT-Account-ID") != scenario.account {
				t.Fatal("refresh merge/save/synthesis restored a different credential identity")
			}
		})
	}
}

func TestCodexDeviceFingerprintOAuthRefreshWebsocketSubject(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-member", true: "new-member"}[changed], func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			executor := NewCodexWebsocketsExecutor(cfg)
			executor.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer executor.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			auth.Metadata["id_token"] = codexDeviceRefreshPlanToken(t, "team")
			auth.Metadata["refresh_token"] = "refresh-ws-identity-" + t.Name()
			auth.Metadata["codex_installation_id"] = codexDeviceTestA
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errTurn := runCodexDeviceWSTurn(t, executor, t.Context(), auth, opts, body, false); errTurn != nil {
				t.Fatal(errTurn)
			}
			<-frames
			claims := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team"}}`)
			if changed {
				_ = claims.Set("https://api\\.openai\\.com/auth.chatgpt_user_id", "user-bbb")
			}
			proxy, teardown := startCodexMockOAuthServers(t, deviceRound3Token(claims))
			defer teardown()
			auth.ProxyURL = proxy
			refreshed, errRefresh := NewCodexExecutor(cfg).Refresh(t.Context(), auth.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			refreshed.ProxyURL = ""
			errTurn := runCodexDeviceWSTurn(t, executor, t.Context(), refreshed, opts, `{"input":[],"previous_response_id":"r0"}`, false)
			if changed {
				if !core.IsUpstreamWebsocketReplayRequired(errTurn) {
					t.Fatalf("new member with identical explicit UUID reused old subject: %v", errTurn)
				}
				if errTurn = runCodexDeviceWSTurn(t, executor, t.Context(), refreshed, opts, body, false); errTurn != nil {
					t.Fatal(errTurn)
				}
				frame := <-frames
				if connections.Load() != 2 || frame.headers.Get("Authorization") != "Bearer new-mock-access-token" {
					t.Fatal("replacement subject did not establish refreshed handshake")
				}
			} else {
				if errTurn != nil {
					t.Fatal(errTurn)
				}
				<-frames
				if connections.Load() != 1 {
					t.Fatal("same subject token rotation unnecessarily reconnected")
				}
			}
		})
	}
}

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
