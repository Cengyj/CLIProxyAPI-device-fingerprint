package executor

import (
	"fmt"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintNativeOAuthSocketSubject(t *testing.T) {
	token := func(issuedAt int, field string) string {
		doc := ojson.NewDocString(`{"iss":"https://issuer.invalid","sub":"subject-a","aud":["client"],"https://api.openai.com/auth":{"chatgpt_account_id":"workspace","chatgpt_user_id":"member-a","chatgpt_plan_type":"free"}}`)
		if errSet := doc.Set("iat", issuedAt); errSet != nil {
			t.Fatal(errSet)
		}
		if field != "" {
			if errSet := doc.Set(field, "changed"); errSet != nil {
				t.Fatal(errSet)
			}
		}
		return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
	}
	for _, tc := range []struct {
		name, accessField, idField        string
		metadataMember, omitID, tokenOnly bool
		reuse                             bool
	}{
		{name: "same-member", reuse: true},
		{name: "same-member-string-audience", accessField: "aud", idField: "aud", reuse: true},
		{name: "same-member-omitted-id", omitID: true, reuse: true},
		{name: "same-member-token-only", omitID: true, tokenOnly: true, reuse: true},
		{name: "access-issuer", accessField: "iss"},
		{name: "access-subject", accessField: "sub"},
		{name: "access-member-free-plan", accessField: "https://api\\.openai\\.com/auth.chatgpt_user_id"},
		{name: "access-account", accessField: "https://api\\.openai\\.com/auth.chatgpt_account_id"},
		{name: "id-issuer", idField: "iss"},
		{name: "id-subject", idField: "sub"},
		{name: "id-member-free-plan", idField: "https://api\\.openai\\.com/auth.chatgpt_user_id"},
		{name: "metadata-member-free-plan", metadataMember: true},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				auth.Metadata["access_token"] = token(1, "")
				auth.Metadata["id_token"] = token(1, "")
				auth.Metadata["account_id"] = "workspace"
				auth.Metadata["plan_type"] = "free"
				auth.Metadata["chatgpt_user_id"] = "member-a"
				if tc.tokenOnly {
					delete(auth.Metadata, "chatgpt_user_id")
				}
				auth.Metadata["use_siwc"] = true
				auth.Metadata["siwc"] = map[string]any{"access_token": "nested-ignored", "device_id": codexDeviceTestA}
				opts := managedInstructionsOptions(t)
				opts.Headers.Set("User-Agent", "codex_cli_rs/0.154.0")
				opts.Headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"client"}`)
				body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				first := <-frames
				oldBearer := auth.Metadata["access_token"].(string)
				if first.connection != 1 || first.headers.Get("Authorization") != "Bearer "+oldBearer || first.headers.Get("ChatGPT-Account-ID") != "workspace" {
					t.Fatal("native request did not establish an outer OAuth handshake")
				}
				changed := auth.Clone()
				changed.Metadata["access_token"] = token(2, tc.accessField)
				changed.Metadata["id_token"] = token(2, tc.idField)
				if tc.omitID {
					delete(changed.Metadata, "id_token")
				}
				if tc.metadataMember {
					changed.Metadata["chatgpt_user_id"] = "member-b"
				}
				if tc.tokenOnly {
					// Executor reconstruction must not depend on a cached ID token
					// to recognize the renewed access token's complete subject.
					rebuilt := NewCodexWebsocketsExecutor(exec.cfg)
					rebuilt.store = exec.store
					exec = rebuilt
				}
				sess := exec.getOrCreateSession(t.Name())
				sess.connMu.Lock()
				policy := sess.device.policy
				sess.connMu.Unlock()
				req := core.Request{Model: "gpt-5.4", Payload: []byte(body)}
				_, errFrozen := exec.prepareCodexWebsocketStreamWithDevice(t.Context(), changed, req, opts, sess, &policy)
				if tc.reuse && errFrozen != nil || !tc.reuse && !core.IsUpstreamWebsocketReplayRequired(errFrozen) {
					t.Errorf("frozen OAuth subject: %v, reuse=%t", errFrozen, tc.reuse)
				}
				continuation := `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`
				errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, continuation, stream)
				wantConn, wantBearer := int32(1), oldBearer
				if tc.reuse {
					if errContinue != nil {
						t.Fatal(errContinue)
					}
					frame := <-frames
					if frame.connection != 1 || frame.headers.Get("Authorization") != "Bearer "+oldBearer {
						t.Fatal("normal outer renewal changed its physical handshake")
					}
				} else {
					if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
						t.Errorf("changed outer subject continuation: %v, want replay", errContinue)
					}
					select {
					case frame := <-frames:
						t.Errorf("changed outer subject wrote on connection %d", frame.connection)
					default:
					}
					wantConn, wantBearer = 2, changed.Metadata["access_token"].(string)
				}
				if connections.Load() != 1 {
					t.Fatal("continuation created a new physical connection")
				}
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				full := <-frames
				if full.connection != wantConn || connections.Load() != wantConn || full.headers.Get("Authorization") != "Bearer "+wantBearer {
					t.Errorf("full request reused wrong outer handshake: connection %d, want %d", full.connection, wantConn)
				}
				if ojson.GetBytes(full.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
					t.Fatal("subject guard changed the explicit public installation ID")
				}
				exec.CloseExecutionSession(t.Name())
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				fresh := <-frames
				if fresh.connection != wantConn+1 || fresh.headers.Get("Authorization") != "Bearer "+changed.Metadata["access_token"].(string) {
					t.Fatal("fresh socket did not use the latest outer bearer")
				}
			})
		}
	}
}
