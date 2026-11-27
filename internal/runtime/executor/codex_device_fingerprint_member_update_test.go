package executor

import (
	"fmt"
	"os"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintCanonicalMemberUpdateHTTP(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", mode, stream), func(t *testing.T) {
				server, captured := fingerprintHTTPServer(t, false)
				cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
				exec := NewCodexExecutor(cfg)
				auth := fingerprintHTTPAuth(server.URL)
				auth.ID, auth.FileName = "canonical-member.json", "canonical-member.json"
				auth.Metadata["account_id"] = "acc-team-1"
				auth.Metadata["chatgpt_user_id"] = "user-aaa"
				auth.Metadata["plan_type"] = "team"
				auth.Metadata["id_token"] = ""
				auth.Attributes["chatgpt_user_id"] = "user-aaa"
				manager := cliproxyauth.NewManager(nil, nil, nil)
				current, errRegister := manager.Register(t.Context(), auth)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
				fingerprintRunHTTP(t, t.Context(), exec, current, req, opts, stream)
				<-captured
				changed := current.Clone()
				changed.Metadata["chatgpt_user_id"] = "user-bbb"
				changed.Metadata["access_token"] = "new-member-bearer"
				updated, errUpdate := manager.Update(t.Context(), changed)
				if errUpdate != nil {
					t.Fatal(errUpdate)
				}
				check := func(executor *CodexExecutor, snapshot *cliproxyauth.Auth) {
					t.Helper()
					fingerprintRunHTTP(t, t.Context(), executor, snapshot, req, opts, stream)
					wire := <-captured
					want := "client-device"
					if mode == "device" {
						want = "fd5de10e-f853-4dd0-92f4-ece041b115a9"
					}
					if got := ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String(); got != want {
						t.Errorf("canonical member update sent installation %q, want %q", got, want)
					}
					if wire.headers.Get("Authorization") != "Bearer new-member-bearer" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" {
						t.Error("updated member credentials did not reach the outgoing request")
					}
				}
				check(exec, updated)
				check(NewCodexExecutor(cfg), updated)
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				path, errSave := store.Save(t.Context(), updated.Clone())
				if errSave != nil {
					t.Fatal(errSave)
				}
				raw, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("cold load: records=%d err=%v", len(loaded), errLoad)
				}
				if loaded[0].Metadata["chatgpt_user_id"] != "user-bbb" {
					t.Fatal("canonical member did not survive persistence")
				}
				loaded[0].Attributes["base_url"] = server.URL
				check(NewCodexExecutor(cfg), loaded[0])
			})
		}
	}
}

func TestCodexDeviceFingerprintCanonicalMemberUpdateWebsocket(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			auth.Metadata["id_token"] = ""
			auth.Attributes["chatgpt_user_id"] = "user-aaa"
			manager := cliproxyauth.NewManager(nil, nil, nil)
			current, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), current, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			first := <-frames
			changed := current.Clone()
			changed.Metadata["chatgpt_user_id"] = "user-bbb"
			changed.Metadata["access_token"] = "new-member-bearer"
			updated, errUpdate := manager.Update(t.Context(), changed)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			sess := exec.getOrCreateSession(t.Name())
			sess.connMu.Lock()
			policy := sess.device.policy
			sess.connMu.Unlock()
			_, errFrozen := exec.prepareCodexWebsocketStreamWithDevice(t.Context(), updated, core.Request{Model: "gpt-5.4", Payload: []byte(body)}, opts, sess, &policy)
			if !core.IsUpstreamWebsocketReplayRequired(errFrozen) {
				t.Errorf("new canonical member accepted frozen policy: %v", errFrozen)
			}
			errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), updated, opts, `{"input":[],"previous_response_id":"r0"}`, stream)
			if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
				t.Errorf("new canonical member continuation: %v, want replay", errContinue)
			}
			select {
			case frame := <-frames:
				t.Errorf("new member wrote on prior physical socket %d", frame.connection)
			default:
			}
			if connections.Load() != 1 {
				t.Fatal("continuation created another connection")
			}
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), updated, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			fresh := <-frames
			if first.connection != 1 || fresh.connection != 2 || connections.Load() != 2 || fresh.headers.Get("Authorization") != "Bearer new-member-bearer" {
				t.Error("full request did not establish a handshake for the updated member")
			}
			if ojson.GetBytes(fresh.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Error("member isolation changed the explicit public installation UUID")
			}
		})
	}
}
