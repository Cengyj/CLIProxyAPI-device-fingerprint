package executor

import (
	"fmt"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintRegistrationDoesNotInheritMember(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			exec := NewCodexExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			manager := cliproxyauth.NewManager(nil, nil, nil)
			auth := fingerprintHTTPAuth(server.URL)
			auth.ID = "commercial-readd.json"
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			old, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			send := func(snapshot *cliproxyauth.Auth, want string) {
				t.Helper()
				fingerprintRunHTTP(t, t.Context(), exec, snapshot, req, opts, stream)
				wire := <-captured
				if got := ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String(); got != want {
					t.Errorf("registration %d sent installation %q, want %q", snapshot.RegistrationEpoch, got, want)
				}
				if wire.headers.Get("Authorization") != "Bearer "+snapshot.Metadata["access_token"].(string) || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" {
					t.Error("request credential headers did not match the selected snapshot")
				}
			}
			send(old, "2d1c341a-5607-4894-ae5e-6cf59c2e7dde")
			manager.Remove(t.Context(), old.ID)
			replacement := old.Clone()
			delete(replacement.Metadata, "chatgpt_user_id")
			delete(replacement.Metadata, "id_token")
			replacement.Metadata["access_token"] = "replacement-opaque-access"
			current, errRegister := manager.Register(t.Context(), replacement)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			if current.RegistrationEpoch <= old.RegistrationEpoch {
				t.Fatal("test did not replace the manager registration")
			}
			// No member is known for the new registration, so the public fallback
			// vector must match a cold process rather than the removed member.
			send(current, "1f7c8a7d-7eeb-467e-ab70-17efd065999f")
			// A request already holding the old immutable snapshot may finish
			// later; it cannot restore that member in the current registration.
			send(old, "2d1c341a-5607-4894-ae5e-6cf59c2e7dde")
			send(current, "1f7c8a7d-7eeb-467e-ab70-17efd065999f")
			current.Metadata["chatgpt_user_id"] = "user-bbb"
			send(current, "fd5de10e-f853-4dd0-92f4-ece041b115a9")
			sparse := current.Clone()
			delete(sparse.Metadata, "chatgpt_user_id")
			send(sparse, "fd5de10e-f853-4dd0-92f4-ece041b115a9")
		})
	}
}

func TestCodexDeviceFingerprintRegistrationWebsocketIsolation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(exec)
			auth := codexDeviceWSAuth(server.URL)
			auth.ID = "commercial-readd.json"
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			delete(auth.Metadata, "codex_installation_id")
			old, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errTurn := runCodexDeviceWSTurn(t, exec, t.Context(), old, opts, body, stream); errTurn != nil {
				t.Fatal(errTurn)
			}
			first := <-frames
			manager.Remove(t.Context(), old.ID)
			replacement := old.Clone()
			delete(replacement.Metadata, "chatgpt_user_id")
			delete(replacement.Metadata, "id_token")
			replacement.Metadata["access_token"] = "replacement-opaque-access"
			current, errRegister := manager.Register(t.Context(), replacement)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), current, opts, `{"input":[],"previous_response_id":"r0"}`, stream)
			if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
				t.Fatalf("removed registration continuation = %v, want replay", errContinue)
			}
			if len(frames) != 0 || connections.Load() != 1 {
				t.Fatal("invalid continuation sent a business frame or opened a connection")
			}
			if errTurn := runCodexDeviceWSTurn(t, exec, t.Context(), current, opts, body, stream); errTurn != nil {
				t.Fatal(errTurn)
			}
			fresh := <-frames
			if first.connection != 1 || fresh.connection != 2 || fresh.headers.Get("Authorization") != "Bearer replacement-opaque-access" {
				t.Fatal("replacement registration did not establish its own physical handshake")
			}
			if got := ojson.GetBytes(fresh.body, "client_metadata.x-codex-installation-id").String(); got != "1f7c8a7d-7eeb-467e-ab70-17efd065999f" {
				t.Fatalf("replacement handshake sent removed member installation %q", got)
			}
		})
	}
}

func TestCodexDeviceFingerprintClearedAccountWebsocketMemberIsolation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.Metadata["account_id"] = ""
			auth.Metadata["id_token"] = ""
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["codex_installation_id"] = codexDeviceTestA
			manager := cliproxyauth.NewManager(nil, nil, nil)
			first, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errTurn := runCodexDeviceWSTurn(t, exec, t.Context(), first, opts, body, stream); errTurn != nil {
				t.Fatal(errTurn)
			}
			initial := <-frames
			replacement := first.Clone()
			replacement.Metadata["chatgpt_user_id"] = "user-bbb"
			second, errUpdate := manager.Update(t.Context(), replacement)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), second, opts, `{"input":[],"previous_response_id":"r0"}`, stream)
			if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
				t.Fatalf("changed explicit member continuation = %v, want replay", errContinue)
			}
			if len(frames) != 0 || connections.Load() != 1 {
				t.Fatal("changed-member continuation wrote a frame or dialed")
			}
			if errTurn := runCodexDeviceWSTurn(t, exec, t.Context(), second, opts, body, stream); errTurn != nil {
				t.Fatal(errTurn)
			}
			fresh := <-frames
			if initial.connection != 1 || fresh.connection != 2 || fresh.headers.Get("Authorization") != "Bearer "+second.Metadata["access_token"].(string) {
				t.Fatal("changed explicit member did not establish its own authenticated socket")
			}
			if ojson.GetBytes(fresh.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("member isolation changed the explicit public installation ID")
			}
		})
	}
}

func TestCodexDeviceFingerprintLateCredentialSnapshotDoesNotRestoreMember(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, rotateBearer := range []bool{false, true} {
			for _, evicted := range []bool{false, true} {
				t.Run(fmt.Sprintf("stream=%t/rotate=%t/evicted=%t", stream, rotateBearer, evicted), func(t *testing.T) {
					server, captured := fingerprintHTTPServer(t, false)
					exec := NewCodexExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
					manager := cliproxyauth.NewManager(nil, nil, nil)
					auth := fingerprintHTTPAuth(server.URL)
					auth.ID = "commercial-readd.json"
					auth.Metadata["account_id"] = "acc-team-1"
					auth.Metadata["chatgpt_user_id"] = "user-aaa"
					auth.Metadata["plan_type"] = "team"
					old, errRegister := manager.Register(t.Context(), auth)
					if errRegister != nil {
						t.Fatal(errRegister)
					}
					req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
					opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
					send := func(snapshot *cliproxyauth.Auth, want string) {
						t.Helper()
						fingerprintRunHTTP(t, t.Context(), exec, snapshot, req, opts, stream)
						wire := <-captured
						if got := ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String(); got != want {
							t.Errorf("credential version %d sent installation %q, want %q", snapshot.CredentialVersion, got, want)
						}
						if wire.headers.Get("Authorization") != "Bearer "+snapshot.Metadata["access_token"].(string) {
							t.Error("outgoing bearer did not match the selected snapshot")
						}
					}
					send(old, "2d1c341a-5607-4894-ae5e-6cf59c2e7dde")
					changed := old.Clone()
					changed.Metadata["chatgpt_user_id"] = "user-bbb"
					if rotateBearer {
						changed.Metadata["access_token"] = "current-member-access"
					}
					current, errUpdate := manager.Update(t.Context(), changed)
					if errUpdate != nil {
						t.Fatal(errUpdate)
					}
					if current.Generation <= old.Generation || current.RegistrationEpoch != old.RegistrationEpoch || (rotateBearer && current.CredentialVersion <= old.CredentialVersion) {
						t.Fatal("test did not advance the credential inside one registration")
					}
					send(current, "fd5de10e-f853-4dd0-92f4-ece041b115a9")
					if evicted {
						for i := range 512 {
							other := current.Clone()
							other.ID = fmt.Sprintf("churn-%d", i)
							exec.deviceResolver.Resolve(exec.cfg, other, false, server.URL+"/responses")
						}
					}
					send(old, "2d1c341a-5607-4894-ae5e-6cf59c2e7dde")
					sparse := current.Clone()
					delete(sparse.Metadata, "chatgpt_user_id")
					want := "fd5de10e-f853-4dd0-92f4-ece041b115a9"
					if evicted {
						want = "1f7c8a7d-7eeb-467e-ab70-17efd065999f"
					}
					send(sparse, want)
				})
			}
		}
	}
}
