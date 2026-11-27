package executor

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintFinalAccountHeaderPriority(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		for _, stream := range []bool{false, true} {
			for _, tc := range []struct {
				name, custom, inbound, modelOverride, want string
			}{
				{name: "native", want: "acct"},
				{name: "literal", custom: "admin-account", want: "admin-account"},
				{name: "dynamic", custom: "$X-Account", inbound: "dynamic-account", want: "dynamic-account"},
				{name: "unresolved", custom: "$X-Account", want: "acct"},
				{name: "model-last", custom: "admin-account", modelOverride: "model-account", want: "model-account"},
				{name: "model-clear", custom: "admin-account", modelOverride: " ", want: ""},
			} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", mode, stream, tc.name), func(t *testing.T) {
					server, frames, connections := newCodexDeviceWSServer(t)
					exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: mode}})
					exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
					defer exec.CloseExecutionSession(t.Name())
					auth := codexDeviceWSAuth(server.URL)
					auth.Attributes["header:chatgpt-account-id"] = tc.custom
					opts := managedInstructionsOptions(t)
					opts.Headers.Set("X-Account", tc.inbound)
					model := "gpt-5.4"
					if tc.modelOverride != "" {
						model = "test-device-account-header"
						reg := registry.GetGlobalRegistry()
						reg.RegisterClient(t.Name(), "codex", []*registry.ModelInfo{{ID: model, Config: &registry.ModelConfig{
							OverrideHeader: map[string]string{"CHATGPT-ACCOUNT-ID": tc.modelOverride},
						}}})
						t.Cleanup(func() { reg.UnregisterClient(t.Name()) })
					}
					req := core.Request{Model: model, Payload: []byte(`{"input":[]}`)}
					if stream {
						result, errExecute := exec.ExecuteStream(t.Context(), auth, req, opts)
						if errExecute != nil {
							t.Fatal(errExecute)
						}
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								t.Fatal(chunk.Err)
							}
						}
					} else if _, errExecute := exec.Execute(t.Context(), auth, req, opts); errExecute != nil {
						t.Fatal(errExecute)
					}
					wire := <-frames
					if connections.Load() != 1 || !slices.Equal(wire.headers.Values("ChatGPT-Account-ID"), []string{tc.want}) {
						t.Fatalf("physical account headers = %q, want only %q", wire.headers.Values("ChatGPT-Account-ID"), tc.want)
					}
				})
			}
		}
	}
}

func TestCodexDeviceFingerprintFinalHandshakeAuthChange(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		for _, stream := range []bool{false, true} {
			for _, header := range []string{"Authorization", "ChatGPT-Account-ID"} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", mode, stream, header), func(t *testing.T) {
					server, frames, connections := newCodexDeviceWSServer(t)
					exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: mode}})
					exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
					defer exec.CloseExecutionSession(t.Name())
					auth := codexDeviceWSAuth(server.URL)
					oldValue, newValue := "account-a", "account-b"
					if header == "Authorization" {
						oldValue, newValue = "Bearer overridden-a", "Bearer overridden-b"
					}
					auth.Attributes["header:"+header] = oldValue
					opts := managedInstructionsOptions(t)
					body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
					if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
						t.Fatal(errExecute)
					}
					initial := <-frames
					if initial.connection != 1 || !slices.Equal(initial.headers.Values(header), []string{oldValue}) {
						t.Fatalf("initial physical handshake %s values = %q, want only the administrator override", header, initial.headers.Values(header))
					}
					changed := auth.Clone()
					changed.Attributes["header:"+header] = newValue
					continuation := `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`
					errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, continuation, stream)
					if mode == "off" {
						if errContinue != nil {
							t.Fatal(errContinue)
						}
						frame := <-frames
						if frame.connection != 1 || !slices.Equal(frame.headers.Values(header), []string{oldValue}) {
							t.Error("disabled mode changed existing connection reuse")
						}
					} else if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
						t.Errorf("changed handshake authentication continuation: %v, want replay", errContinue)
					}
					select {
					case frame := <-frames:
						t.Errorf("changed handshake authentication wrote on connection %d", frame.connection)
					default:
					}
					if connections.Load() != 1 {
						t.Error("continuation created another connection")
					}
					if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
						t.Fatal(errExecute)
					}
					fresh := <-frames
					wantConnection, wantValue := int32(2), newValue
					if mode == "off" {
						wantConnection, wantValue = 1, oldValue
					}
					if fresh.connection != wantConnection || connections.Load() != wantConnection || !slices.Equal(fresh.headers.Values(header), []string{wantValue}) {
						t.Error("full request reused a physical handshake with different final authentication")
					}
				})
			}
		}
	}
}

func TestCodexDeviceFingerprintFinalHandshakeJWTSubject(t *testing.T) {
	token := func(member string, issuedAt int) string {
		claims := ojson.NewDocString(`{"iss":"https://issuer.invalid","sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"workspace"}}`)
		_ = claims.Set("https://api\\.openai\\.com/auth.chatgpt_user_id", member)
		_ = claims.Set("iat", issuedAt)
		return deviceRound3Token(claims)
	}
	for _, stream := range []bool{false, true} {
		for _, same := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/same=%t", stream, same), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				oldHeader := "Bearer " + token("member-a", 1)
				auth.Attributes["header:Authorization"] = oldHeader
				opts := managedInstructionsOptions(t)
				body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				<-frames
				changed := auth.Clone()
				member := "member-a"
				if !same {
					member = "member-b"
				}
				newHeader := "Bearer " + token(member, 2)
				changed.Attributes["header:Authorization"] = newHeader
				errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`, stream)
				if same {
					if errContinue != nil {
						t.Fatal(errContinue)
					}
					wire := <-frames
					if wire.connection != 1 || wire.headers.Get("Authorization") != oldHeader {
						t.Error("same custom bearer subject did not reuse its original physical handshake")
					}
				} else {
					if !core.IsUpstreamWebsocketReplayRequired(errContinue) || len(frames) != 0 {
						t.Fatal("changed custom bearer member reached the old physical socket")
					}
				}
				if connections.Load() != 1 {
					t.Fatal("continuation redialed")
				}
				exec.CloseExecutionSession(t.Name())
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				wire := <-frames
				if wire.connection != 2 || wire.headers.Get("Authorization") != newHeader {
					t.Error("new physical socket did not send the newest custom bearer")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintDuplexFinalHandshakeAuthChange(t *testing.T) {
	server, frames, connections := newCodexDeviceWSServer(t)
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	auth.Attributes["header:Authorization"] = "$X-Upstream-Auth"
	opts := managedInstructionsOptions(t)
	opts.Headers.Set("X-Upstream-Auth", "Bearer initial-override")
	opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		return core.RequestAfterAuthInterceptResponse{Headers: http.Header{"X-Upstream-Auth": {"Bearer changed-override"}}}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := make(chan core.WebsocketInput, 1)
	ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
	result, errExecute := exec.ExecuteStream(ctx, auth, core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[]}`)}, opts)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	defer func() {
		cancel()
		for range result.Chunks {
		}
	}()
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
			break
		}
	}
	first := <-frames
	if first.headers.Get("Authorization") != "Bearer initial-override" {
		t.Fatal("initial custom authorization missing")
	}
	input <- core.WebsocketInput{Payload: []byte(`{"type":"response.append","input":[]}`)}
	rejected := false
	for chunk := range result.Chunks {
		rejected = rejected || core.IsUpstreamWebsocketReplayRequired(chunk.Err)
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
			t.Fatal("duplex used old handshake after final authentication changed")
		}
	}
	if !rejected || len(frames) != 0 || connections.Load() != 1 {
		t.Fatal("duplex did not reject changed authentication before sending")
	}
}
