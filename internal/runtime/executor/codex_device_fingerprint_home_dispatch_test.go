package executor

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintHomeFirstDispatch(t *testing.T) {
	const memberB = "fd5de10e-f853-4dd0-92f4-ece041b115a9"
	for _, source := range []string{"conflicting-attributes", "attributes-only", "admin-overrides", "admin-off", "api-key"} {
		for _, transport := range []string{"http", "http-stream", "ws", "ws-stream"} {
			t.Run(source+"/"+transport, func(t *testing.T) {
				ws := transport == "ws" || transport == "ws-stream"
				stream := transport == "http-stream" || transport == "ws-stream"
				var upstreamURL string
				var capture func() fingerprintHTTPCapture
				if ws {
					server, frames, connections := newCodexDeviceWSServer(t)
					upstreamURL = server.URL
					capture = func() fingerprintHTTPCapture {
						frame := <-frames
						if frame.connection != 1 || connections.Load() != 1 {
							t.Fatal("first dispatch did not establish exactly one physical websocket")
						}
						return fingerprintHTTPCapture{body: frame.body, headers: frame.headers}
					}
				} else {
					server, captures := fingerprintHTTPServer(t, false)
					upstreamURL = server.URL
					capture = func() fingerprintHTTPCapture { return <-captures }
				}
				cfg := &config.Config{Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				auto := NewCodexAutoExecutor(cfg)
				auto.wsExec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				auth := cliproxyauth.Auth{
					ID: "first-home-codex", Provider: "codex", Status: cliproxyauth.StatusActive,
					Attributes: map[string]string{"base_url": upstreamURL, "websockets": "true", "account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"},
					Metadata:   map[string]any{"access_token": "first-home-access", "refresh_token": "first-home-refresh", "expired": "2099-01-01T00:00:00Z", "account_id": "acc-team-1", "id_token": deviceRound3Token(ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`))},
				}
				wantID, wantHeader, wantBearer, wantAccount := memberB, memberB, "first-home-access", "acc-team-1"
				switch source {
				case "attributes-only":
					auth.Attributes["account_id"] = "acc-team-1"
					auth.Attributes["chatgpt_user_id"] = "user-bbb"
					auth.Attributes["id_token"] = auth.Metadata["id_token"].(string)
					delete(auth.Metadata, "account_id")
					delete(auth.Metadata, "id_token")
				case "admin-overrides":
					cfg.Codex.DeviceFingerprintMode = "off"
					auth.Attributes["codex_device_fingerprint"] = "device"
					auth.Metadata["codex_device_fingerprint"] = "off"
					auth.Attributes["codex_installation_id"] = codexDeviceTestA
					auth.Metadata["codex_installation_id"] = codexDeviceTestB
					auth.Attributes["header:X-Codex-Turn-Metadata"] = `{"installation_id":"admin-header","turn_id":"header-turn"}`
					auth.Attributes["header:X-Codex-Installation-Id"] = "admin-standalone"
					wantID, wantHeader = codexDeviceTestA, "admin-header"
				case "admin-off":
					auth.Attributes["codex_device_fingerprint"] = "off"
					auth.Metadata["codex_device_fingerprint"] = "device"
					wantID, wantHeader = "client-device", "client-header"
				case "api-key":
					auth.Attributes["api_key"] = "first-home-key"
					wantID, wantHeader, wantBearer, wantAccount = "client-device", "client-header", "first-home-key", ""
				}
				dispatcher := &terminalCodexHomeDispatcher{auth: auth}
				before := auth.Clone()
				manager := cliproxyauth.NewManager(nil, nil, nil)
				manager.SetConfig(cfg)
				registry := executionregistry.New()
				manager.PublishHomeDispatch(dispatcher, registry, 1)
				manager.RegisterExecutor(auto)
				session := t.Name()
				t.Cleanup(func() {
					manager.CloseExecutionSession(session)
					if errClose := registry.Close(); errClose != nil {
						t.Error(errClose)
					}
				})
				ctx := context.Context(t.Context())
				if ws {
					ctx = core.WithDownstreamWebsocket(ctx)
				}
				opts := core.Options{Stream: stream, SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"Session-Id": {session}, "X-Codex-Turn-Metadata": {`{"installation_id":"client-header","turn_id":"header-turn"}`}}, Metadata: map[string]any{core.ExecutionSessionMetadataKey: session}}
				req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
				if stream {
					result, errStream := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
					if errStream != nil {
						t.Fatal(errStream)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				} else if _, errExecute := manager.Execute(ctx, []string{"codex"}, req, opts); errExecute != nil {
					t.Fatal(errExecute)
				}
				got := capture()
				if dispatcher.calls.Load() != 1 {
					t.Fatalf("Home RPopAuth calls = %d, want 1", dispatcher.calls.Load())
				}
				if got.headers.Get("Authorization") != "Bearer "+wantBearer || got.headers.Get("ChatGPT-Account-ID") != wantAccount {
					t.Error("wire credential/account did not match the selected Home credential")
				}
				doc := ojson.NewDoc(got.body)
				if id := doc.Get("client_metadata.x-codex-installation-id").String(); id != wantID {
					t.Errorf("wire device = %s, want %s", id, wantID)
				}
				inner := ojson.NewDocString(doc.Get("client_metadata.x-codex-turn-metadata").String())
				wantInner := wantID
				if wantID == "client-device" {
					wantInner = "client-turn-device"
				}
				if inner.Get("installation_id").String() != wantInner || inner.Get("turn_id").String() != "turn-original" || inner.Get("session_id").String() != "session-original" || doc.Get("prompt_cache_key").String() != "cache-original" {
					t.Error("wire nested device or non-device metadata changed incorrectly")
				}
				if header := ojson.NewDocString(got.headers.Get("X-Codex-Turn-Metadata")); header.Get("installation_id").String() != wantHeader || header.Get("turn_id").String() != "header-turn" {
					t.Error("actual HTTP/physical handshake turn metadata is incorrect")
				}
				if source == "admin-overrides" && got.headers.Get("X-Codex-Installation-Id") != "admin-standalone" {
					t.Error("administrator standalone header was lost")
				}
				if !reflect.DeepEqual(auth.Metadata, before.Metadata) || !reflect.DeepEqual(auth.Attributes, before.Attributes) {
					t.Error("dispatch preparation modified the source credential")
				}
				if ws {
					if _, errExecute := manager.Execute(ctx, []string{"codex"}, req, opts); errExecute != nil {
						t.Fatal(errExecute)
					}
					again := capture()
					if dispatcher.calls.Load() != 1 || ojson.GetBytes(again.body, "client_metadata.x-codex-installation-id").String() != wantID {
						t.Error("prepared Home selection did not preserve same-subject reuse")
					}
				}
				manager.CloseExecutionSession(session)
				if inFlight := registry.FreezeInFlight(time.Time{}); len(inFlight.Executions) != 0 {
					t.Error("Home scope remained registered after session cleanup")
				}
			})
		}
	}
}
