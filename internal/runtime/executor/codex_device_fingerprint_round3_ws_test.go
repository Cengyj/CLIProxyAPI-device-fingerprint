package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintWebsocketInterruptEscapedMetadata(t *testing.T) {
	for _, payload := range []string{
		`{"type":"response.interrupt","response_id":"active","mode":"discard_partial_items","event_id":"interrupt","extension":900719925474099312345,"client_\u006detadata":{"x-codex-installation-id":"client"}}`,
		`{"type":"response.interrupt","response_id":"active","mode":"discard_partial_items","event_id":"interrupt","extension":900719925474099312345,"client_metadata":{"x-codex-installation-\u0069d":"client"}}`,
	} {
		t.Run(payload, func(t *testing.T) {
			captured := make(chan []byte, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if errUpgrade != nil {
					t.Error(errUpgrade)
					return
				}
				defer func() {
					if errClose := conn.Close(); errClose != nil {
						t.Log(errClose)
					}
				}()
				if _, _, errRead := conn.ReadMessage(); errRead != nil {
					return
				}
				if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"active"}}`)); errWrite != nil {
					return
				}
				_, body, errRead := conn.ReadMessage()
				if errRead != nil {
					return
				}
				captured <- body
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"active","status":"completed","output":[]}}`))
			}))
			defer server.Close()
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result, errExecute := exec.ExecuteStream(ctx, codexDeviceWSAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}, managedInstructionsOptions(t))
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			defer func() {
				cancel()
				for range result.Chunks {
				}
			}()
			created := false
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
				if ojson.GetBytes(chunk.Payload, "type").String() == "response.created" {
					created = true
					break
				}
			}
			if !created {
				t.Fatal("stream ended before active response")
			}
			if errInterrupt := exec.InterruptExecutionSession(t.Context(), t.Name(), []byte(payload)); errInterrupt != nil {
				t.Fatal(errInterrupt)
			}
			frame := <-captured
			deviceCount := 0
			ojson.ParseBytes(frame).ForEach(func(key, value ojson.Result) bool {
				if key.String() == "client_metadata" {
					value.ForEach(func(metadataKey, metadataValue ojson.Result) bool {
						if metadataKey.String() == "x-codex-installation-id" {
							deviceCount++
							if metadataValue.String() != codexDeviceTestA {
								t.Error("escaped interrupt metadata forwarded a client device")
							}
						}
						return true
					})
				}
				return true
			})
			if deviceCount != 1 || ojson.GetBytes(frame, "response_id").String() != "active" || ojson.GetBytes(frame, "mode").String() != "discard_partial_items" || ojson.GetBytes(frame, "event_id").String() != "interrupt" || ojson.GetBytes(frame, "extension").Raw != "900719925474099312345" {
				t.Fatalf("interrupt device count or control fields changed: %s", frame)
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketFinalIdentityShapes(t *testing.T) {
	const third = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	turnMetadata := func(raw string) string {
		doc := ojson.NewDocString(`{"unknown":900719925474099312345}`)
		if errSet := doc.Set("x-codex-turn-metadata", raw); errSet != nil {
			t.Fatal(errSet)
		}
		return doc.String()
	}
	for _, test := range []struct {
		name, first, next string
		header            bool
	}{
		{"body-type", `{"x-codex-installation-id":null,"unknown":900719925474099312345}`, `{"x-codex-installation-id":false,"unknown":900719925474099312345}`, false},
		{"body-escaped-duplicate", `{"x-codex-installation-id":"` + codexDeviceTestA + `","x-codex-installation-\u0069d":"` + codexDeviceTestB + `","unknown":900719925474099312345}`, `{"x-codex-installation-id":"` + codexDeviceTestA + `","x-codex-installation-\u0069d":"` + third + `","unknown":900719925474099312345}`, false},
		{"turn-type", turnMetadata(`{"installation_id":900719925474099312345,"turn_id":"keep"}`), turnMetadata(`{"installation_id":900719925474099312346,"turn_id":"keep"}`), false},
		{"turn-escaped-duplicate", turnMetadata(`{"installation_id":"` + codexDeviceTestA + `","installation_\u0069d":"` + codexDeviceTestB + `","turn_id":"keep"}`), turnMetadata(`{"installation_id":"` + codexDeviceTestA + `","installation_\u0069d":"` + third + `","turn_id":"keep"}`), false},
		{"header-escaped-duplicate", `{"installation_id":"` + codexDeviceTestA + `","installation_\u0069d":"` + codexDeviceTestB + `","turn_id":"keep"}`, `{"installation_id":"` + codexDeviceTestA + `","installation_\u0069d":"` + third + `","turn_id":"keep"}`, true},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", test.name, stream), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				exec := NewCodexWebsocketsExecutor(cfg)
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				opts := managedInstructionsOptions(t)
				setFinal := func(raw string) {
					if test.header {
						auth.Attributes["header:X-Codex-Turn-Metadata"] = raw
					} else {
						cfg.Payload.OverrideRaw = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"client_metadata": raw}}}
					}
				}
				checkFrame := func(frame codexDeviceWSFrame, raw string, connection int32) {
					t.Helper()
					actual := ojson.GetBytes(frame.body, "client_metadata").Raw
					if test.header {
						actual = frame.headers.Get("X-Codex-Turn-Metadata")
					}
					if actual != raw || frame.connection != connection || connections.Load() != connection {
						t.Fatalf("final administrator value or physical connection changed: value=%s connection=%d/%d, want %s on %d", actual, frame.connection, connections.Load(), raw, connection)
					}
				}
				setFinal(test.first)
				for range 2 {
					if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, `{"input":[]}`, stream); errExecute != nil {
						t.Fatal(errExecute)
					}
					checkFrame(<-frames, test.first, 1)
				}
				setFinal(test.next)
				for _, required := range []bool{false, true} {
					ctx := t.Context()
					body := `{"input":[],"previous_response_id":"r1"}`
					if required {
						ctx = core.WithRequiredUpstreamWebsocket(ctx)
						body = `{"input":[]}`
					}
					if errExecute := runCodexDeviceWSTurn(t, exec, ctx, auth, opts, body, stream); !core.IsUpstreamWebsocketReplayRequired(errExecute) {
						t.Fatalf("changed final identity reused a required socket: %v", errExecute)
					}
				}
				if connections.Load() != 1 || len(frames) != 0 {
					t.Fatal("incompatible continuation reached an upstream socket")
				}
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, `{"input":[]}`, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				checkFrame(<-frames, test.next, 2)
			})
		}
	}
}

func TestCodexDeviceFingerprintWebsocketLearnsBodyWithoutHandshake(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			bodies := []string{
				`{"input":[]}`,
				`{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-turn-metadata":"{\"installation_id\":\"client\",\"turn_id\":\"one\"}"}}`,
				`{"input":[],"previous_response_id":"r1","client_metadata":{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\",\"turn_id\":\"two\"}"}}`,
			}
			for step, body := range bodies {
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				frame := <-frames
				if frame.connection != 1 || connections.Load() != 1 || frame.headers.Get("X-Codex-Installation-Id") != "" || frame.headers.Get("X-Codex-Turn-Metadata") != "" {
					t.Fatal("a newly transmitted body field required or fabricated a new handshake")
				}
				if step == 0 {
					if ojson.GetBytes(frame.body, "client_metadata").Exists() {
						t.Fatal("missing device fields were injected")
					}
					continue
				}
				turn := ojson.Parse(ojson.GetBytes(frame.body, "client_metadata.x-codex-turn-metadata").String())
				if turn.Get("installation_id").String() != codexDeviceTestA || ojson.GetBytes(frame.body, "previous_response_id").String() != fmt.Sprintf("r%d", step-1) {
					t.Fatal("new body device or continuation identity was lost")
				}
				if step == 2 && (ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA || turn.Get("turn_id").String() != "two") {
					t.Fatal("same device in a new body location was not transmitted")
				}
			}
			// The absence of fields in the handshake cannot erase the identity
			// learned from successful business frames on that physical socket.
			changed := auth.Clone()
			changed.Metadata["codex_installation_id"] = codexDeviceTestB
			if errExecute := runCodexDeviceWSTurn(t, exec, core.WithRequiredUpstreamWebsocket(t.Context()), changed, opts, bodies[2], stream); !core.IsUpstreamWebsocketReplayRequired(errExecute) {
				t.Fatalf("retained socket forgot the transmitted body identity: %v", errExecute)
			}
			if connections.Load() != 1 || len(frames) != 0 {
				t.Fatal("new identity reached the retained socket")
			}
		})
	}
}
