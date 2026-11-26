package executor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const codexDeviceTestA = "11111111-2222-4333-8444-555555555555"
const codexDeviceTestB = "66666666-7777-4888-9999-aaaaaaaaaaaa"

type codexDeviceWSFrame struct {
	connection int32
	headers    http.Header
	body       []byte
}

func newCodexDeviceWSServer(t *testing.T) (*httptest.Server, <-chan codexDeviceWSFrame, *atomic.Int32) {
	t.Helper()
	frames := make(chan codexDeviceWSFrame, 32)
	connections := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Error(errUpgrade)
			return
		}
		id := connections.Add(1)
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Log(errClose)
			}
		}()
		for turn := 0; ; turn++ {
			_, body, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			frames <- codexDeviceWSFrame{id, r.Header.Clone(), bytes.Clone(body)}
			if ojson.GetBytes(body, "type").String() == "response.steer" {
				accepted := ojson.NewDocString(`{"type":"response.steer.accepted","steer":{"id":"s1"}}`)
				_ = accepted.Set("steer.previous_response_id", ojson.GetBytes(body, "previous_response_id").String())
				if errWrite := conn.WriteMessage(websocket.TextMessage, accepted.Bytes()); errWrite != nil {
					return
				}
			}
			for _, kind := range []string{"response.created", "response.completed"} {
				message := ojson.NewDocString(`{"response":{"status":"completed","output":[]}}`)
				_ = message.Set("type", kind)
				_ = message.Set("response.id", fmt.Sprintf("r%d", turn))
				if errWrite := conn.WriteMessage(websocket.TextMessage, message.Bytes()); errWrite != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, frames, connections
}

func codexDeviceWSAuth(url string) *cliproxyauth.Auth {
	auth := codexOAuthTestAuth(url)
	auth.ID = "device-ws-test"
	auth.Metadata["codex_installation_id"] = codexDeviceTestA
	return auth
}

func runCodexDeviceWSTurn(t *testing.T, exec *CodexWebsocketsExecutor, ctx context.Context, auth *cliproxyauth.Auth, opts core.Options, body string, stream bool) error {
	t.Helper()
	req := core.Request{Model: "gpt-5.4", Payload: []byte(body)}
	if !stream {
		_, errExecute := exec.Execute(ctx, auth, req, opts)
		return errExecute
	}
	result, errExecute := exec.ExecuteStream(ctx, auth, req, opts)
	if errExecute != nil {
		return errExecute
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			return chunk.Err
		}
	}
	return nil
}

func TestCodexDeviceFingerprintWebsocketReuseAndModes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			opts.Headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"client","turn_id":"keep","large":9007199254740993}`)
			opts.Headers.Set("X-Codex-Installation-Id", "client-header")
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\",\"session_id\":\"keep\"}"},"prompt_cache_key":"cache"}`
			for i, step := range []struct {
				mode, id, expected string
				connection         int32
			}{{"device", codexDeviceTestA, codexDeviceTestA, 1}, {"device", codexDeviceTestA, codexDeviceTestA, 1}, {"device", codexDeviceTestB, codexDeviceTestB, 2}, {"off", codexDeviceTestB, "client", 3}, {"device", codexDeviceTestB, codexDeviceTestB, 4}} {
				// Replacement executor mirrors config hot reload while retaining the session store.
				nextCfg := *cfg
				nextCfg.Codex.DeviceFingerprintMode = step.mode
				nextExec := NewCodexWebsocketsExecutor(&nextCfg)
				nextExec.store = exec.store
				auth.Metadata["codex_installation_id"] = step.id
				if i >= 2 {
					delta := ojson.NewDocString(body)
					_ = delta.Set("previous_response_id", "r0")
					for _, deltaCtx := range []context.Context{t.Context(), core.WithRequiredUpstreamWebsocket(t.Context())} {
						if errDelta := runCodexDeviceWSTurn(t, nextExec, deltaCtx, auth, opts, delta.String(), stream); !core.IsUpstreamWebsocketReplayRequired(errDelta) {
							t.Fatalf("step %d incompatible incremental request: %v", i, errDelta)
						}
					}
				}
				if errExecute := runCodexDeviceWSTurn(t, nextExec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatalf("step %d: %v", i, errExecute)
				}
				frame := <-frames
				if frame.connection != step.connection || connections.Load() != step.connection {
					t.Fatalf("step %d connection = %d / %d, want %d", i, frame.connection, connections.Load(), step.connection)
				}
				if id := ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String(); id != step.expected {
					t.Fatalf("step %d installation = %q", i, id)
				}
				if step.mode == "device" {
					turn := ojson.Parse(frame.headers.Get("X-Codex-Turn-Metadata"))
					if turn.Get("installation_id").String() != step.expected || turn.Get("turn_id").String() != "keep" || turn.Get("large").Raw != "9007199254740993" || frame.headers.Get("X-Codex-Installation-Id") != "" {
						t.Fatalf("step %d header convergence failed", i)
					}
				}
				if ojson.GetBytes(frame.body, "prompt_cache_key").String() != "cache" {
					t.Fatal("cache identity changed")
				}
			}
			if opts.Headers.Get("X-Codex-Turn-Metadata") != `{"installation_id":"client","turn_id":"keep","large":9007199254740993}` {
				t.Fatal("shared caller headers mutated")
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketPayloadRules(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, action := range []string{"override", "filter-id", "filter-turn", "filter-metadata"} {
			t.Run(fmt.Sprintf("%v/%s", stream, action), func(t *testing.T) {
				server, frames, _ := newCodexDeviceWSServer(t)
				cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				match := []config.PayloadModelRule{{Name: "*", Match: []map[string]any{{"client_metadata.x-codex-installation-id": codexDeviceTestA}}}}
				path := "client_metadata.x-codex-installation-id"
				switch action {
				case "override":
					cfg.Payload.Override = []config.PayloadRule{{Models: match, Params: map[string]any{path: codexDeviceTestB}}}
				case "filter-turn":
					path = "client_metadata.x-codex-turn-metadata"
				case "filter-metadata":
					path = "client_metadata"
				}
				if action != "override" {
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: match, Params: []string{path}}}
				}
				exec := NewCodexWebsocketsExecutor(cfg)
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				before := helps.PayloadConfigEvaluationCount()
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), codexDeviceWSAuth(server.URL), managedInstructionsOptions(t), `{"input":[],"client_metadata":{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\"}"}}`, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				frame := <-frames
				value := ojson.GetBytes(frame.body, path)
				if action == "override" && value.String() != codexDeviceTestB || action != "override" && value.Exists() {
					t.Fatalf("final user rule lost: %s", frame.body)
				}
				if count := helps.PayloadConfigEvaluationCount() - before; count != 1 {
					t.Fatalf("payload evaluated %d times", count)
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintWebsocketFinalOverrideAndContinuation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"client_metadata.x-codex-installation-id": codexDeviceTestA}}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			<-frames
			// An administrator changes only the effective final ID, not the derived policy.
			cfg.Payload.Override[0].Params["client_metadata.x-codex-installation-id"] = codexDeviceTestB
			for _, ctx := range []context.Context{core.WithRequiredUpstreamWebsocket(t.Context()), t.Context()} {
				errExecute := runCodexDeviceWSTurn(t, exec, ctx, auth, opts, `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`, stream)
				if !core.IsUpstreamWebsocketReplayRequired(errExecute) {
					t.Fatalf("incompatible continuation got %v", errExecute)
				}
			}
			if connections.Load() != 1 {
				t.Fatal("continuation was moved to a new connection")
			}
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			frame := <-frames
			if frame.connection != 2 || ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestB {
				t.Fatal("complete request did not reconnect with the final identity")
			}
			cfg.Payload.Override = nil
			cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"client_metadata"}}}
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			if frame := <-frames; frame.connection != 2 || ojson.GetBytes(frame.body, "client_metadata").Exists() {
				t.Fatal("absence should preserve connection identity without restoring metadata")
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketSessionInstructions(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, change := range []string{"identity", "off"} {
			t.Run(fmt.Sprintf("%v/%s", stream, change), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				exec := NewCodexWebsocketsExecutor(cfg)
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				opts := managedInstructionsOptions(t)
				start := `{"input":"root","instructions":"baseline","client_metadata":{"cpa_session_instructions":"start","x-codex-installation-id":"client"}}`
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, start, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				frame := <-frames
				if ojson.GetBytes(frame.body, "client_metadata.cpa_session_instructions").Exists() || ojson.GetBytes(frame.body, "input.0.content.0.text").String() != "baseline" {
					t.Fatal("session instruction preparation regressed")
				}
				if change == "off" {
					auth.Metadata["codex_device_fingerprint"] = "off"
				} else {
					auth.Metadata["codex_installation_id"] = codexDeviceTestB
				}
				errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, `{"type":"response.append","input":"delta","client_metadata":{"x-codex-installation-id":"client","cpa_session_instructions":"reuse"}}`, stream)
				if !core.IsUpstreamWebsocketTurnError(errExecute) && !core.IsUpstreamWebsocketReplayRequired(errExecute) {
					t.Fatalf("changed device continuation should require replay: %v", errExecute)
				}
				if connections.Load() != 1 {
					t.Fatal("instruction delta moved to a new connection")
				}
				select {
				case <-frames:
					t.Fatal("incompatible delta reached upstream")
				default:
				}
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, `{"input":"full replay","client_metadata":{"cpa_session_instructions":"reuse","x-codex-installation-id":"client"}}`, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				frame = <-frames
				if frame.connection != 2 || ojson.GetBytes(frame.body, "input.0.content.0.text").String() != "baseline" {
					t.Fatal("full instruction replay did not reconnect")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintWebsocketDuplex(t *testing.T) {
	for _, action := range []string{"fixed", "override", "filter"} {
		t.Run(action, func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}}
			match := []config.PayloadModelRule{{Name: "*", Match: []map[string]any{{"client_metadata.x-codex-installation-id": codexDeviceTestA}}}}
			if action == "override" {
				cfg.Payload.Override = []config.PayloadRule{{Models: match, Params: map[string]any{"client_metadata.x-codex-installation-id": codexDeviceTestB}}}
			} else if action == "filter" {
				cfg.Payload.Filter = []config.PayloadFilterRule{{Models: match, Params: []string{"client_metadata"}}}
			}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := make(chan core.WebsocketInput, 1)
			ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
			before := helps.PayloadConfigEvaluationCount()
			first := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			result, errExecute := exec.ExecuteStream(ctx, auth, core.Request{Model: "gpt-5.4", Payload: []byte(first)}, opts)
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			turns := []string{first,
				`{"type":"response.append","input":[],"client_metadata":{"x-codex-installation-id":"next"}}`,
				`{"type":"response.steer","previous_response_id":"r1","event_id":"event","input":[],"client_metadata":{"x-codex-installation-id":"steer"},"extra":9007199254740993}`,
				`{"type":"response.create","input":[],"client_metadata":{"x-codex-installation-id":"last"}}`,
			}
			for turn, payload := range turns {
				if turn > 0 {
					input <- core.WebsocketInput{Payload: []byte(payload)}
				}
				terminal := false
				for !terminal {
					chunk, ok := <-result.Chunks
					if !ok || chunk.Err != nil {
						t.Fatalf("turn %d ended: ok=%v err=%v", turn, ok, chunk.Err)
					}
					for _, line := range bytes.Split(chunk.Payload, []byte("\n")) {
						body := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data:")))
						if ojson.GetBytes(body, "type").String() == "error" {
							t.Fatalf("turn %d error: %s", turn, body)
						}
						terminal = terminal || ojson.GetBytes(body, "type").String() == "response.completed"
					}
				}
				frame := <-frames
				if frame.connection != 1 || connections.Load() != 1 {
					t.Fatal("active duplex reconnected")
				}
				want := codexDeviceTestA
				if action == "override" {
					want = codexDeviceTestB
				}
				if action == "filter" {
					if ojson.GetBytes(frame.body, "client_metadata").Exists() {
						t.Fatalf("turn %d filtered metadata restored", turn)
					}
				} else if ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != want {
					t.Fatalf("turn %d identity changed: %s", turn, frame.body)
				}
				if turn == 2 && (ojson.GetBytes(frame.body, "event_id").String() != "event" || ojson.GetBytes(frame.body, "extra").Raw != "9007199254740993") {
					t.Fatal("steering extensions changed")
				}
				if count := helps.PayloadConfigEvaluationCount() - before; count != int64(turn+1) {
					t.Fatalf("payload evaluated %d times at turn %d", count, turn)
				}
				if turn == 0 && action == "fixed" {
					// The retained executor/connection keeps its device snapshot even
					// when a later request would see disabled global configuration.
					cfg.Codex.DeviceFingerprintMode = "off"
				}
			}
			cancel()
			for range result.Chunks {
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketInterruptSnapshot(t *testing.T) {
	for _, mode := range []string{"missing", "metadata", "final-override"} {
		t.Run(mode, func(t *testing.T) {
			withMetadata := mode != "missing"
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
				_, body, errRead := conn.ReadMessage()
				if errRead == nil {
					captured <- body
				}
			}))
			defer server.Close()
			conn, _, errDial := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
			if errDial != nil {
				t.Fatal(errDial)
			}
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			policy := helps.CodexDevicePolicy{Enabled: true, ID: codexDeviceTestA, InjectMissing: true}
			sess := exec.getOrCreateSession(t.Name())
			sess.conn = conn
			sess.connCloser = newWebsocketConnectionCloser(conn)
			sess.authID = "test"
			sess.device = codexWebsocketDeviceSnapshot{policy: policy, identity: policy.Identity(ojson.NewDocString(`{}`), nil)}
			wantID := codexDeviceTestA
			if mode == "final-override" {
				final := ojson.NewDocString(`{}`)
				_ = final.Set("client_metadata.x-codex-installation-id", codexDeviceTestB)
				sess.device.identity = policy.Identity(final, nil)
				wantID = codexDeviceTestB
			}
			readCh := sess.activate(conn)
			defer sess.clearActive(conn, readCh)
			payload := `{"type":"response.interrupt","response_id":"r1","mode":"discard_partial_items","event_id":"event","extension":9007199254740993}`
			if withMetadata {
				doc := ojson.NewDocString(payload)
				_ = doc.SetRaw("client_metadata", `{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\",\"thread_id\":\"keep\"}","unknown":"keep"}`)
				payload = doc.String()
			}
			// New global settings cannot affect a control frame on an established socket.
			cfg.Codex.DeviceFingerprintMode = "off"
			if errInterrupt := exec.InterruptExecutionSession(t.Context(), t.Name(), []byte(payload)); errInterrupt != nil {
				t.Fatal(errInterrupt)
			}
			body := <-captured
			if ojson.GetBytes(body, "response_id").String() != "r1" || ojson.GetBytes(body, "event_id").String() != "event" || ojson.GetBytes(body, "mode").String() != "discard_partial_items" || ojson.GetBytes(body, "extension").Raw != "9007199254740993" {
				t.Fatal("interrupt control fields changed")
			}
			if withMetadata {
				if ojson.GetBytes(body, "client_metadata.x-codex-installation-id").String() != wantID || ojson.GetBytes(body, "client_metadata.unknown").String() != "keep" {
					t.Fatal("interrupt did not use bound snapshot")
				}
				bound, ok := sess.deviceForConn(conn)
				other := ojson.NewDocString(`{}`)
				different := codexDeviceTestB
				if wantID == different {
					different = codexDeviceTestA
				}
				_ = other.Set("client_metadata.x-codex-installation-id", different)
				if !ok || bound.identity.Compatible(policy.Identity(other, nil)) {
					t.Fatal("interrupt did not bind first presented device values to the connection")
				}
			} else if !bytes.Equal(body, []byte(payload)) {
				t.Fatal("control frame injected missing device metadata")
			}
			exec.CloseExecutionSession(t.Name())
			exec.CloseExecutionSession(t.Name())
			sess.connMu.Lock()
			cleared := sess.conn == nil && !sess.device.policy.Enabled && !sess.device.identity.Enabled
			sess.connMu.Unlock()
			if !cleared {
				t.Fatal("closed connection retains device state")
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketDetachState(t *testing.T) {
	for _, detach := range []string{"target", "lifecycle", "invalidate", "close"} {
		t.Run(detach, func(t *testing.T) {
			conn := new(websocket.Conn)
			policy := helps.CodexDevicePolicy{Enabled: true, ID: codexDeviceTestA}
			sess := &codexWebsocketSession{conn: conn, authID: "a", wsURL: "ws://local/responses", device: codexWebsocketDeviceSnapshot{policy: policy, identity: policy.Identity(nil, nil)}}
			exec := NewCodexWebsocketsExecutor(nil)
			switch detach {
			case "target":
				detachMismatchedCodexWebsocketSessionConn(sess, "b", sess.wsURL, "", nil)
			case "lifecycle":
				sess.detachConnection(conn, nil)
			case "invalidate":
				exec.invalidateUpstreamConn(sess, conn, "test", nil)
			case "close":
				closeCodexWebsocketSession(sess, "test")
			}
			if sess.conn != nil || sess.device.policy.Enabled || sess.device.identity.Enabled {
				t.Fatal("detached physical socket retained device snapshot")
			}
		})
	}
}

func TestCodexDeviceFingerprintWebsocketSIWCAndAPIKey(t *testing.T) {
	server, frames, connections := newCodexDeviceWSServer(t)
	inject := true
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	auth.Metadata["use_siwc"] = true
	auth.Metadata["siwc"] = map[string]any{"access_token": "siwc-test", "device_id": codexDeviceTestB}
	opts := managedInstructionsOptions(t)
	opts.Headers["x-codex-turn-metadata"] = []string{`{"installation_id":"client","turn":"a"}`, `invalid`}
	opts.Headers["X-CODEX-TURN-METADATA"] = []string{`{"installation_id":"client","turn":"b"}`}
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	for _, tc := range []struct {
		name, userAgent, expected, token string
	}{
		{"siwc", "custom-client", codexDeviceTestB, "siwc-test"},
		{"native", "codex_cli_rs/0.154.0", codexDeviceTestA, "oauth-token"},
	} {
		opts.Headers.Set("User-Agent", tc.userAgent)
		if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, true); errExecute != nil {
			t.Fatal(errExecute)
		}
		frame := <-frames
		if ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != tc.expected || frame.headers.Get("Authorization") != "Bearer "+tc.token {
			t.Fatalf("%s did not follow actual SIWC routing", tc.name)
		}
		metadata := frame.headers.Values("X-Codex-Turn-Metadata")
		if len(metadata) != 2 {
			t.Fatalf("%s header value count = %d", tc.name, len(metadata))
		}
		for _, value := range metadata {
			if ojson.Get(value, "installation_id").String() != tc.expected {
				t.Fatal("mixed casing/multivalue handshake metadata did not converge")
			}
		}
	}
	if connections.Load() != 2 {
		t.Fatal("SIWC mode change reused an authenticated socket")
	}
	opts.Headers.Set("User-Agent", "custom-client")
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, `{"input":[]}`, true); errExecute != nil {
		t.Fatal(errExecute)
	}
	if frame := <-frames; ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").Exists() {
		t.Fatal("SIWC injected missing installation")
	}
	keyAuth := codexAPIKeyTestAuth(server.URL)
	keyAuth.ID = auth.ID
	keyAuth.Attributes["codex_device_fingerprint"] = "device"
	keyAuth.Attributes["codex_installation_id"] = codexDeviceTestA
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), keyAuth, opts, body, true); errExecute != nil {
		t.Fatal(errExecute)
	}
	if frame := <-frames; ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != "client" {
		t.Fatal("API-key request received OAuth device policy")
	}
}

func TestCodexDeviceFingerprintWebsocketFrozenPreparation(t *testing.T) {
	server, frames, _ := newCodexDeviceWSServer(t)
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	delete(auth.Metadata, "codex_installation_id")
	opts := managedInstructionsOptions(t)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, true); errExecute != nil {
		t.Fatal(errExecute)
	}
	frame := <-frames
	bound := exec.getOrCreateSession(t.Name())
	bound.connMu.Lock()
	policy := bound.device.policy
	bound.connMu.Unlock()
	cfg.Codex.DeviceFingerprintMode = "off"
	refreshed := auth.Clone()
	refreshed.Metadata["access_token"] = "rotated"
	refreshed.Metadata["codex_device_fingerprint"] = "off"
	req := core.Request{Model: "gpt-5.4", Payload: []byte(body)}
	prepared, errPrepare := exec.prepareCodexWebsocketStreamWithDevice(t.Context(), refreshed, req, opts, bound, &policy)
	if errPrepare != nil {
		t.Fatal(errPrepare)
	}
	if ojson.GetBytes(prepared.clientBody, "client_metadata.x-codex-installation-id").String() != ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() {
		t.Fatal("frozen device policy changed across same-account refresh")
	}
	for _, mutate := range []func(*cliproxyauth.Auth){
		func(a *cliproxyauth.Auth) { a.Metadata["account_id"] = "different-account" },
		func(a *cliproxyauth.Auth) { a.Metadata["codex_installation_id"] = codexDeviceTestB },
		func(a *cliproxyauth.Auth) { a.Attributes["api_key"] = "different-kind" },
	} {
		changed := refreshed.Clone()
		mutate(changed)
		_, errPrepare = exec.prepareCodexWebsocketStreamWithDevice(t.Context(), changed, req, opts, bound, &policy)
		if !core.IsUpstreamWebsocketReplayRequired(errPrepare) {
			t.Fatalf("changed account/device was accepted on frozen connection: %v", errPrepare)
		}
	}
}

func TestCodexDeviceFingerprintWebsocketFailedRedialClearsState(t *testing.T) {
	server, frames, _ := newCodexDeviceWSServer(t)
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	opts := managedInstructionsOptions(t)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, true); errExecute != nil {
		t.Fatal(errExecute)
	}
	<-frames
	server.Close()
	auth.Metadata["codex_installation_id"] = codexDeviceTestB
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, true); errExecute == nil {
		t.Fatal("redial to closed listener unexpectedly succeeded")
	}
	sess := exec.getOrCreateSession(t.Name())
	sess.connMu.Lock()
	cleared := sess.conn == nil && !sess.device.policy.Enabled && !sess.device.identity.Enabled
	sess.connMu.Unlock()
	if !cleared {
		t.Fatal("failed redial retained old device snapshot")
	}
}

func TestCodexDeviceFingerprintWebsocketDuplexRejectsFinalIdentityChange(t *testing.T) {
	for _, kind := range []string{"response.create", "response.steer"} {
		t.Run(kind, func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*", Match: []map[string]any{{"event_id": "different-device"}}}}, Params: map[string]any{"client_metadata.x-codex-installation-id": codexDeviceTestB}}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := make(chan core.WebsocketInput, 1)
			ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
			result, errExecute := exec.ExecuteStream(ctx, codexDeviceWSAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}, managedInstructionsOptions(t))
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
				if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
					break
				}
			}
			<-frames
			doc := ojson.NewDocString(`{"input":[],"event_id":"different-device","previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`)
			_ = doc.Set("type", kind)
			input <- core.WebsocketInput{Payload: doc.Bytes()}
			rejected := false
			for chunk := range result.Chunks {
				rejected = rejected || chunk.Err != nil || ojson.GetBytes(chunk.Payload, "type").String() == "error"
			}
			if !rejected || connections.Load() != 1 {
				t.Fatal("incompatible duplex final identity was not rejected")
			}
			select {
			case <-frames:
				t.Fatal("incompatible final body reached physical socket")
			default:
			}
		})
	}
}
