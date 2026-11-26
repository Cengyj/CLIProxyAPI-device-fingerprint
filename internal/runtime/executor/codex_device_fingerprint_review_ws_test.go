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
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintWebsocketSubjectChangeWithSharedExplicitID(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, filtered := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/filtered=%t", stream, filtered), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
				if filtered {
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"client_metadata"}}}
				}
				exec := NewCodexWebsocketsExecutor(cfg)
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				auth.Metadata["account_id"] = "account-a"
				opts := managedInstructionsOptions(t)
				body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				first := <-frames
				if first.headers.Get("ChatGPT-Account-ID") != "account-a" {
					t.Fatal("test did not establish original OAuth account")
				}
				changed := auth.Clone()
				changed.Metadata["account_id"] = "account-b"
				for _, ctx := range []context.Context{t.Context(), core.WithRequiredUpstreamWebsocket(t.Context())} {
					errExecute := runCodexDeviceWSTurn(t, exec, ctx, changed, opts, `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`, stream)
					if !core.IsUpstreamWebsocketReplayRequired(errExecute) {
						t.Fatalf("new subject reused old authenticated continuation: %v", errExecute)
					}
				}
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				second := <-frames
				if connections.Load() != 2 || second.headers.Get("ChatGPT-Account-ID") != "account-b" {
					t.Fatal("complete request retained previous subject's physical handshake")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintWebsocketInterruptWriteFailureClearsSnapshot(t *testing.T) {
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
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()
	conn, _, errDial := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	exec := NewCodexWebsocketsExecutor(nil)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	policy := helps.CodexDevicePolicy{Enabled: true, ID: codexDeviceTestA}
	sess := exec.getOrCreateSession(t.Name())
	sess.conn = conn
	sess.connCloser = newWebsocketConnectionCloser(conn)
	sess.authID = "closed-control-test"
	sess.device = codexWebsocketDeviceSnapshot{policy: policy, identity: policy.Identity(ojson.NewDocString(`{}`), nil)}
	readCh := sess.activate(conn)
	defer sess.clearActive(conn, readCh)
	if errClose := conn.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	payload := []byte(`{"type":"response.interrupt","response_id":"r1","client_metadata":{"x-codex-installation-id":"client"}}`)
	if errInterrupt := exec.InterruptExecutionSession(t.Context(), t.Name(), payload); errInterrupt == nil {
		t.Fatal("closed control socket accepted a write")
	}
	sess.connMu.Lock()
	cleared := sess.conn == nil && !sess.device.policy.Enabled && !sess.device.identity.Enabled
	sess.connMu.Unlock()
	if !cleared {
		t.Fatal("failed interrupt retained its never-successful device binding")
	}
}

func TestCodexDeviceFingerprintWebsocketDuplexUsesPhysicalPolicy(t *testing.T) {
	server, frames, connections := newCodexDeviceWSServer(t)
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}}
	cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"client_metadata.x-codex-installation-id": codexDeviceTestA}}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	opts := managedInstructionsOptions(t)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, true); errExecute != nil {
		t.Fatal(errExecute)
	}
	<-frames
	// A later complete request still sends final A, even if its built-in policy
	// resolves B. Starting duplex on that reused socket must keep socket policy A.
	changed := auth.Clone()
	changed.Metadata["codex_installation_id"] = codexDeviceTestB
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := make(chan core.WebsocketInput, 1)
	ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
	result, errExecute := exec.ExecuteStream(ctx, changed, core.Request{Model: "gpt-5.4", Payload: []byte(body)}, opts)
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
	<-frames
	if connections.Load() != 1 {
		t.Fatal("same final configured identity should retain physical socket")
	}
	sess := exec.getOrCreateSession(t.Name())
	sess.connMu.Lock()
	physicalPolicy := sess.device.policy
	sess.connMu.Unlock()
	if physicalPolicy.ID != codexDeviceTestA {
		t.Fatal("physical policy unexpectedly changed")
	}
	input <- core.WebsocketInput{Payload: []byte(`{"type":"response.append","input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
	rejected := false
	for chunk := range result.Chunks {
		rejected = rejected || chunk.Err != nil || ojson.GetBytes(chunk.Payload, "type").String() == "error"
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
			t.Fatal("duplex silently froze a new policy instead of the physical connection's policy")
		}
	}
	if !rejected {
		t.Fatal("changed built-in identity should require a new duplex socket")
	}
}

func TestCodexDeviceFingerprintWebsocketNewHandshakeIdentity(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, header := range []string{"X-Codex-Installation-Id", "X-Codex-Turn-Metadata"} {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, header), func(t *testing.T) {
				server, frames, connections := newCodexDeviceWSServer(t)
				exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer exec.CloseExecutionSession(t.Name())
				auth := codexDeviceWSAuth(server.URL)
				opts := managedInstructionsOptions(t)
				body := `{"input":[]}`
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				first := <-frames
				if first.headers.Get(header) != "" {
					t.Fatal("initial header unexpectedly present")
				}
				changed := auth.Clone()
				value := codexDeviceTestB
				if header == "X-Codex-Turn-Metadata" {
					metadata := ojson.NewDocString(`{"turn_id":"keep"}`)
					_ = metadata.Set("installation_id", codexDeviceTestB)
					value = metadata.String()
				}
				changed.Attributes["header:"+header] = value
				for _, required := range []bool{false, true} {
					ctx := t.Context()
					delta := `{"input":[],"previous_response_id":"r0"}`
					if required {
						ctx = core.WithRequiredUpstreamWebsocket(ctx)
						delta = body
					}
					if errExecute := runCodexDeviceWSTurn(t, exec, ctx, changed, opts, delta, stream); !core.IsUpstreamWebsocketReplayRequired(errExecute) {
						t.Fatalf("new handshake identity reused continuation: %v", errExecute)
					}
				}
				if len(frames) != 0 || connections.Load() != 1 {
					t.Fatal("incompatible continuation was sent or redialed")
				}
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				second := <-frames
				if connections.Load() != 2 || second.headers.Get(header) != value {
					t.Fatal("new explicit handshake identity was not sent but connection recorded it")
				}
				// Omission has no new identity requirement. The established handshake
				// remains observable on the same socket rather than being erased.
				if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
					t.Fatal(errExecute)
				}
				third := <-frames
				if connections.Load() != 2 || third.headers.Get(header) != value {
					t.Fatal("omitted candidate header changed the established handshake")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintWebsocketDuplexRejectsUnsentHandshake(t *testing.T) {
	server, frames, connections := newCodexDeviceWSServer(t)
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	opts := managedInstructionsOptions(t)
	opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		return core.RequestAfterAuthInterceptResponse{Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"next"}`}}}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := make(chan core.WebsocketInput, 1)
	ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	result, errExecute := exec.ExecuteStream(ctx, auth, core.Request{Model: "gpt-5.4", Payload: []byte(body)}, opts)
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
	if first.headers.Get("X-Codex-Turn-Metadata") != "" {
		t.Fatal("initial handshake unexpectedly has a device header")
	}
	// The interceptor introduces the same ID in a new handshake location.
	// A duplex cannot re-handshake, even though the body identity matches.
	input <- core.WebsocketInput{Payload: []byte(`{"type":"response.append","input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
	rejected := false
	for chunk := range result.Chunks {
		rejected = rejected || core.IsUpstreamWebsocketReplayRequired(chunk.Err)
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
			t.Fatal("duplex accepted a handshake header that was never sent")
		}
	}
	if !rejected || len(frames) != 0 || connections.Load() != 1 {
		t.Fatal("duplex did not reject the unsent handshake identity before sending")
	}
}

func TestCodexDeviceFingerprintWebsocketDisabledTransportLoss(t *testing.T) {
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
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()
	conn, _, errDial := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	if errClose := conn.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	// The reader can detach an off-mode socket between selection and send.
	// Device bookkeeping must let the original write/read path classify loss.
	sess := &codexWebsocketSession{}
	disabled := codexWebsocketDeviceSnapshot{}
	if !sess.bindDevice(conn, disabled) {
		t.Fatal("disabled device binding converted transport loss into replay-required")
	}
	errWrite := writeCodexWebsocketMessage(sess, conn, []byte(`{"type":"response.create","input":[]}`))
	if errWrite == nil || !core.IsUpstreamWebsocketTurnError(codexWebsocketTurnTransportError(errWrite)) {
		t.Fatalf("closed socket did not retain transport-loss classification: %v", errWrite)
	}
	if sess.device != disabled {
		t.Fatal("disabled binding populated device state")
	}
	policy := helps.CodexDevicePolicy{Enabled: true, ID: codexDeviceTestA}
	enabled := codexWebsocketDeviceSnapshot{policy: policy, identity: policy.Identity(nil, nil)}
	if sess.bindDevice(conn, enabled) {
		t.Fatal("enabled device binding accepted a detached socket")
	}
	sess.conn = conn
	sess.device = enabled
	if sess.bindDevice(conn, disabled) {
		t.Fatal("enabled-to-disabled transition bypassed connection compatibility")
	}
}

func TestCodexDeviceFingerprintWebsocketDisabledSteerDetachParity(t *testing.T) {
	server, frames, _ := newCodexDeviceWSServer(t)
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{ResponseSteering: true}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	sess := exec.getOrCreateSession(t.Name())
	opts := managedInstructionsOptions(t)
	var detachedCloser *websocketConnectionCloser
	defer func() {
		if errClose := detachedCloser.Close(); errClose != nil {
			t.Log(errClose)
		}
	}()
	opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		sess.connMu.Lock()
		conn := sess.conn
		sess.connMu.Unlock()
		// Pause a detach before its close. Disabled mode retains the original
		// transport path; the device module must not manufacture a replay error.
		detachedCloser = sess.detachConnection(conn, nil)
		return core.RequestAfterAuthInterceptResponse{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := make(chan core.WebsocketInput, 1)
	ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
	result, errExecute := exec.ExecuteStream(ctx, codexDeviceWSAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[]}`)}, opts)
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
	<-frames
	input <- core.WebsocketInput{Payload: []byte(`{"type":"response.steer","previous_response_id":"r0","input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
	completed := false
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("disabled device handling changed the baseline steer transport path: %v", chunk.Err)
		}
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
			completed = true
			break
		}
	}
	if !completed {
		t.Fatal("disabled steer did not complete through existing transport")
	}
	frame := <-frames
	if ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != "client" {
		t.Fatal("disabled device metadata changed")
	}
}
