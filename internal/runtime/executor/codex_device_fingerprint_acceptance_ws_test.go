package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexDeviceFingerprintAcceptanceWebsocketHeaderTransitions(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			defer exec.CloseExecutionSession(t.Name() + "-fresh")
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			opts.Headers["X-Codex-Turn-Metadata"] = []string{`{"installation_id":"client-a","turn":"first"}`, `broken`, `{"extension":9007199254740993}`}
			opts.Headers["x-codex-turn-metadata"] = []string{`{"installation_id":"client-b","thread":"other"}`}
			opts.Headers["X-CODEX-INSTALLATION-ID"] = []string{"remove-first", "remove-second"}
			originalHeaders := opts.Headers.Clone()
			model := "codex-device-acceptance-headers"
			registry.GetGlobalRegistry().RegisterClient(t.Name(), "codex", []*registry.ModelInfo{{ID: model, Type: "codex"}})
			defer registry.GetGlobalRegistry().UnregisterClient(t.Name())
			run := func() codexDeviceWSFrame {
				t.Helper()
				req := core.Request{Model: model, Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
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
				frame := <-frames
				if ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
					t.Fatal("handshake configuration rewrote the final body identity")
				}
				return frame
			}
			first := run()
			if first.headers.Get("X-Codex-Installation-Id") != "" || len(first.headers.Values("X-Codex-Turn-Metadata")) != 3 || !reflect.DeepEqual(opts.Headers, originalHeaders) {
				t.Fatal("mixed-case multivalue client headers were changed or incorrectly forwarded")
			}
			for _, value := range first.headers.Values("X-Codex-Turn-Metadata") {
				id := ojson.Get(value, "installation_id")
				if id.Exists() && id.String() != codexDeviceTestA {
					t.Fatal("client turn header did not converge")
				}
			}
			auth.Attributes["header:x-codex-installation-id"] = codexDeviceTestB
			auth.Attributes["header:x-codex-turn-metadata"] = `{"installation_id":"` + codexDeviceTestB + `","turn":"admin"}`
			second := run()
			if connections.Load() != 2 || second.headers.Get("X-Codex-Installation-Id") != codexDeviceTestB || len(second.headers.Values("X-Codex-Turn-Metadata")) != 1 || ojson.Get(second.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != codexDeviceTestB {
				t.Fatal("attribute header change did not establish its actual new handshake")
			}
			const modelID = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
			registry.GetGlobalRegistry().RegisterClient(t.Name(), "codex", []*registry.ModelInfo{{ID: model, Type: "codex", Config: &registry.ModelConfig{OverrideHeader: map[string]string{"X-Codex-Installation-Id": modelID, "X-Codex-Turn-Metadata": `{"installation_id":"` + modelID + `","turn":"model"}`}}}})
			third := run()
			if connections.Load() != 3 || third.headers.Get("X-Codex-Installation-Id") != modelID || ojson.Get(third.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != modelID {
				t.Fatal("model header did not take final priority and force compatible physical handshake")
			}
			delete(auth.Attributes, "header:x-codex-installation-id")
			delete(auth.Attributes, "header:x-codex-turn-metadata")
			registry.GetGlobalRegistry().RegisterClient(t.Name(), "codex", []*registry.ModelInfo{{ID: model, Type: "codex"}})
			opts.Headers = http.Header{"Session-Id": {t.Name()}}
			fourth := run()
			if connections.Load() != 3 || fourth.headers.Get("X-Codex-Installation-Id") != modelID {
				t.Fatal("omitted candidate header must preserve the existing physical handshake")
			}
			// Removing a header cannot unsend it on an existing socket. A new
			// execution session demonstrates its absence on the next handshake.
			opts.Metadata = map[string]any{core.ExecutionSessionMetadataKey: t.Name() + "-fresh"}
			fresh := run()
			if connections.Load() != 4 || fresh.headers.Get("X-Codex-Installation-Id") != "" || len(fresh.headers.Values("X-Codex-Turn-Metadata")) != 0 {
				t.Fatal("removed administrator headers persisted into a fresh handshake")
			}
		})
	}
}

func TestCodexDeviceFingerprintAcceptanceWebsocketCompetingDial(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(fmt.Sprint(same), func(t *testing.T) {
			arrived := make(chan string, 2)
			releaseA, releaseB := make(chan struct{}), make(chan struct{})
			var releaseOnceA, releaseOnceB sync.Once
			frames := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name := r.Header.Get("X-Test-Dial")
				arrived <- name
				if name == "a" {
					<-releaseA
				} else {
					<-releaseB
				}
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
				if _, _, errRead := conn.ReadMessage(); errRead == nil {
					frames <- r.Header.Clone()
					_, _, _ = conn.ReadMessage()
				}
			}))
			defer server.Close()
			defer releaseOnceA.Do(func() { close(releaseA) })
			defer releaseOnceB.Do(func() { close(releaseB) })
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			sess := exec.getOrCreateSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/responses"
			policyA := exec.deviceResolver.Resolve(exec.cfg, auth, false, wsURL)
			policyB := policyA
			if !same {
				policyB.ID = codexDeviceTestB
			}
			type dialResult struct {
				conn *websocket.Conn
				err  error
			}
			resultA, resultB := make(chan dialResult, 1), make(chan dialResult, 1)
			dial := func(name string, policy helps.CodexDevicePolicy, result chan<- dialResult) {
				headers := http.Header{"X-Test-Dial": {name}, "X-Codex-Turn-Metadata": {`{"installation_id":"` + policy.ID + `"}`}}
				device := codexWebsocketDeviceSnapshot{policy: policy, identity: policy.Identity(nil, headers)}
				conn, _, _, errDial := exec.ensureUpstreamConnWithSIWC(t.Context(), auth, sess, auth.ID, wsURL, headers, false, device)
				result <- dialResult{conn, errDial}
			}
			go dial("a", policyA, resultA)
			go dial("b", policyB, resultB)
			<-arrived
			<-arrived
			releaseOnceA.Do(func() { close(releaseA) })
			a := <-resultA
			if a.err != nil || a.conn == nil {
				t.Fatalf("first dial: %v", a.err)
			}
			releaseOnceB.Do(func() { close(releaseB) })
			b := <-resultB
			if same {
				if b.err != nil || b.conn != a.conn {
					t.Fatal("compatible competing dial did not retain the installed connection")
				}
			} else if !core.IsUpstreamWebsocketReplayRequired(b.err) || b.conn != nil {
				t.Fatal("incompatible competing dial replaced the installed device")
			}
			bound, ok := sess.deviceForConn(a.conn)
			if !ok || bound.policy.ID != codexDeviceTestA {
				t.Fatal("losing dial changed the retained connection snapshot")
			}
			if errWrite := writeCodexWebsocketMessage(sess, a.conn, []byte(`{"type":"response.create","input":[]}`)); errWrite != nil {
				t.Fatal(errWrite)
			}
			if header := <-frames; header.Get("X-Test-Dial") != "a" || ojson.Get(header.Get("X-Codex-Turn-Metadata"), "installation_id").String() != codexDeviceTestA {
				t.Fatal("business frame used the losing handshake")
			}
		})
	}
}

func TestCodexDeviceFingerprintAcceptanceWebsocketOldLifecycleCallback(t *testing.T) {
	server, frames, connections := newCodexDeviceWSServer(t)
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	auth := codexDeviceWSAuth(server.URL)
	opts := managedInstructionsOptions(t)
	oldLifecycle := &trackedWebsocketLifecycle{}
	opts.ExecutionLifecycle = oldLifecycle
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, false); errExecute != nil {
		t.Fatal(errExecute)
	}
	<-frames
	oldLifecycle.mu.Lock()
	oldClose := oldLifecycle.close
	oldLifecycle.mu.Unlock()
	newLifecycle := &trackedWebsocketLifecycle{}
	opts.ExecutionLifecycle = newLifecycle
	changed := auth.Clone()
	changed.Metadata["codex_installation_id"] = codexDeviceTestB
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, false); errExecute != nil {
		t.Fatal(errExecute)
	}
	<-frames
	if oldLifecycle.ends.Load() != 1 {
		t.Fatal("replaced lifecycle was not ended once")
	}
	sess := exec.getOrCreateSession(t.Name())
	sess.connMu.Lock()
	newConn := sess.conn
	sess.connMu.Unlock()
	for range 2 {
		if errClose := oldClose(); errClose != nil {
			t.Fatal(errClose)
		}
	}
	bound, ok := sess.deviceForConn(newConn)
	if !ok || bound.policy.ID != codexDeviceTestB || newLifecycle.ends.Load() != 0 {
		t.Fatal("old lifecycle callback detached the replacement device")
	}
	if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), changed, opts, body, false); errExecute != nil {
		t.Fatal(errExecute)
	}
	frame := <-frames
	if connections.Load() != 2 || frame.connection != 2 {
		t.Fatal("replacement socket was closed by its predecessor callback")
	}
	exec.CloseExecutionSession(t.Name())
	exec.CloseExecutionSession(t.Name())
	if oldLifecycle.ends.Load() != 1 || newLifecycle.ends.Load() != 1 {
		t.Fatal("lifecycle End did not retain once semantics")
	}
	sess.connMu.Lock()
	cleared := sess.conn == nil && !sess.device.policy.Enabled
	sess.connMu.Unlock()
	if !cleared {
		t.Fatal("final close retained device state")
	}
}

func TestCodexDeviceFingerprintAcceptanceDuplexLocalSummary(t *testing.T) {
	for _, scenario := range []string{"mode-off", "inject", "explicit-changed", "siwc", "siwc-missing"} {
		t.Run(scenario, func(t *testing.T) {
			type wireRequest struct {
				websocket bool
				headers   http.Header
				body      []byte
			}
			captured := make(chan wireRequest, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !websocket.IsWebSocketUpgrade(r) {
					body, errRead := io.ReadAll(r.Body)
					if errRead != nil {
						t.Error(errRead)
						return
					}
					captured <- wireRequest{headers: r.Header.Clone(), body: body}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"summary\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"DEVICE_SUMMARY\"}]}]}}\n\n")
					return
				}
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
				for turn := 0; ; turn++ {
					_, body, errRead := conn.ReadMessage()
					if errRead != nil {
						return
					}
					captured <- wireRequest{true, r.Header.Clone(), bytes.Clone(body)}
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
			defer server.Close()
			inject := false
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject, ResponseSteering: true}, SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once"}}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.Metadata["use_siwc"] = true
			auth.Metadata["siwc"] = map[string]any{"access_token": "siwc-test", "device_id": codexDeviceTestB}
			opts := managedInstructionsOptions(t)
			opts.Headers.Set("User-Agent", "codex_cli_rs/0.154.0")
			opts.Headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"client","turn":"first"}`)
			opts.RequestAfterAuthInterceptor = func(_ context.Context, request core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
				if ojson.GetBytes(request.Body, "event_id").String() != "compact" {
					return core.RequestAfterAuthInterceptResponse{}
				}
				switch scenario {
				case "mode-off":
					cfg.Codex.DeviceFingerprintMode = "off"
				case "inject":
					inject = true
				case "explicit-changed":
					auth.Metadata["codex_installation_id"] = codexDeviceTestB
				case "siwc", "siwc-missing":
					inject = true
					return core.RequestAfterAuthInterceptResponse{Headers: http.Header{"User-Agent": {"custom-client"}}}
				}
				return core.RequestAfterAuthInterceptResponse{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := make(chan core.WebsocketInput, 1)
			ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
			req := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[{"role":"user","content":"start"}],"client_metadata":{"x-codex-installation-id":"client"}}`), Metadata: map[string]any{"cliproxy.resolved_codex_oauth_model_info": &registry.ModelInfo{ID: "gpt-5.4", IsCompat: true}}}
			before := helps.PayloadConfigEvaluationCount()
			result, errExecute := exec.ExecuteStream(ctx, auth, req, opts)
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			defer func() {
				cancel()
				for range result.Chunks {
				}
			}()
			readCompleted := func() string {
				t.Helper()
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
					for _, line := range bytes.Split(chunk.Payload, []byte("\n")) {
						payload := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data:")))
						if ojson.GetBytes(payload, "type").String() == "error" {
							t.Fatalf("unexpected event: %s", payload)
						}
						if ojson.GetBytes(payload, "type").String() == "response.completed" {
							return ojson.GetBytes(payload, "response.id").String()
						}
					}
				}
				t.Fatal("stream ended before completion")
				return ""
			}
			readCompleted()
			first := <-captured
			if !first.websocket || ojson.GetBytes(first.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("initial physical socket did not use ordinary OAuth device")
			}
			compact := ojson.NewDocString(`{"type":"response.create","event_id":"compact","input":[{"role":"user","content":"history"},{"type":"compaction_trigger"}]}`)
			if scenario != "inject" && scenario != "siwc-missing" {
				_ = compact.Set("client_metadata.x-codex-installation-id", "client-summary")
			}
			input <- core.WebsocketInput{Payload: compact.Bytes()}
			parent := readCompleted()
			summary := <-captured
			if summary.websocket || ojson.GetBytes(summary.body, "audit").Raw != `["once"]` || helps.PayloadConfigEvaluationCount()-before != 2 {
				t.Fatal("local summary did not use one independent HTTP attempt")
			}
			wantBody, wantHeader, wantToken := codexDeviceTestA, codexDeviceTestA, "oauth-token"
			switch scenario {
			case "mode-off":
				wantBody, wantHeader = "client-summary", "client"
			case "explicit-changed":
				wantBody, wantHeader = codexDeviceTestB, codexDeviceTestB
			case "siwc":
				wantBody, wantHeader, wantToken = codexDeviceTestB, codexDeviceTestB, "siwc-test"
			case "siwc-missing":
				wantBody, wantHeader, wantToken = "", codexDeviceTestB, "siwc-test"
			}
			if ojson.GetBytes(summary.body, "client_metadata.x-codex-installation-id").String() != wantBody || ojson.Get(summary.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != wantHeader || summary.headers.Get("Authorization") != "Bearer "+wantToken {
				t.Fatalf("summary policy boundary: body=%s header=%s", summary.body, summary.headers.Get("X-Codex-Turn-Metadata"))
			}
			appendDoc := ojson.NewDocString(`{"type":"response.append","input":"continue"}`)
			_ = appendDoc.Set("previous_response_id", parent)
			if scenario != "inject" {
				_ = appendDoc.Set("client_metadata.x-codex-installation-id", "append-client")
			}
			input <- core.WebsocketInput{Payload: appendDoc.Bytes()}
			if scenario == "explicit-changed" {
				replay := false
				for chunk := range result.Chunks {
					replay = replay || core.IsUpstreamWebsocketReplayRequired(chunk.Err)
				}
				if !replay || len(captured) != 0 {
					t.Fatal("new explicit identity was allowed back onto the frozen physical socket")
				}
				return
			}
			readCompleted()
			appendFrame := <-captured
			wantAppend := codexDeviceTestA
			if scenario == "inject" {
				wantAppend = ""
			}
			if !appendFrame.websocket || ojson.GetBytes(appendFrame.body, "client_metadata.x-codex-installation-id").String() != wantAppend || ojson.GetBytes(appendFrame.body, "previous_response_id").Exists() || !bytes.Contains(appendFrame.body, []byte("DEVICE_SUMMARY")) || bytes.Contains(appendFrame.body, []byte("cpa-ag-compact-v1:")) || ojson.GetBytes(appendFrame.body, "audit").Raw != `["once"]` || helps.PayloadConfigEvaluationCount()-before != 3 {
				t.Fatalf("synthetic parent append did not retain physical device/finalizer semantics: %s", appendFrame.body)
			}
		})
	}
}

func TestCodexDeviceFingerprintAcceptanceDuplexControlSequence(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			captured := make(chan []byte, 5)
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
				turn := 0
				write := func(kind, id string) bool {
					doc := ojson.NewDocString(`{"response":{"status":"completed","output":[]}}`)
					_ = doc.Set("type", kind)
					_ = doc.Set("response.id", id)
					return conn.WriteMessage(websocket.TextMessage, doc.Bytes()) == nil
				}
				for {
					_, body, errRead := conn.ReadMessage()
					if errRead != nil {
						return
					}
					captured <- bytes.Clone(body)
					switch ojson.GetBytes(body, "type").String() {
					case "response.steer":
						turn = 3
						if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.steer.accepted","steer":{"id":"steer1","previous_response_id":"r1"}}`)); errWrite != nil || !write("response.created", "r2") {
							return
						}
					case "response.interrupt":
						if !write("response.completed", "r2") {
							return
						}
					default:
						id := fmt.Sprintf("r%d", turn)
						turn++
						if !write("response.created", id) || !write("response.completed", id) {
							return
						}
					}
				}
			}))
			defer server.Close()
			inject := true
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject, ResponseSteering: true}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once"}}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			opts := managedInstructionsOptions(t)
			opts.RequestAfterAuthInterceptor = func(_ context.Context, request core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
				if ojson.GetBytes(request.Body, "type").String() == "response.steer" {
					cfg.Codex.DeviceFingerprintMode = "off"
					inject = false
				}
				return core.RequestAfterAuthInterceptResponse{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := make(chan core.WebsocketInput, 1)
			ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
			before := helps.PayloadConfigEvaluationCount()
			result, errExecute := exec.ExecuteStream(ctx, codexDeviceWSAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[]}`)}, opts)
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			defer func() {
				cancel()
				for range result.Chunks {
				}
			}()
			readEvent := func(kind, id string) {
				t.Helper()
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
					if ojson.GetBytes(chunk.Payload, "type").String() == kind && ojson.GetBytes(chunk.Payload, "response.id").String() == id {
						return
					}
				}
				t.Fatal("control sequence ended before expected event")
			}
			readEvent("response.completed", "r0")
			first := <-captured
			if ojson.GetBytes(first, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("initial create did not inject bound identity")
			}
			input <- core.WebsocketInput{Payload: []byte(`{"type":"response.append","input":[]}`)}
			readEvent("response.completed", "r1")
			appendFrame := <-captured
			if ojson.GetBytes(appendFrame, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("append lost frozen injection policy")
			}
			steer := ojson.NewDocString(`{"type":"response.steer","previous_response_id":"r1","event_id":"steer-event","input":[],"extension":9007199254740993}`)
			interrupt := ojson.NewDocString(`{"type":"response.interrupt","response_id":"r2","mode":"discard_partial_items","event_id":"interrupt-event","extension":9007199254740993}`)
			if existing {
				for _, doc := range []*ojson.Doc{steer, interrupt} {
					_ = doc.Set("client_metadata.x-codex-installation-id", "client-control")
					_ = doc.Set("client_metadata.x-codex-turn-metadata", `{"installation_id":"client-control","thread_id":"keep"}`)
				}
			}
			input <- core.WebsocketInput{Payload: steer.Bytes()}
			readEvent("response.created", "r2")
			steerFrame := <-captured
			if errInterrupt := exec.InterruptExecutionSession(t.Context(), t.Name(), interrupt.Bytes()); errInterrupt != nil {
				t.Fatal(errInterrupt)
			}
			readEvent("response.completed", "r2")
			interruptFrame := <-captured
			for _, frame := range [][]byte{steerFrame, interruptFrame} {
				if existing {
					if ojson.GetBytes(frame, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA || ojson.Get(ojson.GetBytes(frame, "client_metadata.x-codex-turn-metadata").String(), "installation_id").String() != codexDeviceTestA || ojson.Get(ojson.GetBytes(frame, "client_metadata.x-codex-turn-metadata").String(), "thread_id").String() != "keep" {
						t.Fatal("active control did not use physical device snapshot")
					}
				} else if ojson.GetBytes(frame, "client_metadata").Exists() {
					t.Fatal("control injected missing device metadata")
				}
				if ojson.GetBytes(frame, "extension").Raw != "9007199254740993" {
					t.Fatal("control extension changed")
				}
			}
			if ojson.GetBytes(interruptFrame, "response_id").String() != "r2" || ojson.GetBytes(interruptFrame, "mode").String() != "discard_partial_items" || ojson.GetBytes(interruptFrame, "event_id").String() != "interrupt-event" || ojson.GetBytes(interruptFrame, "audit").Exists() || helps.PayloadConfigEvaluationCount()-before != 3 {
				t.Fatal("interrupt inherited business payload rules or changed control fields")
			}
			input <- core.WebsocketInput{Payload: []byte(`{"type":"response.create","input":[]}`)}
			readEvent("response.completed", "r3")
			final := <-captured
			if ojson.GetBytes(final, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA || ojson.GetBytes(final, "audit").Raw != `["once"]` || helps.PayloadConfigEvaluationCount()-before != 4 {
				t.Fatal("later create did not preserve physical mode/injection snapshot")
			}
		})
	}
}

func TestCodexDeviceFingerprintAcceptanceWebsocketBindFailureCleanup(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			opts := managedInstructionsOptions(t)
			opts.ExecutionLifecycle = rejectingExecutionLifecycle{}
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute == nil {
				t.Fatal("lifecycle rejection unexpectedly succeeded")
			}
			sess := exec.getOrCreateSession(t.Name())
			sess.connMu.Lock()
			cleared := sess.conn == nil && !sess.device.policy.Enabled && !sess.device.identity.Enabled
			sess.connMu.Unlock()
			if !cleared || len(frames) != 0 {
				t.Fatal("failed lifecycle binding sent a frame or retained device state")
			}
			opts.ExecutionLifecycle = nil
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), auth, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			frame := <-frames
			if connections.Load() != 2 || ojson.GetBytes(frame.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Fatal("fresh request reused failed connection state")
			}
		})
	}
}

func TestCodexDeviceFingerprintAcceptanceWebsocketConcurrentInterruptClose(t *testing.T) {
	captured := make(chan []byte, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(captured)
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
		for {
			_, body, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			captured <- bytes.Clone(body)
		}
	}))
	defer server.Close()
	exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(t.Name())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = core.WithDownstreamWebsocket(ctx)
	result, errExecute := exec.ExecuteStream(ctx, codexDeviceWSAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}, managedInstructionsOptions(t))
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		if ojson.GetBytes(chunk.Payload, "type").String() == "response.created" {
			break
		}
	}
	sess := exec.getOrCreateSession(t.Name())
	payload := []byte(`{"type":"response.interrupt","response_id":"active","mode":"discard_partial_items","event_id":"control","extension":9007199254740993,"client_metadata":{"x-codex-installation-id":"client"}}`)
	if errInterrupt := exec.InterruptExecutionSession(t.Context(), t.Name(), payload); errInterrupt != nil {
		t.Fatal(errInterrupt)
	}
	first := <-captured
	if ojson.GetBytes(first, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
		t.Fatal("active connection did not supply interrupt device snapshot")
	}
	start := make(chan struct{})
	var done sync.WaitGroup
	for range 8 {
		done.Go(func() {
			<-start
			_ = exec.InterruptExecutionSession(t.Context(), t.Name(), payload)
		})
	}
	done.Go(func() {
		<-start
		exec.CloseExecutionSession(t.Name())
	})
	close(start)
	done.Wait()
	for range result.Chunks {
	}
	for frame := range captured {
		if ojson.GetBytes(frame, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA || ojson.GetBytes(frame, "response_id").String() != "active" || ojson.GetBytes(frame, "extension").Raw != "9007199254740993" {
			t.Fatal("concurrent controls changed device or non-target fields")
		}
	}
	sess.connMu.Lock()
	cleared := sess.conn == nil && !sess.device.policy.Enabled && !sess.device.identity.Enabled
	sess.connMu.Unlock()
	if !cleared {
		t.Fatal("concurrent close left an enabled device snapshot")
	}
}
