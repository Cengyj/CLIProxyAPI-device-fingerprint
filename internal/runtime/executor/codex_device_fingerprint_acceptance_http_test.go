package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintAutoTransportIdentityHints(t *testing.T) {
	for _, firstWS := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP-to-WS", true: "WS-to-HTTP"}[firstWS], func(t *testing.T) {
			captures := make(chan []byte, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websocket.IsWebSocketUpgrade(r) {
					conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = conn.Close() }()
					for {
						_, raw, errRead := conn.ReadMessage()
						if errRead != nil {
							return
						}
						captures <- raw
						if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(codexCompletedEventBody)); errWrite != nil {
							return
						}
					}
				}
				raw, errRead := io.ReadAll(r.Body)
				if errRead != nil {
					t.Error(errRead)
					return
				}
				captures <- raw
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+codexCompletedEventBody+"\n\n")
			}))
			defer server.Close()
			exec := NewCodexAutoExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.wsExec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := fingerprintHTTPAuth(server.URL)
			auth.Attributes["websockets"] = "true"
			auth.Metadata["account_id"] = "acc-team-1"
			auth.Metadata["chatgpt_user_id"] = "user-aaa"
			auth.Metadata["plan_type"] = "team"
			opts := managedInstructionsOptions(t)
			req := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`)}
			for step, ws := range []bool{firstWS, !firstWS, firstWS} {
				selected := auth.Clone()
				if step > 0 {
					delete(selected.Metadata, "plan_type")
					delete(selected.Metadata, "chatgpt_user_id")
				}
				ctx := context.Context(t.Context())
				if ws {
					ctx = core.WithDownstreamWebsocket(ctx)
				}
				if _, err := exec.Execute(ctx, selected, req, opts); err != nil {
					t.Fatal(err)
				}
				raw := <-captures
				if got := ojson.GetBytes(raw, "client_metadata.x-codex-installation-id").String(); got != "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
					t.Fatalf("step %d transport ws=%v lost same-account hints: %s", step, ws, got)
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintTranslatedHTTPFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		format sdktranslator.Format
		body   string
	}{
		{"responses", sdktranslator.FormatOpenAIResponse, `{"model":"gpt-5.4","input":[{"role":"user","content":"hello"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`},
		{"chat", sdktranslator.FormatOpenAI, `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`},
		{"claude", sdktranslator.FormatClaude, `{"model":"gpt-5.4","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}]}`},
		{"gemini", sdktranslator.FormatGemini, `{"model":"gpt-5.4","contents":[{"role":"user","parts":[{"text":"hello"}]}],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{"type":"object"}}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				server, captured := fingerprintHTTPServer(t, false)
				var baseline *ojson.Doc
				for _, mode := range []string{"off", "device-no-inject", "device-inject"} {
					inject := mode == "device-inject"
					cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject}}
					if mode == "off" {
						cfg.Codex.DeviceFingerprintMode = "off"
					}
					opts := core.Options{SourceFormat: tc.format, ResponseFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","session_id":"same","big":900719925474099312345}`}, "Session-Id": {"same-session"}}}
					fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), fingerprintHTTPAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(tc.body)}, opts, stream)
					got := <-captured
					doc := ojson.NewDoc(got.body)
					if mode == "off" {
						baseline = doc
						continue
					}
					id := doc.Get("client_metadata.x-codex-installation-id")
					if inject && id.String() != fingerprintHTTPID {
						t.Fatal("translated injection absent")
					}
					if !inject && id.Exists() {
						t.Fatal("missing translated metadata was injected by default")
					}
					turn := ojson.Parse(got.headers.Get("X-Codex-Turn-Metadata"))
					if turn.Get("installation_id").String() != fingerprintHTTPID || turn.Get("session_id").String() != "same" || turn.Get("big").Raw != "900719925474099312345" {
						t.Fatal("translated header fields changed incorrectly")
					}
					for _, field := range []string{"input", "tools", "instructions", "model", "parallel_tool_calls", "prompt_cache_key"} {
						if doc.Get(field).Raw != baseline.Get(field).Raw {
							t.Fatalf("device changed translated %s", field)
						}
					}
					if !doc.Get("input").IsArray() || !doc.Get("tools").IsArray() {
						t.Fatal("test did not exercise translated message/tools")
					}
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintCompressionMultivalueHeaders(t *testing.T) {
	for _, rejection := range []int{http.StatusBadRequest, http.StatusUnsupportedMediaType} {
		for _, mode := range []string{"execute", "stream", "compact"} {
			t.Run(http.StatusText(rejection)+"/"+mode, func(t *testing.T) {
				captured := make(chan fingerprintHTTPCapture, 2)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, errRead := io.ReadAll(r.Body)
					if errRead != nil {
						t.Error(errRead)
						return
					}
					compressed := r.Header.Get("Content-Encoding") == "zstd"
					if compressed {
						decoder, errDecoder := zstd.NewReader(nil)
						if errDecoder != nil {
							t.Error(errDecoder)
							return
						}
						body, errRead = decoder.DecodeAll(body, nil)
						decoder.Close()
						if errRead != nil {
							t.Error(errRead)
							return
						}
					}
					captured <- fingerprintHTTPCapture{body, r.Header.Clone(), r.URL.Path}
					if compressed {
						w.WriteHeader(rejection)
						return
					}
					if strings.HasSuffix(r.URL.Path, "/compact") {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"id":"cmp_device","object":"response.compaction","output":[]}`)
					} else {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "data: "+codexCompletedEventBody+"\n\n")
					}
				}))
				defer server.Close()
				destination, errURL := url.Parse(server.URL)
				if errURL != nil {
					t.Fatal(errURL)
				}
				transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					mapped := req.Clone(req.Context())
					mapped.URL.Scheme, mapped.URL.Host, mapped.Host = destination.Scheme, destination.Host, destination.Host
					return http.DefaultTransport.RoundTrip(mapped)
				})
				ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", transport)
				cfg := codexCompressionConfig()
				cfg.Codex.DeviceFingerprintMode = "device"
				cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once"}}}
				headers := http.Header{
					"X-Codex-Turn-Metadata": {`{"installation_id":"old","order":1}`, `null`, `{"installation_id":"old","order":2}`},
					"x-codex-turn-metadata": {`{"installation_id":"old","order":3}`, `{"order":4,"big":900719925474099312345}`},
				}
				beforeHeaders := headers.Clone()
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: headers}
				if mode == "compact" {
					opts.Alt = "responses/compact"
				}
				doc := ojson.NewDocString(fingerprintHTTPBody)
				_ = doc.Set("input", strings.Repeat("compressible ", 1000))
				beforeRules := helps.PayloadConfigEvaluationCount()
				fingerprintRunHTTP(t, ctx, NewCodexExecutor(cfg), fingerprintHTTPAuth("https://chatgpt.com/backend-api/codex"), core.Request{Model: "gpt-5.4", Payload: doc.Bytes()}, opts, mode == "stream")
				first, second := <-captured, <-captured
				if first.headers.Get("Content-Encoding") != "zstd" || second.headers.Get("Content-Encoding") != "" || !bytes.Equal(first.body, second.body) || helps.PayloadConfigEvaluationCount()-beforeRules != 1 {
					t.Fatal("fallback changed final body, compression or rule count")
				}
				if !reflect.DeepEqual(first.headers.Values("X-Codex-Turn-Metadata"), second.headers.Values("X-Codex-Turn-Metadata")) {
					t.Fatal("compression fallback reordered caller metadata values")
				}
				values := second.headers.Values("X-Codex-Turn-Metadata")
				if len(values) != 4 {
					t.Fatalf("kept %d values, want four valid objects", len(values))
				}
				for index, value := range values {
					turn := ojson.Parse(value)
					if turn.Get("order").Int() != int64(index+1) {
						t.Fatal("case variants were not merged in stable key order")
					}
					if index < 3 && turn.Get("installation_id").String() != fingerprintHTTPID {
						t.Fatal("header ID did not converge")
					}
					if index == 3 && (turn.Get("installation_id").Exists() || turn.Get("big").Raw != "900719925474099312345") {
						t.Fatal("non-device metadata changed")
					}
				}
				if !reflect.DeepEqual(beforeHeaders, headers) {
					t.Fatal("caller headers mutated")
				}
			})
		}
	}
}

type fingerprintAcceptanceHook struct {
	cliproxyauth.NoopHook
	results chan cliproxyauth.Result
}

func (h *fingerprintAcceptanceHook) OnResult(_ context.Context, result cliproxyauth.Result) {
	h.results <- result
}

func TestCodexDeviceFingerprintInvalidInputManagerIsolation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			var upstreamCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			hook := &fingerprintAcceptanceHook{results: make(chan cliproxyauth.Result, 8)}
			manager := cliproxyauth.NewManager(nil, nil, hook)
			manager.SetConfig(cfg)
			manager.SetRetryConfig(2, 0, 2)
			manager.RegisterExecutor(NewCodexExecutor(cfg))
			var authIDs []string
			for _, account := range []string{"acc-test-1", "acc-test-2"} {
				auth := fingerprintHTTPAuth(server.URL)
				auth.ID = t.Name() + "/" + account
				auth.Status = cliproxyauth.StatusActive
				auth.Metadata["account_id"] = account
				if _, err := manager.Register(t.Context(), auth); err != nil {
					t.Fatal(err)
				}
				authIDs = append(authIDs, auth.ID)
				registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5.4", Type: "codex", Object: "model", OwnedBy: "openai"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			}
			req := core.Request{Model: "gpt-5.4", Payload: []byte(`{"input":[],"client_metadata":{"x-codex-installation-id":"first"},"client_\u006detadata":{"x-codex-installation-id":"second"}}`)}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			var errRun error
			if stream {
				_, errRun = manager.ExecuteStream(t.Context(), []string{"codex"}, req, opts)
			} else {
				_, errRun = manager.Execute(t.Context(), []string{"codex"}, req, opts)
			}
			var status interface{ StatusCode() int }
			var scoped interface{ IsRequestScoped() bool }
			if !errors.As(errRun, &status) || status.StatusCode() != http.StatusBadRequest || !errors.As(errRun, &scoped) || !scoped.IsRequestScoped() {
				t.Fatalf("wrong request-level failure: %v", errRun)
			}
			if upstreamCalls.Load() != 0 {
				t.Fatal("ambiguous input reached upstream")
			}
			if len(hook.results) != 1 {
				t.Fatalf("recorded %d attempts; invalid input must not retry another account", len(hook.results))
			}
			result := <-hook.results
			if result.Success || result.CompletedResponse || result.Error == nil || !result.Error.IsRequestScoped() {
				t.Fatal("invalid input recorded as generation/account failure")
			}
			for _, id := range authIDs {
				auth, ok := manager.GetByID(id)
				if !ok || auth.Unavailable || !auth.NextRetryAfter.IsZero() || auth.Quota.Exceeded {
					t.Fatal("invalid input cooled or exhausted an account")
				}
				for _, state := range auth.ModelStates {
					if state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded) {
						t.Fatal("invalid input cooled a model")
					}
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintExcludedInheritedContext(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	exec := NewCodexExecutor(cfg)
	server, captured := fingerprintHTTPServer(t, false)
	auth := fingerprintHTTPAuth(server.URL)
	policy := exec.deviceResolver.Resolve(cfg, auth, false, server.URL+"/responses")
	ctx := helps.WithCodexDevicePolicy(t.Context(), policy)
	for _, path := range []string{"/images/generations", "/alpha/search", "/live", "/responses-extra"} {
		req, body, err := exec.cacheHelper(ctx, sdktranslator.FormatOpenAIResponse, server.URL+path, core.Request{}, []byte(fingerprintHTTPBody), auth)
		if err != nil {
			t.Fatal(err)
		}
		applyCodexHeaders(req, auth, "synthetic", false, cfg, http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"original"}`}})
		if string(body) != fingerprintHTTPBody || ojson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "original" {
			t.Fatal("inherited snapshot escaped route scope")
		}
		_ = req.Body.Close()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/responses", strings.NewReader(fingerprintHTTPBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Codex-Installation-Id", "plugin-original")
	response, err := exec.HttpRequest(ctx, auth, req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	got := <-captured
	if string(got.body) != fingerprintHTTPBody || got.headers.Get("X-Codex-Installation-Id") != "plugin-original" {
		t.Fatal("plugin request inherited device convergence")
	}
}

func TestCodexDeviceFingerprintHTTPJSONWireEdges(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			exec := NewCodexExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			// Escaped duplicate target names must not leave a second client ID on
			// the wire. Unknown duplicate keys and exact integers remain intact.
			body := `{"input":[],"prompt_cache_key":"keep-cache","client_metadata":{"x-codex-installation-id":"first","x-codex-installation-\u0069d":"second","x-codex-turn-metadata":"{\"installation_id\":\"old-a\",\"installation_\\u0069d\":\"old-b\",\"turn_id\":\"keep-turn\",\"big\":900719925474099312345,\"text\":\"雪 \\\\ \\\" 🚀\",\"unknown\":1,\"unknown\":2}","thread_id":"keep-thread","unknown":1,"unknown":2}}`
			fingerprintRunHTTP(t, t.Context(), exec, fingerprintHTTPAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(body)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, stream)
			got := <-captured
			metadata := ojson.GetBytes(got.body, "client_metadata")
			counts := map[string]int{}
			metadata.ForEach(func(key, value ojson.Result) bool { counts[key.String()]++; return true })
			if counts["x-codex-installation-id"] != 1 || counts["unknown"] != 2 || metadata.Get("x-codex-installation-id").String() != fingerprintHTTPID {
				t.Fatal("outer target duplicates escaped convergence or unknown duplicates changed")
			}
			turn := ojson.Parse(metadata.Get("x-codex-turn-metadata").String())
			counts = map[string]int{}
			turn.ForEach(func(key, value ojson.Result) bool { counts[key.String()]++; return true })
			originalTurn := ojson.Parse(ojson.Get(body, "client_metadata.x-codex-turn-metadata").String())
			if counts["installation_id"] != 1 || counts["unknown"] != 2 || turn.Get("installation_id").String() != fingerprintHTTPID || turn.Get("big").Raw != "900719925474099312345" || turn.Get("text").String() != originalTurn.Get("text").String() || turn.Get("turn_id").String() != "keep-turn" || metadata.Get("thread_id").String() != "keep-thread" || ojson.GetBytes(got.body, "prompt_cache_key").String() != "keep-cache" {
				t.Fatal("inner target convergence changed non-device values")
			}
			for _, raw := range []string{`{"input":[],"client_metadata":null}`, `{"input":[],"client_metadata":[]}`, `{"input":[],"client_metadata":17}`, `{"input":[],"client_metadata":{"x-codex-turn-metadata":null}}`, `{"input":[],"client_metadata":{"x-codex-turn-metadata":[]}}`, `{"input":[],"client_metadata":{"x-codex-turn-metadata":"[]"}}`, `{"input":[],"client_metadata":{"x-codex-turn-metadata":"bad"}}`, `{"input":[],"client_metadata":{"x-codex-turn-metadata":"{\"turn_id\":\"keep\"}"}}`} {
				fingerprintRunHTTP(t, t.Context(), exec, fingerprintHTTPAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(raw)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, stream)
				wire := <-captured
				before := ojson.Get(raw, "client_metadata")
				after := ojson.GetBytes(wire.body, "client_metadata")
				if !before.IsObject() {
					if before.Raw != after.Raw {
						t.Fatal("invalid metadata shape was remodeled")
					}
					continue
				}
				value := before.Get("x-codex-turn-metadata")
				if value.Type == ojson.String && ojson.Parse(value.String()).IsObject() {
					if after.Get("x-codex-turn-metadata").String() != value.String() {
						t.Fatal("missing nested ID was injected")
					}
				} else if after.Get("x-codex-turn-metadata").Exists() {
					t.Fatal("invalid turn-metadata reached upstream")
				}
			}
		})
	}
}
