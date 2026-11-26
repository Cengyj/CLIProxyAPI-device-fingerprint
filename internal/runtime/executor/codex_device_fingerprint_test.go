package executor

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

const fingerprintHTTPID = "e1e46a26-def3-4e3e-9ee2-185e59ed0444"
const fingerprintOperatorID = "11111111-2222-4333-8444-555555555555"
const fingerprintHTTPBody = `{"model":"gpt-5.4","input":"hello","prompt_cache_key":"cache-original","client_metadata":{"x-codex-installation-id":"client-device","x-codex-turn-metadata":"{\"installation_id\":\"client-turn-device\",\"session_id\":\"session-original\",\"thread_id\":\"thread-original\",\"window_id\":\"window-original\",\"turn_id\":\"turn-original\",\"big\":900719925474099312345,\"extra\":\"你好\\\\tail\"}","other":"keep"}}`

type fingerprintHTTPCapture struct {
	body    []byte
	headers http.Header
	path    string
}

func fingerprintHTTPServer(t *testing.T, rejectCompression bool) (*httptest.Server, <-chan fingerprintHTTPCapture) {
	t.Helper()
	captured := make(chan fingerprintHTTPCapture, 16)
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
		if compressed && rejectCompression {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if strings.Contains(r.URL.Path, "/images/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"created":1,"data":[{"b64_json":"AA=="}]}`)
		} else if strings.HasSuffix(r.URL.Path, "/compact") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"cmp_device","object":"response.compaction","output":[]}`)
		} else {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"id":"resp_device","object":"response","status":"completed","output":[{"type":"image_generation_call","id":"img_device","status":"completed","result":"AA=="}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`+"\n\n")
		}
	}))
	t.Cleanup(server.Close)
	return server, captured
}

func fingerprintHTTPAuth(base string) *cliproxyauth.Auth {
	auth := codexOAuthTestAuth(base)
	auth.ID = "device-http.json"
	auth.Metadata["account_id"] = "acc-test-1"
	return auth
}

func fingerprintRunHTTP(t *testing.T, ctx context.Context, exec *CodexExecutor, auth *cliproxyauth.Auth, req core.Request, opts core.Options, stream bool) {
	t.Helper()
	if stream {
		result, errStream := exec.ExecuteStream(ctx, auth, req, opts)
		if errStream != nil {
			t.Fatal(errStream)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
		}
	} else if _, errExecute := exec.Execute(ctx, auth, req, opts); errExecute != nil {
		t.Fatal(errExecute)
	}
}

func TestCodexDeviceFingerprintHTTPFinalBarrier(t *testing.T) {
	for _, route := range []string{"execute", "stream", "compact", "image", "image-stream"} {
		for _, rule := range []string{"builtin", "override", "filter-installation", "filter-turn", "filter-metadata"} {
			t.Run(route+"/"+rule, func(t *testing.T) {
				server, captured := fingerprintHTTPServer(t, false)
				inject := true
				cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject}}
				cfg.Payload.Default = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"default_marker": "once"}}}
				cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*", Match: []map[string]any{{"client_metadata.x-codex-installation-id": fingerprintHTTPID}}}}, Params: map[string]any{"audit.-1": "once"}}}
				wantID := fingerprintHTTPID
				if rule == "override" {
					cfg.Payload.Override = append(cfg.Payload.Override, config.PayloadRule{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"client_metadata.x-codex-installation-id": fingerprintOperatorID}})
					wantID = fingerprintOperatorID
				}
				filters := map[string]string{"filter-installation": "client_metadata.x-codex-installation-id", "filter-turn": "client_metadata.x-codex-turn-metadata", "filter-metadata": "client_metadata"}
				if path := filters[rule]; path != "" {
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{path}}}
				}
				auth := fingerprintHTTPAuth(server.URL)
				headers := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"old","turn_id":"header-turn","big":900719925474099312345}`, "broken", `{"other":"unchanged"}`}, "x-codex-turn-metadata": {`{"installation_id":"other-old","window_id":"header-window"}`}, "X-Codex-Installation-Id": {"remove"}, "X-Client-Request-Id": {"request-original"}, "X-Codex-Turn-State": {"state-original"}}
				before := headers.Clone()
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: headers}
				req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
				if route == "compact" {
					opts.Alt = "responses/compact"
				}
				if strings.HasPrefix(route, "image") {
					req = core.Request{Model: "legacy-image", Payload: []byte(`{"model":"legacy-image","prompt":"draw"}`)}
					opts = codexOpenAIImageTestOptions(codexImagesGenerationsPath, route == "image-stream")
					opts.Headers = headers
				}
				evaluations := helps.PayloadConfigEvaluationCount()
				fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), auth, req, opts, route == "stream" || route == "image-stream")
				got := <-captured
				if got.path != "/responses" && got.path != "/responses/compact" {
					t.Fatalf("unexpected route %s", got.path)
				}
				body := ojson.NewDoc(got.body)
				if body.Get("audit").Raw != `["once"]` || body.Get("default_marker").String() != "once" || helps.PayloadConfigEvaluationCount()-evaluations != 1 {
					t.Fatalf("final rules did not observe device stage exactly once: %s", got.body)
				}
				if rule == "filter-installation" || rule == "filter-metadata" {
					if body.Get("client_metadata.x-codex-installation-id").Exists() {
						t.Fatal("filtered installation restored")
					}
				} else if body.Get("client_metadata.x-codex-installation-id").String() != wantID {
					t.Fatalf("wrong final ID: %s", got.body)
				}
				if path := filters[rule]; path != "" && body.Get(path).Exists() {
					t.Fatalf("filter restored %s", path)
				}
				if !strings.HasPrefix(route, "image") {
					if body.Get("prompt_cache_key").String() != "cache-original" {
						t.Fatal("cache identity changed")
					}
					if rule != "filter-metadata" && body.Get("client_metadata.other").String() != "keep" {
						t.Fatal("unknown metadata changed")
					}
					if rule != "filter-metadata" && rule != "filter-turn" {
						turn := ojson.NewDocString(body.Get("client_metadata.x-codex-turn-metadata").String())
						if turn.Get("installation_id").String() != fingerprintHTTPID || turn.Get("big").Raw != "900719925474099312345" || turn.Get("turn_id").String() != "turn-original" || turn.Get("session_id").String() != "session-original" || turn.Get("thread_id").String() != "thread-original" || turn.Get("window_id").String() != "window-original" {
							t.Fatalf("wrong turn metadata: %s", turn.Bytes())
						}
					}
				}
				values := got.headers.Values("X-Codex-Turn-Metadata")
				if len(values) != 3 {
					t.Fatalf("lost valid multi-value headers: %v", values)
				}
				for _, value := range values {
					turn := ojson.NewDocString(value)
					if id := turn.Get("installation_id"); id.Exists() && id.String() != fingerprintHTTPID {
						t.Fatalf("header differs from built-in identity: %s", value)
					}
				}
				if got.headers.Get("X-Codex-Installation-Id") != "" || got.headers.Get("X-Client-Request-Id") != "request-original" || got.headers.Get("X-Codex-Turn-State") != "state-original" {
					t.Fatal("wrong header rewrite scope")
				}
				if !reflect.DeepEqual(before, headers) {
					t.Fatal("mutated caller headers")
				}
			})
		}
	}
}

func TestCodexDeviceFingerprintHTTPCompressionFallback(t *testing.T) {
	for _, mode := range []string{"execute", "stream", "compact"} {
		t.Run(mode, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, true)
			destination, errURL := url.Parse(server.URL)
			if errURL != nil {
				t.Fatal(errURL)
			}
			transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				mapped := req.Clone(req.Context())
				mapped.URL.Scheme, mapped.URL.Host = destination.Scheme, destination.Host
				mapped.Host = destination.Host
				return http.DefaultTransport.RoundTrip(mapped)
			})
			ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", transport)
			cfg := codexCompressionConfig()
			cfg.Codex.DeviceFingerprintMode = "device"
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once", "client_metadata.x-codex-installation-id": fingerprintOperatorID}}}
			doc := ojson.NewDocString(fingerprintHTTPBody)
			_ = doc.Set("input", strings.Repeat("compressible ", 1000))
			auth := fingerprintHTTPAuth("https://chatgpt.com/backend-api/codex")
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"old"}`}}}
			if mode == "compact" {
				opts.Alt = "responses/compact"
			}
			before := helps.PayloadConfigEvaluationCount()
			fingerprintRunHTTP(t, ctx, NewCodexExecutor(cfg), auth, core.Request{Model: "gpt-5.4", Payload: doc.Bytes()}, opts, mode == "stream")
			first, second := <-captured, <-captured
			if first.headers.Get("Content-Encoding") != "zstd" || second.headers.Get("Content-Encoding") != "" || !bytes.Equal(first.body, second.body) {
				t.Fatal("compression fallback changed final payload")
			}
			if ojson.GetBytes(second.body, "audit").Raw != `["once"]` || helps.PayloadConfigEvaluationCount()-before != 1 || ojson.GetBytes(second.body, "client_metadata.x-codex-installation-id").String() != fingerprintOperatorID {
				t.Fatal("fallback reran/overrode final configuration")
			}
			if first.headers.Get("X-Codex-Turn-Metadata") != second.headers.Get("X-Codex-Turn-Metadata") {
				t.Fatal("fallback changed device headers")
			}
		})
	}
}

func TestCodexDeviceFingerprintHTTPScopeAndCloaking(t *testing.T) {
	for _, mode := range []string{"off", "api-key-global", "api-key-attribute", "api-key-metadata", "device", "device-uncloaked", "auth-off", "auth-device", "siwc", "siwc-codex-client"} {
		t.Run(mode, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			auth := fingerprintHTTPAuth(server.URL)
			ctx := t.Context()
			want := fingerprintHTTPID
			switch mode {
			case "off":
				cfg.Codex.DeviceFingerprintMode = "off"
				want = "client-device"
			case "api-key-global", "api-key-attribute", "api-key-metadata":
				auth.Attributes["api_key"] = "fake-api-key"
				want = "client-device"
				if mode == "api-key-attribute" {
					auth.Attributes["codex_device_fingerprint"] = "device"
				}
				if mode == "api-key-metadata" {
					auth.Metadata["codex_device_fingerprint"] = "device"
				}
			case "device-uncloaked":
				cfg.Codex.DisableCodexCloaking = true
			case "auth-off":
				auth.Metadata["codex_device_fingerprint"] = "off"
				want = "client-device"
			case "auth-device":
				cfg.Codex.DeviceFingerprintMode = "off"
				auth.Metadata["codex_device_fingerprint"] = "device"
			case "siwc", "siwc-codex-client":
				auth.Metadata["use_siwc"] = true
				auth.Metadata["siwc"] = map[string]any{"access_token": "synthetic-siwc", "device_id": fingerprintOperatorID}
				if mode == "siwc" {
					want = fingerprintOperatorID
				} else {
					ctx = cliproxyauth.WithCodexClientRequest(ctx, true)
				}
			}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client-device"}`}}}
			fingerprintRunHTTP(t, ctx, NewCodexExecutor(cfg), auth, core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}, opts, false)
			got := <-captured
			if ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != want {
				t.Fatalf("wrong scope: %s", got.body)
			}
			if value := got.headers.Get("X-Codex-Turn-Metadata"); value != "" && ojson.Get(value, "installation_id").String() != want {
				t.Fatalf("body/header snapshot diverged: %s", value)
			}
		})
	}
}

func TestCodexDeviceFingerprintHTTPNonResponsesAndHeaders(t *testing.T) {
	for _, path := range []string{"/images/generations", "/images/edits", "/alpha/search", "/live", "/responses-extra"} {
		t.Run(path, func(t *testing.T) {
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			exec := NewCodexExecutor(cfg)
			auth := fingerprintHTTPAuth("http://example.invalid")
			raw := []byte(fingerprintHTTPBody)
			request, body, err := exec.cacheHelper(t.Context(), sdktranslator.FormatOpenAIResponse, "http://example.invalid"+path, core.Request{}, raw, auth)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if errClose := request.Body.Close(); errClose != nil {
					t.Error(errClose)
				}
			}()
			request.Header["x-codex-installation-id"] = []string{"standalone"}
			headers := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"original"}`}}
			applyCodexHeaders(request, auth, "test", false, cfg, headers)
			if !bytes.Equal(raw, body) || request.Header["x-codex-installation-id"][0] != "standalone" || ojson.Get(request.Header.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "original" {
				t.Fatal("device behavior leaked outside Responses")
			}
		})
	}
	t.Run("custom-headers-win", func(t *testing.T) {
		server, captured := fingerprintHTTPServer(t, false)
		cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
		auth := fingerprintHTTPAuth(server.URL)
		auth.Attributes["header:X-Codex-Installation-Id"] = fingerprintOperatorID
		auth.Attributes["header:X-Codex-Turn-Metadata"] = `{"installation_id":"operator-header"}`
		fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), auth, core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
		got := <-captured
		if got.headers.Get("X-Codex-Installation-Id") != fingerprintOperatorID || ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "operator-header" || ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != fingerprintHTTPID {
			t.Fatal("custom headers lost final priority")
		}
	})
	t.Run("plugin-request-bypass", func(t *testing.T) {
		server, captured := fingerprintHTTPServer(t, false)
		exec := NewCodexExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/responses", strings.NewReader(fingerprintHTTPBody))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Codex-Installation-Id", "plugin-original")
		response, err := exec.HttpRequest(t.Context(), fingerprintHTTPAuth(server.URL), request)
		if err != nil {
			t.Fatal(err)
		}
		if errClose := response.Body.Close(); errClose != nil {
			t.Fatal(errClose)
		}
		got := <-captured
		if string(got.body) != fingerprintHTTPBody || got.headers.Get("X-Codex-Installation-Id") != "plugin-original" {
			t.Fatal("plugin HttpRequest unexpectedly converged")
		}
	})
}

func TestCodexDeviceFingerprintHTTPDuplicateMetadataRejected(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	for _, body := range []string{
		`{"input":"hello","client_metadata":{"x-codex-installation-id":"first"},"client_metadata":{"x-codex-installation-id":"second"}}`,
		`{"input":"hello","instructions":"A","client_metadata":{"cpa_session_instructions":"start","x-codex-installation-id":"first"},"client_metadata":{"x-codex-installation-id":"second"}}`,
	} {
		_, err := NewCodexExecutor(cfg).Execute(t.Context(), fingerprintHTTPAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(body)}, managedInstructionsOptions(t))
		if err == nil {
			t.Fatal("ambiguous client_metadata was sent")
		}
	}
	select {
	case <-captured:
		t.Fatal("ambiguous request reached upstream")
	default:
	}
}

func TestCodexDeviceFingerprintHTTPAttemptSnapshot(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	exec := NewCodexExecutor(cfg)
	auth := fingerprintHTTPAuth("http://example.invalid")
	headers := http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}
	first, bodyA, err := exec.cacheHelper(t.Context(), sdktranslator.FormatOpenAIResponse, "http://example.invalid/responses", core.Request{Payload: []byte(fingerprintHTTPBody)}, []byte(fingerprintHTTPBody), auth, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := first.Body.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	auth.Metadata["account_id"] = "acc-test-2"
	applyCodexHeaders(first, auth, "test", false, cfg, headers)
	if ojson.GetBytes(bodyA, "client_metadata.x-codex-installation-id").String() != fingerprintHTTPID || ojson.Get(first.Header.Get("X-Codex-Turn-Metadata"), "installation_id").String() != fingerprintHTTPID {
		t.Fatal("headers reread changed auth")
	}
	second, bodyB, err := exec.cacheHelper(first.Context(), sdktranslator.FormatOpenAIResponse, "http://example.invalid/responses", core.Request{Payload: []byte(fingerprintHTTPBody)}, []byte(fingerprintHTTPBody), auth, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := second.Body.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	applyCodexHeaders(second, auth, "test", false, cfg, headers)
	if ojson.GetBytes(bodyB, "client_metadata.x-codex-installation-id").String() != "3216ba40-955f-42a6-aabf-a9ac6ae94a30" || second.Header.Get("X-Codex-Turn-Metadata") == first.Header.Get("X-Codex-Turn-Metadata") {
		t.Fatal("new auth inherited old attempt policy")
	}
}

func TestCodexDeviceFingerprintHTTPManagerReselection(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			captured := make(chan fingerprintHTTPCapture, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, errRead := io.ReadAll(r.Body)
				if errRead != nil {
					t.Error(errRead)
					return
				}
				captured <- fingerprintHTTPCapture{body, r.Header.Clone(), r.URL.Path}
				if len(captured) == 1 {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":{"message":"synthetic credential failure"}}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+codexCompletedEventBody+"\n\n")
			}))
			defer server.Close()
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once"}}}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.SetConfig(cfg)
			manager.SetRetryConfig(1, 0, 2)
			manager.RegisterExecutor(NewCodexExecutor(cfg))
			for i, account := range []string{"acc-test-1", "acc-test-2"} {
				auth := fingerprintHTTPAuth(server.URL)
				auth.ID = t.Name() + "/" + account
				auth.Status = cliproxyauth.StatusActive
				auth.Metadata["account_id"] = account
				auth.Metadata["access_token"] = []string{"token-a", "token-b"}[i]
				if _, errRegister := manager.Register(t.Context(), auth); errRegister != nil {
					t.Fatal(errRegister)
				}
				registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5.4", Type: "codex", Object: "model", OwnedBy: "openai"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			}
			req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
			if stream {
				result, errStream := manager.ExecuteStream(t.Context(), []string{"codex"}, req, opts)
				if errStream != nil {
					t.Fatal(errStream)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else if _, errExecute := manager.Execute(t.Context(), []string{"codex"}, req, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			first, second := <-captured, <-captured
			if first.headers.Get("Authorization") == second.headers.Get("Authorization") {
				t.Fatal("credential was not reselected")
			}
			for _, got := range []fingerprintHTTPCapture{first, second} {
				want := fingerprintHTTPID
				if got.headers.Get("Authorization") == "Bearer token-b" {
					want = "3216ba40-955f-42a6-aabf-a9ac6ae94a30"
				}
				if ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != want || ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != want || ojson.GetBytes(got.body, "audit").Raw != `["once"]` {
					t.Fatal("attempt reused another auth identity or configured body")
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintHTTPModelHeaderOverrides(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	const model = "codex-device-header-test"
	client := t.Name()
	registry.GetGlobalRegistry().RegisterClient(client, "codex", []*registry.ModelInfo{{ID: model, Type: "codex", Config: &registry.ModelConfig{OverrideHeader: map[string]string{"X-Codex-Installation-Id": "model-final", "X-Codex-Turn-Metadata": `{"installation_id":"model-final"}`}}}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(client) })
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	auth := fingerprintHTTPAuth(server.URL)
	auth.Attributes["header:X-Codex-Turn-Metadata"] = `{"installation_id":"auth-override"}`
	fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), auth, core.Request{Model: model, Payload: []byte(fingerprintHTTPBody)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
	got := <-captured
	if got.headers.Get("X-Codex-Installation-Id") != "model-final" || ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "model-final" {
		t.Fatal("model headers did not retain final priority")
	}
}

func TestCodexDeviceFingerprintHTTPDirectImagesAndLocalCount(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	auth := fingerprintHTTPAuth(server.URL)
	exec := NewCodexExecutor(cfg)
	opts := codexOpenAIImageTestOptions(codexImagesGenerationsPath, false)
	opts.Headers = make(http.Header)
	opts.Headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"direct-original"}`)
	req := core.Request{Model: "gpt-image-2", Payload: []byte(`{"model":"gpt-image-2","prompt":"draw","client_metadata":{"x-codex-installation-id":"direct-original"}}`)}
	fingerprintRunHTTP(t, t.Context(), exec, auth, req, opts, false)
	got := <-captured
	if got.path != "/images/generations" || ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != "direct-original" || ojson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "direct-original" {
		t.Fatal("direct image scope leaked")
	}
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Error("CountTokens attempted network request")
		return nil, io.ErrUnexpectedEOF
	}))
	if _, errCount := exec.CountTokens(ctx, auth, core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}); errCount != nil {
		t.Fatal(errCount)
	}
}

func TestCodexDeviceFingerprintHTTPWebsocketFallback(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					w.WriteHeader(http.StatusUpgradeRequired)
					return
				}
				server.Config.Handler.ServeHTTP(w, r)
			}))
			defer fallback.Close()
			cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"audit.-1": "once", "client_metadata.x-codex-installation-id": fingerprintOperatorID}}}
			exec := NewCodexWebsocketsExecutor(cfg)
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			err := runCodexDeviceWSTurn(t, exec, t.Context(), fingerprintHTTPAuth(fallback.URL), opts, fingerprintHTTPBody, stream)
			if err != nil {
				t.Fatal(err)
			}
			got := <-captured
			if ojson.GetBytes(got.body, "audit").Raw != `["once"]` || ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != fingerprintOperatorID {
				t.Fatal("HTTP fallback reused already configured WS payload")
			}
		})
	}
}

func TestCodexDeviceFingerprintHTTPMultipartResponsesImage(t *testing.T) {
	server, captured := fingerprintHTTPServer(t, false)
	inject := true
	cfg := &config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device", DeviceFingerprintInjectMissing: &inject}}
	cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*", Match: []map[string]any{{"client_metadata.x-codex-installation-id": fingerprintHTTPID}}}}, Params: map[string]any{"audit.-1": "once"}}}
	var raw bytes.Buffer
	writer := multipart.NewWriter(&raw)
	if errField := writer.WriteField("prompt", "draw"); errField != nil {
		t.Fatal(errField)
	}
	if errField := writer.WriteField("model", "legacy-image"); errField != nil {
		t.Fatal(errField)
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	opts := codexOpenAIImageTestOptions(codexImagesEditsPath, false)
	opts.Headers = http.Header{"Content-Type": {writer.FormDataContentType()}}
	fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), fingerprintHTTPAuth(server.URL), core.Request{Model: "legacy-image", Payload: raw.Bytes()}, opts, false)
	got := <-captured
	if got.path != "/responses" || ojson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != fingerprintHTTPID || ojson.GetBytes(got.body, "audit").Raw != `["once"]` {
		t.Fatal("multipart-to-Responses skipped final device stage")
	}
}
