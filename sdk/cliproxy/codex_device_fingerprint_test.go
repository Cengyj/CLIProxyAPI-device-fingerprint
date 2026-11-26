package cliproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	serviceDeviceID        = "11111111-2222-4333-8444-555555555555"
	serviceDeviceIDChanged = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	serviceDeviceModel     = "gpt-6-luna"
)

type serviceDeviceCapture struct {
	connection int32
	headers    http.Header
	body       []byte
}

type serviceDeviceAuthHook struct {
	coreauth.NoopHook
	updates chan *coreauth.Auth
}

func (h *serviceDeviceAuthHook) OnAuthRegistered(_ context.Context, auth *coreauth.Auth) {
	h.updates <- auth
}

func (h *serviceDeviceAuthHook) OnAuthUpdated(_ context.Context, auth *coreauth.Auth) {
	h.updates <- auth
}

type serviceDeviceHarness struct {
	t                                            *testing.T
	service                                      *Service
	watcher                                      *WatcherWrapper
	configPath, authPath, sessionID, upstreamURL string
	authID                                       string
	revision                                     int
	updates                                      <-chan *coreauth.Auth
	captures                                     <-chan serviceDeviceCapture
	connections                                  atomic.Int32
}

// This harness uses the real watcher configuration reload, file synthesis,
// asynchronous Service auth consumer, Manager selection and Codex executors.
// Only the upstream route is attached after synthesis to keep all traffic local.
func newServiceDeviceHarness(t *testing.T, legacy bool, mode string) *serviceDeviceHarness {
	t.Helper()
	h := &serviceDeviceHarness{t: t, sessionID: t.Name()}
	captures := make(chan serviceDeviceCapture, 64)
	h.captures = captures
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if websocket.IsWebSocketUpgrade(r) {
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
			connection := h.connections.Add(1)
			for turn := 0; ; turn++ {
				_, body, errRead := conn.ReadMessage()
				if errRead != nil {
					return
				}
				captures <- serviceDeviceCapture{connection: connection, headers: r.Header.Clone(), body: body}
				for _, event := range []string{"response.created", "response.completed"} {
					doc := ojson.NewDocString(`{"response":{"status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
					if errSet := doc.Set("type", event); errSet != nil {
						t.Error(errSet)
						return
					}
					if errSet := doc.Set("response.id", fmt.Sprintf("service-response-%d", turn)); errSet != nil {
						t.Error(errSet)
						return
					}
					if errWrite := conn.WriteMessage(websocket.TextMessage, doc.Bytes()); errWrite != nil {
						return
					}
				}
			}
		}
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Error(errRead)
			return
		}
		captures <- serviceDeviceCapture{headers: r.Header.Clone(), body: body}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"service-http-response\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
	}))
	t.Cleanup(upstream.Close)
	h.upstreamURL = upstream.URL
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	if errMkdir := os.MkdirAll(authDir, 0o700); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	h.configPath = filepath.Join(dir, "config.yaml")
	h.authPath = filepath.Join(authDir, "device.json")
	raw := fmt.Sprintf("port: 8317\nauth-dir: %q\nrequest-retry: 0\n", filepath.ToSlash(authDir))
	if legacy {
		raw += fmt.Sprintf("codex: {device-fingerprint-mode: %q, response-steering: true}\n", mode)
	} else {
		raw += fmt.Sprintf("oauth: {providers: {codex: {device-fingerprint-mode: %q, response-steering: true}}}\n", mode)
	}
	if errWrite := os.WriteFile(h.configPath, []byte(raw), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cfg, errLoad := internalconfig.LoadConfig(h.configPath)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	hook := &serviceDeviceAuthHook{updates: make(chan *coreauth.Auth, 64)}
	h.updates = hook.updates
	manager := coreauth.NewManager(nil, nil, hook)
	manager.SetConfig(cfg)
	h.service = &Service{cfg: cfg, configPath: h.configPath, coreManager: manager, pluginHost: pluginhost.New()}
	level := log.GetLevel()
	t.Cleanup(func() {
		log.SetLevel(level)
		sdkAuth.RegisterPluginAuthParser(nil)
		sdktranslator.SetPluginHooks(nil)
	})
	wrapped, errWatcher := defaultWatcherFactory(h.configPath, authDir, h.service.applyWatcherConfigUpdate)
	if errWatcher != nil {
		t.Fatal(errWatcher)
	}
	h.watcher = wrapped
	h.service.setWatcher(wrapped)
	wrapped.SetConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	h.service.ensureAuthUpdateQueue(ctx)
	wrapped.SetAuthUpdateQueue(h.service.authUpdates)
	t.Cleanup(func() {
		cancel()
		manager.CloseExecutionSession(h.sessionID)
		if errStop := wrapped.Stop(); errStop != nil {
			t.Error(errStop)
		}
		GlobalModelRegistry().UnregisterClient(h.authID)
	})
	return h
}

func (h *serviceDeviceHarness) loadAuth(doc *ojson.Doc) {
	h.t.Helper()
	h.revision++
	revision := strconv.Itoa(h.revision)
	if errSet := doc.Set("acceptance_revision", revision); errSet != nil {
		h.t.Fatal(errSet)
	}
	if errWrite := os.WriteFile(h.authPath, doc.Bytes(), 0o600); errWrite != nil {
		h.t.Fatal(errWrite)
	}
	auths, errSnapshot := h.watcher.SnapshotAuthFile(h.authPath)
	if errSnapshot != nil || len(auths) != 1 {
		h.t.Fatalf("SnapshotAuthFile count=%d error=%v", len(auths), errSnapshot)
	}
	auth := auths[0]
	auth.Attributes["base_url"] = h.upstreamURL
	h.authID = auth.ID
	if !h.watcher.DispatchRuntimeAuthUpdate(watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: auth.ID, Auth: auth}) {
		h.t.Fatal("watcher did not dispatch synthesized auth")
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case updated := <-h.updates:
			if updated.ID != h.authID || updated.Metadata["acceptance_revision"] != revision {
				continue
			}
			if registered := h.service.authRegistrationWaitCh(h.authID); registered != nil {
				select {
				case <-registered:
				case <-deadline:
					h.t.Fatal("Service did not finish auth model registration")
				}
			}
			return
		case <-deadline:
			h.t.Fatal("Service consumer did not publish synthesized auth")
		}
	}
}

func (h *serviceDeviceHarness) reload(mode string, inject bool) {
	h.t.Helper()
	before := h.service.currentConfig()
	previous, _ := h.service.coreManager.Executor("codex")
	updated := before.CloneForRuntime()
	updated.Codex.DeviceFingerprintMode = mode
	updated.Codex.DeviceFingerprintInjectMissing = &inject
	if errSave := internalconfig.SaveConfigPreserveComments(h.configPath, updated, true); errSave != nil {
		h.t.Fatal(errSave)
	}
	h.watcher.ReloadConfigIfChanged()
	current := h.service.currentConfig()
	if current == before || current.Codex.DeviceFingerprintMode != mode || current.Codex.DeviceFingerprintInjectMissing == nil || *current.Codex.DeviceFingerprintInjectMissing != inject {
		saved, _ := os.ReadFile(h.configPath)
		h.t.Fatalf("saved configuration did not reach the Service runtime snapshot: same=%t mode=%q inject=%v disk=%s", current == before, current.Codex.DeviceFingerprintMode, current.Codex.DeviceFingerprintInjectMissing, saved)
	}
	next, ok := h.service.coreManager.Executor("codex")
	if !ok || next == previous {
		h.t.Fatal("watcher reload did not replace the Codex executor")
	}
	if user, okUser := next.(interface{ UsesConfig(*config.Config) bool }); !okUser || !user.UsesConfig(current) {
		h.t.Fatal("new executor does not use the committed configuration snapshot")
	}
	snapshot, errSnapshot := yaml.Marshal(current)
	if errSnapshot != nil {
		h.t.Fatal(errSnapshot)
	}
	restored, errParse := internalconfig.ParseConfigBytes(snapshot)
	if errParse != nil || restored.Codex.DeviceFingerprintMode != mode || restored.Codex.DeviceFingerprintInjectMissing == nil || *restored.Codex.DeviceFingerprintInjectMissing != inject {
		h.t.Fatal("runtime YAML snapshot lost device settings")
	}
	if current.ForAPIKey().Codex.DeviceFingerprintMode != "" || current.ForAPIKey().Codex.DeviceFingerprintInjectMissing != nil {
		h.t.Fatal("saved device settings escaped their OAuth scope")
	}
}

func serviceDeviceAuth() *ojson.Doc {
	return ojson.NewDocString(`{"type":"codex","access_token":"synthetic-access","account_id":"acc-test-1","websockets":true,"codex_installation_id":"11111111-2222-4333-8444-555555555555"}`)
}

func (h *serviceDeviceHarness) options() coreexecutor.Options {
	return coreexecutor.Options{
		Stream:         true,
		SourceFormat:   sdktranslator.FormatOpenAIResponse,
		ResponseFormat: sdktranslator.FormatOpenAIResponse,
		Headers:        http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client-device","turn":"keep-turn"}`}},
		Metadata: map[string]any{
			coreexecutor.ExecutionSessionMetadataKey: h.sessionID,
			coreexecutor.PinnedAuthMetadataKey:       h.authID,
		},
	}
}

func (h *serviceDeviceHarness) stream(ctx context.Context, body string) (*coreexecutor.StreamResult, error) {
	return h.service.coreManager.ExecuteStream(ctx, []string{"codex"}, coreexecutor.Request{Model: serviceDeviceModel, Payload: []byte(body)}, h.options())
}

func (h *serviceDeviceHarness) run(ctx context.Context, body string) serviceDeviceCapture {
	h.t.Helper()
	result, errExecute := h.stream(ctx, body)
	if errExecute != nil {
		h.t.Fatal(errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			h.t.Fatal(chunk.Err)
		}
	}
	return h.capture()
}

func (h *serviceDeviceHarness) capture() serviceDeviceCapture {
	h.t.Helper()
	select {
	case captured := <-h.captures:
		return captured
	case <-time.After(10 * time.Second):
		h.t.Fatal("local upstream did not receive a request")
		return serviceDeviceCapture{}
	}
}

func assertServiceDevice(t *testing.T, captured serviceDeviceCapture, id, headerID string) {
	t.Helper()
	if got := ojson.GetBytes(captured.body, "client_metadata.x-codex-installation-id").String(); got != id {
		t.Fatalf("upstream installation=%q, want %q", got, id)
	}
	if got := ojson.Get(captured.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String(); got != headerID {
		t.Fatalf("upstream header installation=%q, want %q", got, headerID)
	}
}

func TestCodexDeviceFingerprintServiceConfigLifecycle(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			h := newServiceDeviceHarness(t, legacy, "off")
			auth := serviceDeviceAuth()
			h.loadAuth(auth)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device","thread_id":"keep-thread"},"prompt_cache_key":"keep-cache"}`
			assertServiceDevice(t, h.run(t.Context(), body), "client-device", "client-device")
			h.reload("device", false)
			assertServiceDevice(t, h.run(t.Context(), body), serviceDeviceID, serviceDeviceID)
			assertServiceDevice(t, h.run(t.Context(), `{"input":[]}`), "", serviceDeviceID)
			h.reload("device", true)
			assertServiceDevice(t, h.run(t.Context(), `{"input":[]}`), serviceDeviceID, serviceDeviceID)
			if errSet := auth.Set("codex_device_fingerprint", "off"); errSet != nil {
				t.Fatal(errSet)
			}
			h.loadAuth(auth)
			assertServiceDevice(t, h.run(t.Context(), body), "client-device", "client-device")
			h.reload("off", false)
			if errSet := auth.Set("codex_device_fingerprint", " DeViCe "); errSet != nil {
				t.Fatal(errSet)
			}
			h.loadAuth(auth)
			capture := h.run(t.Context(), body)
			assertServiceDevice(t, capture, serviceDeviceID, serviceDeviceID)
			if ojson.GetBytes(capture.body, "client_metadata.thread_id").String() != "keep-thread" || ojson.GetBytes(capture.body, "prompt_cache_key").String() != "keep-cache" {
				t.Fatal("device config reload changed unrelated request identifiers")
			}
		})
	}
}

func TestCodexDeviceFingerprintServiceWebsocketConfigBoundary(t *testing.T) {
	h := newServiceDeviceHarness(t, false, "off")
	auth := serviceDeviceAuth()
	h.loadAuth(auth)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
	ctx := coreexecutor.WithDownstreamWebsocket(t.Context())
	first := h.run(ctx, body)
	assertServiceDevice(t, first, "client-device", "client-device")
	h.reload("device", false)
	for _, required := range []bool{false, true} {
		continuationCtx := ctx
		continuation := `{"input":[],"previous_response_id":"service-response-0"}`
		if required {
			continuationCtx = coreexecutor.WithRequiredUpstreamWebsocket(ctx)
			continuation = body
		}
		result, errExecute := h.stream(continuationCtx, continuation)
		if result != nil {
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					errExecute = chunk.Err
				}
			}
		}
		if !coreexecutor.IsUpstreamWebsocketReplayRequired(errExecute) {
			t.Fatalf("changed mode on retained continuation: %v", errExecute)
		}
	}
	second := h.run(ctx, body)
	assertServiceDevice(t, second, serviceDeviceID, serviceDeviceID)
	if first.connection == second.connection || h.connections.Load() != 2 {
		t.Fatal("complete request did not replace the incompatible physical connection")
	}
	if errSet := auth.Set("codex_installation_id", serviceDeviceIDChanged); errSet != nil {
		t.Fatal(errSet)
	}
	h.loadAuth(auth)
	third := h.run(ctx, body)
	assertServiceDevice(t, third, serviceDeviceIDChanged, serviceDeviceIDChanged)
	if third.connection == second.connection || h.connections.Load() != 3 {
		t.Fatal("auth file update reused an incompatible device handshake")
	}
	h.reload("off", false)
	fourth := h.run(ctx, body)
	assertServiceDevice(t, fourth, "client-device", "client-device")
	if fourth.connection == third.connection || h.connections.Load() != 4 {
		t.Fatal("mode disable did not take effect at the next full request")
	}
}

func TestCodexDeviceFingerprintServiceActiveDuplexConfigSnapshot(t *testing.T) {
	h := newServiceDeviceHarness(t, false, "device")
	h.loadAuth(serviceDeviceAuth())
	input := make(chan coreexecutor.WebsocketInput, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = coreexecutor.WithWebsocketInput(coreexecutor.WithDownstreamWebsocket(ctx), input)
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
	result, errExecute := h.stream(ctx, body)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	defer func() {
		cancel()
		for range result.Chunks {
		}
	}()
	readTurn := func() serviceDeviceCapture {
		t.Helper()
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
			payload := strings.TrimSpace(string(chunk.Payload))
			payload = strings.TrimPrefix(payload, "data: ")
			if ojson.Get(payload, "type").String() == "response.completed" {
				return h.capture()
			}
		}
		t.Fatal("duplex closed before the response completed")
		return serviceDeviceCapture{}
	}
	first := readTurn()
	assertServiceDevice(t, first, serviceDeviceID, serviceDeviceID)
	h.reload("off", true)
	assertServiceDevice(t, h.run(t.Context(), body), "client-device", "client-device")
	for _, frame := range []string{
		`{"type":"response.create","input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`,
		`{"type":"response.append","input":[]}`,
	} {
		input <- coreexecutor.WebsocketInput{Payload: []byte(frame)}
		capture := readTurn()
		want := serviceDeviceID
		if ojson.Get(frame, "type").String() == "response.append" {
			want = ""
		}
		assertServiceDevice(t, capture, want, serviceDeviceID)
		if capture.connection != first.connection {
			t.Fatal("config replacement moved the active duplex to a new socket")
		}
	}
	cancel()
	for range result.Chunks {
	}
	h.service.coreManager.CloseExecutionSession(h.sessionID)
	final := h.run(coreexecutor.WithDownstreamWebsocket(t.Context()), body)
	assertServiceDevice(t, final, "client-device", "client-device")
	if final.connection == first.connection {
		t.Fatal("new websocket did not adopt the reloaded disabled policy")
	}
}

func TestCodexDeviceFingerprintServiceAuthFilePlanAndTransport(t *testing.T) {
	h := newServiceDeviceHarness(t, false, "device")
	body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client-device"}}`
	for i, step := range []struct {
		plan, user, want string
		websocket        bool
	}{
		{plan: "team", user: "user-aaa", want: "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"},
		{user: "user-aaa", want: "2d1c341a-5607-4894-ae5e-6cf59c2e7dde", websocket: true},
		{plan: "free", user: "user-aaa"},
		{plan: "team", user: "user-aaa", want: "2d1c341a-5607-4894-ae5e-6cf59c2e7dde", websocket: true},
		{plan: "business", user: "user-bbb", want: "fd5de10e-f853-4dd0-92f4-ece041b115a9", websocket: true},
		{user: "user-bbb", want: "fd5de10e-f853-4dd0-92f4-ece041b115a9"},
	} {
		claims := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1"}}`)
		if errSet := claims.Set("https://api\\.openai\\.com/auth.chatgpt_user_id", step.user); errSet != nil {
			t.Fatal(errSet)
		}
		if step.plan != "" {
			if errSet := claims.Set("https://api\\.openai\\.com/auth.chatgpt_plan_type", step.plan); errSet != nil {
				t.Fatal(errSet)
			}
		}
		auth := ojson.NewDocString(`{"type":"codex","access_token":"synthetic-access","account_id":"acc-team-1","websockets":true}`)
		if errSet := auth.Set("id_token", "eyJhbGciOiJub25lIn0."+base64.RawURLEncoding.EncodeToString(claims.Bytes())+".sig"); errSet != nil {
			t.Fatal(errSet)
		}
		h.loadAuth(auth)
		ctx := t.Context()
		if step.websocket {
			ctx = coreexecutor.WithDownstreamWebsocket(ctx)
		}
		capture := h.run(ctx, body)
		if step.want == "" {
			got := ojson.GetBytes(capture.body, "client_metadata.x-codex-installation-id").String()
			if got == "" || got == "client-device" || got == "2d1c341a-5607-4894-ae5e-6cf59c2e7dde" {
				t.Fatal("explicit free was ignored as if the plan claim were missing")
			}
			continue
		}
		if got := ojson.GetBytes(capture.body, "client_metadata.x-codex-installation-id").String(); got != step.want {
			t.Fatalf("step %d lost member identity across file synthesis and transport selection: got %q want %q", i, got, step.want)
		}
		assertServiceDevice(t, capture, step.want, step.want)
	}
}
