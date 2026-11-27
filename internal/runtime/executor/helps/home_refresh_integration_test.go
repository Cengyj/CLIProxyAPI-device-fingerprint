package helps_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

const homeMemberA = "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"
const homeMemberB = "fd5de10e-f853-4dd0-92f4-ece041b115a9"
const homeAccount = "c2a63432-aabe-4908-8fe6-ec89af8327c9"
const homeExplicit = "11111111-2222-4333-8444-555555555555"
const homeBusinessBody = `{"model":"gpt-5.4","input":[],"prompt_cache_key":"keep-cache","client_metadata":{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\",\"turn_id\":\"keep-turn\"}"}}`

type homeWireCapture struct {
	body       []byte
	headers    http.Header
	connection int32
}

func homeToken(t *testing.T, account, member, plan string) string {
	t.Helper()
	doc := ojson.NewDocString(`{"https://api.openai.com/auth":{}}`)
	for key, value := range map[string]string{"chatgpt_account_id": account, "chatgpt_user_id": member, "chatgpt_plan_type": plan} {
		if value != "" {
			if errSet := doc.Set("https://api\\.openai\\.com/auth."+key, value); errSet != nil {
				t.Fatal(errSet)
			}
		}
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
}

func homeWireServer(t *testing.T) (*httptest.Server, <-chan homeWireCapture, *atomic.Int32) {
	t.Helper()
	captures := make(chan homeWireCapture, 32)
	connections := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if errUpgrade != nil {
				t.Error(errUpgrade)
				return
			}
			id := connections.Add(1)
			defer func() { _ = conn.Close() }()
			for {
				_, body, errRead := conn.ReadMessage()
				if errRead != nil {
					return
				}
				captures <- homeWireCapture{body, r.Header.Clone(), id}
				for _, kind := range []string{"response.created", "response.completed"} {
					response := ojson.NewDocString(`{"response":{"id":"r0","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
					if errSet := response.Set("type", kind); errSet != nil {
						t.Error(errSet)
						return
					}
					if errWrite := conn.WriteMessage(websocket.TextMessage, response.Bytes()); errWrite != nil {
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
		if r.Header.Get("Content-Encoding") == "zstd" {
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
		captures <- homeWireCapture{body, r.Header.Clone(), 0}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"id":"r0","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`+"\n\n")
	}))
	t.Cleanup(server.Close)
	return server, captures, connections
}

func assertHomeWire(t *testing.T, wire homeWireCapture, wantID, account, bearer string) {
	t.Helper()
	if got := ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String(); got != wantID {
		t.Errorf("wire installation mismatch: got %s want %s", got, wantID)
	}
	inner := ojson.GetBytes(wire.body, "client_metadata.x-codex-turn-metadata").String()
	if ojson.Get(inner, "installation_id").String() != wantID || ojson.Get(inner, "turn_id").String() != "keep-turn" {
		t.Error("wire nested installation or turn changed")
	}
	if ojson.Get(wire.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != wantID {
		t.Error("actual HTTP/handshake device header disagrees")
	}
	if wire.headers.Get("Authorization") != "Bearer "+bearer || wire.headers.Get("ChatGPT-Account-ID") != account {
		t.Error("actual credential and account header disagree with selected snapshot")
	}
	if ojson.GetBytes(wire.body, "prompt_cache_key").String() != "keep-cache" {
		t.Error("cache identifier changed")
	}
}

func TestCodexDeviceFingerprintHomeRefreshToWire(t *testing.T) {
	for _, tc := range []struct {
		name, account, member, tokenPlan, plan, want string
		attrs                                        map[string]string
		explicit                                     bool
		stream                                       bool
	}{
		{"metadata-free-attribute-default", "acc-team-1", "user-aaa", "", "free", homeAccount, map[string]string{"plan_type": "free", "plan_type_defaulted": "true"}, false, false},
		{"foreign-attribute-member", "acc-team-1", "user-bbb", "team", "", homeMemberB, map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"}, false, true},
		{"same-explicit-new-member", "acc-team-1", "user-bbb", "team", "", homeExplicit, map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team"}, true, false},
		{"same-subject-bearer-rotation", "acc-team-1", "user-aaa", "team", "", homeMemberA, nil, false, true},
		{"attributes-only-identity", "acc-team-1", "user-bbb", "business", "", homeMemberB, nil, false, false},
		{"matching-metadata-attributes", "acc-team-1", "user-bbb", "enterprise", "", homeMemberB, map[string]string{"account_id": "acc-team-1", "chatgpt_user_id": "user-bbb", "plan_type": "enterprise"}, false, true},
		{"new-account", "acc-team-2", "user-bbb", "edu", "", "e7586ede-1b70-4428-9407-367a6aa12ea6", map[string]string{"account_id": "acc-team-1", "chatgpt_user_id": "user-aaa", "plan_type": "team"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, captures, connections := homeWireServer(t)
			cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			auto := executor.NewCodexAutoExecutor(cfg)
			session := t.Name()
			defer auto.CloseExecutionSession(session)
			auth := &cliproxyauth.Auth{ID: "home-source.json", FileName: "home-source.json", Index: "home-source", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "websockets": "true"}, Metadata: map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "old-refresh", "account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-aaa", "team"), "chatgpt_user_id": "user-aaa", "chatgpt_plan_type": "team", "plan_type": "team", "plan_type_defaulted": false, "expired": "2099-01-01T00:00:00Z", "operator_note": "keep", "websockets": true}}
			if tc.explicit {
				auth.Metadata["codex_installation_id"] = homeExplicit
			}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			// Local selection uses the real Manager; only refresh delegates to Home.
			localCfg := *cfg
			localCfg.Home.Enabled = false
			manager.SetConfig(&localCfg)
			manager.RegisterExecutor(auto)
			registered, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			auth = registered
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			if _, errSave := store.Save(t.Context(), auth); errSave != nil {
				t.Fatal(errSave)
			}
			registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5.4"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"Session-Id": {session}, "X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"keep"}`}}, Metadata: map[string]any{core.CallerScopeMetadataKey: "home-test", core.ExecutionSessionMetadataKey: session}}
			execute := func(ws bool, body string) error {
				ctx := t.Context()
				if ws {
					ctx = core.WithDownstreamWebsocket(ctx)
				}
				req := core.Request{Model: "gpt-5.4", Payload: []byte(body)}
				if !tc.stream {
					_, errExecute := manager.Execute(ctx, []string{"codex"}, req, opts)
					return errExecute
				}
				result, errStream := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
				if errStream != nil {
					return errStream
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						return chunk.Err
					}
				}
				return nil
			}
			oldID := homeMemberA
			if tc.explicit {
				oldID = homeExplicit
			}
			for _, ws := range []bool{false, true} {
				if errExecute := execute(ws, homeBusinessBody); errExecute != nil {
					t.Fatal(errExecute)
				}
				assertHomeWire(t, <-captures, oldID, "acc-team-1", "old-access")
			}
			if connections.Load() != 1 {
				t.Fatal("initial physical connection was not established")
			}
			returned := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "home-access", "refresh_token": "home-refresh", "account_id": tc.account, "id_token": homeToken(t, tc.account, tc.member, tc.tokenPlan), "expired": "2099-01-01T00:00:00Z"}, Attributes: tc.attrs}
			if tc.plan != "" {
				returned.Metadata["plan_type"] = tc.plan
			}
			if tc.name == "attributes-only-identity" {
				returned.Attributes = map[string]string{"account_id": tc.account, "id_token": returned.Metadata["id_token"].(string), "chatgpt_user_id": tc.member, "plan_type": tc.tokenPlan}
				delete(returned.Metadata, "account_id")
				delete(returned.Metadata, "id_token")
			}
			// Account and team-member switches can belong to the same CPA record.
			if tc.name == "new-account" || tc.name == "same-explicit-new-member" {
				returned.ID = auth.ID
			}
			envelope := ojson.NewDocString(`{}`)
			if errSet := envelope.Set("auth", returned); errSet != nil {
				t.Fatal(errSet)
			}
			wantIndex := auth.Index
			if tc.name == "new-account" {
				wantIndex = "home-updated-index"
				if errSet := envelope.Set("auth_index", wantIndex); errSet != nil {
					t.Fatal(errSet)
				}
			}
			var refreshCalls atomic.Int32
			helps.SetHomeRefreshForTest(t, func(_ context.Context, index, digest string) ([]byte, error) {
				refreshCalls.Add(1)
				if index != "home-source" || digest != cliproxyauth.AccessTokenSHA256(auth) {
					t.Error("Home refresh used a different baseline credential")
				}
				return envelope.Bytes(), nil
			})
			refreshed, errRefresh := auto.Refresh(t.Context(), auth.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			if refreshCalls.Load() != 1 {
				t.Fatal("actual Home refresh boundary was not used")
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), auth, refreshed)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			if refreshed.ID != auth.ID || merged.ID != auth.ID || refreshed.Index != wantIndex {
				t.Error("Home refresh lost the record ID or returned index")
			}
			if errExecute := execute(false, homeBusinessBody); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, tc.want, tc.account, "home-access")
			continuation := ojson.NewDocString(homeBusinessBody)
			if errSet := continuation.Set("previous_response_id", "r0"); errSet != nil {
				t.Fatal(errSet)
			}
			errContinuation := execute(true, continuation.String())
			changed := tc.name != "same-subject-bearer-rotation"
			if changed {
				if !core.IsUpstreamWebsocketReplayRequired(errContinuation) {
					t.Errorf("changed identity continuation must request replay, got %v", errContinuation)
				}
				if errContinuation == nil {
					<-captures
				}
				if errExecute := execute(true, homeBusinessBody); errExecute != nil {
					t.Fatal(errExecute)
				}
				wire := <-captures
				assertHomeWire(t, wire, tc.want, tc.account, "home-access")
				if wire.connection != 2 || connections.Load() != 2 {
					t.Error("changed identity failed to establish a new physical handshake")
				}
			} else {
				if errContinuation != nil {
					t.Fatal(errContinuation)
				}
				wire := <-captures
				assertHomeWire(t, wire, tc.want, tc.account, "old-access")
				if wire.connection != 1 || connections.Load() != 1 {
					t.Error("same subject bearer rotation unnecessarily redialed")
				}
			}
			path, errSave := store.Save(t.Context(), merged)
			if errSave != nil {
				t.Fatal(errSave)
			}
			if path != filepath.Join(cfg.AuthDir, auth.FileName) {
				t.Fatal("saved unexpected credential path")
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if tc.plan == "free" && ojson.GetBytes(raw, "plan_type_defaulted").Bool() {
				t.Error("explicit metadata free persisted as a defaulted plan")
			}
			if ojson.GetBytes(raw, "chatgpt_user_id").String() != tc.member {
				t.Error("adopted member did not persist")
			}
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: &localCfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("synthesis failed: %v, count=%d", errLoad, len(loaded))
			}
			loaded[0].Attributes["base_url"] = server.URL
			selected, errUpdate := manager.Update(t.Context(), loaded[0])
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			if errExecute := execute(false, homeBusinessBody); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, tc.want, tc.account, "home-access")
			cold := executor.NewCodexAutoExecutor(&localCfg)
			if _, errExecute := cold.Execute(t.Context(), selected, core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, tc.want, tc.account, "home-access")
		})
	}
}

func TestCodexDeviceFingerprintHomeConcurrentAdoption(t *testing.T) {
	for _, action := range []string{"administrator-edit", "administrator-delete", "superseded-outer-independent-siwc"} {
		t.Run(action, func(t *testing.T) {
			server, captures, _ := homeWireServer(t)
			cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			auto := executor.NewCodexAutoExecutor(cfg)
			base := &cliproxyauth.Auth{ID: "home-concurrent.json", FileName: "home-concurrent.json", Index: "home-concurrent", Provider: "codex",
				Attributes: map[string]string{"base_url": server.URL, "codex_device_fingerprint": "device", "codex_installation_id": homeExplicit, "header:X-Operator": "old-admin"},
				Metadata: map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "old-refresh", "account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-aaa", "team"), "chatgpt_user_id": "user-aaa", "chatgpt_plan_type": "team", "plan_type": "team", "expired": "2099-01-01T00:00:00Z", "codex_device_fingerprint": "device", "codex_installation_id": homeExplicit, "headers": map[string]any{"X-Operator": "old-admin"}, "operator_note": "old-admin", "use_siwc": false,
					"siwc": map[string]any{"access_token": "old-siwc", "refresh_token": "old-siwc-refresh", "client_id": "local-client", "device_id": homeExplicit, "expired": "2099-01-01T00:00:00Z"}},
			}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			registered, errRegister := manager.Register(t.Context(), base)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			base = registered
			request := core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
			if _, errExecute := auto.Execute(t.Context(), base, request, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, homeExplicit, "acc-team-1", "old-access")
			returned := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "home-access", "refresh_token": "home-refresh", "account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-bbb", "team"), "expired": "2099-01-01T00:00:00Z", "codex_device_fingerprint": "device", "codex_installation_id": homeExplicit, "headers": map[string]any{"X-Operator": "old-admin"}, "operator_note": "old-admin",
				"siwc": map[string]any{"access_token": "home-siwc", "refresh_token": "home-siwc-refresh", "client_id": "local-client", "device_id": homeExplicit, "expired": "2099-01-01T00:00:00Z"}},
				Attributes: map[string]string{"account_id": "acc-team-2", "chatgpt_user_id": "user-aaa", "plan_type": "team", "codex_device_fingerprint": "device", "codex_installation_id": homeExplicit, "header:X-Operator": "old-admin"},
			}
			envelope := ojson.NewDocString(`{}`)
			if errSet := envelope.Set("auth", returned); errSet != nil {
				t.Fatal(errSet)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			helps.SetHomeRefreshForTest(t, func(ctx context.Context, _, _ string) ([]byte, error) {
				close(entered)
				select {
				case <-release:
					return envelope.Bytes(), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
			type refreshResult struct {
				auth *cliproxyauth.Auth
				err  error
			}
			refreshedCh := make(chan refreshResult, 1)
			go func() {
				refreshed, errRefresh := auto.Refresh(t.Context(), base.Clone())
				refreshedCh <- refreshResult{refreshed, errRefresh}
			}()
			<-entered
			current := base.Clone()
			for _, key := range []string{"codex_device_fingerprint", "codex_installation_id", "headers"} {
				delete(current.Metadata, key)
			}
			for _, key := range []string{"codex_device_fingerprint", "codex_installation_id", "header:X-Operator"} {
				delete(current.Attributes, key)
			}
			current.Metadata["operator_note"] = "new-admin"
			want, bearer, account := homeMemberB, "home-access", "acc-team-1"
			if action == "administrator-edit" {
				want = "66666666-7777-4888-9999-aaaaaaaaaaaa"
				current.Metadata["codex_device_fingerprint"] = "device"
				current.Metadata["codex_installation_id"] = want
				current.Metadata["headers"] = map[string]any{"X-Operator": "new-admin"}
				current.Attributes["codex_device_fingerprint"] = "device"
				current.Attributes["codex_installation_id"] = want
				current.Attributes["header:X-Operator"] = "new-admin"
			}
			if action == "superseded-outer-independent-siwc" {
				account, bearer, want = "acc-team-2", "latest-access", "e7586ede-1b70-4428-9407-367a6aa12ea6"
				current.Metadata["access_token"] = bearer
				current.Metadata["refresh_token"] = "latest-refresh"
				current.Metadata["account_id"] = account
				current.Metadata["id_token"] = homeToken(t, account, "user-bbb", "team")
				current.Metadata["chatgpt_user_id"] = "user-bbb"
			}
			if _, errUpdate := manager.Update(t.Context(), current); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			if _, errSave := store.Save(t.Context(), current); errSave != nil {
				t.Fatal(errSave)
			}
			once.Do(func() { close(release) })
			result := <-refreshedCh
			if result.err != nil {
				t.Fatal(result.err)
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, result.auth)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			assertCandidate := func(candidate *cliproxyauth.Auth) {
				t.Helper()
				candidate.Attributes["base_url"] = server.URL
				if _, errExecute := auto.Execute(t.Context(), candidate, request, opts); errExecute != nil {
					t.Fatal(errExecute)
				}
				wire := <-captures
				assertHomeWire(t, wire, want, account, bearer)
				wantHeader := ""
				if action == "administrator-edit" {
					wantHeader = "new-admin"
				}
				if wire.headers.Get("X-Operator") != wantHeader || candidate.Metadata["operator_note"] != "new-admin" {
					t.Error("late Home refresh displaced administrator changes")
				}
				if action != "administrator-edit" {
					for _, key := range []string{"codex_device_fingerprint", "codex_installation_id", "headers"} {
						if _, exists := candidate.Metadata[key]; exists {
							t.Errorf("deleted administrator metadata restored: %s", key)
						}
					}
					for _, key := range []string{"codex_device_fingerprint", "codex_installation_id", "header:X-Operator"} {
						if _, exists := candidate.Attributes[key]; exists {
							t.Errorf("deleted administrator attribute restored: %s", key)
						}
					}
				}
				if siwc := candidate.Metadata["siwc"].(map[string]any); siwc["access_token"] != "home-siwc" {
					t.Error("matching SIWC partition was rejected with unrelated outer state")
				}
			}
			assertCandidate(merged)
			path, errSave := store.Save(t.Context(), merged)
			if errSave != nil {
				t.Fatal(errSave)
			}
			assertCandidate(merged)
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("synthesis failed: %v count=%d", errLoad, len(loaded))
			}
			assertCandidate(loaded[0])
			if action == "superseded-outer-independent-siwc" {
				siwc := loaded[0].Clone()
				siwc.Metadata["use_siwc"] = true
				if _, errExecute := auto.Execute(t.Context(), siwc, request, opts); errExecute != nil {
					t.Fatal(errExecute)
				}
				wire := <-captures
				if wire.headers.Get("Authorization") != "Bearer home-siwc" || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != homeExplicit {
					t.Error("independently adopted SIWC did not reach wire")
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintHomeIdentityPersistence(t *testing.T) {
	for _, name := range []string{"plan-absent", "plan-null", "plan-empty", "plan-wrong-type", "plan-free", "plan-null-current-claim", "claim-plan-null", "foreign-auxiliary-token", "matching-auxiliary-token"} {
		t.Run(name, func(t *testing.T) {
			server, captures, _ := homeWireServer(t)
			cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
			localCfg := *cfg
			localCfg.Home.Enabled = false
			auto := executor.NewCodexAutoExecutor(cfg)
			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.SetConfig(&localCfg)
			manager.RegisterExecutor(auto)
			initial := &cliproxyauth.Auth{ID: "home-persist.json", FileName: "home-persist.json", Index: "home-persist", Provider: "codex", Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{"type": "codex", "account_id": "acc-team-1", "id_token": homeToken(t, "acc-team-1", "user-bbb", "team"), "access_token": "old-access", "refresh_token": "old-refresh", "chatgpt_user_id": "user-bbb", "plan_type": "team", "chatgpt_plan_type": "team", "expired": "2099-01-01T00:00:00Z"}}
			baseline, errRegister := manager.Register(t.Context(), initial)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			registry.GetGlobalRegistry().RegisterClient(baseline.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5.4"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(baseline.ID) })
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			if _, errSave := store.Save(t.Context(), baseline); errSave != nil {
				t.Fatal(errSave)
			}
			request := core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}
			opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
			if _, errExecute := manager.Execute(t.Context(), []string{"codex"}, request, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, homeMemberB, "acc-team-1", "old-access")
			returned := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"account_id": "acc-team-1", "access_token": "home-access", "refresh_token": "home-refresh", "id_token": homeToken(t, "acc-team-1", "user-bbb", ""), "expired": "2099-01-01T00:00:00Z"}, Attributes: map[string]string{"account_id": "acc-team-1", "chatgpt_plan_type": "team"}}
			wantCold, wantWarm, wantPlan, wantAlias := homeAccount, homeMemberB, "free", ""
			wantDefaulted := true
			switch name {
			case "plan-absent":
				wantCold, wantPlan, wantAlias, wantDefaulted = homeMemberB, "team", "team", false
			case "plan-null":
				returned.Metadata["plan_type"] = nil
			case "plan-empty":
				returned.Metadata["plan_type"] = ""
			case "plan-wrong-type":
				returned.Metadata["plan_type"] = []any{"team"}
			case "plan-free":
				returned.Metadata["plan_type"] = "free"
				wantWarm, wantDefaulted = homeAccount, false
			case "plan-null-current-claim":
				returned.Metadata["plan_type"] = nil
				returned.Metadata["id_token"] = homeToken(t, "acc-team-1", "user-bbb", "business")
				wantCold, wantPlan, wantAlias, wantDefaulted = homeMemberB, "business", "business", false
			case "claim-plan-null":
				returned.Metadata["chatgpt_plan_type"] = nil
			case "foreign-auxiliary-token":
				delete(returned.Metadata, "id_token")
				returned.Attributes = map[string]string{"id_token": homeToken(t, "acc-team-2", "user-aaa", "team"), "chatgpt_plan_type": "team"}
			case "matching-auxiliary-token":
				delete(returned.Metadata, "id_token")
				returned.Attributes = map[string]string{"id_token": homeToken(t, "acc-team-1", "user-bbb", "team"), "chatgpt_plan_type": "team"}
				wantCold, wantPlan, wantAlias, wantDefaulted = homeMemberB, "team", "team", false
			}
			envelope := ojson.NewDocString(`{}`)
			if errSet := envelope.Set("auth", returned); errSet != nil {
				t.Fatal(errSet)
			}
			var calls atomic.Int32
			helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { calls.Add(1); return envelope.Bytes(), nil })
			refreshed, errRefresh := auto.Refresh(t.Context(), baseline.Clone())
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), baseline, refreshed)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			assertIdentity := func(candidate *cliproxyauth.Auth) {
				t.Helper()
				if candidate.Metadata["plan_type"] != wantPlan || candidate.Metadata["plan_type_defaulted"] != wantDefaulted {
					t.Error("plan and provenance differ from accepted source")
				}
				alias, _ := candidate.Metadata["chatgpt_plan_type"].(string)
				if alias != wantAlias {
					t.Error("auxiliary plan alias survived canonical clearing")
				}
				if name == "foreign-auxiliary-token" {
					if token, _ := candidate.Metadata["id_token"].(string); token != "" {
						t.Error("foreign auxiliary token promoted into canonical credentials")
					}
					if candidate.Attributes["id_token"] != "" {
						t.Error("foreign auxiliary token survived in attributes")
					}
					if candidate.Storage != nil {
						if storage, ok := candidate.Storage.(*codexauth.CodexTokenStorage); ok && storage.IDToken != "" {
							t.Error("foreign auxiliary token survived in storage")
						}
					}
				}
			}
			assertIdentity(merged)
			if _, errExecute := manager.Execute(t.Context(), []string{"codex"}, request, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, wantWarm, "acc-team-1", "home-access")
			path, errSave := store.Save(t.Context(), merged)
			if errSave != nil {
				t.Fatal(errSave)
			}
			assertIdentity(merged)
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "chatgpt_plan_type").String() != wantAlias {
				t.Error("disk retained cleared auxiliary plan alias")
			}
			if name == "foreign-auxiliary-token" && ojson.GetBytes(raw, "id_token").String() != "" {
				t.Error("disk persisted foreign auxiliary token")
			}
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: &localCfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("synthesis: %v count %d", errLoad, len(loaded))
			}
			assertIdentity(loaded[0])
			loaded[0].Attributes["base_url"] = server.URL
			selected, errUpdate := manager.Update(t.Context(), loaded[0])
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			cold := executor.NewCodexAutoExecutor(&localCfg)
			manager.RegisterExecutor(cold)
			if _, errExecute := manager.Execute(t.Context(), []string{"codex"}, request, opts); errExecute != nil {
				t.Fatal(errExecute)
			}
			assertHomeWire(t, <-captures, wantCold, "acc-team-1", "home-access")
			// The next refresh must not restore a token rejected before persistence.
			if name == "foreign-auxiliary-token" {
				delete(returned.Attributes, "id_token")
				delete(returned.Attributes, "chatgpt_plan_type")
				if errSet := envelope.Set("auth", returned); errSet != nil {
					t.Fatal(errSet)
				}
				next, errNext := auto.Refresh(t.Context(), selected.Clone())
				if errNext != nil {
					t.Fatal(errNext)
				}
				assertIdentity(next)
			}
			if calls.Load() == 0 {
				t.Error("Home refresh was not invoked")
			}
		})
	}
}
