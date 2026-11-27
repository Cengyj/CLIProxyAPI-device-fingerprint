package helps_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintHomeSIWCWebsocketSubject(t *testing.T) {
	oidcToken := func(member string, issuedAt int, withMember bool, changedClaim string) string {
		doc := ojson.NewDocString(`{"iss":"https://issuer.invalid","aud":"siwc-client"}`)
		if withMember {
			if errSet := doc.Set("https://api\\.openai\\.com/auth.chatgpt_account_id", "nested-workspace"); errSet != nil {
				t.Fatal(errSet)
			}
			if errSet := doc.Set("https://api\\.openai\\.com/auth.chatgpt_user_id", member); errSet != nil {
				t.Fatal(errSet)
			}
		}
		if errSet := doc.Set("sub", member); errSet != nil {
			t.Fatal(errSet)
		}
		if errSet := doc.Set("iat", issuedAt); errSet != nil {
			t.Fatal(errSet)
		}
		if changedClaim != "" {
			if errSet := doc.Set(changedClaim, "changed"); errSet != nil {
				t.Fatal(errSet)
			}
		}
		return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".sig"
	}
	for _, tc := range []struct {
		name, member, tokenFormat string
		native, omitID            bool
		changedClaim              string
	}{
		{name: "same-member", member: "member-a"},
		{name: "changed-member", member: "member-b"},
		{name: "oidc-same-member", member: "member-a", tokenFormat: "id-token"},
		{name: "oidc-changed-member", member: "member-b", tokenFormat: "id-token"},
		{name: "oidc-bearer-same-member", member: "member-a", tokenFormat: "oidc-bearer"},
		{name: "oidc-bearer-changed-member", member: "member-b", tokenFormat: "oidc-bearer"},
		{name: "bearer-same-member", member: "member-a", tokenFormat: "bearer"},
		{name: "bearer-same-member-omitted-id", member: "member-a", tokenFormat: "bearer", omitID: true},
		{name: "bearer-changed-member-omitted-id", member: "member-b", tokenFormat: "bearer", omitID: true},
		{name: "bearer-changed-account-omitted-id", member: "member-a", tokenFormat: "bearer", omitID: true, changedClaim: "https://api\\.openai\\.com/auth.chatgpt_account_id"},
		{name: "bearer-changed-issuer-omitted-id", member: "member-a", tokenFormat: "bearer", omitID: true, changedClaim: "iss"},
		{name: "bearer-changed-subject-omitted-id", member: "member-a", tokenFormat: "bearer", omitID: true, changedClaim: "sub"},
		{name: "bearer-changed-member-stale-id-token", member: "member-b", tokenFormat: "bearer"},
		{name: "opaque-rotated-without-id", member: "member-a", tokenFormat: "opaque", omitID: true},
		{name: "native-codex-uses-outer", member: "member-b", native: true},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				server, frames, connections := homeWireServer(t)
				cfg := &config.Config{AuthDir: t.TempDir(), Home: config.HomeConfig{Enabled: true}, Codex: config.CodexConfig{DeviceFingerprintMode: "device", ResponseSteering: true}}
				auto := executor.NewCodexAutoExecutor(cfg)
				defer auto.CloseExecutionSession(t.Name())
				oldNestedBearer, nextNestedBearer := "nested-a", "nested-b"
				oldIDToken := homeToken(t, "nested-workspace", "member-a", "team")
				nextIDToken := homeToken(t, "nested-workspace", tc.member, "team")
				switch tc.tokenFormat {
				case "id-token":
					oldIDToken, nextIDToken = oidcToken("member-a", 1, false, ""), oidcToken(tc.member, 2, false, "")
				case "bearer", "oidc-bearer":
					oldNestedBearer = oidcToken("member-a", 1, tc.tokenFormat == "bearer", "")
					nextNestedBearer = oidcToken(tc.member, 2, tc.tokenFormat == "bearer", tc.changedClaim)
					// A fresh bearer must identify a member switch even when Home
					// still carries the previously issued auxiliary ID token.
					nextIDToken = oldIDToken
				case "opaque":
					oldIDToken, nextIDToken = "", ""
				}
				initial := &cliproxyauth.Auth{ID: "siwc.json", FileName: "siwc.json", Provider: "codex", Index: "siwc",
					Attributes: map[string]string{"base_url": server.URL, "websockets": "true"},
					Metadata: map[string]any{"type": "codex", "access_token": "outer", "refresh_token": "outer-refresh", "account_id": "acc-team-1",
						"id_token": homeToken(t, "acc-team-1", "user-aaa", "team"), "expired": "2000-01-01T00:00:00Z", "websockets": true, "use_siwc": true,
						"siwc": map[string]any{"access_token": oldNestedBearer, "refresh_token": "nested-refresh", "client_id": "client", "device_id": homeExplicit, "id_token": oldIDToken, "expired": "2099-01-01T00:00:00Z"}},
				}
				manager := cliproxyauth.NewManager(nil, nil, nil)
				base, errRegister := manager.Register(t.Context(), initial)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				path, errSave := store.Save(t.Context(), base)
				if errSave != nil {
					t.Fatal(errSave)
				}
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse,
					Headers:  http.Header{"Session-Id": {t.Name()}, "X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}},
					Metadata: map[string]any{core.CallerScopeMetadataKey: "test", core.ExecutionSessionMetadataKey: t.Name()}}
				firstBearer, account, device := oldNestedBearer, "", homeExplicit
				if tc.native {
					opts.Headers.Set("User-Agent", "codex_cli_rs/0.122.0")
					firstBearer, account, device = "outer", "acc-team-1", homeMemberA
				}
				execute := func(auth *cliproxyauth.Auth, payload []byte) error {
					ctx := core.WithDownstreamWebsocket(t.Context())
					req := core.Request{Model: "gpt-5.4", Payload: payload}
					if !stream {
						_, errExecute := auto.Execute(ctx, auth, req, opts)
						return errExecute
					}
					result, errExecute := auto.ExecuteStream(ctx, auth, req, opts)
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
				if errExecute := execute(base, []byte(homeBusinessBody)); errExecute != nil {
					t.Fatal(errExecute)
				}
				first := <-frames
				assertHomeWire(t, first, device, account, firstBearer)
				if first.connection != 1 || connections.Load() != 1 {
					t.Fatal("initial request did not establish one physical WebSocket")
				}
				returned := base.Clone()
				returned.Metadata["expired"] = "2099-01-01T00:00:00Z"
				nested := returned.Metadata["siwc"].(map[string]any)
				nested["access_token"], nested["id_token"] = nextNestedBearer, nextIDToken
				if tc.omitID {
					nextIDToken = ""
					delete(nested, "id_token")
				}
				envelope := ojson.NewDocString(`{}`)
				if errSet := envelope.Set("auth", returned); errSet != nil {
					t.Fatal(errSet)
				}
				helps.SetHomeRefreshForTest(t, func(context.Context, string, string) ([]byte, error) { return envelope.Bytes(), nil })
				check := func(stage string, auth *cliproxyauth.Auth) {
					t.Helper()
					siwc, _ := auth.Metadata["siwc"].(map[string]any)
					idToken, _ := siwc["id_token"].(string)
					if auth.ID != base.ID || auth.Metadata["account_id"] != "acc-team-1" || auth.Metadata["access_token"] != "outer" ||
						idToken != nextIDToken || siwc["access_token"] != nextNestedBearer || siwc["device_id"] != homeExplicit {
						t.Fatalf("%s did not preserve the selected credential partition", stage)
					}
				}
				refreshed, errRefresh := auto.Refresh(t.Context(), base.Clone())
				if errRefresh != nil {
					t.Fatal(errRefresh)
				}
				check("executor", refreshed)
				executorDisk, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if ojson.GetBytes(executorDisk, "siwc.id_token").String() != nextIDToken || ojson.GetBytes(executorDisk, "siwc.access_token").String() != nextNestedBearer {
					t.Fatal("executor refresh patch did not persist the adopted SIWC credential")
				}
				merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, refreshed)
				if errMerge != nil {
					t.Fatal(errMerge)
				}
				check("manager", merged)
				if _, errSave = store.Save(t.Context(), merged); errSave != nil {
					t.Fatal(errSave)
				}
				raw, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if ojson.GetBytes(raw, "siwc.id_token").String() != nextIDToken || ojson.GetBytes(raw, "siwc.access_token").String() != nextNestedBearer {
					t.Fatal("new SIWC credential did not reach the file")
				}
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("reload: %v, count=%d", errLoad, len(loaded))
				}
				check("reload", loaded[0])
				loaded[0].Attributes["base_url"] = server.URL
				continuation := ojson.NewDocString(homeBusinessBody)
				if errSet := continuation.Set("previous_response_id", "r0"); errSet != nil {
					t.Fatal(errSet)
				}
				errContinue := execute(loaded[0], continuation.Bytes())
				wantConn, wantBearer := int32(1), firstBearer
				if (tc.member != "member-a" || tc.changedClaim != "" || tc.tokenFormat == "opaque") && !tc.native {
					if !core.IsUpstreamWebsocketReplayRequired(errContinue) {
						t.Fatalf("changed SIWC member continuation: %v, want replay", errContinue)
					}
					if connections.Load() != 1 {
						t.Fatal("rejected continuation opened another socket")
					}
					select {
					case frame := <-frames:
						t.Fatalf("rejected continuation wrote a frame on connection %d", frame.connection)
					default:
					}
					wantConn, wantBearer = 2, nextNestedBearer
				} else {
					if errContinue != nil {
						t.Fatal(errContinue)
					}
					frame := <-frames
					assertHomeWire(t, frame, device, account, firstBearer)
					if frame.connection != 1 || ojson.GetBytes(frame.body, "previous_response_id").String() != "r0" {
						t.Fatal("continuation did not reuse its original physical handshake")
					}
				}
				if errExecute := execute(loaded[0], []byte(homeBusinessBody)); errExecute != nil {
					t.Fatal(errExecute)
				}
				full := <-frames
				assertHomeWire(t, full, device, account, wantBearer)
				if full.connection != wantConn || connections.Load() != wantConn || ojson.GetBytes(full.body, "previous_response_id").Exists() {
					t.Errorf("full request on connection %d, want %d", full.connection, wantConn)
				}
				if stream && tc.name == "bearer-same-member-omitted-id" {
					// A duplex on this reused socket freezes the old physical
					// policy while subsequent frames inspect the renewed auth.
					ctx, cancel := context.WithCancel(t.Context())
					input := make(chan core.WebsocketInput, 1)
					ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
					result, errDuplex := auto.ExecuteStream(ctx, loaded[0], core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}, opts)
					if errDuplex != nil {
						cancel()
						t.Fatal(errDuplex)
					}
					defer func() {
						cancel()
						for range result.Chunks {
						}
					}()
					for _, kind := range []string{"", "response.append", "response.steer"} {
						if kind != "" {
							control := ojson.NewDocString(homeBusinessBody)
							if errSet := control.Set("type", kind); errSet != nil {
								t.Fatal(errSet)
							}
							if kind == "response.steer" {
								if errSet := control.Set("previous_response_id", "r0"); errSet != nil {
									t.Fatal(errSet)
								}
							}
							input <- core.WebsocketInput{Payload: control.Bytes()}
						}
						completed := false
						for !completed {
							chunk, ok := <-result.Chunks
							if !ok || chunk.Err != nil {
								t.Fatalf("frozen renewal %s rejected: ok=%t err=%v", kind, ok, chunk.Err)
							}
							for _, line := range bytes.Split(chunk.Payload, []byte("\n")) {
								body := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data:")))
								switch ojson.GetBytes(body, "type").String() {
								case "error":
									t.Fatalf("frozen renewal %s returned an error", kind)
								case "response.completed":
									completed = true
								}
							}
						}
						frame := <-frames
						assertHomeWire(t, frame, device, account, firstBearer)
						if frame.connection != 1 || connections.Load() != 1 {
							t.Fatal("frozen policy rejected the renewed subject")
						}
					}
					cancel()
					for range result.Chunks {
					}
				}
				// Reusing an authenticated socket preserves its original bearer.
				// A newly opened socket must instead use the adopted credential.
				auto.CloseExecutionSession(t.Name())
				if errExecute := execute(loaded[0], []byte(homeBusinessBody)); errExecute != nil {
					t.Fatal(errExecute)
				}
				latestBearer := nextNestedBearer
				if tc.native {
					latestBearer = "outer"
				}
				reopened := <-frames
				assertHomeWire(t, reopened, device, account, latestBearer)
				if reopened.connection != wantConn+1 || connections.Load() != wantConn+1 {
					t.Fatal("new session did not establish a fresh physical handshake")
				}
			})
		}
	}
}
