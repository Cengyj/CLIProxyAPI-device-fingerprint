package executor

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintCanonicalAccountClearHTTP(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		for _, value := range []any{"", nil, true} {
			t.Run(fmt.Sprintf("%s/%T", mode, value), func(t *testing.T) {
				server, captured := fingerprintHTTPServer(t, false)
				cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
				exec := NewCodexExecutor(cfg)
				auth := fingerprintHTTPAuth(server.URL)
				auth.ID = "codex-a.json"
				auth.FileName = auth.ID
				auth.Metadata["id_token"] = ""
				auth.Attributes["account_id"] = "acc-test-1"
				manager := cliproxyauth.NewManager(nil, nil, nil)
				current, errRegister := manager.Register(t.Context(), auth)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				req := core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}
				opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
				fingerprintRunHTTP(t, t.Context(), exec, current, req, opts, false)
				initial := <-captured
				if initial.headers.Get("ChatGPT-Account-ID") != "acc-test-1" {
					t.Fatal("initial account header was not sent")
				}
				changed := current.Clone()
				changed.Metadata["access_token"] = "replacement-without-claims"
				changed.Metadata["account_id"] = value
				changed.Metadata["id_token"] = value
				updated, errUpdate := manager.Update(t.Context(), changed)
				if errUpdate != nil {
					t.Fatal(errUpdate)
				}
				checkRequest := func(executor *CodexExecutor, snapshot *cliproxyauth.Auth) {
					t.Helper()
					fingerprintRunHTTP(t, t.Context(), executor, snapshot, req, opts, false)
					wire := <-captured
					if wire.headers.Get("Authorization") != "Bearer replacement-without-claims" || wire.headers.Get("ChatGPT-Account-ID") != "" {
						t.Fatal("canonical credential replacement did not reach HTTP")
					}
					want := "client-device"
					if mode == "device" {
						want = "e1adc2d3-5830-4ecd-b4ad-dcc4dd155b9a"
					}
					if got := ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String(); got != want {
						t.Errorf("cleared account recovered stale device %q, want %q", got, want)
					}
				}
				// A direct SDK update may leave auxiliary attributes in place. Both
				// warm and rebuilt executors must honor the canonical clear.
				checkRequest(exec, updated)
				checkRequest(NewCodexExecutor(cfg), updated)
				store := fileauth.NewFileTokenStore()
				store.SetBaseDir(cfg.AuthDir)
				path, errSave := store.Save(t.Context(), updated.Clone())
				if errSave != nil {
					t.Fatal(errSave)
				}
				raw, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
				if errLoad != nil || len(loaded) != 1 {
					t.Fatalf("cold load: records=%d err=%v", len(loaded), errLoad)
				}
				for _, key := range []string{"account_id", "id_token"} {
					if stored, present := loaded[0].Metadata[key]; !present || !reflect.DeepEqual(stored, value) {
						t.Errorf("persisted canonical %s clear changed", key)
					}
				}
				// Runtime routing is supplied separately from persisted OAuth data.
				loaded[0].Attributes["base_url"] = server.URL
				checkRequest(NewCodexExecutor(cfg), loaded[0])
			})
		}
	}
}

func TestCodexDeviceFingerprintCanonicalAccountClearWebsocket(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			server, frames, connections := newCodexDeviceWSServer(t)
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			auth := codexDeviceWSAuth(server.URL)
			auth.Metadata["account_id"] = "acc-test-1"
			auth.Metadata["id_token"] = ""
			auth.Attributes["account_id"] = "acc-test-1"
			manager := cliproxyauth.NewManager(nil, nil, nil)
			current, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			opts := managedInstructionsOptions(t)
			body := `{"input":[],"client_metadata":{"x-codex-installation-id":"client"}}`
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), current, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			initial := <-frames
			if initial.connection != 1 || initial.headers.Get("ChatGPT-Account-ID") != "acc-test-1" {
				t.Fatal("initial outer OAuth handshake missing")
			}
			changed := current.Clone()
			changed.Metadata["access_token"] = "replacement-without-claims"
			changed.Metadata["account_id"] = ""
			changed.Metadata["id_token"] = ""
			updated, errUpdate := manager.Update(t.Context(), changed)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			sess := exec.getOrCreateSession(t.Name())
			sess.connMu.Lock()
			policy := sess.device.policy
			sess.connMu.Unlock()
			_, errFrozen := exec.prepareCodexWebsocketStreamWithDevice(t.Context(), updated, core.Request{Model: "gpt-5.4", Payload: []byte(body)}, opts, sess, &policy)
			if !core.IsUpstreamWebsocketReplayRequired(errFrozen) {
				t.Errorf("cleared account accepted frozen policy: %v", errFrozen)
			}
			continuation := `{"input":[],"previous_response_id":"r0","client_metadata":{"x-codex-installation-id":"client"}}`
			if errContinue := runCodexDeviceWSTurn(t, exec, t.Context(), updated, opts, continuation, stream); !core.IsUpstreamWebsocketReplayRequired(errContinue) {
				t.Errorf("cleared subject continuation: %v, want replay", errContinue)
			}
			select {
			case frame := <-frames:
				t.Errorf("replacement credential reached old connection %d", frame.connection)
			default:
			}
			if connections.Load() != 1 {
				t.Fatal("continuation opened another socket")
			}
			if errExecute := runCodexDeviceWSTurn(t, exec, t.Context(), updated, opts, body, stream); errExecute != nil {
				t.Fatal(errExecute)
			}
			fresh := <-frames
			if fresh.connection != 2 || connections.Load() != 2 || fresh.headers.Get("Authorization") != "Bearer replacement-without-claims" || fresh.headers.Get("ChatGPT-Account-ID") != "" {
				t.Error("full request did not open a socket with the replacement credential")
			}
			if ojson.GetBytes(fresh.body, "client_metadata.x-codex-installation-id").String() != codexDeviceTestA {
				t.Error("explicit public installation UUID changed")
			}
		})
	}
}
