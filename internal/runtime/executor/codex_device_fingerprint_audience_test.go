package executor

import (
	"net/http"
	"os"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintStringAudienceLifecycle(t *testing.T) {
	for _, mode := range []string{"off", "device"} {
		t.Run(mode, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			cfg := &config.Config{AuthDir: t.TempDir(), Codex: config.CodexConfig{DeviceFingerprintMode: mode}}
			exec := NewCodexExecutor(cfg)
			auth := fingerprintHTTPAuth(server.URL)
			auth.ID, auth.FileName = "audience.json", "audience.json"
			auth.Metadata["refresh_token"] = "audience-grant-" + mode
			auth.Metadata["account_id"] = "previous-account"
			auth.Metadata["expired"] = "2000-01-01T00:00:00Z"
			manager := cliproxyauth.NewManager(nil, nil, nil)
			base, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(cfg.AuthDir)
			path, errSave := store.Save(t.Context(), base)
			if errSave != nil {
				t.Fatal(errSave)
			}
			claims := ojson.NewDocString(`{"aud":"codex-client","iss":"https://issuer.invalid","sub":"user-aaa","https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team"}}`)
			proxyURL, teardown := startCodexMockOAuthServers(t, deviceRound3Token(claims))
			defer teardown()
			request := base.Clone()
			request.ProxyURL = proxyURL
			refreshed, errRefresh := exec.Refresh(t.Context(), request)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			check := func(stage string, current *cliproxyauth.Auth) {
				t.Helper()
				if current.Metadata["account_id"] != "acc-team-1" || current.Metadata["chatgpt_user_id"] != "user-aaa" || current.Metadata["plan_type"] != "team" {
					t.Errorf("%s: a legal string audience discarded account/member/plan claims", stage)
				}
			}
			check("executor", refreshed)
			merged, errMerge := manager.UpdateRefreshedAuth(t.Context(), base, refreshed)
			if errMerge != nil {
				t.Fatal(errMerge)
			}
			check("manager", merged)
			if _, errSave := store.Save(t.Context(), merged); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if ojson.GetBytes(raw, "account_id").String() != "acc-team-1" || ojson.GetBytes(raw, "chatgpt_user_id").String() != "user-aaa" || ojson.GetBytes(raw, "plan_type").String() != "team" {
				t.Error("persisted refreshed token lost its account/member/plan")
			}
			loaded, errLoad := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
			if errLoad != nil || len(loaded) != 1 {
				t.Fatalf("cold load: %v, count=%d", errLoad, len(loaded))
			}
			check("cold load", loaded[0])
			loaded[0].Attributes["base_url"] = server.URL
			loaded[0].ProxyURL = ""
			for _, stream := range []bool{false, true} {
				fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), loaded[0], core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}, stream)
				wire := <-captured
				if wire.headers.Get("Authorization") != "Bearer new-mock-access-token" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" {
					t.Errorf("stream=%t: refreshed token and account header differ", stream)
				}
				want := "client-device"
				if mode == "device" {
					want = "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"
				}
				if ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != want {
					t.Errorf("stream=%t: legal JWT audience changed the expected device identity", stream)
				}
			}
		})
	}
}
