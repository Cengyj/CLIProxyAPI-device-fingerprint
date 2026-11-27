package auth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type codexFingerprintLoginAuthenticator struct{ record *coreauth.Auth }

func (a codexFingerprintLoginAuthenticator) Provider() string            { return "codex" }
func (a codexFingerprintLoginAuthenticator) RefreshLead() *time.Duration { return nil }
func (a codexFingerprintLoginAuthenticator) Login(context.Context, *config.Config, *auth.LoginOptions) (*coreauth.Auth, error) {
	return a.record, nil
}

func TestCodexDeviceFingerprintReloginReachesSelectedExecutor(t *testing.T) {
	type capture struct {
		body    []byte
		headers http.Header
	}
	captured := make(chan capture, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Error(errRead)
			return
		}
		captured <- capture{body: body, headers: r.Header.Clone()}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"id":"resp-login","object":"response","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`+"\n\n")
	}))
	defer upstream.Close()
	claims := ojson.NewDocString(`{"email":"synthetic@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"acc-team-1","chatgpt_user_id":"user-bbb","chatgpt_plan_type":"team"}}`)
	token := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims.Bytes()) + ".sig"
	record, errBuild := auth.BuildCodexAuthRecordForTest(&codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
		IDToken: token, AccessToken: "new-access", RefreshToken: "new-refresh", AccountID: "acc-team-1",
		Email: "synthetic@example.test", PlanType: "team", Expire: "2099-01-01T00:00:00Z",
	}})
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, record.FileName)
	old := ojson.NewDocString(`{"type":"codex","access_token":"old-access","refresh_token":"old-refresh","account_id":"acc-team-1","chatgpt_user_id":"user-aaa","chatgpt_plan_type":"team","plan_type":"team","plan_type_defaulted":false,"codex_device_fingerprint":"device","operator_note":"keep"}`)
	if errWrite := os.WriteFile(path, old.Bytes(), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cfg := &config.Config{AuthDir: dir}
	loginManager := auth.NewManager(auth.NewFileTokenStore(), codexFingerprintLoginAuthenticator{record})
	loggedIn, savedPath, errLogin := loginManager.Login(t.Context(), "codex", cfg, nil)
	if errLogin != nil || savedPath != path {
		t.Fatalf("login failed: %v", errLogin)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	loaded, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if errSynthesize != nil || len(loaded) != 1 {
		t.Fatalf("synthesis failed: %v count=%d", errSynthesize, len(loaded))
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(executor.NewCodexExecutor(cfg))
	const model = "gpt-5.4"
	for _, adopted := range []*coreauth.Auth{loggedIn, loaded[0]} {
		adopted.Attributes["base_url"] = upstream.URL
		if _, errRegister := manager.Register(coreauth.WithSkipPersist(t.Context()), adopted); errRegister != nil {
			t.Fatal(errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(adopted.ID, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(adopted.ID) })
		_, errExecute := manager.Execute(t.Context(), []string{"codex"}, coreexecutor.Request{
			Model: model, Payload: []byte(`{"model":"gpt-5.4","input":[],"client_metadata":{"x-codex-installation-id":"client","x-codex-turn-metadata":"{\"installation_id\":\"client\",\"turn_id\":\"keep\"}"}}`),
		}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client","turn_id":"keep"}`}}})
		if errExecute != nil {
			t.Fatal(errExecute)
		}
		wire := <-captured
		const want = "fd5de10e-f853-4dd0-92f4-ece041b115a9"
		if ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != want || ojson.Get(wire.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != want {
			t.Fatal("selected executor did not send the new login member identity")
		}
		if wire.headers.Get("Authorization") != "Bearer new-access" || wire.headers.Get("ChatGPT-Account-ID") != "acc-team-1" {
			t.Fatal("selected executor sent a different credential version")
		}
		if adopted.Metadata["operator_note"] != "keep" {
			t.Fatal("administrator setting was lost before execution")
		}
	}
}
