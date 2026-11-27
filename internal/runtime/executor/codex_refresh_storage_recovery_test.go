package executor

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexRefreshRecoversAfterCredentialFileFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.json")
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	cfg := &config.Config{AuthDir: dir, Codex: config.CodexConfig{DeviceFingerprintMode: "device"}}
	manager := auth.NewManager(store, nil, nil)
	manager.RegisterExecutor(NewCodexExecutor(cfg))
	base, errRegister := manager.Register(auth.WithAuthCreationIntent(t.Context()), &auth.Auth{
		ID: "recovery.json", FileName: "recovery.json", Provider: "codex", Status: auth.StatusActive,
		Metadata: map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "recovery-grant",
			"expired": "2000-01-01T00:00:00Z", "codex_device_fingerprint": "device", "codex_installation_id": fingerprintOperatorID},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if errParse := r.ParseForm(); errParse != nil || r.Form.Get("refresh_token") != "recovery-grant" {
			t.Error("renewal did not submit the expected grant")
		}
		// Simulate an interrupted administrator write after the grant was sent.
		// The refresh must retain this invalid source instead of overwriting it.
		if errWrite := os.WriteFile(path, []byte(`{"interrupted":`), 0o600); errWrite != nil {
			t.Error(errWrite)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"recovered-access","refresh_token":"recovered-grant","expires_in":604800}`)
	}))
	t.Cleanup(endpoint.Close)
	target, errURL := url.Parse(endpoint.URL)
	if errURL != nil {
		t.Fatal(errURL)
	}
	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "auth.openai.com" {
			return original.RoundTrip(req)
		}
		forwarded := req.Clone(req.Context())
		forwarded.URL.Scheme, forwarded.URL.Host = target.Scheme, target.Host
		return original.RoundTrip(forwarded)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	if _, errRefresh := manager.ForceRefreshAuth(t.Context(), base.ID); errRefresh == nil {
		t.Fatal("refresh reported success despite an invalid credential source")
	}
	current, exists := manager.GetByID(base.ID)
	if !exists || current.Metadata["access_token"] != "old-access" || calls.Load() != 1 {
		t.Fatal("failed persistence changed Manager credentials or replayed the grant")
	}
	if raw, errRead := os.ReadFile(path); errRead != nil || string(raw) != `{"interrupted":` {
		t.Fatal("failed refresh overwrote the interrupted administrator write")
	}
	// The operator restores the old source, then a fresh Manager/executor recovers
	// the completed grant from the durable journal without a second exchange.
	if errWrite := codex.WriteJSONFileAtomic(path, base.Metadata); errWrite != nil {
		t.Fatal(errWrite)
	}
	loaded, errList := store.List(t.Context())
	if errList != nil || len(loaded) != 1 {
		t.Fatalf("restore source: count=%d err=%v", len(loaded), errList)
	}
	restarted := auth.NewManager(store, nil, nil)
	restarted.RegisterExecutor(NewCodexExecutor(cfg))
	if _, errRegister = restarted.Register(auth.WithSkipPersist(t.Context()), loaded[0]); errRegister != nil {
		t.Fatal(errRegister)
	}
	updated, errRefresh := restarted.ForceRefreshAuth(t.Context(), loaded[0].ID)
	if errRefresh != nil || updated == nil || updated.Metadata["access_token"] != "recovered-access" || calls.Load() != 1 {
		t.Fatalf("receipt recovery failed or resubmitted the grant: calls=%d err=%v", calls.Load(), errRefresh)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	cold, errCold := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{Config: cfg, AuthDir: dir, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator()}, path, raw)
	if errCold != nil || len(cold) != 1 || cold[0].Metadata["refresh_token"] != "recovered-grant" {
		t.Fatalf("cold reload lost the recovered pair: count=%d err=%v", len(cold), errCold)
	}
	if _, _, needed := auth.CodexOuterNeedsRefresh(cold[0], time.Now()); needed {
		t.Error("cold recovery immediately scheduled another renewal")
	}
	server, captured := fingerprintHTTPServer(t, false)
	cold[0].Attributes["base_url"] = server.URL
	fingerprintRunHTTP(t, t.Context(), NewCodexExecutor(cfg), cold[0], core.Request{Model: "gpt-5.4", Payload: []byte(fingerprintHTTPBody)}, core.Options{SourceFormat: translator.FormatOpenAIResponse}, false)
	wire := <-captured
	if wire.headers.Get("Authorization") != "Bearer recovered-access" || ojson.GetBytes(wire.body, "client_metadata.x-codex-installation-id").String() != fingerprintOperatorID {
		t.Error("cold request lost the recovered bearer or administrator device identity")
	}
}
