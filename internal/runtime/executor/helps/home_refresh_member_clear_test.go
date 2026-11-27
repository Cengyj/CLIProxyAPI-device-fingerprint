package helps_test

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexHomeExplicitMemberClear(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"empty", ""},
		{"null", nil},
		{"wrong-type", true},
	} {
		for _, repeatToken := range []bool{false, true} {
			for _, mode := range []string{"off", "device"} {
				for _, file := range []bool{false, true} {
					persistence, tokenMode := "memory", "omitted-token"
					if file {
						persistence = "file"
					}
					if repeatToken {
						tokenMode = "repeated-token"
					}
					t.Run(tc.name+"/"+tokenMode+"/"+mode+"/"+persistence, func(t *testing.T) {
						cfg, manager, store, path, base := homeGrantFixture(t, file, "2099-01-01T00:00:00Z", false)
						cfg.Codex.DeviceFingerprintMode = mode
						server, frames, _ := homeWireServer(t)
						base.Attributes["base_url"] = server.URL
						exec := executor.NewCodexExecutor(cfg)
						options := core.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Turn-Metadata": {`{"installation_id":"client"}`}}}
						request := core.Request{Model: "gpt-5.4", Payload: []byte(homeBusinessBody)}
						if _, errExecute := exec.Execute(t.Context(), base, request, options); errExecute != nil {
							t.Fatal(errExecute)
						}
						<-frames
						returned := &auth.Auth{Metadata: map[string]any{
							"access_token": "outer-old", "expired": "2099-01-01T00:00:00Z", "account_id": "acc-team-1",
							"chatgpt_user_id": tc.value, "plan_type": "team",
						}, Attributes: map[string]string{"chatgpt_user_id": "user-aaa"}}
						if repeatToken {
							returned.Metadata["id_token"] = base.Metadata["id_token"]
						}
						homeGrantResponse(t, returned)
						updated, errRefresh := exec.Refresh(t.Context(), base)
						if errRefresh != nil {
							t.Fatal(errRefresh)
						}
						cold := homeGrantPersist(t, cfg, manager, store, path, base, updated, func(stage string, candidate *auth.Auth) {
							t.Helper()
							member, present := candidate.Metadata["chatgpt_user_id"]
							if !present || member != "" {
								t.Errorf("%s lost the explicit canonical member clear", stage)
							}
							if candidate.Metadata["account_id"] != "acc-team-1" || candidate.Metadata["plan_type"] != "team" {
								t.Errorf("%s changed the independently retained account or plan", stage)
							}
							if candidate.Attributes["chatgpt_user_id"] != "" {
								t.Errorf("%s retained a stale auxiliary member", stage)
							}
						})
						warm, _ := manager.GetByID(base.ID)
						wantID := "97aeab4b-a871-417f-ab82-943a324cdafe"
						if mode == "off" {
							wantID = "client"
						}
						for i, candidate := range []*auth.Auth{warm, cold} {
							candidate.Attributes["base_url"] = server.URL
							sender := exec
							if i == 1 {
								sender = executor.NewCodexExecutor(cfg)
							}
							if _, errExecute := sender.Execute(t.Context(), candidate, request, options); errExecute != nil {
								t.Fatal(errExecute)
							}
							assertHomeWire(t, <-frames, wantID, "acc-team-1", "outer-old")
						}
					})
				}
			}
		}
	}
}
