package executor

import (
	"sync"
	"testing"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestClaudeSetupTokenMetadataFlags(t *testing.T) {
	const bearer = "sk-ant-oat-setup-metadata-probe"
	for _, key := range []string{"skip_account_profile", "is_setup_token", "setup_token"} {
		t.Run(key, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				value any
				want  bool
			}{
				{name: "true", value: true, want: true},
				{name: "false", value: false},
				{name: "null", value: nil},
				{name: "string", value: "true"},
				{name: "number", value: 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					auth := &cliproxyauth.Auth{Metadata: map[string]any{key: tc.value}}
					if got := isClaudeSetupToken(auth, bearer); got != tc.want {
						t.Fatalf("setup flag = %t, want %t", got, tc.want)
					}
					if isClaudeSetupToken(auth, "ordinary-api-key") {
						t.Fatal("setup flag affected an API-key credential")
					}
				})
			}
		})
	}
	for _, auth := range []*cliproxyauth.Auth{nil, {}, {Metadata: map[string]any{}}} {
		if isClaudeSetupToken(auth, bearer) {
			t.Fatal("missing setup metadata was treated as enabled")
		}
	}
}

func TestClaudeSetupTokenConcurrentMetadataReads(t *testing.T) {
	for _, key := range []string{"skip_account_profile", "is_setup_token", "setup_token"} {
		t.Run(key, func(t *testing.T) {
			auth := &cliproxyauth.Auth{Metadata: map[string]any{key: true}}
			start := make(chan struct{})
			var workers sync.WaitGroup
			workers.Add(2)
			go func() {
				defer workers.Done()
				<-start
				for range 4096 {
					claudeauth.StoreMetadataString(&auth.Metadata, "account_uuid", "profile-account")
				}
			}()
			go func() {
				defer workers.Done()
				<-start
				for range 4096 {
					if !isClaudeSetupToken(auth, "sk-ant-oat-setup-metadata-probe") {
						t.Error("setup flag changed during unrelated profile writes")
						return
					}
				}
			}()
			close(start)
			workers.Wait()
		})
	}
}
