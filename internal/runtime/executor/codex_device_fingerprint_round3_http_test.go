package executor

import (
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexDeviceFingerprintEscapedSingletonWire(t *testing.T) {
	for _, raw := range []string{
		`{"input":[],"client_\u006detadata":{"x-codex-installation-\u0069d":"old","unknown":900719925474099312345}}`,
		`{"input":[],"client_metadata":{"x-codex-turn-\u006detadata":"{\"installation_\\u0069d\":\"old\",\"unknown\":900719925474099312345}"}}`,
		`{"input":[],"client_metadata":{"x-codex-installation-id":null,"x-codex-installation-\u0069d":"old","unknown":900719925474099312345}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			server, captured := fingerprintHTTPServer(t, false)
			exec := NewCodexExecutor(&config.Config{Codex: config.CodexConfig{DeviceFingerprintMode: "device"}})
			fingerprintRunHTTP(t, t.Context(), exec, fingerprintHTTPAuth(server.URL), core.Request{Model: "gpt-5.4", Payload: []byte(raw)}, core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}, false)
			wire := <-captured
			var metadata ojson.Result
			metadataCount := 0
			ojson.ParseBytes(wire.body).ForEach(func(key, value ojson.Result) bool {
				if key.String() == "client_metadata" {
					metadata = value
					metadataCount++
				}
				return true
			})
			if metadataCount != 1 {
				t.Fatal("escaped outer object was duplicated or lost")
			}
			count := 0
			metadata.ForEach(func(key, value ojson.Result) bool {
				if key.String() == "x-codex-installation-id" {
					count++
					if value.String() != fingerprintHTTPID {
						t.Fatal("escaped installation survived on wire")
					}
				}
				if key.String() == "x-codex-turn-metadata" {
					ojson.Parse(value.String()).ForEach(func(innerKey, innerValue ojson.Result) bool {
						if innerKey.String() == "installation_id" {
							count++
							if innerValue.String() != fingerprintHTTPID {
								t.Fatal("escaped turn installation survived on wire")
							}
						}
						return true
					})
				}
				return true
			})
			if count != 1 {
				t.Fatalf("wire has %d device values, want one", count)
			}
		})
	}
}
