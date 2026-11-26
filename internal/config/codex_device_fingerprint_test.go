package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCodexDeviceFingerprintConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields string
		mode   string
		inject *bool
	}{
		{name: "omitted"},
		{name: "off", fields: "device-fingerprint-mode: off", mode: "off"},
		{name: "device", fields: "device-fingerprint-mode: device", mode: "device"},
		{name: "case and whitespace", fields: "device-fingerprint-mode: ' DeViCe '", mode: " DeViCe "},
		{name: "empty", fields: "device-fingerprint-mode: ''"},
		{name: "null", fields: "device-fingerprint-mode: null"},
		{name: "unknown remains disabled by resolver", fields: "device-fingerprint-mode: full", mode: "full"},
		{name: "explicit false", fields: "device-fingerprint-inject-missing: false", inject: new(false)},
		{name: "null injection", fields: "device-fingerprint-inject-missing: null"},
		{name: "explicit true", fields: "device-fingerprint-inject-missing: true", inject: new(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prefix := range []string{"codex: {", "oauth: {providers: {codex: {"} {
				raw := prefix + tc.fields + strings.Repeat("}", strings.Count(prefix, "{")) + "\n"
				cfg, err := ParseConfigBytes([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Codex.DeviceFingerprintMode != tc.mode || !reflect.DeepEqual(cfg.Codex.DeviceFingerprintInjectMissing, tc.inject) {
					t.Fatalf("configuration lost mode or optional injection: %+v", cfg.Codex)
				}
				snapshot, errMarshal := yaml.Marshal(cfg)
				if errMarshal != nil {
					t.Fatal(errMarshal)
				}
				decoded, errParse := ParseConfigBytes(snapshot)
				if errParse != nil {
					t.Fatal(errParse)
				}
				if decoded.Codex.DeviceFingerprintMode != tc.mode || !reflect.DeepEqual(decoded.Codex.DeviceFingerprintInjectMissing, tc.inject) {
					t.Fatal("YAML snapshot changed configuration intent")
				}
			}
		})
	}
}

func TestCodexDeviceFingerprintConfigScopeSaveAndMigration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "v8", true: "legacy migration"}[legacy], func(t *testing.T) {
			raw := []byte("oauth: {providers: {codex: {device-fingerprint-mode: device, device-fingerprint-inject-missing: false}}}\n")
			if legacy {
				raw = []byte("codex: {device-fingerprint-mode: device, device-fingerprint-inject-missing: false}\n")
			}
			cfg, err := ParseConfigBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			assertScope := func(value *Config) {
				t.Helper()
				for _, key := range []string{"codex.device-fingerprint-mode", "codex.device-fingerprint-inject-missing"} {
					if !value.OAuthOnlyFields[key] {
						t.Fatalf("missing OAuth scope for %s", key)
					}
				}
				api := value.ForAPIKey()
				if api.Codex.DeviceFingerprintMode != "" || api.Codex.DeviceFingerprintInjectMissing != nil {
					t.Fatal("API-key view inherited OAuth-only device settings")
				}
				if value.Codex.DeviceFingerprintMode != "device" || value.Codex.DeviceFingerprintInjectMissing == nil || *value.Codex.DeviceFingerprintInjectMissing {
					t.Fatal("API-key view mutated shared OAuth configuration")
				}
			}
			if !legacy {
				assertScope(cfg)
				assertScope(cfg.CloneForRuntime())
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if errWrite := os.WriteFile(path, raw, 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			if errSave := SaveConfigPreserveComments(path, cfg, legacy); errSave != nil {
				t.Fatal(errSave)
			}
			saved, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if errValidate := ValidateV8Config(saved); errValidate != nil {
				t.Fatalf("saved configuration is not v8: %v", errValidate)
			}
			reloaded, errLoad := LoadConfig(path)
			if errLoad != nil {
				t.Fatal(errLoad)
			}
			assertScope(cfg)
			assertScope(reloaded)
			snapshot, errMarshal := yaml.Marshal(reloaded)
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			decoded, errParse := ParseConfigBytes(snapshot)
			if errParse != nil {
				t.Fatal(errParse)
			}
			assertScope(decoded)
			var tree yaml.Node
			if errYAML := yaml.Unmarshal(saved, &tree); errYAML != nil {
				t.Fatal(errYAML)
			}
			root := tree.Content[0]
			if yamlPath(root, "oauth.providers.codex.device-fingerprint-mode") == nil || yamlPath(root, "codex.device-fingerprint-mode") != nil || yamlPath(root, "upstream.codex.device-fingerprint-mode") != nil {
				t.Fatal("device settings were saved outside oauth.providers.codex")
			}
		})
	}
}

func TestCodexDeviceFingerprintConfigV8PrecedenceAndExample(t *testing.T) {
	raw := []byte("codex: {device-fingerprint-mode: device, device-fingerprint-inject-missing: true}\noauth: {providers: {codex: {device-fingerprint-mode: off, device-fingerprint-inject-missing: false}}}\n")
	cfg, err := ParseConfigBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Codex.DeviceFingerprintMode != "off" || cfg.Codex.DeviceFingerprintInjectMissing == nil || *cfg.Codex.DeviceFingerprintInjectMissing {
		t.Fatal("explicit v8 off/false must override legacy device/true")
	}
	example, errRead := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	if errValidate := ValidateV8Config(example); errValidate != nil {
		t.Fatal(errValidate)
	}
	defaults, errParse := ParseConfigBytes(example)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if defaults.Codex.DeviceFingerprintMode != "off" || defaults.Codex.DeviceFingerprintInjectMissing == nil || *defaults.Codex.DeviceFingerprintInjectMissing {
		t.Fatal("example must explicitly disable convergence and injection")
	}
	if errValidate := ValidateV8Config([]byte("upstream: {codex: {device-fingerprint-mode: device}}")); errValidate == nil {
		t.Fatal("device configuration must not be accepted under upstream.codex")
	}
}
