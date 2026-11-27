package helps

import (
	"bytes"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

// FuzzCodexDeviceFingerprintPayload checks the wire contract independently of
// identity derivation: convergence is idempotent and preserves unrelated JSON.
func FuzzCodexDeviceFingerprintPayload(f *testing.F) {
	for _, metadata := range []string{
		`{}`,
		`null`,
		`[]`,
		`[] `,
		`{"x-codex-installation-id":null,"keep":900719925474099312345}`,
		`{"x-codex-installation-id":"one","x-codex-installation-\u0069d":"two","keep":{"a":1,"a":2}}`,
		`{"x-codex-turn-metadata":"{\"installation_id\":\"old\",\"keep\":900719925474099312345}"}`,
		`{"x-codex-turn-metadata":"invalid","keep":"你好\\tail"}`,
		`{"x-codex-turn-metadata":"{}","x-codex-turn-metadata":null}`,
	} {
		f.Add(metadata, true, false, false)
		f.Add(metadata, true, true, false)
		f.Add(metadata, true, false, true)
		f.Add(metadata, false, false, false)
	}
	f.Fuzz(func(t *testing.T, metadata string, inject, siwc, control bool) {
		if len(metadata) > 32768 || !ojson.Valid(metadata) {
			return
		}
		raw := []byte(`{"client_metadata":` + metadata + `,"keep":900719925474099312345,"input":[{"text":"unchanged"}]}`)
		const id = "11111111-2222-4333-8444-555555555555"
		policy := CodexDevicePolicy{Enabled: true, ID: id, InjectMissing: inject, SIWC: siwc}
		doc := ojson.NewDoc(raw)
		if err := policy.ApplyDoc(doc, control, raw); err != nil {
			t.Fatal(err)
		}
		wire := append([]byte(nil), doc.Bytes()...)
		if !ojson.ValidBytes(wire) {
			t.Fatal("convergence produced invalid JSON")
		}
		for _, field := range []string{"keep", "input"} {
			if ojson.GetBytes(raw, field).Raw != ojson.GetBytes(wire, field).Raw {
				t.Fatalf("unrelated root field %s changed", field)
			}
		}
		before, after := ojson.GetBytes(raw, "client_metadata"), ojson.GetBytes(wire, "client_metadata")
		if !before.IsObject() {
			if before.Raw != after.Raw {
				t.Fatal("non-object metadata changed")
			}
		} else {
			unknown := func(value ojson.Result) []string {
				var fields []string
				value.ForEach(func(key, val ojson.Result) bool {
					if key.String() != "x-codex-installation-id" && key.String() != "x-codex-turn-metadata" {
						fields = append(fields, key.Raw, val.Raw)
					}
					return true
				})
				return fields
			}
			a, b := unknown(before), unknown(after)
			if len(a) != len(b) {
				t.Fatal("unrelated metadata fields were added or removed")
			}
			for i := range a {
				if a[i] != b[i] {
					t.Fatal("unrelated metadata changed value, precision, order, or escaping")
				}
			}
			countBefore, countAfter := 0, 0
			before.ForEach(func(key, _ ojson.Result) bool {
				if key.String() == "x-codex-installation-id" {
					countBefore++
				}
				return true
			})
			after.ForEach(func(key, value ojson.Result) bool {
				if key.String() == "x-codex-installation-id" {
					countAfter++
					if value.Type != ojson.String || value.Str != id {
						t.Fatal("old installation survived convergence")
					}
				}
				return true
			})
			want := 0
			if countBefore > 0 || (inject && !siwc && !control) {
				want = 1
			}
			if countAfter != want {
				t.Fatalf("installation count = %d, want %d", countAfter, want)
			}
		}
		second := ojson.NewDoc(wire)
		if err := policy.ApplyDoc(second, control, wire); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wire, second.Bytes()) {
			t.Fatal("convergence was not idempotent")
		}
	})
}
