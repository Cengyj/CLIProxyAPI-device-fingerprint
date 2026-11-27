package codex

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSIWCRefreshReceiptKeepsCallerDevice(t *testing.T) {
	const firstDevice = "11111111-2222-4333-8444-555555555555"
	const nextDevice = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Get("refresh_token") != "device-receipt-grant" {
					t.Error("unexpected grant submitted")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"renewed-access","refresh_token":"renewed-grant","expires_in":7200,"scope":"openid chatgpt.tokens.use.direct"}`))
			}))
			t.Cleanup(server.Close)
			t.Cleanup(OverrideSIWCTokenEndpointURLForTest(server.URL))
			var journal RefreshJournal = &memoryRefreshJournal{}
			dir := t.TempDir()
			makeClient := func() *CodexAuth {
				client := NewCodexAuth(nil)
				if persistent {
					client.SetRefreshJournal(&FileRefreshJournal{Dir: dir})
				} else {
					client.SetRefreshJournal(journal)
				}
				return client
			}
			first, err := makeClient().RefreshSIWCTokens(t.Context(), "device-receipt-grant", "oaiapp_device", firstDevice)
			if err != nil {
				t.Fatal(err)
			}
			for _, device := range []string{nextDevice, ""} {
				current, err := makeClient().RefreshSIWCTokens(t.Context(), "device-receipt-grant", "oaiapp_device", device)
				if err != nil {
					t.Fatal(err)
				}
				if current.DeviceID != device {
					t.Errorf("receipt replaced caller device: got %q, want %q", current.DeviceID, device)
				}
				if current.AccessToken != "renewed-access" || current.RefreshToken != "renewed-grant" {
					t.Error("receipt lost the recovered token pair")
				}
			}
			if calls.Load() != 1 || first.DeviceID != firstDevice {
				t.Errorf("recovery replayed grant or mutated first result: calls=%d device=%q", calls.Load(), first.DeviceID)
			}
		})
	}
}
