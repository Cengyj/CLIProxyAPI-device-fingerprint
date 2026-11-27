package helps

import (
	"fmt"
	"sync"
	"testing"
)

func TestCodexDeviceFingerprintConcurrentRegistrationHints(t *testing.T) {
	var resolver CodexDeviceResolver
	cfg := codexDeviceTestConfig()
	first := codexDeviceTestAuth("shared-record", "acc-team-1")
	first.RegistrationEpoch = 1
	first.Metadata["plan_type"] = "team"
	first.Metadata["chatgpt_user_id"] = "user-aaa"
	second := first.Clone()
	second.RegistrationEpoch = 3
	second.Metadata["chatgpt_user_id"] = "user-bbb"
	resolver.Resolve(cfg, first, false, codexDeviceTestURL)
	resolver.Resolve(cfg, second, false, codexDeviceTestURL)
	delete(first.Metadata, "chatgpt_user_id")
	delete(second.Metadata, "chatgpt_user_id")
	start := make(chan struct{})
	var work sync.WaitGroup
	for worker := range 16 {
		work.Go(func() {
			<-start
			auth, want := first, "2d1c341a-5607-4894-ae5e-6cf59c2e7dde"
			if worker%2 == 1 {
				auth, want = second, "fd5de10e-f853-4dd0-92f4-ece041b115a9"
			}
			for range 32 {
				if got := resolver.Resolve(cfg, auth, false, codexDeviceTestURL).ID; got != want {
					t.Errorf("registration %d borrowed another member: %q", auth.RegistrationEpoch, got)
					return
				}
			}
		})
	}
	close(start)
	work.Wait()
	// Repeated registrations retain the existing cache bound, even when each
	// generation has an in-flight request still holding an older snapshot.
	for epoch := uint64(4); epoch < 600; epoch++ {
		auth := first.Clone()
		auth.RegistrationEpoch = epoch
		auth.Metadata["chatgpt_user_id"] = "user-aaa"
		resolver.Resolve(cfg, auth, false, codexDeviceTestURL)
	}
	if len(resolver.entries) != 512 || resolver.recent.Len() != 512 {
		t.Fatal("registration isolation removed the identity-cache capacity bound")
	}
	if resolver.entries[codexDeviceCacheKey{id: "shared-record", registrationEpoch: 1}] != nil {
		t.Fatal("old registration was not evicted")
	}
}

func TestCodexDeviceFingerprintLateVersionDoesNotReadCurrentHints(t *testing.T) {
	var resolver CodexDeviceResolver
	cfg := codexDeviceTestConfig()
	current := codexDeviceTestAuth("commercial-readd.json", "acc-team-1")
	current.RegistrationEpoch, current.CredentialVersion = 1, 2
	current.Metadata["plan_type"] = "team"
	current.Metadata["chatgpt_user_id"] = "user-bbb"
	resolver.Resolve(cfg, current, false, codexDeviceTestURL)
	oldSparse := current.Clone()
	oldSparse.CredentialVersion = 1
	delete(oldSparse.Metadata, "chatgpt_user_id")
	if got := resolver.Resolve(cfg, oldSparse, false, codexDeviceTestURL).ID; got != "1f7c8a7d-7eeb-467e-ab70-17efd065999f" {
		t.Fatalf("old credential borrowed current member: %q", got)
	}
	delete(current.Metadata, "chatgpt_user_id")
	if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL).ID; got != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
		t.Fatalf("old request displaced current member hint: %q", got)
	}
	// A normal renewal retains compatible warm hints when the current fence
	// is known. This must not degrade merely because the token version advanced.
	current.CredentialVersion++
	current.Generation++
	if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL).ID; got != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
		t.Fatalf("compatible renewal lost the current member hint: %q", got)
	}
}

func TestCodexDeviceFingerprintEvictionHistoryRemainsBounded(t *testing.T) {
	var resolver CodexDeviceResolver
	cfg := codexDeviceTestConfig()
	old := codexDeviceTestAuth("commercial-readd.json", "acc-team-1")
	old.RegistrationEpoch, old.CredentialVersion, old.Generation = 1, 1, 1
	old.Metadata["plan_type"] = "team"
	old.Metadata["chatgpt_user_id"] = "user-aaa"
	current := old.Clone()
	current.CredentialVersion, current.Generation = 2, 2
	current.Metadata["chatgpt_user_id"] = "user-bbb"
	resolver.Resolve(cfg, current, false, codexDeviceTestURL)
	// Repeated churn must not reset the history of a discarded ordering fence.
	for i := range 8192 {
		other := current.Clone()
		other.ID = fmt.Sprintf("long-lived-churn-%d", i)
		resolver.Resolve(cfg, other, false, codexDeviceTestURL)
	}
	resolver.Resolve(cfg, old, false, codexDeviceTestURL)
	delete(current.Metadata, "chatgpt_user_id")
	if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL).ID; got != "1f7c8a7d-7eeb-467e-ab70-17efd065999f" {
		t.Fatalf("long-lived eviction restored an old member: %q", got)
	}
	// Supplying a confirmed current identity restores normal same-snapshot
	// recovery even for a record whose earlier ordering fence was evicted.
	current.Metadata["chatgpt_user_id"] = "user-bbb"
	resolver.Resolve(cfg, current, false, codexDeviceTestURL)
	delete(current.Metadata, "chatgpt_user_id")
	if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL).ID; got != "fd5de10e-f853-4dd0-92f4-ece041b115a9" {
		t.Fatalf("confirmed current member did not recover after eviction: %q", got)
	}
	if len(resolver.entries) != 512 || resolver.recent.Len() != 512 {
		t.Fatal("long-lived cache history exceeded the identity-entry bound")
	}
}

func TestCodexDeviceFingerprintClearedAccountKeepsExplicitSocketMember(t *testing.T) {
	var resolver CodexDeviceResolver
	cfg := codexDeviceTestConfig()
	first := codexDeviceTestAuth("cleared-socket-member", "")
	first.RegistrationEpoch, first.CredentialVersion, first.Generation = 1, 1, 1
	first.Metadata["id_token"] = ""
	first.Metadata["access_token"] = "opaque-access"
	first.Metadata["chatgpt_user_id"] = "user-aaa"
	first.Metadata["codex_installation_id"] = codexDeviceTestID
	firstPolicy := resolver.Resolve(cfg, first, false, codexDeviceTestURL)
	second := first.Clone()
	second.Generation++
	second.Metadata["chatgpt_user_id"] = "user-bbb"
	secondPolicy := resolver.Resolve(cfg, second, false, codexDeviceTestURL)
	if firstPolicy.ID != codexDeviceTestID || secondPolicy.ID != codexDeviceTestID {
		t.Fatal("explicit installation override was changed")
	}
	if firstPolicy.Identity(nil, nil).CompatibleHandshake(secondPolicy.Identity(nil, nil)) {
		t.Fatal("clearing account hints erased an explicit changed socket member")
	}
}

func TestCodexDeviceFingerprintVersionedClearSurvivesLateSnapshot(t *testing.T) {
	for _, warmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "warm"}[warmed], func(t *testing.T) {
			var resolver CodexDeviceResolver
			cfg := codexDeviceTestConfig()
			old := codexDeviceTestAuth("commercial-readd.json", "acc-team-1")
			old.RegistrationEpoch, old.CredentialVersion = 1, 1
			old.Metadata["plan_type"] = "team"
			old.Metadata["chatgpt_user_id"] = "user-aaa"
			if warmed {
				resolver.Resolve(cfg, old, false, codexDeviceTestURL)
			}
			cleared := old.Clone()
			cleared.CredentialVersion = 2
			cleared.Metadata = map[string]any{"account_id": "", "id_token": ""}
			resolver.Resolve(cfg, cleared, false, codexDeviceTestURL)
			resolver.Resolve(cfg, old, false, codexDeviceTestURL)
			cleared.Metadata = map[string]any{}
			if got := resolver.Resolve(cfg, cleared, false, codexDeviceTestURL).ID; got != "1f7c8a7d-7eeb-467e-ab70-17efd065999f" {
				t.Fatalf("late pre-clear snapshot restored removed identity: %q", got)
			}
		})
	}
}

func TestCodexDeviceFingerprintLateSnapshotAfterCacheEviction(t *testing.T) {
	for _, metadataOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "credential-version", true: "metadata-generation"}[metadataOnly], func(t *testing.T) {
			var resolver CodexDeviceResolver
			cfg := codexDeviceTestConfig()
			old := codexDeviceTestAuth("commercial-readd.json", "acc-team-1")
			old.RegistrationEpoch, old.CredentialVersion, old.Generation = 1, 1, 1
			old.Metadata["plan_type"] = "team"
			old.Metadata["chatgpt_user_id"] = "user-aaa"
			current := old.Clone()
			current.Generation = 2
			if !metadataOnly {
				current.CredentialVersion = 2
			}
			current.Metadata["chatgpt_user_id"] = "user-bbb"
			resolver.Resolve(cfg, current, false, codexDeviceTestURL)
			for i := range 512 {
				other := current.Clone()
				other.ID = fmt.Sprintf("churn-%d", i)
				resolver.Resolve(cfg, other, false, codexDeviceTestURL)
			}
			resolver.Resolve(cfg, old, false, codexDeviceTestURL)
			delete(current.Metadata, "chatgpt_user_id")
			// Losing the current hint permits the documented cold fallback,
			// never recovery from an older credential that arrives later.
			if got := resolver.Resolve(cfg, current, false, codexDeviceTestURL).ID; got != "1f7c8a7d-7eeb-467e-ab70-17efd065999f" {
				t.Fatalf("eviction restored a removed member identity: %q", got)
			}
			if len(resolver.entries) > 512 || resolver.recent.Len() > 512 {
				t.Fatal("version isolation exceeded the cache bound")
			}
		})
	}
}
