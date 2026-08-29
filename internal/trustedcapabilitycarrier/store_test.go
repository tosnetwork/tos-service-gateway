package trustedcapabilitycarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixedEpoch uint64

func (epoch fixedEpoch) CheckSourceState(_ context.Context, _ string, generation, _ uint64, commitment []byte) error {
	if uint64(epoch) != generation || len(commitment) != 32 {
		return context.Canceled
	}
	return nil
}

func TestCarrierRetainsObjectWithoutAuthorityClaim(t *testing.T) {
	store, err := New("carrier:test", 1, func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatal(err)
	}
	wire, err := newTestObject()
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Publish(wire, []string{"review", "security"}, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	if record.Provenance != "carrier-retained-unverified-object" {
		t.Fatal("Carrier asserted authority")
	}
	page, err := store.Search("security", 0, 10)
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestDurableCarrierPreservesCursorAndSignsCoverage(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	root := filepath.Join(t.TempDir(), "carrier")
	store, err := Open(root, "carrier:test", 7, func() time.Time { return time.Unix(100, 0) }, key, fixedEpoch(7))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := newTestObject()
	record, err := store.PublishForPrincipal("principal:a", wire, []string{"security"}, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Search("security", 0, 10)
	if err != nil || VerifySnapshot(page.Snapshot) != nil || !EqualSnapshotContent(page) || page.Snapshot.HighWater != record.Sequence {
		t.Fatalf("invalid signed page: %+v %v", page, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, "carrier:test", 7, func() time.Time { return time.Unix(101, 0) }, key, fixedEpoch(7))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	resumed, err := reopened.Search("security", record.Sequence, 10)
	if err != nil || resumed.Snapshot.CursorReset || resumed.Snapshot.HighWater != record.Sequence {
		t.Fatalf("cursor continuity failed: %+v %v", resumed, err)
	}
	reset, err := reopened.Search("security", record.Sequence+1, 10)
	if err != nil || !reset.Snapshot.CursorReset || reset.Complete {
		t.Fatal("out-of-range cursor did not expose reset")
	}
}

func TestCarrierHTTPChargesAuthenticatedPrincipal(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	store, err := Open(filepath.Join(t.TempDir(), "carrier"), "carrier:test", 1, time.Now, key, fixedEpoch(1))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := Handler(store, func(request *http.Request, _ bool) (string, error) {
		return request.Header.Get("X-Test-Principal"), nil
	})
	wire, _ := newTestObject()
	body, _ := json.Marshal(map[string]any{"canonical": wire, "keywords": []string{"security"}, "publisher_hint": "publisher"})
	request := httptest.NewRequest(http.MethodPost, "/v1/capability-objects", bytes.NewReader(body))
	request.Header.Set("X-Test-Principal", "principal:a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || store.principalEntries["principal:a"] != 1 || store.principalEntries["anonymous"] != 0 {
		t.Fatalf("principal quota not charged: status=%d quotas=%v", response.Code, store.principalEntries)
	}
}

func TestDurableCarrierFencesSecondWriter(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	root := filepath.Join(t.TempDir(), "carrier")
	first, err := Open(root, "carrier:test", 1, time.Now, key, fixedEpoch(1))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Open(root, "carrier:test", 1, time.Now, key, fixedEpoch(1)); err == nil {
		_ = second.Close()
		t.Fatal("second Carrier writer was not fenced")
	}
}

func TestDurableCarrierRejectsRestoredSameGenerationFork(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	base := t.TempDir()
	root := filepath.Join(base, "carrier")
	authority, err := OpenFileEpochAuthority(filepath.Join(base, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(root, "carrier:test", 3, time.Now, key, authority)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := os.ReadFile(filepath.Join(root, "carrier-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := newTestObject()
	if _, err := store.Publish(wire, []string{"security"}, "publisher"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "carrier-state.json"), genesis, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, "carrier:test", 3, time.Now, key, authority); err == nil {
		t.Fatal("same-generation restored Carrier state was accepted")
	}
	_ = authority.Close()
}
