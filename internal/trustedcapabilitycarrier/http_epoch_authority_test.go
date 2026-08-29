package trustedcapabilitycarrier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func TestExternalEpochAuthorityRejectsCoordinatedCarrierDirectoryRestore(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	recoveryKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	lease := GenerationLease{CarrierID: "carrier:test", Generation: 1, IssuedAtUnix: 90, ExpiresAtUnix: 200, Nonce: bytes.Repeat([]byte{7}, 32)}
	message, _ := GenerationLeaseMessage(lease)
	lease.Signature = ed25519.Sign(recoveryKey, message)
	var mu sync.Mutex
	state := sourceState{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/carrier-source-state" || request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		if readErr != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		var input struct {
			CarrierID             string `json:"carrier_id"`
			Generation            uint64 `json:"generation"`
			Sequence              uint64 `json:"sequence"`
			Commitment            string `json:"commitment"`
			GenerationLeaseDigest string `json:"generation_lease_digest"`
			Challenge             string `json:"challenge"`
		}
		if json.Unmarshal(raw, &input) != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if state.Generation == input.Generation && input.Sequence < state.Sequence {
			http.Error(response, "rollback", http.StatusConflict)
			return
		}
		state.Generation, state.Sequence = input.Generation, input.Sequence
		requestDigest := sha256.Sum256(append([]byte("tos.capability-carrier-source-state-request.v1\x00"), raw...))
		output := SourceStateAcknowledgement{CarrierID: input.CarrierID, Generation: input.Generation, Sequence: input.Sequence, Commitment: input.Commitment,
			GenerationLeaseDigest: input.GenerationLeaseDigest, Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), Nonce: bytes.Repeat([]byte{10}, 32)}
		output.Signature = ed25519.Sign(recoveryKey, SourceStateAcknowledgementMessage(output))
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPEpochAuthority(server.URL+"/v1/carrier-source-state", token, lease, recoveryKey.Public().(ed25519.PublicKey), time.Unix(100, 0), client)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "carrier")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	store, err := Open(root, "carrier:test", 1, time.Now, key, authority)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := newTestObject()
	if _, err := store.Publish(object, []string{"test"}, "publisher"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The external service still holds sequence 1. A restored carrier snapshot
	// at sequence 0 cannot restore that service with the local directory.
	if err := authority.CheckSourceState(t.Context(), "carrier:test", 1, 0, make([]byte, 32)); err == nil {
		t.Fatal("external authority accepted a coordinated local rollback")
	}
}

func TestExternalEpochAuthorityRejectsSignedAcknowledgementReplay(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	lease := GenerationLease{CarrierID: "carrier:replay", Generation: 1, IssuedAtUnix: 90, ExpiresAtUnix: 200, Nonce: bytes.Repeat([]byte{13}, 32)}
	message, _ := GenerationLeaseMessage(lease)
	lease.Signature = ed25519.Sign(key, message)
	var cached SourceStateAcknowledgement
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		if cached.CarrierID != "" {
			_ = json.NewEncoder(response).Encode(cached)
			return
		}
		var input struct {
			CarrierID             string `json:"carrier_id"`
			Commitment            string `json:"commitment"`
			GenerationLeaseDigest string `json:"generation_lease_digest"`
			Challenge             string `json:"challenge"`
			Generation            uint64 `json:"generation"`
			Sequence              uint64 `json:"sequence"`
		}
		if json.Unmarshal(raw, &input) != nil {
			http.Error(response, "bad", http.StatusBadRequest)
			return
		}
		requestDigest := sha256.Sum256(append([]byte("tos.capability-carrier-source-state-request.v1\x00"), raw...))
		cached = SourceStateAcknowledgement{CarrierID: input.CarrierID, Generation: input.Generation, Sequence: input.Sequence, Commitment: input.Commitment,
			GenerationLeaseDigest: input.GenerationLeaseDigest, Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), Nonce: bytes.Repeat([]byte{14}, 32)}
		cached.Signature = ed25519.Sign(key, SourceStateAcknowledgementMessage(cached))
		_ = json.NewEncoder(response).Encode(cached)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPEpochAuthority(server.URL+"/v1/carrier-source-state", token, lease, key.Public().(ed25519.PublicKey), time.Unix(100, 0), client)
	if err != nil {
		t.Fatal(err)
	}
	commitment := bytes.Repeat([]byte{15}, 32)
	if err = authority.CheckSourceState(t.Context(), lease.CarrierID, 1, 0, commitment); err != nil {
		t.Fatal(err)
	}
	if err = authority.CheckSourceState(t.Context(), lease.CarrierID, 1, 0, commitment); err == nil {
		t.Fatal("signed acknowledgement replay survived a fresh client challenge")
	}
}

func newTestObject() ([]byte, error) {
	body, err := trusted.NewConformanceBodyValue("artifact", 7)
	if err != nil {
		return nil, err
	}
	object, err := trusted.NewObject(trusted.DomainOwnerLocal, []byte("domain"), "artifact", body)
	if err != nil {
		return nil, err
	}
	return trusted.EncodeObject(object)
}
