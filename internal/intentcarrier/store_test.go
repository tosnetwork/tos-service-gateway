package intentcarrier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestCarrierPublishesSearchesAndSurvivesRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, err := Open(directory, "carrier:test", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := signedIntent(t, now)
	proof := admissionFor(t, store, intent)
	action, fence := publicationAction(t, store, intent, authorityKey)
	first, firstResolution, err := store.PublishAdmitted(intent, proof, action, fence)
	if err != nil {
		t.Fatal(err)
	}
	if firstResolution.State != commerce.ActionTerminal {
		t.Fatalf("publication resolution=%+v", firstResolution)
	}
	if retry, resolution, err := store.PublishAdmitted(intent, proof, action, fence); err != nil || retry.IntentDigest != first.IntentDigest || resolution.State != commerce.ActionTerminal {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	page, err := store.Search(Query{Modes: []commerce.IntentMode{commerce.IntentRequest}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
		TaxonomyPrefix: "tos.taxonomy.v1/service", Keywords: []string{"review"}, Limit: 5})
	if err != nil || len(page.Results) != 1 || page.CarrierID != "carrier:test" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(directory, "carrier:test", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.now = store.now
	page, err = restarted.Search(Query{Limit: 5})
	if err != nil || len(page.Results) != 1 {
		t.Fatalf("restart page=%+v err=%v", page, err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Hour) }
	if page, err = store.Search(Query{Limit: 5}); err != nil || len(page.Results) != 0 {
		t.Fatalf("expired Intent remained searchable: page=%+v err=%v", page, err)
	}
	if retained, err := store.Get(first.IntentDigest); err != nil || retained.IntentDigest != first.IntentDigest {
		t.Fatalf("expired predecessor could not be resolved: result=%+v err=%v", retained, err)
	}
}

func TestCarrierHTTPIsBoundedAndAuthorized(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, _ := Open(directory, "carrier:http", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := signedIntent(t, now)
	action, fence := publicationAction(t, store, intent, authorityKey)
	raw, _ := json.Marshal(struct {
		Intent    commerce.SignedAgentIntent       `json:"intent"`
		Admission commerce.OperationAdmissionProof `json:"admission"`
		Action    commerce.AuthorizedAction        `json:"authorized_action"`
		Fence     commerce.WriterFence             `json:"writer_fence"`
	}{intent, admissionFor(t, store, intent), action, fence})
	handler := Handler(store, testHTTPAuth{})
	request := httptest.NewRequest(http.MethodPost, "/v1/intents", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer relay")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/intents?limit=1&keyword=review", nil)
	request.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "carrier:http") {
		t.Fatalf("search status=%d body=%s", response.Code, response.Body.String())
	}
	var published struct {
		Result Result `json:"result"`
	}
	if err := json.Unmarshal(responseForPublish(t, handler, raw).Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/intents/"+strings.TrimPrefix(published.Result.IntentDigest, "sha256:"), nil)
	request.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), published.Result.IntentDigest) {
		t.Fatalf("resolve status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/intents?limit=1001", nil)
	request.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unbounded status=%d", response.Code)
	}
}

func TestCarrierWithdrawalPreservesBytesButRemovesDiscovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, err := Open(directory, "carrier:withdraw", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent, issuerKey := signedIntentWithKey(t, now)
	publication, publicationFence := publicationAction(t, store, intent, authorityKey)
	result, _, err := store.PublishAdmitted(intent, admissionFor(t, store, intent), publication, publicationFence)
	if err != nil {
		t.Fatal(err)
	}
	withdrawal, err := commerce.SignIntentWithdrawal(commerce.AgentIntentWithdrawalBody{SchemaVersion: 1,
		NetworkID: intent.Body.NetworkID, IssuerAgentID: intent.Body.IssuerAgentID, Audience: intent.Body.Audience,
		ObjectID: intent.Body.ObjectID, IntentRevision: intent.Body.Revision, IntentDigest: result.IntentDigest,
		ReasonCode: "capacity-unavailable", CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	action, fence := withdrawalAction(t, store, withdrawal, authorityKey)
	canonical, _ := protocolcodec.Marshal(withdrawal)
	challenge, err := store.IssueAdmissionFor("publication.withdraw", withdrawal.Body.IssuerAgentID,
		withdrawal.Body.Audience, uint64(len(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := store.WithdrawAdmitted(withdrawal, proof, action, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("withdrawal resolution=%+v err=%v", resolution, err)
	}
	if page, err := store.Search(Query{Limit: 10}); err != nil || len(page.Results) != 0 {
		t.Fatalf("withdrawn Intent remained discoverable: page=%+v err=%v", page, err)
	}
	if retained, err := store.Get(result.IntentDigest); err != nil || retained.IntentDigest != result.IntentDigest {
		t.Fatalf("withdrawal erased retained signed bytes: result=%+v err=%v", retained, err)
	}
}

func TestCarrierCursorFollowsPublicationOrderAndStoreIsSingleWriter(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	pins := PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)}
	store, err := Open(directory, "carrier:cursor", 10, 10, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if concurrent, err := Open(directory, "carrier:cursor", 10, 10, pins); err == nil {
		_ = concurrent.Close()
		t.Fatal("second Carrier writer acquired the same directory")
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	first, issuerKey := signedIntentWithKey(t, now)
	secondBody := first.Body
	secondBody.ObjectID = "intent:" + strings.Repeat("c", 64)
	second, err := commerce.SignIntent(secondBody, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, intent := range []commerce.SignedAgentIntent{first, second} {
		action, fence := publicationAction(t, store, intent, authorityKey)
		if _, _, err := store.PublishAdmitted(intent, admissionFor(t, store, intent), action, fence); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.Search(Query{Limit: 1})
	if err != nil || len(page.Results) != 1 || page.Results[0].CarrierSequence != 1 || page.Next != "seq:1" {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	page, err = store.Search(Query{Limit: 1, AfterCursor: 1})
	if err != nil || len(page.Results) != 1 || page.Results[0].CarrierSequence != 2 || page.Next != "seq:2" {
		t.Fatalf("second page=%+v err=%v", page, err)
	}
}

func TestCarrierActorQuotaPreventsOneIssuerFromFillingSharedCapacity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, err := Open(directory, "carrier:quota", 10, 1, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	first, issuerKey := signedIntentWithKey(t, now)
	secondBody := first.Body
	secondBody.ObjectID = "intent:" + strings.Repeat("e", 64)
	second, err := commerce.SignIntent(secondBody, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	action, fence := publicationAction(t, store, first, authorityKey)
	if _, _, err := store.PublishAdmitted(first, admissionFor(t, store, first), action, fence); err != nil {
		t.Fatal(err)
	}
	action, fence = publicationAction(t, store, second, authorityKey)
	if _, _, err := store.PublishAdmitted(second, admissionFor(t, store, second), action, fence); err == nil {
		t.Fatal("one issuer exceeded its retained-entry quota")
	}
}

func TestCarrierRejectsSameGenerationFenceEquivocation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, err := Open(directory, "carrier:fence", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	first, issuerKey := signedIntentWithKey(t, now)
	action, fence := publicationAction(t, store, first, authorityKey)
	if _, _, err := store.PublishAdmitted(first, admissionFor(t, store, first), action, fence); err != nil {
		t.Fatal(err)
	}
	secondBody := first.Body
	secondBody.ObjectID = "intent:" + strings.Repeat("f", 64)
	second, err := commerce.SignIntent(secondBody, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	equivocatedFence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test",
		AgentID: second.Body.IssuerAgentID, InstanceID: "instance:other", LeaseID: "lease:other", WriterGeneration: 1,
		IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority:test", Scope: []string{"publication.publish"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	equivocatedAction := publicationActionWithFence(t, store, second, authorityKey, equivocatedFence)
	if _, _, err := store.PublishAdmitted(second, admissionFor(t, store, second), equivocatedAction, equivocatedFence); err == nil {
		t.Fatal("Carrier admitted another authority fence at the same writer generation")
	}
}

func testAuthorityKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicationAction(t *testing.T, store *Store, intent commerce.SignedAgentIntent,
	authorityKey ed25519.PrivateKey) (commerce.AuthorizedAction, commerce.WriterFence) {
	t.Helper()
	now := store.now().UTC()
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test",
		AgentID: intent.Body.IssuerAgentID, InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 1,
		IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority:test", Scope: []string{"publication.publish"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicationActionWithFence(t, store, intent, authorityKey, fence), fence
}

func publicationActionWithFence(t *testing.T, store *Store, intent commerce.SignedAgentIntent,
	authorityKey ed25519.PrivateKey, fence commerce.WriterFence) commerce.AuthorizedAction {
	t.Helper()
	now := store.now().UTC()
	canonical, err := protocolcodec.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	operationDigest, err := protocolcodec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(intent.Body.IssuerAgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(operationDigest)}
	action, err := commerce.BuildAuthorizedAction("owner:test", intent.Body.IssuerAgentID, "publication.publish", fields,
		canonical, fence, 1, "sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(action, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func withdrawalAction(t *testing.T, store *Store, withdrawal commerce.SignedAgentIntentWithdrawal,
	authorityKey ed25519.PrivateKey) (commerce.AuthorizedAction, commerce.WriterFence) {
	t.Helper()
	now := store.now().UTC()
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test",
		AgentID: withdrawal.Body.IssuerAgentID, InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 2,
		IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority:test", Scope: []string{"publication.withdraw"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := protocolcodec.Marshal(withdrawal)
	operationDigest, _ := protocolcodec.Digest("tos.agent-intent-withdrawal-operation.v1", withdrawal)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(withdrawal.Body.IssuerAgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(withdrawal.Body.ObjectID),
		"withdrawn_revision": commerce.U64(withdrawal.Body.IntentRevision), "withdrawal_operation_digest": commerce.Digest32(operationDigest)}
	action, err := commerce.BuildAuthorizedAction("owner:test", withdrawal.Body.IssuerAgentID, "publication.withdraw", fields,
		canonical, fence, 1, "sha256:"+strings.Repeat("1", 64), "", "published", withdrawal.Body.ExpiresAtUnix)
	if err == nil {
		action, err = commerce.SignAuthorizedAction(action, authorityKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	return action, fence
}

func responseForPublish(t *testing.T, handler http.Handler, raw []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/intents", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer relay")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish retry status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}

func admissionFor(t *testing.T, store *Store, intent commerce.SignedAgentIntent) commerce.OperationAdmissionProof {
	t.Helper()
	canonical, err := protocolcodec.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.IssueAdmission(intent.Body.IssuerAgentID, intent.Body.Audience, uint64(len(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

type testHTTPAuth struct{}

func (testHTTPAuth) Authorize(header string, write bool) error {
	want := "Bearer read"
	if write {
		want = "Bearer relay"
	}
	if header != want {
		return os.ErrPermission
	}
	return nil
}

func signedIntent(t *testing.T, now time.Time) commerce.SignedAgentIntent {
	t.Helper()
	intent, _ := signedIntentWithKey(t, now)
	return intent
}

func signedIntentWithKey(t *testing.T, now time.Time) (commerce.SignedAgentIntent, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	detail := []byte("review one source tree")
	digest := sha256.Sum256(detail)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:testnet", IssuerAgentID: "agent:" + strings.Repeat("a", 64),
		Audience: "public:indexable", ObjectID: "intent:" + strings.Repeat("b", 64), Revision: 1, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{
			Summary: "Review source", IntentModes: []commerce.IntentMode{commerce.IntentRequest}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"}, Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}},
			ValueState: commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact", MinimumDecimal: "50", MaximumDecimal: "50", Unit: "total"}},
			Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:      []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: "agent:" + strings.Repeat("a", 64)}}}}
	signed, err := commerce.SignIntent(body, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, key
}
