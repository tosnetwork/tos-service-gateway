package intentcarrier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestOutcomeHTTPBoundaryIsAuthorizedStrictAndBounded(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	now := time.Unix(2_000_000_000, 0).UTC()
	store, err := Open(directory, "carrier:http-outcome", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.now = func() time.Time { return now }
	request, action, fence := authorizedOutcomePublication(t, store, authorityKey, now)
	canonical, _ := codec.Marshal(request)
	challenge, err := store.IssueAdmissionFor("operation.publish", outcomeActorID(), "public", uint64(len(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(struct {
		Submission commerce.OperationCarrierSubmissionV1 `json:"submission"`
		Admission  commerce.OperationAdmissionProof      `json:"admission"`
	}{commerce.OperationCarrierSubmissionV1{Request: request, AuthorizedAction: action, WriterFence: fence}, proof})
	handler := Handler(store, testHTTPAuth{})

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/operations?limit=1", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	post := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewReader(body))
	post.Header.Set("Authorization", "Bearer relay")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}

	query := httptest.NewRequest(http.MethodGet, "/v1/operations?limit=1", nil)
	query.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, query)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), request.OperationEnvelopeDigest) {
		t.Fatalf("search status=%d body=%s", response.Code, response.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewReader(append(body, []byte(` {"trailing":true}`)...)))
	bad.Header.Set("Authorization", "Bearer relay")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, bad)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status=%d", response.Code)
	}

	bounded := httptest.NewRequest(http.MethodGet, "/v1/operations/subscribe?limit=1&wait_seconds=26", nil)
	bounded.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, bounded)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unbounded subscription status=%d", response.Code)
	}

	badQuery := httptest.NewRequest(http.MethodGet, "/v1/operations?limit=1001", nil)
	badQuery.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, badQuery)
	if response.Code != http.StatusBadRequest || response.Header().Get("X-TOS-Error-Code") == "" {
		t.Fatalf("stable error status=%d headers=%v", response.Code, response.Header())
	}
}

func TestOutcomeCarrierRetainsExactAssertionsWithoutBecomingAuthority(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	store, err := Open(directory, "carrier:outcome", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	request := outcomeCarrierRequest(t, store, now)
	canonical, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: outcomeActorID(),
		InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Second).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), AuthorityID: "authority:test", Scope: []string{"operation.publish"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1("owner:test", outcomeActorID(), request)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:test", outcomeActorID(), "operation.publish", fields, canonical, fence, 1,
		"sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(action, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.IssueAdmissionFor("operation.publish", outcomeActorID(), "public", uint64(len(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	result, resolution, err := store.PublishOutcomeAdmitted(request, proof, action, fence)
	if err != nil || resolution.State != commerce.ActionTerminal || result.Provenance != "carrier-retained-unverified-assertion" {
		t.Fatalf("result=%+v resolution=%+v err=%v", result, resolution, err)
	}
	if retry, retryResolution, err := store.PublishOutcomeAdmitted(request, proof, action, fence); err != nil || retry.Request.OperationEnvelopeDigest != result.Request.OperationEnvelopeDigest || retryResolution.State != commerce.ActionTerminal {
		t.Fatalf("retry failed: %v", err)
	}
	page, err := store.SearchOutcomes(OutcomeQuery{EventKinds: []commerce.OperationOutcomeEventKind{commerce.OutcomeObservation},
		SubjectProfileURI: "tos.subject.test.v1", ActorAgentID: outcomeActorID(), Limit: 10})
	if err != nil || len(page.Results) != 1 || page.Results[0].Provenance != "carrier-retained-unverified-assertion" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if _, err := store.GetOutcome(request.OperationEnvelopeDigest); err != nil {
		t.Fatal(err)
	}
	path := store.outcomePath(request.OperationEnvelopeDigest)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(append([]byte(nil), raw...), []byte(" {}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetOutcome(request.OperationEnvelopeDigest); err == nil {
		t.Fatal("stored outcome accepted trailing JSON")
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SearchOutcomes(OutcomeQuery{SubjectID: strings.Repeat("x", 4097), Limit: 1}); err == nil {
		t.Fatal("oversized outcome query was accepted")
	}
	var corrupted OutcomeResult
	if err := json.Unmarshal(raw, &corrupted); err != nil {
		t.Fatal(err)
	}
	corrupted.Receipt.SinkProof[0] ^= 0xff
	raw, _ = json.Marshal(corrupted)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SearchOutcomes(OutcomeQuery{Limit: 1}); err == nil {
		t.Fatal("search silently omitted a retained record with a forged receipt")
	}
	if _, err := store.ResolveOutcomeAction(action.StableActionID, action.ExactRequestDigest); err == nil {
		t.Fatal("terminal Action concealed corrupt retained Outcome bytes")
	}
}

func TestOutcomeCarrierRebuildsFromExactRetainedCorpusAfterDatabaseLoss(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := testAuthorityKey(t)
	now := time.Unix(2_000_000_000, 0).UTC()
	store, err := Open(directory, "carrier:rebuild", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	request, action, fence := authorizedOutcomePublication(t, store, authorityKey, now)
	publishOutcomeForTest(t, store, request, action, fence)
	keyBackup, err := os.ReadFile(filepath.Join(directory, ".carrier-admission-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate loss of the Carrier database. Identity-key recovery is explicit:
	// a deployment that loses both retained corpus and its pinned Carrier key
	// cannot make a continuity claim.
	if err = os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, ".carrier-admission-ed25519"), keyBackup, 0o600); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := Open(directory, "carrier:rebuild", 10, 10, PinnedAuthorities{"authority:test": authorityKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.Close()
	rebuilt.now = func() time.Time { return now }
	publishOutcomeForTest(t, rebuilt, request, action, fence)
	page, err := rebuilt.SearchOutcomes(OutcomeQuery{Limit: 10})
	if err != nil || len(page.Results) != 1 || page.Results[0].Request.OperationEnvelopeDigest != request.OperationEnvelopeDigest {
		t.Fatalf("rebuild page=%+v err=%v", page, err)
	}
}

func authorizedOutcomePublication(t *testing.T, store *Store, authorityKey ed25519.PrivateKey, now time.Time) (commerce.OperationCarrierRequestV1, commerce.AuthorizedAction, commerce.WriterFence) {
	t.Helper()
	request := outcomeCarrierRequest(t, store, now)
	canonical, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: outcomeActorID(),
		InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Second).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), AuthorityID: "authority:test", Scope: []string{"operation.publish"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1("owner:test", outcomeActorID(), request)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:test", outcomeActorID(), "operation.publish", fields, canonical, fence, 1,
		"sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err == nil {
		action, err = commerce.SignAuthorizedAction(action, authorityKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	return request, action, fence
}

func publishOutcomeForTest(t *testing.T, store *Store, request commerce.OperationCarrierRequestV1, action commerce.AuthorizedAction, fence commerce.WriterFence) {
	t.Helper()
	canonical, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.IssueAdmissionFor("operation.publish", outcomeActorID(), "public", uint64(len(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	if _, resolution, err := store.PublishOutcomeAdmitted(request, proof, action, fence); err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("publish resolution=%+v err=%v", resolution, err)
	}
}

func outcomeActorID() string { return "agent:" + strings.Repeat("a", 64) }

func outcomeCarrierRequest(t *testing.T, store *Store, now time.Time) commerce.OperationCarrierRequestV1 {
	t.Helper()
	assertion, _ := codec.Marshal(commerce.ActionResolutionReferencePayloadV1{
		StableActionID: "sha256:" + strings.Repeat("5", 64), ExactRequestDigest: "sha256:" + strings.Repeat("6", 64),
		AuthorizedActionDigest: "sha256:" + strings.Repeat("7", 64), ActionResolutionDigest: "sha256:" + strings.Repeat("8", 64),
		ResolutionState: commerce.ActionTerminal, ResolutionStateRevision: 1})
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.test.v1", SubjectID: "subject:test"}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertion, commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"), commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: outcomeActorID(), AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: "sha256:" + strings.Repeat("2", 64)},
		AudienceDescriptor: "public", ObjectID: contentID, OrderingDomain: "outcome:test", Epoch: 1, Sequence: 1, CreatedAtUnix: uint64(now.Unix()),
		PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, body.ActorAgentID, key, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return commerce.OperationCarrierRequestV1{SchemaVersion: 1, CarrierID: store.carrierID,
		CarrierProfile:       commerce.ProfileRefV1{ProfileURI: "tos.carrier.outcome.v1", ProfileVersion: 1, ProfileDigest: "sha256:" + strings.Repeat("3", 64)},
		AudiencePolicyDigest: "sha256:" + strings.Repeat("4", 64), OperationID: body.OperationID,
		OperationEnvelopeDigest: envelopeDigest, OperationEnvelope: envelopeBytes, EventPayload: eventPayload,
		Artifacts: commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion,
			EvidenceManifest: commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"), ExtensionSet: commerce.EmptyOutcomeExtensionSetV1(),
			AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}}
}
