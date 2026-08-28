package intentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type OutcomeQuery struct {
	EventKinds           []commerce.OperationOutcomeEventKind
	AssertionProfileURIs []string
	SubjectProfileURI    string
	SubjectID            string
	ActorAgentID         string
	Limit                uint32
	AfterCursor          uint64
}

type OutcomeResult struct {
	Request          commerce.OperationCarrierRequestV1    `json:"request"`
	EventBody        commerce.OperationOutcomeEventBodyV1  `json:"event_body"`
	ActorAgentID     string                                `json:"actor_agent_id"`
	StoredAtUnix     uint64                                `json:"stored_at_unix"`
	CarrierSequence  uint64                                `json:"carrier_sequence"`
	Provenance       string                                `json:"provenance"`
	Receipt          commerce.OperationSubmissionReceiptV1 `json:"receipt"`
	CarrierPublicKey string                                `json:"carrier_public_key"`
}

type OutcomePage struct {
	CarrierID string          `json:"carrier_id"`
	Results   []OutcomeResult `json:"results"`
	Next      string          `json:"next_cursor,omitempty"`
}

type outcomeSelfResolver struct{}

func (outcomeSelfResolver) AuthorizeAgentOperationKey(string, commerce.ProfileRefV1, ed25519.PublicKey, time.Time, []byte) error {
	return nil
}

func (store *Store) ResolveOutcomeAction(actionID, requestDigest string) (commerce.ActionResolution, error) {
	resolution, err := store.ResolveAction(actionID, requestDigest)
	if err != nil || resolution.State != commerce.ActionTerminal {
		return resolution, err
	}
	if _, err = store.GetOutcome(resolution.SinkReference); err != nil {
		return commerce.ActionResolution{}, errors.New("terminal outcome publication has no valid retained record")
	}
	return resolution, nil
}

func (store *Store) PublishOutcomeAdmitted(request commerce.OperationCarrierRequestV1, proof commerce.OperationAdmissionProof,
	action commerce.AuthorizedAction, fence commerce.WriterFence) (OutcomeResult, commerce.ActionResolution, error) {
	if store == nil || commerce.ValidateOperationCarrierRequestV1(request) != nil || request.CarrierID != store.carrierID {
		return OutcomeResult{}, commerce.ActionResolution{}, errors.New("outcome Carrier request is invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil {
		return OutcomeResult{}, commerce.ActionResolution{}, errors.New("outcome envelope is not canonical")
	}
	now := store.now().UTC()
	body, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, request.EventPayload, outcomeSelfResolver{}, now)
	if err != nil {
		return OutcomeResult{}, commerce.ActionResolution{}, err
	}
	canonicalRequest, err := codec.Marshal(request)
	if err != nil {
		return OutcomeResult{}, commerce.ActionResolution{}, err
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1(action.OwnerID, action.AgentID, request)
	if err != nil {
		return OutcomeResult{}, commerce.ActionResolution{}, err
	}
	resolution, err := store.admitPublicationActionKind("operation.publish", action, fence, fields, canonicalRequest, envelope.Body.ActorAgentID, now)
	if err != nil {
		return OutcomeResult{}, resolution, err
	}
	if resolution.State == commerce.ActionTerminal {
		result, getErr := store.GetOutcome(request.OperationEnvelopeDigest)
		return result, resolution, getErr
	}
	resourceDigest, err := commerce.AdmissionResourceVectorDigest("operation.publish", uint64(len(canonicalRequest)),
		map[string]uint64{"index_entries": 1, "retained_bytes": uint64(len(canonicalRequest))})
	if err != nil || commerce.VerifyOperationAdmission(proof, store.admissionKey.Public().(ed25519.PublicKey), envelope.Body.ActorAgentID,
		"operation.publish", envelope.Body.AudienceDescriptor, uint64(len(canonicalRequest)), resourceDigest, now) != nil || proof.Challenge.Body.CarrierID != store.carrierID {
		return OutcomeResult{}, resolution, errors.New("outcome publication admission proof is invalid")
	}
	if err := store.consumeAdmission(proof.ChallengeDigest, request.OperationEnvelopeDigest); err != nil {
		return OutcomeResult{}, resolution, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := store.outcomePath(request.OperationEnvelopeDigest)
	if raw, readErr := os.ReadFile(path); readErr == nil {
		existing, decodeErr := store.decodeOutcomeResult(raw, request.OperationEnvelopeDigest)
		if decodeErr != nil {
			return OutcomeResult{}, resolution, errors.New("outcome envelope digest has invalid retained bytes")
		}
		existingRequest, marshalErr := codec.Marshal(existing.Request)
		if marshalErr == nil && bytes.Equal(existingRequest, canonicalRequest) &&
			existing.Request.OperationEnvelopeDigest == request.OperationEnvelopeDigest {
			resolution, err = store.completeActionLocked(action, request.OperationEnvelopeDigest)
			return existing, resolution, err
		}
		return OutcomeResult{}, resolution, errors.New("outcome envelope digest conflicts with retained bytes")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return OutcomeResult{}, resolution, readErr
	}
	paths, err := store.outcomePaths()
	if err != nil {
		return OutcomeResult{}, resolution, err
	}
	if len(paths) >= int(store.maxEntries) {
		return OutcomeResult{}, resolution, errors.New("outcome Carrier capacity reached")
	}
	actorEntries := uint32(0)
	for _, existingPath := range paths {
		raw, readErr := os.ReadFile(existingPath)
		if readErr != nil {
			return OutcomeResult{}, resolution, errors.New("outcome Carrier quota index is unavailable")
		}
		digest := "sha256:" + strings.TrimSuffix(strings.TrimPrefix(filepath.Base(existingPath), "outcome-"), ".json")
		existing, decodeErr := store.decodeOutcomeResult(raw, digest)
		if decodeErr != nil {
			return OutcomeResult{}, resolution, errors.New("outcome Carrier quota index contains invalid retained bytes")
		}
		if existing.ActorAgentID == envelope.Body.ActorAgentID {
			actorEntries++
		}
	}
	if actorEntries >= store.maxActorEntries {
		return OutcomeResult{}, resolution, errors.New("outcome Carrier actor quota reached")
	}
	sequence, err := store.nextSequenceLocked()
	if err != nil {
		return OutcomeResult{}, resolution, err
	}
	result := OutcomeResult{Request: request, EventBody: body, ActorAgentID: envelope.Body.ActorAgentID,
		StoredAtUnix: uint64(now.Unix()), CarrierSequence: sequence, Provenance: "carrier-retained-unverified-assertion",
		CarrierPublicKey: "ed25519:" + hex.EncodeToString(store.admissionKey.Public().(ed25519.PublicKey))}
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", request.Artifacts)
	if err != nil {
		return OutcomeResult{}, resolution, err
	}
	result.Receipt, err = commerce.SignOperationSubmissionReceiptV1(commerce.OperationSubmissionReceiptV1{SchemaVersion: 1,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest, State: commerce.ActionTerminal,
		SinkID: store.carrierID, SinkReference: request.OperationEnvelopeDigest, AuthorityTimeUnix: uint64(now.Unix()),
		StateRevision: 2, EvidenceDigest: artifactDigest}, store.admissionKey)
	if err != nil {
		return OutcomeResult{}, resolution, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
		return OutcomeResult{}, resolution, errors.New("outcome exceeds Carrier storage bound")
	}
	if err := writeExclusive(path, raw); err != nil {
		return OutcomeResult{}, resolution, err
	}
	resolution, err = store.completeActionLocked(action, request.OperationEnvelopeDigest)
	return result, resolution, err
}

func (store *Store) GetOutcome(envelopeDigest string) (OutcomeResult, error) {
	if store == nil || !canonicalDigest(envelopeDigest) {
		return OutcomeResult{}, errors.New("outcome envelope digest is invalid")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	raw, err := os.ReadFile(store.outcomePath(envelopeDigest))
	if err != nil {
		return OutcomeResult{}, err
	}
	if len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
		return OutcomeResult{}, errors.New("stored outcome is oversized")
	}
	return store.decodeOutcomeResult(raw, envelopeDigest)
}

func (store *Store) SearchOutcomes(query OutcomeQuery) (OutcomePage, error) {
	if store == nil || !validOutcomeQuery(query) {
		return OutcomePage{}, errors.New("outcome Carrier query is invalid or unbounded")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	paths, err := store.outcomePaths()
	if err != nil {
		return OutcomePage{}, err
	}
	results := make([]OutcomeResult, 0, query.Limit)
	for _, path := range paths {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return OutcomePage{}, errors.New("outcome Carrier retained record is unavailable")
		}
		digest := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "outcome-"), ".json")
		value, decodeErr := store.decodeOutcomeResult(raw, "sha256:"+digest)
		if decodeErr != nil {
			return OutcomePage{}, decodeErr
		}
		if value.CarrierSequence <= query.AfterCursor || !matchesOutcome(value, query) {
			continue
		}
		results = append(results, value)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CarrierSequence < results[j].CarrierSequence })
	page := OutcomePage{CarrierID: store.carrierID}
	if len(results) > int(query.Limit) {
		results = results[:query.Limit]
	}
	page.Results = results
	if len(results) == int(query.Limit) {
		page.Next = "seq:" + strconv.FormatUint(results[len(results)-1].CarrierSequence, 10)
	}
	return page, nil
}

func (store *Store) decodeOutcomeResult(raw []byte, envelopeDigest string) (OutcomeResult, error) {
	if len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
		return OutcomeResult{}, errors.New("stored outcome is oversized")
	}
	var result OutcomeResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || requireJSONEOF(decoder) != nil || result.Request.OperationEnvelopeDigest != envelopeDigest || result.CarrierSequence == 0 ||
		result.Request.CarrierID != store.carrierID || commerce.ValidateOperationCarrierRequestV1(result.Request) != nil ||
		commerce.VerifyOperationSubmissionReceiptV1(result.Receipt, store.admissionKey.Public().(ed25519.PublicKey)) != nil ||
		result.Receipt.State != commerce.ActionTerminal || result.Receipt.SinkID != store.carrierID || result.Receipt.SinkReference != envelopeDigest ||
		result.CarrierPublicKey != "ed25519:"+hex.EncodeToString(store.admissionKey.Public().(ed25519.PublicKey)) ||
		result.ActorAgentID == "" || result.StoredAtUnix == 0 || result.Provenance != "carrier-retained-unverified-assertion" {
		return OutcomeResult{}, errors.New("stored outcome is invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(result.Request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != result.ActorAgentID {
		return OutcomeResult{}, errors.New("stored outcome actor binding is invalid")
	}
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(result.Request.EventPayload, &body) != nil || !reflect.DeepEqual(body, result.EventBody) {
		return OutcomeResult{}, errors.New("stored outcome event binding is invalid")
	}
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", result.Request.Artifacts)
	if err != nil || artifactDigest != result.Receipt.EvidenceDigest {
		return OutcomeResult{}, errors.New("stored outcome receipt evidence binding is invalid")
	}
	return result, nil
}

func validOutcomeQuery(query OutcomeQuery) bool {
	if query.Limit == 0 || query.Limit > MaxSearchResults || len(query.EventKinds) > 8 || len(query.AssertionProfileURIs) > 32 ||
		!boundedOutcomeQueryText(query.SubjectProfileURI, 256) || !boundedOutcomeQueryText(query.SubjectID, 4096) ||
		!boundedOutcomeQueryText(query.ActorAgentID, 256) {
		return false
	}
	seenKinds := make(map[commerce.OperationOutcomeEventKind]bool, len(query.EventKinds))
	for _, kind := range query.EventKinds {
		if seenKinds[kind] || kind != commerce.OutcomeObservation && kind != commerce.OutcomeTransitionObservation &&
			kind != commerce.OutcomeTerminalObservation && kind != commerce.OutcomeAvailabilityObservation && kind != commerce.OutcomeCohortCheckpoint {
			return false
		}
		seenKinds[kind] = true
	}
	seenProfiles := make(map[string]bool, len(query.AssertionProfileURIs))
	for _, profile := range query.AssertionProfileURIs {
		if !boundedOutcomeQueryText(profile, 256) || profile == "" || seenProfiles[profile] {
			return false
		}
		seenProfiles[profile] = true
	}
	return true
}

func boundedOutcomeQueryText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return value == ""
		}
	}
	return true
}

func (store *Store) SubscribeOutcomes(ctx context.Context, query OutcomeQuery, wait time.Duration) (OutcomePage, error) {
	if ctx == nil || wait < 0 || wait > 25*time.Second {
		return OutcomePage{}, errors.New("outcome subscription wait is invalid")
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		page, err := store.SearchOutcomes(query)
		if err != nil || len(page.Results) > 0 || wait == 0 {
			return page, err
		}
		select {
		case <-ctx.Done():
			return OutcomePage{}, ctx.Err()
		case <-deadline.C:
			return OutcomePage{CarrierID: store.carrierID}, nil
		case <-ticker.C:
		}
	}
}

func matchesOutcome(value OutcomeResult, query OutcomeQuery) bool {
	if query.ActorAgentID != "" && value.ActorAgentID != query.ActorAgentID || query.SubjectProfileURI != "" && value.EventBody.PrimarySubjectRef.SubjectProfileURI != query.SubjectProfileURI ||
		query.SubjectID != "" && value.EventBody.PrimarySubjectRef.SubjectID != query.SubjectID {
		return false
	}
	if len(query.EventKinds) > 0 {
		found := false
		for _, kind := range query.EventKinds {
			if kind == value.EventBody.EventKind {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if len(query.AssertionProfileURIs) > 0 {
		found := false
		for _, profile := range query.AssertionProfileURIs {
			if profile == value.EventBody.AssertionProfileURI {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (store *Store) outcomePath(digest string) string {
	return filepath.Join(store.directory, "outcome-"+strings.TrimPrefix(digest, "sha256:")+".json")
}
func (store *Store) outcomePaths() ([]string, error) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "outcome-") && strings.HasSuffix(entry.Name(), ".json") && len(entry.Name()) == len("outcome-")+64+5 {
			paths = append(paths, filepath.Join(store.directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}
