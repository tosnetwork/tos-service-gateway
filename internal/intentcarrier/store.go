// Package intentcarrier implements a bounded, non-authoritative Intent Carrier.
// The Carrier stores exact signed objects and derived index fields. Consumers
// must independently verify issuer authorization and never treat this store as
// a market head, winner, Agreement, or settlement authority.
package intentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxStoredIntentBytes = 2 << 20
	MaxSearchResults     = 1000
)

type Query struct {
	Modes          []commerce.IntentMode
	SubjectClasses []commerce.SubjectClass
	TaxonomyPrefix string
	Keywords       []string
	Limit          uint32
	AfterCursor    uint64
}

type Result struct {
	Intent             commerce.SignedAgentIntent `json:"intent"`
	IntentDigest       string                     `json:"intent_digest"`
	AuthorizationLevel string                     `json:"authorization_level"`
	StoredAtUnix       uint64                     `json:"stored_at_unix"`
	CarrierSequence    uint64                     `json:"carrier_sequence"`
}

type Page struct {
	CarrierID  string            `json:"carrier_id"`
	Results    []Result          `json:"results"`
	Operations []OperationResult `json:"operations"`
	Next       string            `json:"next_cursor,omitempty"`
}

type WithdrawalResult struct {
	Withdrawal       commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
	WithdrawalDigest string                               `json:"withdrawal_digest"`
	StoredAtUnix     uint64                               `json:"stored_at_unix"`
	CarrierSequence  uint64                               `json:"carrier_sequence"`
}

type OperationResult struct {
	Kind            string            `json:"kind"`
	CarrierSequence uint64            `json:"carrier_sequence"`
	Intent          *Result           `json:"intent,omitempty"`
	Withdrawal      *WithdrawalResult `json:"withdrawal,omitempty"`
}

type Store struct {
	mu              sync.RWMutex
	directory       string
	lock            *os.File
	carrierID       string
	maxEntries      uint32
	maxActorEntries uint32
	now             func() time.Time
	admissionKey    ed25519.PrivateKey
	authority       commerce.FenceAuthorityResolver
}

func Open(directory, carrierID string, maxEntries, maxActorEntries uint32, authority commerce.FenceAuthorityResolver) (*Store, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || carrierID == "" || maxEntries == 0 || maxEntries > 1_000_000 ||
		maxActorEntries == 0 || maxActorEntries > maxEntries || authority == nil {
		return nil, errors.New("Intent Carrier configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Intent Carrier directory is not private")
	}
	key, err := loadOrCreateAdmissionKey(directory)
	if err != nil {
		return nil, err
	}
	lock, err := acquireStoreLock(directory)
	if err != nil {
		return nil, err
	}
	return &Store{directory: directory, lock: lock, carrierID: carrierID, maxEntries: maxEntries,
		maxActorEntries: maxActorEntries, now: time.Now, admissionKey: key, authority: authority}, nil
}

func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lock == nil {
		return nil
	}
	err := releaseStoreLock(store.lock)
	store.lock = nil
	for index := range store.admissionKey {
		store.admissionKey[index] = 0
	}
	return err
}

func (store *Store) IssueAdmission(actorID, audience string, declaredBytes uint64) (commerce.SignedOperationAdmissionChallenge, error) {
	return store.IssueAdmissionFor("publication.publish", actorID, audience, declaredBytes)
}

func (store *Store) IssueAdmissionFor(operationKind, actorID, audience string, declaredBytes uint64) (commerce.SignedOperationAdmissionChallenge, error) {
	if store == nil || actorID == "" || audience == "" || declaredBytes == 0 || declaredBytes > MaxStoredIntentBytes {
		return commerce.SignedOperationAdmissionChallenge{}, errors.New("Intent publication admission request is invalid")
	}
	if operationKind != "publication.publish" && operationKind != "publication.withdraw" {
		return commerce.SignedOperationAdmissionChallenge{}, errors.New("unsupported Carrier admission operation")
	}
	resourceDigest, err := commerce.AdmissionResourceVectorDigest(operationKind, declaredBytes,
		map[string]uint64{"index_entries": 1, "retained_bytes": declaredBytes})
	if err != nil {
		return commerce.SignedOperationAdmissionChallenge{}, err
	}
	now := store.now().UTC()
	return commerce.NewOperationAdmissionChallenge(commerce.OperationAdmissionChallengeBody{SchemaVersion: 1,
		ProfileURI: "tos.operation-admission.hashcash.v1", CarrierID: store.carrierID, ActorID: actorID,
		OperationKind: operationKind, Audience: audience, DeclaredBytes: declaredBytes,
		ResourceVectorDigest: resourceDigest, DifficultyBits: 12, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(2 * time.Minute).Unix())}, store.admissionKey)
}

func (store *Store) WithdrawAdmitted(withdrawal commerce.SignedAgentIntentWithdrawal, proof commerce.OperationAdmissionProof,
	action commerce.AuthorizedAction, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if store == nil {
		return commerce.ActionResolution{}, errors.New("Intent Carrier is unavailable")
	}
	now := store.now().UTC()
	if err := commerce.VerifyIntentWithdrawal(withdrawal, selfSignatureResolver{}, now); err != nil {
		return commerce.ActionResolution{}, err
	}
	intent, err := store.Get(withdrawal.Body.IntentDigest)
	if err != nil || intent.Intent.Body.IssuerAgentID != withdrawal.Body.IssuerAgentID ||
		intent.Intent.Body.ObjectID != withdrawal.Body.ObjectID || intent.Intent.Body.Revision != withdrawal.Body.IntentRevision ||
		intent.Intent.Body.NetworkID != withdrawal.Body.NetworkID || intent.Intent.Body.Audience != withdrawal.Body.Audience {
		return commerce.ActionResolution{}, errors.New("Intent withdrawal does not bind a retained exact revision")
	}
	canonical, err := codec.Marshal(withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	operationDigest, err := codec.Digest("tos.agent-intent-withdrawal-operation.v1", withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(action.OwnerID), "agent_id": commerce.ID(action.AgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(withdrawal.Body.ObjectID),
		"withdrawn_revision": commerce.U64(withdrawal.Body.IntentRevision), "withdrawal_operation_digest": commerce.Digest32(operationDigest)}
	resolution, err := store.admitPublicationActionKind("publication.withdraw", action, fence, fields, canonical,
		withdrawal.Body.IssuerAgentID, now)
	if err != nil || resolution.State == commerce.ActionTerminal {
		return resolution, err
	}
	resourceDigest, err := commerce.AdmissionResourceVectorDigest("publication.withdraw", uint64(len(canonical)),
		map[string]uint64{"index_entries": 1, "retained_bytes": uint64(len(canonical))})
	if err != nil || commerce.VerifyOperationAdmission(proof, store.admissionKey.Public().(ed25519.PublicKey),
		withdrawal.Body.IssuerAgentID, "publication.withdraw", withdrawal.Body.Audience, uint64(len(canonical)), resourceDigest, now) != nil ||
		proof.Challenge.Body.CarrierID != store.carrierID {
		return resolution, errors.New("Intent withdrawal admission proof is invalid")
	}
	withdrawalDigest, err := commerce.IntentWithdrawalDigest(withdrawal.Body)
	if err != nil || store.consumeAdmission(proof.ChallengeDigest, withdrawalDigest) != nil {
		return resolution, errors.New("Intent withdrawal admission proof was already consumed")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := store.withdrawalPath(withdrawal.Body.IntentDigest)
	if existing, readErr := os.ReadFile(path); readErr == nil {
		var stored WithdrawalResult
		decodeErr := json.Unmarshal(existing, &stored)
		storedDigest, digestErr := commerce.IntentWithdrawalDigest(stored.Withdrawal.Body)
		if decodeErr != nil || digestErr != nil || storedDigest != withdrawalDigest ||
			stored.WithdrawalDigest != withdrawalDigest || stored.Withdrawal.PublicKey != withdrawal.PublicKey || stored.Withdrawal.Signature != withdrawal.Signature {
			return resolution, errors.New("Intent revision has a conflicting withdrawal")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return resolution, readErr
	} else {
		sequence, sequenceErr := store.nextSequenceLocked()
		if sequenceErr != nil {
			return resolution, sequenceErr
		}
		stored := WithdrawalResult{Withdrawal: withdrawal, WithdrawalDigest: withdrawalDigest,
			StoredAtUnix: uint64(now.Unix()), CarrierSequence: sequence}
		raw, marshalErr := json.Marshal(stored)
		if marshalErr != nil {
			return resolution, marshalErr
		}
		if err := writeExclusive(path, raw); err != nil {
			return resolution, err
		}
	}
	return store.completeActionLocked(action, withdrawalDigest)
}

// Publish validates the exact envelope and cryptographic self-signature. Agent
// controller authorization is deliberately rechecked by every consumer from
// finalized state, because a Carrier is not an identity authority.
func (store *Store) PublishAdmitted(intent commerce.SignedAgentIntent, proof commerce.OperationAdmissionProof,
	action commerce.AuthorizedAction, fence commerce.WriterFence) (Result, commerce.ActionResolution, error) {
	if store == nil {
		return Result{}, commerce.ActionResolution{}, errors.New("Intent Carrier is unavailable")
	}
	now := store.now().UTC()
	resolver := selfSignatureResolver{}
	if err := commerce.VerifyIntent(intent, resolver, now); err != nil {
		return Result{}, commerce.ActionResolution{}, err
	}
	digest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		return Result{}, commerce.ActionResolution{}, err
	}
	canonicalIntent, err := codec.Marshal(intent)
	if err != nil {
		return Result{}, commerce.ActionResolution{}, err
	}
	operationDigest, err := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		return Result{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(action.OwnerID), "agent_id": commerce.ID(action.AgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(operationDigest)}
	resolution, err := store.admitPublicationAction(action, fence, fields, canonicalIntent, intent.Body.IssuerAgentID, now)
	if err != nil {
		return Result{}, resolution, err
	}
	if resolution.State == commerce.ActionTerminal {
		result, getErr := store.Get(digest)
		return result, resolution, getErr
	}
	resourceDigest, err := commerce.AdmissionResourceVectorDigest("publication.publish", uint64(len(canonicalIntent)),
		map[string]uint64{"index_entries": 1, "retained_bytes": uint64(len(canonicalIntent))})
	if err != nil || commerce.VerifyOperationAdmission(proof, store.admissionKey.Public().(ed25519.PublicKey), intent.Body.IssuerAgentID,
		"publication.publish", intent.Body.Audience, uint64(len(canonicalIntent)), resourceDigest, now) != nil || proof.Challenge.Body.CarrierID != store.carrierID {
		return Result{}, resolution, errors.New("Intent publication admission proof is invalid")
	}
	if err := store.consumeAdmission(proof.ChallengeDigest, digest); err != nil {
		return Result{}, resolution, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := store.path(digest)
	if existing, readErr := os.ReadFile(path); readErr == nil {
		var stored Result
		if json.Unmarshal(existing, &stored) == nil && stored.IntentDigest == digest {
			resolution, err = store.completeActionLocked(action, digest)
			return stored, resolution, err
		}
		return Result{}, resolution, errors.New("Intent digest conflicts with stored bytes")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Result{}, resolution, readErr
	}
	entries, err := store.paths()
	if err != nil {
		return Result{}, resolution, err
	}
	if len(entries) >= int(store.maxEntries) {
		return Result{}, resolution, errors.New("Intent Carrier capacity reached")
	}
	actorEntries := uint32(0)
	for _, existingPath := range entries {
		raw, readErr := os.ReadFile(existingPath)
		var existing Result
		if readErr == nil && json.Unmarshal(raw, &existing) == nil && existing.Intent.Body.IssuerAgentID == intent.Body.IssuerAgentID {
			actorEntries++
		}
	}
	if actorEntries >= store.maxActorEntries {
		return Result{}, resolution, errors.New("Intent Carrier actor retention quota reached")
	}
	sequence, err := store.nextSequenceLocked()
	if err != nil {
		return Result{}, resolution, err
	}
	result := Result{Intent: intent, IntentDigest: digest, AuthorizationLevel: "self-signature+carrier-admission",
		StoredAtUnix: uint64(now.Unix()), CarrierSequence: sequence}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
		return Result{}, resolution, errors.New("signed Intent exceeds Carrier storage bounds")
	}
	if err := writeExclusive(path, raw); err != nil {
		return Result{}, resolution, err
	}
	resolution, err = store.completeActionLocked(action, digest)
	return result, resolution, err
}

func (store *Store) admitPublicationAction(action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, canonical []byte, issuerAgentID string, now time.Time) (commerce.ActionResolution, error) {
	return store.admitPublicationActionKind("publication.publish", action, fence, fields, canonical, issuerAgentID, now)
}

func (store *Store) admitPublicationActionKind(kind string, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, canonical []byte, issuerAgentID string, now time.Time) (commerce.ActionResolution, error) {
	if action.ActionKind != kind || action.OwnerID == "" || action.AgentID != issuerAgentID ||
		commerce.VerifyAuthorizedAction(action, fields, canonical, fence, store.authority, now) != nil {
		return commerce.ActionResolution{}, errors.New("Intent publication action authorization is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	highPath := store.writerHighwaterPath(action.OwnerID, action.AgentID)
	high, highFence, err := readWriterHighWater(highPath)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	if action.WriterGeneration < high {
		return commerce.ActionResolution{}, errors.New("stale writer cannot publish an Intent")
	}
	if action.WriterGeneration == high && highFence != "" && highFence != fenceDigest {
		return commerce.ActionResolution{}, errors.New("writer generation equivocates between authority fences")
	}
	if action.WriterGeneration > high || highFence == "" {
		if err := writeWriterHighWater(highPath, action.WriterGeneration, fenceDigest); err != nil {
			return commerce.ActionResolution{}, err
		}
	}
	path := store.actionPath(action.StableActionID)
	if raw, readErr := os.ReadFile(path); readErr == nil {
		var existing commerce.ActionResolution
		if json.Unmarshal(raw, &existing) != nil || commerce.ValidateActionResolution(existing) != nil {
			return commerce.ActionResolution{}, errors.New("stored publication action resolution is invalid")
		}
		if existing.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
				State: commerce.ActionConflict, StateRevision: existing.StateRevision + 1}, errors.New("publication action identity conflicts with another request")
		}
		return existing, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return commerce.ActionResolution{}, readErr
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionPrepared, StateRevision: 1}
	raw, _ := json.Marshal(resolution)
	if err := writeExclusive(path, raw); err != nil {
		return commerce.ActionResolution{}, err
	}
	return resolution, nil
}

func (store *Store) completeActionLocked(action commerce.AuthorizedAction, intentDigest string) (commerce.ActionResolution, error) {
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, SinkReference: intentDigest, EvidenceRefs: []string{intentDigest}, StateRevision: 2}
	raw, _ := json.Marshal(resolution)
	if err := writeAtomic(store.actionPath(action.StableActionID), raw); err != nil {
		return commerce.ActionResolution{}, err
	}
	return resolution, nil
}

func (store *Store) ResolveAction(actionID, requestDigest string) (commerce.ActionResolution, error) {
	if !canonicalDigest(actionID) || !canonicalDigest(requestDigest) {
		return commerce.ActionResolution{}, errors.New("publication action query is invalid")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	raw, err := os.ReadFile(store.actionPath(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
			State: commerce.ActionUnknown, StateRevision: 1}, nil
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var resolution commerce.ActionResolution
	if json.Unmarshal(raw, &resolution) != nil || commerce.ValidateActionResolution(resolution) != nil {
		return commerce.ActionResolution{}, errors.New("stored publication action resolution is invalid")
	}
	if resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
			State: commerce.ActionConflict, StateRevision: resolution.StateRevision + 1}, nil
	}
	return resolution, nil
}

func (store *Store) Search(query Query) (Page, error) {
	if store == nil || query.Limit == 0 || query.Limit > MaxSearchResults || len(query.Keywords) > 32 || len(query.Modes) > 16 || len(query.SubjectClasses) > 16 {
		return Page{}, errors.New("Intent Carrier query is invalid or unbounded")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	paths, err := store.paths()
	if err != nil {
		return Page{}, err
	}
	page := Page{CarrierID: store.carrierID, Results: make([]Result, 0, query.Limit), Operations: make([]OperationResult, 0, query.Limit)}
	now := store.now().UTC()
	all := make([]OperationResult, 0, len(paths))
	for _, path := range paths {
		digest := strings.TrimSuffix(filepath.Base(path), ".json")
		raw, readErr := os.ReadFile(path)
		if readErr != nil || len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
			continue
		}
		var result Result
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || result.IntentDigest != "sha256:"+digest || result.CarrierSequence == 0 ||
			result.CarrierSequence <= query.AfterCursor || store.isWithdrawn(result.IntentDigest) ||
			!now.Before(time.Unix(int64(result.Intent.Body.ExpiresAtUnix), 0)) || !matches(result.Intent.Body.Payload.DiscoveryCard, query) {
			continue
		}
		copy := result
		all = append(all, OperationResult{Kind: "intent", CarrierSequence: result.CarrierSequence, Intent: &copy})
	}
	withdrawals, withdrawalErr := store.withdrawalPaths()
	if withdrawalErr != nil {
		return Page{}, withdrawalErr
	}
	for _, path := range withdrawals {
		raw, readErr := os.ReadFile(path)
		if readErr != nil || len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
			continue
		}
		var result WithdrawalResult
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || result.CarrierSequence <= query.AfterCursor || result.CarrierSequence == 0 ||
			result.StoredAtUnix == 0 || result.WithdrawalDigest == "" {
			continue
		}
		computed, digestErr := commerce.IntentWithdrawalDigest(result.Withdrawal.Body)
		if digestErr != nil || computed != result.WithdrawalDigest {
			continue
		}
		copy := result
		all = append(all, OperationResult{Kind: "withdrawal", CarrierSequence: result.CarrierSequence, Withdrawal: &copy})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CarrierSequence == all[j].CarrierSequence {
			return all[i].Kind < all[j].Kind
		}
		return all[i].CarrierSequence < all[j].CarrierSequence
	})
	for _, operation := range all {
		page.Operations = append(page.Operations, operation)
		if operation.Intent != nil {
			page.Results = append(page.Results, *operation.Intent)
		}
		if len(page.Operations) == int(query.Limit) {
			page.Next = "seq:" + strconv.FormatUint(operation.CarrierSequence, 10)
			break
		}
	}
	return page, nil
}

func (store *Store) withdrawalPaths() ([]string, error) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "withdrawal-") && strings.HasSuffix(entry.Name(), ".json") &&
			len(entry.Name()) == len("withdrawal-")+64+len(".json") {
			paths = append(paths, filepath.Join(store.directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// Subscribe is a bounded long poll over a source-local monotonic cursor. It is
// an availability optimization only; it does not create a canonical market
// stream or promise that another Carrier observes the same ordering.
func (store *Store) Subscribe(ctx context.Context, query Query, wait time.Duration) (Page, error) {
	if ctx == nil || wait < 0 || wait > 25*time.Second {
		return Page{}, errors.New("Intent Carrier subscription wait is invalid")
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		page, err := store.Search(query)
		if err != nil || len(page.Results) > 0 || wait == 0 {
			return page, err
		}
		select {
		case <-ctx.Done():
			return Page{}, ctx.Err()
		case <-deadline.C:
			return Page{CarrierID: store.carrierID}, nil
		case <-ticker.C:
		}
	}
}

// Get resolves exact retained bytes by digest, including an expired
// predecessor. Expiry affects search visibility, not revision-chain recovery.
// The returned object remains non-authoritative and must be independently
// verified by the consumer.
func (store *Store) Get(digest string) (Result, error) {
	if store == nil || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return Result{}, errors.New("Intent digest is invalid")
	}
	for _, character := range digest[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return Result{}, errors.New("Intent digest is not canonical lowercase hex")
		}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	raw, err := os.ReadFile(store.path(digest))
	if err != nil {
		return Result{}, err
	}
	if len(raw) == 0 || len(raw) > MaxStoredIntentBytes {
		return Result{}, errors.New("stored Intent is invalid or oversized")
	}
	var result Result
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.IntentDigest != digest || result.CarrierSequence == 0 {
		return Result{}, errors.New("stored Intent conflicts with requested digest")
	}
	if digestCheck, err := commerce.IntentBodyDigest(result.Intent.Body); err != nil || digestCheck != digest {
		return Result{}, errors.New("stored Intent body digest is invalid")
	}
	return result, nil
}

func (store *Store) paths() ([]string, error) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") && len(entry.Name()) == 64+5 {
			paths = append(paths, filepath.Join(store.directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (store *Store) path(digest string) string {
	return filepath.Join(store.directory, strings.TrimPrefix(digest, "sha256:")+".json")
}

func (store *Store) withdrawalPath(intentDigest string) string {
	return filepath.Join(store.directory, "withdrawal-"+strings.TrimPrefix(intentDigest, "sha256:")+".json")
}

func (store *Store) isWithdrawn(intentDigest string) bool {
	_, err := os.Stat(store.withdrawalPath(intentDigest))
	return err == nil
}

type selfSignatureResolver struct{}

func (selfSignatureResolver) AuthorizeIntentKey(string, ed25519.PublicKey, time.Time) error {
	return nil
}

func matches(card commerce.DiscoveryCard, query Query) bool {
	if len(query.Modes) > 0 && !modeIntersection(card.IntentModes, query.Modes) ||
		len(query.SubjectClasses) > 0 && !classIntersection(card.SubjectClasses, query.SubjectClasses) {
		return false
	}
	if query.TaxonomyPrefix != "" {
		found := false
		for _, taxonomy := range card.TaxonomyPaths {
			if strings.HasPrefix(taxonomy, query.TaxonomyPrefix) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, wanted := range query.Keywords {
		found := false
		for _, keyword := range card.Keywords {
			if keyword.Text == wanted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func modeIntersection(left, right []commerce.IntentMode) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func classIntersection(left, right []commerce.SubjectClass) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func writeExclusive(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func loadOrCreateAdmissionKey(directory string) (ed25519.PrivateKey, error) {
	path := filepath.Join(directory, ".carrier-admission-ed25519")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize {
			return nil, errors.New("Carrier admission key file is invalid")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(raw), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(path, key); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateAdmissionKey(directory)
		}
		return nil, err
	}
	return key, nil
}

func (store *Store) consumeAdmission(challengeDigest, operationDigest string) error {
	if len(challengeDigest) != 71 || len(operationDigest) != 71 {
		return errors.New("Carrier admission identity is invalid")
	}
	path := filepath.Join(store.directory, ".admission-"+strings.TrimPrefix(challengeDigest, "sha256:"))
	if err := writeExclusive(path, []byte(operationDigest)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil || string(existing) != operationDigest {
		return errors.New("Carrier admission proof was replayed for another operation")
	}
	return nil
}

func (store *Store) writerHighwaterPath(ownerID, agentID string) string {
	digest := sha256.Sum256([]byte("tos.intent-carrier.writer.v1\x00" + ownerID + "\x00" + agentID))
	return filepath.Join(store.directory, ".writer-"+hex.EncodeToString(digest[:]))
}

func (store *Store) actionPath(actionID string) string {
	return filepath.Join(store.directory, ".action-"+strings.TrimPrefix(actionID, "sha256:"))
}

func (store *Store) nextSequenceLocked() (uint64, error) {
	path := filepath.Join(store.directory, ".carrier-sequence")
	current, err := readUint64(path)
	if err != nil || current == ^uint64(0) {
		return 0, errors.New("Carrier sequence state is invalid or exhausted")
	}
	next := current + 1
	if err := writeAtomic(path, uint64Bytes(next)); err != nil {
		return 0, err
	}
	return next, nil
}

func canonicalDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func readUint64(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil || len(raw) != 8 {
		return 0, errors.New("stored writer high-water state is invalid")
	}
	return binary.BigEndian.Uint64(raw), nil
}

func readWriterHighWater(path string) (uint64, string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	if len(raw) == 8 {
		return binary.BigEndian.Uint64(raw), "", nil
	}
	if len(raw) != 40 {
		return 0, "", errors.New("stored writer high-water state is invalid")
	}
	return binary.BigEndian.Uint64(raw[:8]), "sha256:" + hex.EncodeToString(raw[8:]), nil
}

func writeWriterHighWater(path string, generation uint64, fenceDigest string) error {
	rawDigest, err := hex.DecodeString(strings.TrimPrefix(fenceDigest, "sha256:"))
	if err != nil || len(rawDigest) != 32 || !canonicalDigest(fenceDigest) {
		return errors.New("writer fence digest is invalid")
	}
	raw := make([]byte, 40)
	binary.BigEndian.PutUint64(raw[:8], generation)
	copy(raw[8:], rawDigest)
	return writeAtomic(path, raw)
}

func uint64Bytes(value uint64) []byte {
	raw := make([]byte, 8)
	binary.BigEndian.PutUint64(raw, value)
	return raw
}

func writeAtomic(path string, raw []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".intent-carrier-tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(raw)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}
