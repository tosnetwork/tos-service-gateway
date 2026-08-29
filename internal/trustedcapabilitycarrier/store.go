// Package trustedcapabilitycarrier is a bounded, non-authoritative Carrier for
// exact Trusted Capability V1 objects. It never asserts Admission, Promotion,
// publisher trust, compatibility, revocation, or global search completeness.
package trustedcapabilitycarrier

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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

const (
	MaxObjectBytes        = 1 << 20
	MaxEntries            = 4096
	MaxPage               = 100
	MaxAggregateBytes     = 64 << 20
	MaxPrincipalBytes     = 8 << 20
	MaxPrincipalEntries   = 256
	MaxPublisherHintBytes = 128
)

type Record struct {
	Digest           string   `json:"digest"`
	ObjectKind       string   `json:"object_kind"`
	Canonical        []byte   `json:"canonical"`
	AdvisoryKeywords []string `json:"advisory_keywords"`
	PublisherHint    string   `json:"publisher_hint"`
	Sequence         uint64   `json:"source_sequence"`
	StoredAtUnix     uint64   `json:"stored_at_unix"`
	Provenance       string   `json:"provenance"`
}

type SnapshotDescriptor struct {
	CarrierID        string `json:"carrier_id"`
	SourceGeneration uint64 `json:"source_generation"`
	QueryCommitment  []byte `json:"query_commitment"`
	AfterSequence    uint64 `json:"after_sequence"`
	ThroughSequence  uint64 `json:"through_sequence"`
	HighWater        uint64 `json:"high_water"`
	Complete         bool   `json:"complete"`
	CursorReset      bool   `json:"cursor_reset"`
	OrderedRoot      []byte `json:"ordered_root"`
	SignedAtUnix     uint64 `json:"signed_at_unix"`
	SigningPublicKey []byte `json:"signing_public_key"`
	Signature        []byte `json:"signature"`
}

type Page struct {
	CarrierID        string             `json:"carrier_id"`
	SourceGeneration uint64             `json:"source_generation"`
	Records          []Record           `json:"records"`
	NextSequence     uint64             `json:"next_sequence"`
	Complete         bool               `json:"complete"`
	Snapshot         SnapshotDescriptor `json:"snapshot"`
}

type EpochAuthority interface {
	CheckSourceState(context.Context, string, uint64, uint64, []byte) error
}

type durableState struct {
	SchemaVersion    uint16            `json:"schema_version"`
	CarrierID        string            `json:"carrier_id"`
	SourceGeneration uint64            `json:"source_generation"`
	Sequence         uint64            `json:"sequence"`
	Records          map[string]Record `json:"records"`
	TotalBytes       uint64            `json:"total_bytes"`
	PrincipalBytes   map[string]uint64 `json:"principal_bytes"`
	PrincipalEntries map[string]uint32 `json:"principal_entries"`
	SigningPublicKey []byte            `json:"signing_public_key"`
}

type Store struct {
	id               string
	generation       uint64
	now              func() time.Time
	mu               sync.RWMutex
	sequence         uint64
	records          map[string]Record
	totalBytes       uint64
	principalBytes   map[string]uint64
	principalEntries map[string]uint32
	root             string
	durable          bool
	epoch            EpochAuthority
	signingKey       ed25519.PrivateKey
	writerLock       *os.File
	poisoned         bool
}

// New creates an explicitly in-memory test/development Carrier. HTTP refuses
// to mount it because restart/cursor continuity cannot be proved.
func New(id string, generation uint64, now func() time.Time) (*Store, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return newStore(id, generation, now, key)
}

func newStore(id string, generation uint64, now func() time.Time, key ed25519.PrivateKey) (*Store, error) {
	if id == "" || generation == 0 || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("Carrier identity, source generation, and signing key are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{id: id, generation: generation, now: now, signingKey: append(ed25519.PrivateKey(nil), key...), records: map[string]Record{}, principalBytes: map[string]uint64{}, principalEntries: map[string]uint32{}}, nil
}

// Open creates a production-capable persistent Carrier. Epoch authority must
// be outside the Carrier database so restoring an old database cannot silently
// reuse a lower source generation.
func Open(root, id string, generation uint64, now func() time.Time, key ed25519.PrivateKey, epoch EpochAuthority) (*Store, error) {
	if root == "" || epoch == nil {
		return nil, errors.New("durable Carrier root and external epoch authority are required")
	}
	store, err := newStore(id, generation, now, key)
	if err != nil {
		return nil, err
	}
	store.root = filepath.Clean(root)
	store.durable = true
	store.epoch = epoch
	if err := os.MkdirAll(store.root, 0o700); err != nil {
		return nil, err
	}
	writerLock, err := acquireStoreLock(store.root)
	if err != nil {
		return nil, err
	}
	store.writerLock = writerLock
	keepLock := false
	defer func() {
		if !keepLock {
			_ = releaseStoreLock(writerLock)
		}
	}()
	raw, err := os.ReadFile(filepath.Join(store.root, "carrier-state.json"))
	if errors.Is(err, os.ErrNotExist) {
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
		keepLock = true
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state durableState
	if err := json.Unmarshal(raw, &state); err != nil || state.SchemaVersion != 1 || state.CarrierID != id || state.SourceGeneration != generation ||
		!bytes.Equal(state.SigningPublicKey, key.Public().(ed25519.PublicKey)) {
		return nil, errors.New("Carrier state identity, schema, or generation mismatch")
	}
	store.sequence, store.records, store.totalBytes = state.Sequence, state.Records, state.TotalBytes
	store.principalBytes, store.principalEntries = state.PrincipalBytes, state.PrincipalEntries
	if store.records == nil || store.principalBytes == nil || store.principalEntries == nil {
		return nil, errors.New("Carrier durable accounting is incomplete")
	}
	if err := store.verifyAccounting(); err != nil {
		return nil, err
	}
	commitment, err := durableStateCommitment(state)
	if err != nil || epoch.CheckSourceState(context.Background(), id, generation, state.Sequence, commitment) != nil {
		return nil, errors.New("Carrier state does not match external sequence authority")
	}
	keepLock = true
	return store, nil
}

func (s *Store) ProductionReady() bool { return s != nil && s.durable && s.epoch != nil }

func (s *Store) Close() error {
	if s == nil || s.writerLock == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := releaseStoreLock(s.writerLock)
	s.writerLock = nil
	return err
}

func (s *Store) Publish(canonical []byte, keywords []string, publisherHint string) (Record, error) {
	return s.PublishForPrincipal("anonymous", canonical, keywords, publisherHint)
}

// PublishForPrincipal applies resource accounting to the authenticated
// transport principal. Principal identity is quota metadata only and never a
// publisher/trust assertion.
func (s *Store) PublishForPrincipal(principal string, canonical []byte, keywords []string, publisherHint string) (Record, error) {
	if len(canonical) == 0 || len(canonical) > MaxObjectBytes || !sort.StringsAreSorted(keywords) || len(keywords) > 32 {
		return Record{}, errors.New("capability Carrier publication is invalid or unbounded")
	}
	if principal == "" || len(principal) > 256 || strings.TrimSpace(principal) != principal || len(publisherHint) > MaxPublisherHintBytes {
		return Record{}, errors.New("Carrier principal or publisher hint is invalid")
	}
	for i, k := range keywords {
		if k == "" || len(k) > 64 || k != strings.ToLower(k) || i > 0 && k == keywords[i-1] {
			return Record{}, errors.New("advisory keywords are not canonical")
		}
	}
	object, err := trusted.DecodeObject(canonical)
	if err != nil {
		return Record{}, err
	}
	if object.ObjectKind != "artifact" && object.ObjectKind != "publisher-envelope" && object.ObjectKind != "publisher-revocation-observation" {
		return Record{}, errors.New("Carrier accepts only released discovery and publisher status objects")
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		return Record{}, err
	}
	key := hex.EncodeToString(digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return Record{}, errors.New("Carrier is fenced after ambiguous persistence")
	}
	if existing, ok := s.records[key]; ok {
		return existing, nil
	}
	if len(s.records) >= MaxEntries {
		return Record{}, errors.New("capability Carrier capacity reached")
	}
	want := uint64(len(canonical))
	if want > MaxAggregateBytes-s.totalBytes || want > MaxPrincipalBytes-s.principalBytes[principal] || s.principalEntries[principal] >= MaxPrincipalEntries {
		return Record{}, errors.New("capability Carrier byte or principal quota reached")
	}
	s.sequence++
	record := Record{"sha256:" + key, object.ObjectKind, append([]byte(nil), canonical...), append([]string(nil), keywords...), publisherHint, s.sequence, uint64(s.now().UTC().Unix()), "carrier-retained-unverified-object"}
	s.records[key] = record
	s.totalBytes += want
	s.principalBytes[principal] += want
	s.principalEntries[principal]++
	if s.durable {
		if err := s.persistLocked(); err != nil {
			delete(s.records, key)
			s.sequence--
			s.totalBytes -= want
			s.principalBytes[principal] -= want
			s.principalEntries[principal]--
			s.poisoned = true
			return Record{}, err
		}
	}
	return record, nil
}

func (s *Store) Exact(digest string) (Record, error) {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+sha256.Size*2 {
		return Record{}, errors.New("exact object digest is invalid")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[digest[len("sha256:"):]]
	if !ok {
		return Record{}, os.ErrNotExist
	}
	return record, nil
}

func (s *Store) Search(query string, after uint64, limit int) (Page, error) {
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	if len(tokens) == 0 || len(tokens) > 16 || limit <= 0 || limit > MaxPage {
		return Page{}, errors.New("capability Carrier query is invalid or unbounded")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.poisoned {
		return Page{}, errors.New("Carrier is fenced after ambiguous persistence")
	}
	cursorReset := after > s.sequence
	values := make([]Record, 0, len(s.records))
	if !cursorReset {
		for _, record := range s.records {
			if record.Sequence <= after {
				continue
			}
			text := strings.Join(record.AdvisoryKeywords, " ") + " " + strings.ToLower(record.PublisherHint)
			matched := true
			for _, token := range tokens {
				if !strings.Contains(text, token) {
					matched = false
					break
				}
			}
			if matched {
				values = append(values, record)
			}
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Sequence < values[j].Sequence })
	page := Page{CarrierID: s.id, SourceGeneration: s.generation, Complete: !cursorReset}
	if len(values) > limit {
		page.Records = append([]Record(nil), values[:limit]...)
		page.NextSequence = values[limit-1].Sequence
		page.Complete = false
	} else {
		page.Records = append([]Record(nil), values...)
		if len(values) > 0 {
			page.NextSequence = values[len(values)-1].Sequence
		} else {
			page.NextSequence = after
		}
	}
	page.Snapshot = s.signSnapshotLocked(query, after, page.NextSequence, page.Complete, cursorReset, page.Records)
	return page, nil
}

func (s *Store) signSnapshotLocked(query string, after, through uint64, complete, reset bool, records []Record) SnapshotDescriptor {
	queryHash := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(query))))
	descriptor := SnapshotDescriptor{CarrierID: s.id, SourceGeneration: s.generation, QueryCommitment: queryHash[:], AfterSequence: after,
		ThroughSequence: through, HighWater: s.sequence, Complete: complete, CursorReset: reset, OrderedRoot: orderedRoot(records),
		SignedAtUnix: uint64(s.now().UTC().Unix()), SigningPublicKey: append([]byte(nil), s.signingKey.Public().(ed25519.PublicKey)...)}
	descriptor.Signature = ed25519.Sign(s.signingKey, snapshotMessage(descriptor))
	return descriptor
}

func VerifySnapshot(descriptor SnapshotDescriptor) error {
	if descriptor.CarrierID == "" || descriptor.SourceGeneration == 0 || len(descriptor.QueryCommitment) != sha256.Size ||
		len(descriptor.OrderedRoot) != sha256.Size || len(descriptor.SigningPublicKey) != ed25519.PublicKeySize || len(descriptor.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(descriptor.SigningPublicKey, snapshotMessage(descriptor), descriptor.Signature) {
		return errors.New("Carrier snapshot signature or shape is invalid")
	}
	return nil
}

func SnapshotRoot(page Page) []byte { return orderedRoot(page.Records) }

func orderedRoot(records []Record) []byte {
	h := sha256.New()
	h.Write([]byte("tos.capability-carrier-ordered-page.v1\x00"))
	var number [8]byte
	for _, record := range records {
		binary.BigEndian.PutUint64(number[:], record.Sequence)
		h.Write(number[:])
		h.Write([]byte(record.Digest))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func snapshotMessage(value SnapshotDescriptor) []byte {
	h := sha256.New()
	h.Write([]byte("tos.capability-carrier-snapshot.v1\x00"))
	write := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		h.Write(size[:])
		h.Write(value)
	}
	write([]byte(value.CarrierID))
	var number [8]byte
	for _, field := range []uint64{value.SourceGeneration, value.AfterSequence, value.ThroughSequence, value.HighWater, value.SignedAtUnix} {
		binary.BigEndian.PutUint64(number[:], field)
		h.Write(number[:])
	}
	write(value.QueryCommitment)
	write(value.OrderedRoot)
	if value.Complete {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	if value.CursorReset {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	write(value.SigningPublicKey)
	return h.Sum(nil)
}

func (s *Store) persistLocked() error {
	state := durableState{1, s.id, s.generation, s.sequence, s.records, s.totalBytes, s.principalBytes, s.principalEntries,
		append([]byte(nil), s.signingKey.Public().(ed25519.PublicKey)...)}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, ".carrier-state-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(s.root, "carrier-state.json"))
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	commitment, err := durableStateCommitment(state)
	if err != nil {
		return err
	}
	return s.epoch.CheckSourceState(context.Background(), s.id, s.generation, s.sequence, commitment)
}

func durableStateCommitment(state durableState) ([]byte, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.capability-carrier-state.v1\x00"), raw...))
	return digest[:], nil
}

func (s *Store) verifyAccounting() error {
	var total uint64
	for key, record := range s.records {
		if record.Sequence == 0 || record.Sequence > s.sequence || record.Digest != "sha256:"+key {
			return errors.New("Carrier record sequence or digest is corrupt")
		}
		total += uint64(len(record.Canonical))
	}
	if total != s.totalBytes || total > MaxAggregateBytes || len(s.records) > MaxEntries {
		return fmt.Errorf("Carrier durable accounting mismatch")
	}
	return nil
}

func EqualSnapshotContent(page Page) bool {
	return bytes.Equal(page.Snapshot.OrderedRoot, orderedRoot(page.Records))
}
