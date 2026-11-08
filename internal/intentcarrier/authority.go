package intentcarrier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// authorityKeyFileBytes is the exact size of a pinned key file: the 1,312-byte
// ML-DSA-44 public key in lowercase hex, optionally followed by one newline.
const authorityKeyFileBytes = 2 * mldsa44.PublicKeySize

// PinnedAuthority is one deployment-pinned Action Authority key: its
// ML-DSA-44 controller key ID and the 1,312-byte public key that derives it.
type PinnedAuthority struct {
	KeyID     [mldsa44.KeyIDSize]byte
	PublicKey []byte
}

// PinnedAuthorities is the deployment's explicit owner Action Authority trust
// set. Carrier storage never learns authority from an untrusted publication:
// a key is authorized only for the authority it is pinned under, and every
// signature is checked by the configured ML-DSA-44 verifier.
type PinnedAuthorities struct {
	pins     map[string]PinnedAuthority
	verifier mldsa44.Verifier
}

var _ commerce.FenceAuthorityResolver = (*PinnedAuthorities)(nil)

// NewPinnedAuthorities refuses an empty trust set, a missing verifier, and a
// pin whose key is not an ML-DSA-44 public key deriving the pinned key ID.
func NewPinnedAuthorities(pins map[string]PinnedAuthority, verifier mldsa44.Verifier) (*PinnedAuthorities, error) {
	if len(pins) == 0 {
		return nil, errors.New("at least one Action Authority pin is required")
	}
	if verifier == nil {
		return nil, errors.New("an ML-DSA-44 verifier is required for Action Authority pins")
	}
	copied := make(map[string]PinnedAuthority, len(pins))
	for authorityID, pin := range pins {
		if authorityID == "" || len(authorityID) > 256 {
			return nil, errors.New("Action Authority pin has an invalid authority ID")
		}
		derived, err := mldsa44.KeyID(pin.PublicKey)
		if err != nil || derived != pin.KeyID {
			return nil, fmt.Errorf("Action Authority pin for %s does not derive its key ID", authorityID)
		}
		copied[authorityID] = PinnedAuthority{KeyID: pin.KeyID, PublicKey: append([]byte(nil), pin.PublicKey...)}
	}
	return &PinnedAuthorities{pins: copied, verifier: verifier}, nil
}

// Verify implements mldsa44.Verifier through the configured verifier.
func (p *PinnedAuthorities) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if p == nil || p.verifier == nil {
		return mldsa44.ErrUnavailable
	}
	return p.verifier.Verify(ctx, use, payload, publicKey, signature)
}

// ResolveActionAuthorityKey returns the pinned key only for the exact
// authority and key ID pair.
func (p *PinnedAuthorities) ResolveActionAuthorityKey(authorityID string, keyID [mldsa44.KeyIDSize]byte,
	_ time.Time) ([]byte, error) {
	if p == nil {
		return nil, errors.New("publication Action Authority key is not pinned")
	}
	pin, found := p.pins[authorityID]
	if !found || pin.KeyID != keyID {
		return nil, errors.New("publication Action Authority key is not pinned")
	}
	return append([]byte(nil), pin.PublicKey...), nil
}

// Describe lists the pinned authority IDs and key IDs, never key bytes.
func (p *PinnedAuthorities) Describe() string {
	if p == nil {
		return ""
	}
	entries := make([]string, 0, len(p.pins))
	for authorityID, pin := range p.pins {
		entries = append(entries, authorityID+"="+mldsa44.KeyIDText(pin.KeyID))
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

// ParseAuthorityPin reads one pin of the form
// AUTHORITY_ID=mldsa44:<64 lowercase hex key ID>@<absolute key file>. The key
// file must be an owner-only regular file holding exactly the 1,312-byte
// public key in lowercase hex, optionally followed by one newline, and the key
// must derive the pinned key ID.
func ParseAuthorityPin(value string) (string, PinnedAuthority, error) {
	authorityID, reference, found := strings.Cut(value, "=")
	if !found || authorityID == "" || len(authorityID) > 256 || strings.TrimSpace(authorityID) != authorityID {
		return "", PinnedAuthority{}, errors.New("authority pin must be AUTHORITY_ID=mldsa44:<key ID>@<key file>")
	}
	keyIDText, path, found := strings.Cut(reference, "@")
	if !found {
		if _, err := commerce.ParseActionAuthorityKeyID(reference); errors.Is(err, commerce.ErrEd25519ActionAuthority) {
			return "", PinnedAuthority{}, err
		}
		return "", PinnedAuthority{}, errors.New("authority pin must be AUTHORITY_ID=mldsa44:<key ID>@<key file>")
	}
	keyID, err := commerce.ParseActionAuthorityKeyID(keyIDText)
	if err != nil {
		return "", PinnedAuthority{}, err
	}
	key, err := readAuthorityKeyFile(path)
	if err != nil {
		return "", PinnedAuthority{}, err
	}
	derived, err := mldsa44.KeyID(key)
	if err != nil || derived != keyID {
		return "", PinnedAuthority{}, errors.New("authority pin key file does not derive the pinned key ID")
	}
	return authorityID, PinnedAuthority{KeyID: keyID, PublicKey: key}, nil
}

// ParseAuthorityPins parses each pin and refuses a duplicated authority.
func ParseAuthorityPins(values []string) (map[string]PinnedAuthority, error) {
	pins := make(map[string]PinnedAuthority, len(values))
	for _, value := range values {
		authorityID, pin, err := ParseAuthorityPin(value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := pins[authorityID]; duplicate {
			return nil, errors.New("authority pin is duplicated")
		}
		pins[authorityID] = pin
	}
	return pins, nil
}

func readAuthorityKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("authority pin key file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !authorityFileOwner(before) || before.Mode().Perm() != 0o600 ||
		before.Size() < authorityKeyFileBytes || before.Size() > authorityKeyFileBytes+1 {
		return nil, errors.New("authority pin key file must be an owner-only mode-0600 regular file of one ML-DSA-44 key")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("authority pin key file cannot be opened")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("authority pin key file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, authorityKeyFileBytes+2))
	if err != nil {
		return nil, errors.New("authority pin key file cannot be read")
	}
	text := bytes.TrimSuffix(raw, []byte("\n"))
	if len(text) != authorityKeyFileBytes || !lowercaseHex(text) {
		return nil, errors.New("authority pin key file must hold one ML-DSA-44 public key in lowercase hex")
	}
	key := make([]byte, mldsa44.PublicKeySize)
	if _, err := hex.Decode(key, text); err != nil {
		return nil, errors.New("authority pin key file must hold one ML-DSA-44 public key in lowercase hex")
	}
	return key, nil
}

func lowercaseHex(value []byte) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
