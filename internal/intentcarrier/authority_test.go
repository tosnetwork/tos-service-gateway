package intentcarrier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-gateway/internal/actionauthoritytest"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

func writeKeyFile(t *testing.T, directory, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseAuthorityPinReadsOneOwnerOnlyMLDSA44Key(t *testing.T) {
	fake := &mldsa44test.Fake{}
	key, other := fake.PublicKey("pinned"), fake.PublicKey("other")
	keyID := fake.KeyID("pinned")
	directory := t.TempDir()
	withNewline := writeKeyFile(t, directory, "newline.hex", hex.EncodeToString(key)+"\n", 0o600)
	bare := writeKeyFile(t, directory, "bare.hex", hex.EncodeToString(key), 0o600)
	for _, path := range []string{withNewline, bare} {
		authorityID, pin, err := ParseAuthorityPin("authority:test=" + keyID + "@" + path)
		if err != nil || authorityID != "authority:test" || mldsa44.KeyIDText(pin.KeyID) != keyID || string(pin.PublicKey) != string(key) {
			t.Fatalf("pin %s: id=%q err=%v", path, authorityID, err)
		}
	}
	link := filepath.Join(directory, "link.hex")
	if err := os.Symlink(bare, link); err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(keyID, mldsa44.KeyIDPrefix)
	refusals := map[string]string{
		"no authority":               "=" + keyID + "@" + bare,
		"no key file":                "authority:test=" + keyID,
		"upper-case key ID":          "authority:test=mldsa44:" + strings.ToUpper(body) + "@" + bare,
		"short key ID":               "authority:test=mldsa44:" + body[:63] + "@" + bare,
		"all-zero key ID":            "authority:test=mldsa44:" + strings.Repeat("0", 64) + "@" + bare,
		"relative path":              "authority:test=" + keyID + "@newline.hex",
		"unclean path":               "authority:test=" + keyID + "@" + directory + "/./bare.hex",
		"symlinked key file":         "authority:test=" + keyID + "@" + link,
		"group-readable key file":    "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "group.hex", hex.EncodeToString(key), 0o640),
		"Ed25519-length key":         "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "short.hex", strings.Repeat("ab", 32), 0o600),
		"upper-case key hex":         "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "upper.hex", strings.ToUpper(hex.EncodeToString(key)), 0o600),
		"two trailing newlines":      "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "two.hex", hex.EncodeToString(key)+"\n\n", 0o600),
		"trailing space":             "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "space.hex", hex.EncodeToString(key)+" ", 0o600),
		"key of another key ID":      "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "other.hex", hex.EncodeToString(other), 0o600),
		"missing key file":           "authority:test=" + keyID + "@" + filepath.Join(directory, "absent.hex"),
		"non-hex key file":           "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "nonhex.hex", strings.Repeat("zz", mldsa44.PublicKeySize), 0o600),
		"whitespace in authority ID": " authority:test=" + keyID + "@" + bare,
	}
	for name, value := range refusals {
		if _, _, err := ParseAuthorityPin(value); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	for _, value := range []string{"authority:test=ed25519:" + strings.Repeat("ab", 32),
		"authority:test=ed25519:" + strings.Repeat("ab", 32) + "@" + bare} {
		if _, _, err := ParseAuthorityPin(value); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
			t.Fatalf("an Ed25519 pin was not refused with the Ed25519 diagnostic: %v", err)
		}
	}
	if _, err := ParseAuthorityPins([]string{"authority:test=" + keyID + "@" + bare, "authority:test=" + keyID + "@" + withNewline}); err == nil {
		t.Fatal("a duplicated authority pin was accepted")
	}
}

func TestPinnedAuthoritiesResolveOnlyTheExactAuthorityAndKey(t *testing.T) {
	fake := &mldsa44test.Fake{}
	pinned, err := mldsa44.ParseKeyIDText(fake.KeyID("pinned"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := mldsa44.ParseKeyIDText(fake.KeyID("other"))
	if err != nil {
		t.Fatal(err)
	}
	pin := PinnedAuthority{KeyID: pinned, PublicKey: fake.PublicKey("pinned")}
	for name, pins := range map[string]map[string]PinnedAuthority{
		"empty set":            {},
		"key of another ID":    {"authority:test": {KeyID: other, PublicKey: fake.PublicKey("pinned")}},
		"Ed25519-length key":   {"authority:test": {KeyID: pinned, PublicKey: make([]byte, 32)}},
		"empty authority name": {"": pin},
	} {
		if _, err := NewPinnedAuthorities(pins, fake); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := NewPinnedAuthorities(map[string]PinnedAuthority{"authority:test": pin}, nil); err == nil {
		t.Fatal("pins without a verifier were accepted")
	}
	authorities, err := NewPinnedAuthorities(map[string]PinnedAuthority{"authority:test": pin}, fake)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := authorities.ResolveActionAuthorityKey("authority:test", pinned, time.Now()); err != nil || string(key) != string(pin.PublicKey) {
		t.Fatalf("pinned key was not resolved: %v", err)
	}
	if _, err := authorities.ResolveActionAuthorityKey("authority:other", pinned, time.Now()); err == nil {
		t.Fatal("a key resolved for another authority")
	}
	if _, err := authorities.ResolveActionAuthorityKey("authority:test", other, time.Now()); err == nil {
		t.Fatal("another key ID resolved")
	}
	if described := authorities.Describe(); described != "authority:test="+fake.KeyID("pinned") {
		t.Fatalf("description = %q", described)
	}
}

type carrierFixture struct {
	custody   *actionauthoritytest.Custody
	owner     testAuthority
	store     *Store
	directory string
	intent    commerce.SignedAgentIntent
	proof     commerce.OperationAdmissionProof
	action    commerce.AuthorizedAction
	fence     commerce.WriterFence
}

func custodyAuthority(t *testing.T, custody *actionauthoritytest.Custody, controller string) testAuthority {
	t.Helper()
	return testAuthority{signer: custody.Signer, verifier: custody.Signer, controller: controller,
		keyID: custody.KeyID(t, controller), publicKey: custody.PublicKeys[controller]}
}

func pinOf(t *testing.T, authority testAuthority) PinnedAuthority {
	t.Helper()
	keyID, err := mldsa44.ParseKeyIDText(authority.keyID)
	if err != nil {
		t.Fatal(err)
	}
	return PinnedAuthority{KeyID: keyID, PublicKey: authority.publicKey}
}

// newCarrierFixture opens a Carrier pinning a real ML-DSA-44 controller for
// authority:test and another for authority:foreign.
func newCarrierFixture(t *testing.T) *carrierFixture {
	t.Helper()
	custody := actionauthoritytest.NewCustody(t, actionauthoritytest.Controller, "second-key", "foreign")
	owner := custodyAuthority(t, custody, actionauthoritytest.Controller)
	pins, err := NewPinnedAuthorities(map[string]PinnedAuthority{"authority:test": pinOf(t, owner),
		"authority:foreign": pinOf(t, custodyAuthority(t, custody, "foreign"))}, custody.Signer)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "carrier")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(directory, "carrier:pq", 10, 10, pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := signedIntent(t, now)
	proof := admissionFor(t, store, intent)
	action, fence := publicationAction(t, store, intent, owner)
	return &carrierFixture{custody: custody, owner: owner, store: store, directory: directory, intent: intent,
		proof: proof, action: action, fence: fence}
}

func (fixture *carrierFixture) authorityNamed(t *testing.T, keyID string) testAuthority {
	t.Helper()
	for _, name := range []string{actionauthoritytest.Controller, "second-key", "foreign"} {
		if fixture.custody.KeyID(t, name) == keyID {
			return custodyAuthority(t, fixture.custody, name)
		}
	}
	t.Fatalf("no custody controller has key ID %s", keyID)
	return testAuthority{}
}

// carrierState digests every file the Carrier holds except its lock.
func carrierState(t *testing.T, directory string) string {
	t.Helper()
	var names []string
	contents := map[string][]byte{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || strings.Contains(entry.Name(), "lock") {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		names = append(names, path)
		contents[path] = raw
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write(contents[name])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func TestCarrierRefusesEveryNonActionAuthorityPublication(t *testing.T) {
	fixture := newCarrierFixture(t)
	before := carrierState(t, fixture.directory)
	fenceMessage, err := commerce.WriterFenceSignatureMessage(fixture.fence.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, fixture.owner.controller, "second-key",
		fixture.fence.KeyID, fixture.fence.Proof, fenceMessage) {
		// A variant that still encodes canonically gets an action freshly
		// bound to it and validly signed by the controller holding its key
		// ID, so only the fence signature or pin can refuse it.
		bad := fixture.fence
		bad.KeyID, bad.Proof = variant.KeyID, variant.Signature
		action := fixture.action
		if _, digestErr := commerce.WriterFenceDigest(bad); digestErr == nil {
			action = publicationActionWithFence(t, fixture.store, fixture.intent, fixture.authorityNamed(t, bad.KeyID), bad)
		}
		if _, _, err := fixture.store.PublishAdmitted(fixture.intent, fixture.proof, action, bad); err == nil {
			t.Fatalf("Carrier admitted a fence with %s", variant.Name)
		}
		if carrierState(t, fixture.directory) != before {
			t.Fatalf("Carrier wrote state for a fence with %s", variant.Name)
		}
	}
	actionMessage, err := commerce.AuthorizedActionSignatureMessage(fixture.action)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, fixture.owner.controller, "second-key",
		fixture.action.AuthorityKeyID, fixture.action.AuthorizationProof, actionMessage) {
		bad := fixture.action
		bad.AuthorityKeyID, bad.AuthorizationProof = variant.KeyID, variant.Signature
		if _, _, err := fixture.store.PublishAdmitted(fixture.intent, fixture.proof, bad, fixture.fence); err == nil {
			t.Fatalf("Carrier admitted an action with %s", variant.Name)
		}
		if carrierState(t, fixture.directory) != before {
			t.Fatalf("Carrier wrote state for an action with %s", variant.Name)
		}
	}
	if _, _, err := fixture.store.PublishAdmitted(fixture.intent, fixture.proof, fixture.action, fixture.fence); err != nil {
		t.Fatalf("the real ML-DSA-44 publication was refused: %v", err)
	}
}

// TestCarrierRefusesAKeyPinnedForAnotherAuthority checks that a key is
// authorized only for the authority it is pinned under.
func TestCarrierRefusesAKeyPinnedForAnotherAuthority(t *testing.T) {
	fixture := newCarrierFixture(t)
	foreign := custodyAuthority(t, fixture.custody, "foreign")
	action, fence := publicationAction(t, fixture.store, fixture.intent, foreign)
	before := carrierState(t, fixture.directory)
	if _, _, err := fixture.store.PublishAdmitted(fixture.intent, fixture.proof, action, fence); err == nil {
		t.Fatal("Carrier admitted a fence signed by a key pinned for another authority")
	}
	if carrierState(t, fixture.directory) != before {
		t.Fatal("Carrier wrote state for a foreign authority key")
	}
}
