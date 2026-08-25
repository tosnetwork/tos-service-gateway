package intentcarrier

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// PinnedAuthorities is the deployment's explicit owner Action Authority trust
// set. Carrier storage never learns authority from an untrusted publication.
type PinnedAuthorities map[string]ed25519.PublicKey

func (pins PinnedAuthorities) AuthorizeFenceKey(authorityID string, key ed25519.PublicKey, _ time.Time) error {
	expected, found := pins[authorityID]
	if !found || !expected.Equal(key) {
		return errors.New("publication Action Authority key is not pinned")
	}
	return nil
}
