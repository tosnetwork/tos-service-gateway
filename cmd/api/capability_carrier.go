package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/tosnetwork/tos-service-gateway/internal/config"
	"github.com/tosnetwork/tos-service-gateway/internal/trustedcapabilitycarrier"
)

func loadCapabilityCarrierSigningKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Capability Carrier signing key must be a private 0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 256 {
		return nil, errors.New("Capability Carrier signing key is unavailable or oversized")
	}
	encoded := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(encoded, "ed25519:") {
		return nil, errors.New("Capability Carrier signing key must use ed25519:<hex> encoding")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(encoded, "ed25519:"))
	if err != nil {
		return nil, errors.New("Capability Carrier signing key is invalid")
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) == ed25519.PrivateKeySize {
		key := ed25519.PrivateKey(append([]byte(nil), decoded...))
		if !key.Public().(ed25519.PublicKey).Equal(decoded[ed25519.SeedSize:]) {
			return nil, errors.New("Capability Carrier private key has an inconsistent public suffix")
		}
		return key, nil
	}
	return nil, errors.New("Capability Carrier signing key has an invalid length")
}

func loadCapabilityCarrierGenerationLease(path, publicKeyText, carrierID string, generation uint64) (trustedcapabilitycarrier.GenerationLease, ed25519.PublicKey, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return trustedcapabilitycarrier.GenerationLease{}, nil, errors.New("Carrier generation lease must be an immutable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64<<10 {
		return trustedcapabilitycarrier.GenerationLease{}, nil, errors.New("Carrier generation lease is unavailable or oversized")
	}
	var lease trustedcapabilitycarrier.GenerationLease
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&lease) != nil || lease.CarrierID != carrierID || lease.Generation != generation {
		return trustedcapabilitycarrier.GenerationLease{}, nil, errors.New("Carrier generation lease scope is invalid")
	}
	if !strings.HasPrefix(publicKeyText, "ed25519:") {
		return trustedcapabilitycarrier.GenerationLease{}, nil, errors.New("Carrier recovery authority key is invalid")
	}
	key, err := hex.DecodeString(strings.TrimPrefix(publicKeyText, "ed25519:"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return trustedcapabilitycarrier.GenerationLease{}, nil, errors.New("Carrier recovery authority key is invalid")
	}
	return lease, ed25519.PublicKey(key), nil
}

func loadCapabilityCarrierAuthorityToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("Capability Carrier authority token must be a private 0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return "", errors.New("Capability Carrier authority token is unavailable or oversized")
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("Capability Carrier authority token is invalid")
	}
	return token, nil
}

type capabilityCarrierAuthorizer struct{ principalTokens map[string]string }

func (authorizer capabilityCarrierAuthorizer) Authorize(r *http.Request, _ bool) (string, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || strings.ContainsAny(header, "\r\n") {
		return "", errors.New("missing bearer credential")
	}
	presented := strings.TrimPrefix(header, "Bearer ")
	matched := ""
	for principal, token := range authorizer.principalTokens {
		if len(token) == len(presented) && subtle.ConstantTimeCompare([]byte(token), []byte(presented)) == 1 {
			if matched != "" {
				return "", errors.New("ambiguous bearer credential")
			}
			matched = principal
		}
	}
	if matched == "" {
		return "", errors.New("invalid bearer credential")
	}
	return matched, nil
}

func capabilityServiceURL(cfg config.Config) string {
	if cfg.CapabilityCarrier.Directory == "" {
		return ""
	}
	return cfg.PublicBaseURL + "/v1/capability-objects"
}
