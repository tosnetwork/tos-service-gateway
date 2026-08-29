package trustedcapabilitycarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPEpochAuthority stores the Carrier source high-water outside the Carrier
// failure domain. Restoring the Carrier data directory therefore cannot roll
// this authority back with it.
type HTTPEpochAuthority struct {
	endpoint     string
	token        string
	client       *http.Client
	lease        GenerationLease
	leaseDigest  []byte
	authorityKey ed25519.PublicKey
}

type GenerationLease struct {
	CarrierID       string `json:"carrier_id"`
	Generation      uint64 `json:"generation"`
	PriorGeneration uint64 `json:"prior_generation"`
	IssuedAtUnix    uint64 `json:"issued_at_unix"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
	Nonce           []byte `json:"nonce"`
	Signature       []byte `json:"signature"`
}

func OpenHTTPEpochAuthority(endpoint, token string, lease GenerationLease, authorityKey ed25519.PublicKey, now time.Time, client *http.Client) (*HTTPEpochAuthority, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Carrier epoch authority URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	if parsed.Path != "/v1/carrier-source-state" {
		return nil, errors.New("Carrier epoch authority URL must end at /v1/carrier-source-state")
	}
	if len(token) < 32 || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("Carrier epoch authority token is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, errors.New("Carrier epoch authority HTTP timeout must be bounded")
	}
	clone := *client
	baseTransport, ok := clone.Transport.(*http.Transport)
	if !ok && clone.Transport != nil {
		return nil, errors.New("Carrier epoch authority requires an inspectable HTTP transport")
	}
	if baseTransport == nil {
		baseTransport = http.DefaultTransport.(*http.Transport)
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	host := parsed.Hostname()
	parsedHostIP := net.ParseIP(host)
	allowLoopback := parsedHostIP != nil && parsedHostIP.IsLoopback()
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify && !allowLoopback {
		return nil, errors.New("Carrier epoch authority forbids insecure TLS outside literal loopback tests")
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		targetHost, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		answers, err := net.DefaultResolver.LookupIPAddr(ctx, targetHost)
		if err != nil || len(answers) == 0 || len(answers) > 32 {
			return nil, errors.New("Carrier epoch authority DNS resolution failed policy")
		}
		var last error
		for _, answer := range answers {
			ip := answer.IP
			prohibited := ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
			if prohibited && !(allowLoopback && ip != nil && ip.IsLoopback()) {
				continue
			}
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			last = dialErr
		}
		if last != nil {
			return nil, last
		}
		return nil, errors.New("Carrier epoch authority resolved only to prohibited addresses")
	}
	clone.Transport = transport
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("Carrier epoch authority redirects are forbidden")
	}
	client = &clone
	message, wire := GenerationLeaseMessage(lease)
	current := uint64(now.UTC().Unix())
	if len(authorityKey) != ed25519.PublicKeySize || lease.CarrierID == "" || lease.Generation == 0 || lease.PriorGeneration >= lease.Generation ||
		lease.IssuedAtUnix == 0 || current < lease.IssuedAtUnix || current >= lease.ExpiresAtUnix || len(lease.Nonce) != 32 || !ed25519.Verify(authorityKey, message, lease.Signature) {
		return nil, errors.New("Carrier generation lease is invalid, expired, or not signed by the pinned recovery authority")
	}
	digest := sha256.Sum256(append([]byte("tos.capability-carrier-generation-lease.v1/digest\x00"), wire...))
	return &HTTPEpochAuthority{endpoint: parsed.String(), token: token, client: client, lease: lease, leaseDigest: digest[:], authorityKey: append(ed25519.PublicKey(nil), authorityKey...)}, nil
}

func GenerationLeaseMessage(lease GenerationLease) ([]byte, []byte) {
	unsigned := lease
	unsigned.Signature = nil
	wire, _ := json.Marshal(unsigned)
	message := sha256.Sum256(append([]byte("tos.capability-carrier-generation-lease.v1\x00"), wire...))
	return message[:], wire
}

func (authority *HTTPEpochAuthority) CheckSourceState(ctx context.Context, carrierID string, generation, sequence uint64, commitment []byte) error {
	if carrierID == "" || carrierID != authority.lease.CarrierID || generation != authority.lease.Generation || len(commitment) != 32 {
		return errors.New("Carrier source state is incomplete")
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return errors.New("Carrier epoch authority challenge generation failed")
	}
	input := struct {
		CarrierID             string          `json:"carrier_id"`
		Generation            uint64          `json:"generation"`
		Sequence              uint64          `json:"sequence"`
		Commitment            string          `json:"commitment"`
		GenerationLease       GenerationLease `json:"generation_lease"`
		GenerationLeaseDigest string          `json:"generation_lease_digest"`
		Challenge             string          `json:"challenge"`
	}{carrierID, generation, sequence, hex.EncodeToString(commitment), authority.lease, hex.EncodeToString(authority.leaseDigest), hex.EncodeToString(challenge)}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authority.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+authority.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := authority.client.Do(request)
	if err != nil {
		return fmt.Errorf("Carrier epoch authority unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
		return fmt.Errorf("Carrier epoch authority rejected source state: HTTP %d", response.StatusCode)
	}
	var output SourceStateAcknowledgement
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Carrier epoch authority returned an invalid acknowledgement")
	}
	requestDigest := sha256.Sum256(append([]byte("tos.capability-carrier-source-state-request.v1\x00"), body...))
	if output.CarrierID != carrierID || output.Generation != generation || output.Sequence != sequence || output.Commitment != hex.EncodeToString(commitment) ||
		output.GenerationLeaseDigest != hex.EncodeToString(authority.leaseDigest) || output.Challenge != input.Challenge || output.RequestDigest != hex.EncodeToString(requestDigest[:]) ||
		len(output.Nonce) != 32 || !ed25519.Verify(authority.authorityKey, SourceStateAcknowledgementMessage(output), output.Signature) {
		return errors.New("Carrier epoch authority acknowledgement is unsigned, replayed, or cross-state")
	}
	return nil
}

type SourceStateAcknowledgement struct {
	CarrierID             string `json:"carrier_id"`
	Generation            uint64 `json:"generation"`
	Sequence              uint64 `json:"sequence"`
	Commitment            string `json:"commitment"`
	GenerationLeaseDigest string `json:"generation_lease_digest"`
	Challenge             string `json:"challenge"`
	RequestDigest         string `json:"request_digest"`
	Nonce                 []byte `json:"nonce"`
	Signature             []byte `json:"signature"`
}

func SourceStateAcknowledgementMessage(value SourceStateAcknowledgement) []byte {
	value.Signature = nil
	wire, _ := json.Marshal(value)
	digest := sha256.Sum256(append([]byte("tos.capability-carrier-source-state-ack.v1\x00"), wire...))
	return digest[:]
}
