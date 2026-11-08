// Package quotesource loads an owner-private provider profile and constructs
// the production non-canonical Quote source on the Service Actor rail. The
// price, storage fee and terms come from the actor's finalized policy, read at
// the same quorum-finalized checkpoint as the Capability; the profile carries
// no price and grants no authority.
package quotesource

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteprovider"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const Schema = "tos.service.provider-quote-profile.v2"

const (
	minimumEndpoints = 3
	maximumEndpoints = 8
	cellHashPrefix   = "tvm-cell-sha256:"
)

type Profile struct {
	Schema           string `json:"schema"`
	ProviderAgentID  string `json:"provider_agent_id"`
	ManifestCBORFile string `json:"manifest_cbor_file"`
	Transport        struct {
		SecurityMode    uint8  `json:"security_mode"`
		MaxRequestBytes uint32 `json:"max_request_bytes"`
		BaseURL         string `json:"base_url"`
	} `json:"transport"`
	ProposalTTLSeconds uint64 `json:"proposal_ttl_seconds"`
	// TOSRPCEndpoints are the JSON-RPC endpoints read under a strict-majority
	// quorum for the finalized Capability and Service Actor state.
	TOSRPCEndpoints []string `json:"tos_rpc_endpoints"`
	// RegistryCodeBOCFile is the owner-only base64 Native Registry code BOC.
	RegistryCodeBOCFile string `json:"registry_code_boc_file"`
	// ServiceActorCodeHash pins the Service Actor release.
	ServiceActorCodeHash string `json:"service_actor_code_hash"`
	// StateDirectory is an owner-only directory for the finalized checkpoint
	// high-water files.
	StateDirectory string `json:"state_directory"`
}

// LoadProfile reads and validates the profile and its canonical manifest.
// It refuses a profile whose manifest names a Service Actor of another
// release than the one pinned.
func LoadProfile(path string) (Profile, []byte, error) {
	raw, err := readPrivate(path, 64<<10)
	if err != nil {
		return Profile{}, nil, err
	}
	var profile Profile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, nil, errors.New("decode provider Quote profile")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || profile.Schema != Schema {
		return Profile{}, nil, errors.New("invalid provider Quote profile schema or trailing data")
	}
	if profile.ProviderAgentID == "" || profile.ProposalTTLSeconds > 3600 {
		return Profile{}, nil, errors.New("provider Quote profile identity or timing is invalid")
	}
	if len(profile.TOSRPCEndpoints) < minimumEndpoints || len(profile.TOSRPCEndpoints) > maximumEndpoints {
		return Profile{}, nil, errors.New("provider Quote profile needs 3 to 8 TOS JSON-RPC endpoints")
	}
	codeHash, err := cellHash(profile.ServiceActorCodeHash)
	if err != nil {
		return Profile{}, nil, errors.New("provider Quote profile must pin the Service Actor release as tvm-cell-sha256:<64 lowercase hex>")
	}
	if err := privateDirectory(profile.StateDirectory); err != nil {
		return Profile{}, nil, err
	}
	manifest, err := readPrivate(profile.ManifestCBORFile, 1<<20)
	if err != nil {
		return Profile{}, nil, err
	}
	decoded, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(manifest)
	if err != nil {
		return Profile{}, nil, errors.New("provider Quote manifest is not canonical")
	}
	if !bytes.Equal(decoded.Settlement.ActorCodeHash, codeHash) {
		return Profile{}, nil, errors.New("provider Quote manifest names a Service Actor release other than the pinned one")
	}
	return profile, manifest, nil
}

// NewProvider builds the Quote provider over a finalized session source.
func NewProvider(profile Profile, manifest []byte, sessions quoteprovider.SessionSource, network *nativev1.NetworkDomain,
	registryCodeHash string, timeout time.Duration) (*quoteprovider.Provider, error) {
	return quoteprovider.New(quoteprovider.Config{Sessions: sessions, Network: network,
		RegistryCodeHash: registryCodeHash, ProviderAgentID: profile.ProviderAgentID, ManifestCBOR: manifest,
		Transport: nativecore.TransportBindingV1{SecurityMode: profile.Transport.SecurityMode,
			MaxRequestBytes: profile.Transport.MaxRequestBytes, BaseURL: profile.Transport.BaseURL},
		ProposalTTL:       time.Duration(profile.ProposalTTLSeconds) * time.Second,
		ResolutionTimeout: timeout, CallerID: "tos-service-provider-quote-source"})
}

// Load reads the profile and opens a quorum-finalized Service Actor reader
// for it: the Capability and the actor are read at one checkpoint.
func Load(path string, network *nativev1.NetworkDomain, registryCodeHash string,
	timeout time.Duration) (*quoteprovider.Provider, error) {
	profile, manifest, err := LoadProfile(path)
	if err != nil {
		return nil, err
	}
	reader, err := openReader(profile, network, registryCodeHash)
	if err != nil {
		return nil, err
	}
	return NewProvider(profile, manifest, quoteprovider.FromChain(reader), network, registryCodeHash, timeout)
}

func openReader(profile Profile, network *nativev1.NetworkDomain, registryCodeHash string) (*toschain.ServiceActorReader, error) {
	if network == nil {
		return nil, errors.New("provider Quote source needs the network domain")
	}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId, Endpoints: append([]string(nil), profile.TOSRPCEndpoints...),
		Quorum: len(profile.TOSRPCEndpoints)/2 + 1})
	if err != nil {
		return nil, err
	}
	code, err := readPrivate(profile.RegistryCodeBOCFile, 1<<20)
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(network, 0, strings.Join(strings.Fields(string(code)), ""), registryCodeHash)
	if err != nil {
		return nil, errors.New("provider Quote Registry code does not match the pinned Registry code hash")
	}
	registry, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(profile.StateDirectory, "registry.checkpoint"))
	if err != nil {
		return nil, err
	}
	return toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: network,
		ActorCodeHash: profile.ServiceActorCodeHash, Registry: registry,
		CheckpointPath: filepath.Join(profile.StateDirectory, "service-actor.checkpoint")})
}

func cellHash(value string) ([]byte, error) {
	body, found := strings.CutPrefix(value, cellHashPrefix)
	if !found || len(body) != 64 || body != strings.ToLower(body) {
		return nil, errors.New("invalid cell hash")
	}
	raw, err := hex.DecodeString(body)
	if err != nil || bytes.Equal(raw, make([]byte, 32)) {
		return nil, errors.New("invalid cell hash")
	}
	return raw, nil
}

func privateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("provider Quote state directory must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !fileOwner(info) || info.Mode().Perm() != 0o700 {
		return errors.New("provider Quote state directory must be an existing owner-only mode-0700 directory")
	}
	return nil
}

func readPrivate(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("provider Quote file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !fileOwner(before) || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 ||
		before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("provider Quote file must be an owner-only bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("provider Quote file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("provider Quote file exceeds bound")
	}
	return raw, nil
}
