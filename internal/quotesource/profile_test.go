package quotesource

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

var (
	actorAccount  = bytes.Repeat([]byte{0x77}, 32)
	actorCodeHash = bytes.Repeat([]byte{0x8e}, 32)
	attestorKey   = "mldsa44:" + strings.Repeat("99", 32)
)

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

// testManifest is a synthetic software-work manifest whose key 21 names a
// Service Actor of the given release code hash.
func testManifest(codeHash []byte) nativecore.SoftwareWorkManifestV1 {
	return nativecore.SoftwareWorkManifestV1{
		Protocol: nativecore.SoftwareWorkManifestProtocolV1, Version: "1.0.0", Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation: nativecore.SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: []string{"test", "./..."},
			WorkingDirectory: "/workspace/source"},
		NetworkPolicy: "none", Limits: nativecore.SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1 << 30,
			ScratchBytes: 2 << 30, OutputBytes: 16 << 20, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.tos.service.software-artifact.v1+tar"},
		ReportMediaTypes:   []string{"application/vnd.tos.service.test-report.v1+json"},
		SuccessCondition:   "exit-code-zero-and-valid-reports", RefundConditions: []string{nativecore.NoAttestedResponseRefund},
		EndpointCommitment:           "sha256:" + strings.Repeat("44", 32),
		ExecutionSignerAuthorization: nativecore.SettlementAttestorAuthorization(attestorKey), RetentionSeconds: 86400,
		SupportedAssets: []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.NativeTOSAsset}},
		Settlement: nativecore.SoftwareWorkSettlementV1{Rail: nativecore.ServiceActorRail, ActorWorkchain: 0,
			ActorAccountID: actorAccount, ActorCodeHash: codeHash, AttestorKey: attestorKey},
	}
}

type profileFiles struct {
	directory string
	manifest  []byte
	digest    string
}

func writePrivate(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newProfileFiles(t *testing.T, codeHash []byte) profileFiles {
	t.Helper()
	directory := t.TempDir()
	manifest, digest, err := nativecore.CanonicalSoftwareWorkManifest(testManifest(codeHash))
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(directory, "manifest.cbor"), manifest)
	writePrivate(t, filepath.Join(directory, "registry.boc"), []byte("te6cc"))
	if err := os.Mkdir(filepath.Join(directory, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	return profileFiles{directory: directory, manifest: manifest, digest: digest}
}

func (files profileFiles) document() map[string]any {
	return map[string]any{
		"schema": Schema, "provider_agent_id": "agent_" + strings.Repeat("44", 32),
		"manifest_cbor_file":      filepath.Join(files.directory, "manifest.cbor"),
		"transport":               map[string]any{"security_mode": 1, "max_request_bytes": 1 << 20, "base_url": "https://provider.example"},
		"proposal_ttl_seconds":    900,
		"tos_rpc_endpoints":       []string{"http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"},
		"registry_code_boc_file":  filepath.Join(files.directory, "registry.boc"),
		"service_actor_code_hash": "tvm-cell-sha256:" + hex.EncodeToString(actorCodeHash),
		"state_directory":         filepath.Join(files.directory, "state"),
	}
}

func (files profileFiles) write(t *testing.T, document map[string]any, mode os.FileMode) string {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(files.directory, "profile.json")
	writePrivate(t, path, raw)
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProfileAcceptsTheServiceActorProfile(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	profile, manifest, err := LoadProfile(files.write(t, files.document(), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, files.manifest) || len(profile.TOSRPCEndpoints) != 3 || profile.ProposalTTLSeconds != 900 {
		t.Fatalf("profile=%+v", profile)
	}
}

func TestLoadProfileRefusesEscrowFieldsAndUnboundActors(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	mutations := map[string]func(map[string]any){
		"escrow-era schema":        func(document map[string]any) { document["schema"] = "tos.service.provider-quote-profile.v1" },
		"stablecoin maximum price": func(document map[string]any) { document["maximum_price"] = map[string]any{"atomic_amount": "1"} },
		"provider address":         func(document map[string]any) { document["provider_address"] = "0:" + strings.Repeat("aa", 32) },
		"funding window":           func(document map[string]any) { document["funding_window_seconds"] = 600 },
		"refund delay":             func(document map[string]any) { document["refund_delay_seconds"] = 600 },
		"two endpoints":            func(document map[string]any) { document["tos_rpc_endpoints"] = []string{"http://a", "http://b"} },
		"nine endpoints": func(document map[string]any) {
			document["tos_rpc_endpoints"] = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}
		},
		"upper-case code hash": func(document map[string]any) {
			document["service_actor_code_hash"] = "tvm-cell-sha256:" + strings.ToUpper(hex.EncodeToString(actorCodeHash))
		},
		"zero code hash": func(document map[string]any) {
			document["service_actor_code_hash"] = "tvm-cell-sha256:" + strings.Repeat("0", 64)
		},
		"relative state dir": func(document map[string]any) { document["state_directory"] = "state" },
		"no provider":        func(document map[string]any) { document["provider_agent_id"] = "" },
		"long TTL":           func(document map[string]any) { document["proposal_ttl_seconds"] = 3601 },
		"other release": func(document map[string]any) {
			document["service_actor_code_hash"] = "tvm-cell-sha256:" + strings.Repeat("ab", 32)
		},
	}
	for name, mutate := range mutations {
		document := files.document()
		mutate(document)
		if _, _, err := LoadProfile(files.write(t, document, 0o600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, _, err := LoadProfile(files.write(t, files.document(), 0o640)); err == nil {
		t.Fatal("a group-readable profile was accepted")
	}
	if err := os.Chmod(filepath.Join(files.directory, "state"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadProfile(files.write(t, files.document(), 0o600)); err == nil {
		t.Fatal("a group-accessible state directory was accepted")
	}
}

// actorSessions is a fake finalized checkpoint holding the Capability and
// the actor.
type actorSessions struct {
	state  *nativev1.NativeStateV1
	policy nativecore.ServiceActorPolicyV1
	actor  string
}

func (a *actorSessions) BeginSession(context.Context) (serviceactor.Session, error) {
	return actorSession{a}, nil
}

type actorSession struct{ a *actorSessions }

func (s actorSession) Checkpoint() uint64   { return 10 }
func (s actorSession) ChainTime() time.Time { return time.Unix(2_000_000_000, 0) }
func (s actorSession) ResolveRegistry(context.Context, string) (*nativev1.NativeStateV1, bool, error) {
	return proto.Clone(s.a.state).(*nativev1.NativeStateV1), true, nil
}
func (s actorSession) ReadActor(_ context.Context, actor string) (*toschain.ActorAccount, bool, error) {
	s.a.actor = actor
	return &toschain.ActorAccount{Address: actor, Data: &nativecore.ServiceActorDataV1{Active: true, Policy: s.a.policy}}, true, nil
}

func TestNewProviderQuotesTheFinalizedActorPolicy(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	profile, manifest, err := LoadProfile(files.write(t, files.document(), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	network := testNetwork()
	capabilityID := "cap_" + strings.Repeat("33", 32)
	registryCodeHash := "tvm-cell-sha256:" + strings.Repeat("55", 32)
	state := &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("66", 32),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: registryCodeHash,
			TransactionHash: "sha256:" + strings.Repeat("77", 32)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: profile.ProviderAgentID, Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: files.digest}}}}}
	attestor, err := mldsa44.ParseKeyIDText(attestorKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: capabilityID, ProviderAgentID: profile.ProviderAgentID, CapabilityVersion: "1.0.0", ManifestDigest: files.digest})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &actorSessions{state: state, policy: nativecore.ServiceActorPolicyV1{PolicyVersion: 2,
		PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000), CleanupBounty: big.NewInt(100_000_000),
		ResponseSLA: 3600, RefundClaimWindow: 3600, OpenAccess: true, MetadataHash: metadata,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme, HasAttestor: true, AttestorKeyID: attestor}}
	provider, err := NewProvider(profile, manifest, sessions, network, registryCodeHash, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := &nativev1.RequestQuoteProposalRequest{Context: &nativev1.RequestContext{RequestId: "buyer-request"},
		CapabilityId: capabilityID, CapabilityVersion: "1.0.0", BuyerAddress: "0:" + strings.Repeat("cc", 32)}
	value, err := provider.RequestQuoteProposal(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quoteexchange.Validate(network, request, value, time.Now()); err != nil {
		t.Fatalf("proposal failed validation: %v", err)
	}
	terms, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(sessions.policy))
	if err != nil {
		t.Fatal(err)
	}
	if value.Proposal.TermsHash != hex.EncodeToString(terms[:]) || value.Proposal.PriceNanotos != "300000000" ||
		value.Proposal.StorageFeeNanotos != "200000000" || sessions.actor != "0:"+hex.EncodeToString(actorAccount) {
		t.Fatalf("proposal does not carry the finalized actor policy: %+v", value.Proposal)
	}
}
