// Package quotesource loads an owner-private provider commercial profile and
// constructs the production non-canonical Quote source.
package quotesource

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteprovider"
)

const Schema = "tos.service.provider-quote-profile.v1"

type Profile struct {
	Schema           string `json:"schema"`
	ProviderAgentID  string `json:"provider_agent_id"`
	ProviderAddress  string `json:"provider_address"`
	ManifestCBORFile string `json:"manifest_cbor_file"`
	Transport        struct {
		SecurityMode    uint8  `json:"security_mode"`
		MaxRequestBytes uint32 `json:"max_request_bytes"`
		BaseURL         string `json:"base_url"`
	} `json:"transport"`
	Price struct {
		MasterWorkchain int32  `json:"master_workchain"`
		MasterAccountID string `json:"master_account_id"`
		MasterCodeHash  string `json:"master_code_hash"`
		WalletCodeHash  string `json:"wallet_code_hash"`
		Decimals        uint32 `json:"decimals"`
		AtomicAmount    string `json:"atomic_amount"`
	} `json:"maximum_price"`
	ProposalTTLSeconds   uint64 `json:"proposal_ttl_seconds"`
	FundingWindowSeconds uint64 `json:"funding_window_seconds"`
	RefundDelaySeconds   uint64 `json:"refund_delay_seconds"`
}

func Load(path string, resolver quoteprovider.NativeResolver, network *nativev1.NetworkDomain,
	registryCodeHash string, timeout time.Duration) (*quoteprovider.Provider, error) {
	raw, err := readPrivate(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var profile Profile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return nil, errors.New("decode provider Quote profile")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || profile.Schema != Schema {
		return nil, errors.New("invalid provider Quote profile schema or trailing data")
	}
	manifest, err := readPrivate(profile.ManifestCBORFile, 1<<20)
	if err != nil {
		return nil, err
	}
	account, err := hex.DecodeString(profile.Price.MasterAccountID)
	if err != nil || len(account) != 32 {
		return nil, errors.New("invalid provider Quote asset account")
	}
	if profile.ProposalTTLSeconds > 3600 || profile.FundingWindowSeconds > 3600 || profile.RefundDelaySeconds > 86400 {
		return nil, errors.New("provider Quote timing value exceeds bound")
	}
	return quoteprovider.New(quoteprovider.Config{Resolver: resolver, Network: network,
		RegistryCodeHash: registryCodeHash, ProviderAgentID: profile.ProviderAgentID,
		ProviderAddress: profile.ProviderAddress, ManifestCBOR: manifest,
		Transport: nativecore.TransportBindingV1{SecurityMode: profile.Transport.SecurityMode,
			MaxRequestBytes: profile.Transport.MaxRequestBytes, BaseURL: profile.Transport.BaseURL},
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: profile.Price.MasterWorkchain, AccountId: account, CodeHash: profile.Price.MasterCodeHash},
			WalletCodeHash: profile.Price.WalletCodeHash, Decimals: profile.Price.Decimals}, AtomicAmount: profile.Price.AtomicAmount},
		ProposalTTL:       time.Duration(profile.ProposalTTLSeconds) * time.Second,
		FundingWindow:     time.Duration(profile.FundingWindowSeconds) * time.Second,
		RefundDelay:       time.Duration(profile.RefundDelaySeconds) * time.Second,
		ResolutionTimeout: timeout, CallerID: "tos-service-provider-quote-source"})
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
