package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-gateway/internal/intentcarrier"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func validConfig() Config {
	return Config{Addr: "127.0.0.1:8080", PublicBaseURL: "https://gateway.example", NativeReadToken: "read", NativeRelayToken: "relay",
		TOSRPC: TOSRPCConfig{URL: "https://tos-service-protocol.internal", Token: "backend", Timeout: time.Second, MaxMessageBytes: 1024},
		Catalog: CatalogConfig{Directory: "/var/lib/tos-service/catalog", NetworkID: "test", GenesisRootHash: "sha256:root",
			GenesisFileHash: "sha256:file", RegistryCodeHash: "tvm-cell-sha256:code", MaxEntries: 100}}
}

func TestValidateNativeOnlyConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg.NativeRelayToken = cfg.NativeReadToken
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("error = %v", err)
	}
	cfg = validConfig()
	cfg.PublicBaseURL = "http://gateway.example"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("error = %v", err)
	}
	cfg = validConfig()
	cfg.TOSRPC.URL = "http://127.0.0.1:9443"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "INSECURE") {
		t.Fatalf("error = %v", err)
	}
	cfg = validConfig()
	cfg.QuoteProfileFile = "relative/profile.json"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v", err)
	}
}

func TestIntentCarrierRequiresPinsAndTheVerifyOnlyHelper(t *testing.T) {
	cfg := validConfig()
	cfg.IntentCarrier = IntentCarrierConfig{Directory: "/var/lib/tos-service/intents", CarrierID: "carrier:test",
		MaxEntries: 10, MaxActorEntries: 1,
		AuthorityPins: map[string]intentcarrier.PinnedAuthority{"authority:test": {}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "TOS_SERVICE_TOSCTL") {
		t.Fatalf("carrier without the helper: error = %v", err)
	}
	cfg.IntentCarrier.TosctlBinary, cfg.IntentCarrier.TosctlSHA256 = "/usr/local/bin/tosctl", strings.Repeat("a", 64)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.IntentCarrier.AuthorityPins = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled carrier without pins was accepted")
	}
	for name, partial := range map[string]IntentCarrierConfig{
		"pins without carrier":   {AuthorityPins: map[string]intentcarrier.PinnedAuthority{"authority:test": {}}},
		"helper without carrier": {TosctlBinary: "/usr/local/bin/tosctl"},
		"hash without carrier":   {TosctlSHA256: strings.Repeat("a", 64)},
	} {
		cfg := validConfig()
		cfg.IntentCarrier = partial
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestAuthorityPinsRefuseEd25519(t *testing.T) {
	_, err := parseAuthorityPins("authority:test=ed25519:" + strings.Repeat("ab", 32))
	if !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("error = %v", err)
	}
	if pins, err := parseAuthorityPins(" "); err != nil || len(pins) != 0 {
		t.Fatalf("empty pins: %v %v", pins, err)
	}
}
