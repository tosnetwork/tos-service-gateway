package config

import (
	"strings"
	"testing"
	"time"
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
