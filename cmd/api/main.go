// Command api runs the stateless tos_service_v1 gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/tosnetwork/tos-service-gateway/internal/adapters/serviceprotocol"
	"github.com/tosnetwork/tos-service-gateway/internal/config"
	"github.com/tosnetwork/tos-service-gateway/internal/intentcarrier"
	"github.com/tosnetwork/tos-service-gateway/internal/nativegateway"
	"github.com/tosnetwork/tos-service-gateway/internal/quotesource"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/tos-service-protocol/pkg/capabilitycatalog"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	backend, err := toprotocol.New(toprotocol.Config{
		BaseURL: cfg.TOSRPC.URL, BearerToken: cfg.TOSRPC.Token,
		Timeout: cfg.TOSRPC.Timeout, MaxMessageBytes: cfg.TOSRPC.MaxMessageBytes,
		Insecure: cfg.TOSRPC.Insecure, ServerName: cfg.TOSRPC.ServerName,
		CAFile: cfg.TOSRPC.CAFile, ClientCertFile: cfg.TOSRPC.ClientCertFile,
		ClientKeyFile: cfg.TOSRPC.ClientKeyFile,
	})
	if err != nil {
		logger.Error("configure tos-service-protocol backend", "error", err)
		os.Exit(2)
	}
	defer backend.Close()
	catalog, err := capabilitycatalog.New(capabilitycatalog.Config{
		Directory: cfg.Catalog.Directory, Resolver: catalogBackend{backend},
		Network: &nativev1.NetworkDomain{NetworkId: cfg.Catalog.NetworkID,
			GenesisRootHash: cfg.Catalog.GenesisRootHash, GenesisFileHash: cfg.Catalog.GenesisFileHash},
		RegistryCodeHash: cfg.Catalog.RegistryCodeHash, CallerID: "tos-service-capability-catalog",
		ResolveTimeout: cfg.TOSRPC.Timeout, MaxEntries: cfg.Catalog.MaxEntries,
	})
	if err != nil {
		logger.Error("configure Capability catalog", "error", err)
		os.Exit(2)
	}
	network := &nativev1.NetworkDomain{NetworkId: cfg.Catalog.NetworkID,
		GenesisRootHash: cfg.Catalog.GenesisRootHash, GenesisFileHash: cfg.Catalog.GenesisFileHash}
	var quoteSource nativegateway.QuoteSource
	if cfg.QuoteProfileFile != "" {
		quoteSource, err = quotesource.Load(cfg.QuoteProfileFile, catalogBackend{backend}, network,
			cfg.Catalog.RegistryCodeHash, cfg.TOSRPC.Timeout)
		if err != nil {
			logger.Error("configure provider Quote source", "error", err)
			os.Exit(2)
		}
	}

	readyCtx, cancelReady := context.WithTimeout(context.Background(), cfg.TOSRPC.Timeout)
	err = backend.CheckReady(readyCtx)
	cancelReady()
	if err != nil {
		logger.Error("tos-service-protocol backend is unavailable", "error", err)
		os.Exit(1)
	}

	gateway := &nativegateway.Server{
		Authorizer: nativegateway.NewTokenAuthorizer(cfg.NativeReadToken, cfg.NativeRelayToken),
		Backend:    backend, Catalog: catalog, QuoteSource: quoteSource, Network: network,
	}
	mux := http.NewServeMux()
	path, handler := tosservicev1connect.NewNativeServiceHandler(gateway)
	mux.Handle(path, handler)
	dnsPath, dnsHandler := tosservicev1connect.NewDNSAliasServiceHandler(gateway)
	mux.Handle(dnsPath, dnsHandler)
	discoveryPath, discoveryHandler := tosservicev1connect.NewCapabilityDiscoveryServiceHandler(gateway)
	mux.Handle(discoveryPath, discoveryHandler)
	if cfg.IntentCarrier.Directory != "" {
		carrier, carrierErr := intentcarrier.Open(cfg.IntentCarrier.Directory, cfg.IntentCarrier.CarrierID, cfg.IntentCarrier.MaxEntries,
			cfg.IntentCarrier.MaxActorEntries,
			intentcarrier.PinnedAuthorities(cfg.IntentCarrier.AuthorityPins))
		if carrierErr != nil {
			logger.Error("configure Intent Carrier", "error", carrierErr)
			os.Exit(2)
		}
		defer carrier.Close()
		intentHandler := intentcarrier.Handler(carrier, intentCarrierAuthorizer{gateway.Authorizer})
		mux.Handle("/v1/intents", intentHandler)
		mux.Handle("/v1/intents/", intentHandler)
		mux.Handle("/v1/intent-actions/", intentHandler)
	}
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", readinessHandler(backend, cfg.TOSRPC.Timeout))
	mux.HandleFunc("GET /.well-known/tos-service.json", gatewayDiscoveryHandler(cfg, time.Now))

	server := &http.Server{
		Addr: cfg.Addr, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("TOS Native Service gateway listening", "address", cfg.Addr)
		errCh <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
	case serveErr := <-errCh:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("gateway stopped", "error", serveErr)
			os.Exit(1)
		}
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("gateway shutdown failed", "error", err)
	}
}

type gatewayDiscoveryDocument struct {
	Schema           string                   `json:"schema"`
	Protocol         string                   `json:"protocol"`
	Network          gatewayDiscoveryNetwork  `json:"network"`
	RegistryCodeHash string                   `json:"registry_code_hash"`
	Services         gatewayDiscoveryServices `json:"services"`
	Limits           gatewayDiscoveryLimits   `json:"limits"`
	ExpiresAt        int64                    `json:"expires_at_unix_seconds"`
}

type gatewayDiscoveryNetwork struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}
type gatewayDiscoveryServices struct {
	NativeConnect string `json:"native_connect"`
	DNSConnect    string `json:"dns_alias_connect"`
	IntentHTTP    string `json:"intent_http,omitempty"`
}
type gatewayDiscoveryLimits struct {
	MaxRequestBytes  int `json:"max_request_bytes"`
	MaxResponseBytes int `json:"max_response_bytes"`
}

func gatewayDiscoveryHandler(cfg config.Config, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		document := gatewayDiscoveryDocument{Schema: "tos.service.gateway-discovery.v1", Protocol: "tos_service_v1",
			Network:          gatewayDiscoveryNetwork{cfg.Catalog.NetworkID, cfg.Catalog.GenesisRootHash, cfg.Catalog.GenesisFileHash},
			RegistryCodeHash: cfg.Catalog.RegistryCodeHash, Services: gatewayDiscoveryServices{NativeConnect: cfg.PublicBaseURL, DNSConnect: cfg.PublicBaseURL,
				IntentHTTP: intentServiceURL(cfg)},
			Limits:    gatewayDiscoveryLimits{MaxRequestBytes: 1 << 20, MaxResponseBytes: cfg.TOSRPC.MaxMessageBytes},
			ExpiresAt: now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(document)
	}
}

func intentServiceURL(cfg config.Config) string {
	if cfg.IntentCarrier.Directory == "" {
		return ""
	}
	return cfg.PublicBaseURL + "/v1/intents"
}

type intentCarrierAuthorizer struct{ authorizer nativegateway.Authorizer }

func (authorizer intentCarrierAuthorizer) Authorize(header string, write bool) error {
	permission := nativegateway.PermissionRead
	if write {
		permission = nativegateway.PermissionRelay
	}
	if authorizer.authorizer == nil {
		return errors.New("Intent Carrier authorization is unavailable")
	}
	return authorizer.authorizer.Authorize(header, permission)
}

type catalogBackend struct{ client *toprotocol.Client }

func (b catalogBackend) ResolveNativeState(ctx context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	response, err := b.client.ResolveNativeState(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

type readinessChecker interface{ CheckReady(context.Context) error }

func readinessHandler(checker readinessChecker, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		if checker == nil || checker.CheckReady(ctx) != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
