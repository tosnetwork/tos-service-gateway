package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/tosnetwork/tos-service-gateway/internal/config"
	"github.com/tosnetwork/tos-service-gateway/internal/ingress"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1/tosservicev1connect"
)

type countingConnectServer struct {
	tosservicev1connect.UnimplementedNativeServiceHandler
	tosservicev1connect.UnimplementedDNSAliasServiceHandler
	tosservicev1connect.UnimplementedCapabilityDiscoveryServiceHandler
	publishCalls atomic.Int32
}

func (s *countingConnectServer) PublishSoftwareWorkManifest(context.Context, *connect.Request[nativev1.PublishSoftwareWorkManifestRequest]) (*connect.Response[nativev1.PublishSoftwareWorkManifestResponse], error) {
	s.publishCalls.Add(1)
	return connect.NewResponse(&nativev1.PublishSoftwareWorkManifestResponse{}), nil
}

func newPublicConnectTestServer(t *testing.T, limits ingress.Limits) (*countingConnectServer, *httptest.Server) {
	t.Helper()
	limiter, err := ingress.NewLimiter(limits, nil)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	server := &countingConnectServer{}
	mux := http.NewServeMux()
	registerPublicConnect(mux, server, limiter)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return server, httpServer
}

func TestPublicConnectRejectsMessagesAboveAdvertisedLimit(t *testing.T) {
	server, httpServer := newPublicConnectTestServer(t, ingress.DefaultLimits())
	// Gzip makes a zero-filled message tiny on the wire, so this exercises the
	// decoded-message bound rather than only the raw body bound.
	client := tosservicev1connect.NewCapabilityDiscoveryServiceClient(httpServer.Client(), httpServer.URL,
		connect.WithSendGzip(), connect.WithSendMaxBytes(4*ingress.MaxRequestBytes))

	oversized := &nativev1.PublishSoftwareWorkManifestRequest{CanonicalCbor: make([]byte, ingress.MaxRequestBytes+1)}
	_, err := client.PublishSoftwareWorkManifest(context.Background(), connect.NewRequest(oversized))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized compressed message: error %v (code %v), want resource_exhausted", err, connect.CodeOf(err))
	}
	if calls := server.publishCalls.Load(); calls != 0 {
		t.Fatalf("handler ran %d times for an oversized message", calls)
	}

	small := &nativev1.PublishSoftwareWorkManifestRequest{CanonicalCbor: make([]byte, 1024)}
	if _, err := client.PublishSoftwareWorkManifest(context.Background(), connect.NewRequest(small)); err != nil {
		t.Fatalf("small message refused: %v", err)
	}
	if calls := server.publishCalls.Load(); calls != 1 {
		t.Fatalf("handler ran %d times, want 1", calls)
	}
}

func TestPublicConnectRateLimitsEveryService(t *testing.T) {
	server, httpServer := newPublicConnectTestServer(t, ingress.Limits{GlobalConcurrent: 4, ClientConcurrent: 4,
		ClientRequestsPerWindow: 1, Window: time.Hour, MaxClients: 4, ClientAddressHeader: ingress.HeaderXForwardedFor})
	discovery := tosservicev1connect.NewCapabilityDiscoveryServiceClient(httpServer.Client(), httpServer.URL)
	request := connect.NewRequest(&nativev1.PublishSoftwareWorkManifestRequest{})
	if _, err := discovery.PublishSoftwareWorkManifest(context.Background(), request); err != nil {
		t.Fatalf("first request refused: %v", err)
	}
	_, err := discovery.PublishSoftwareWorkManifest(context.Background(), connect.NewRequest(&nativev1.PublishSoftwareWorkManifestRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("rate-limited request: error %v (code %v), want unavailable", err, connect.CodeOf(err))
	}
	if calls := server.publishCalls.Load(); calls != 1 {
		t.Fatalf("handler ran %d times, want 1", calls)
	}
	// The limiter is shared by all public services: the client's window is
	// already spent, so the Native and DNS services refuse it too instead of
	// each granting a fresh allowance.
	native := tosservicev1connect.NewNativeServiceClient(httpServer.Client(), httpServer.URL)
	_, err = native.ResolveNativeState(context.Background(), connect.NewRequest(&nativev1.ResolveNativeStateRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("Native service after the window was spent: error %v (code %v), want unavailable", err, connect.CodeOf(err))
	}
	dns := tosservicev1connect.NewDNSAliasServiceClient(httpServer.Client(), httpServer.URL)
	_, err = dns.ResolveDNSAlias(context.Background(), connect.NewRequest(&nativev1.ResolveDNSAliasRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("DNS service after the window was spent: error %v (code %v), want unavailable", err, connect.CodeOf(err))
	}
}

func TestGatewayDiscoveryAdvertisesEnforcedRequestLimit(t *testing.T) {
	response := httptest.NewRecorder()
	gatewayDiscoveryHandler(config.Config{PublicBaseURL: "https://gateway.example"}, time.Now)(response,
		httptest.NewRequest(http.MethodGet, "/.well-known/tos-service.json", nil))
	var document gatewayDiscoveryDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}
	if document.Limits.MaxRequestBytes != ingress.MaxRequestBytes {
		t.Fatalf("advertised max_request_bytes %d, enforced %d", document.Limits.MaxRequestBytes, ingress.MaxRequestBytes)
	}
}
