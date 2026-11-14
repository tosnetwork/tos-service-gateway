package ingress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func proxiedRequest(remote string, headers map[string][]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/svc", nil)
	r.RemoteAddr = remote
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	return r
}

func TestClientKeyTrustsOnlyTheLoopbackTerminatorsHeader(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 8,
		ClientRequestsPerWindow: 8, Window: time.Minute, MaxClients: 8, ClientAddressHeader: HeaderXForwardedFor})
	cases := []struct {
		name    string
		remote  string
		headers map[string][]string
		want    string
	}{
		{"terminator forwards a client", "127.0.0.1:5000", map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7"},
		{"right-most entry is the terminator's", "127.0.0.1:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7"}}, "203.0.113.7"},
		{"last header line wins", "[::1]:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1", "203.0.113.8"}}, "203.0.113.8"},
		{"non-loopback peer cannot claim a client", "192.0.2.10:5000",
			map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "192.0.2.10"},
		{"missing header falls back to the peer", "127.0.0.1:5000", nil, "127.0.0.1"},
		{"malformed header falls back to the peer", "127.0.0.1:5000",
			map[string][]string{"X-Forwarded-For": {"not-an-ip"}}, "127.0.0.1"},
		{"IPv6 clients are keyed by their /64", "127.0.0.1:5000",
			map[string][]string{"X-Forwarded-For": {"2001:db8:1:2:aaaa::1"}}, "2001:db8:1:2::/64"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := limiter.clientKey(proxiedRequest(test.remote, test.headers)); got != test.want {
				t.Fatalf("clientKey = %q, want %q", got, test.want)
			}
		})
	}
	first := limiter.clientKey(proxiedRequest("127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"2001:db8:1:2::ffff"}}))
	second := limiter.clientKey(proxiedRequest("127.0.0.1:2", map[string][]string{"X-Forwarded-For": {"2001:db8:1:2:1::9"}}))
	if first != second {
		t.Fatal("two addresses in one IPv6 /64 were keyed apart")
	}
}

func TestClientKeyUsesOnlyTheConfiguredHeader(t *testing.T) {
	for header, value := range map[string]string{HeaderXRealIP: "203.0.113.9", HeaderCFConnectingIP: "203.0.113.10"} {
		limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 8,
			ClientRequestsPerWindow: 8, Window: time.Minute, MaxClients: 8, ClientAddressHeader: header})
		if got := limiter.clientKey(proxiedRequest("127.0.0.1:5000", map[string][]string{header: {value}})); got != value {
			t.Fatalf("%s: clientKey = %q, want %q", header, got, value)
		}
		forwarded := map[string][]string{HeaderXForwardedFor: {"198.51.100.1"}}
		if got := limiter.clientKey(proxiedRequest("127.0.0.1:5000", forwarded)); got != "127.0.0.1" {
			t.Fatalf("%s: an unconfigured header was trusted: %q", header, got)
		}
	}
	none, _ := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 8,
		ClientRequestsPerWindow: 8, Window: time.Minute, MaxClients: 8, ClientAddressHeader: HeaderNone})
	forwarded := map[string][]string{HeaderXForwardedFor: {"203.0.113.7"}}
	if got := none.clientKey(proxiedRequest("127.0.0.1:5000", forwarded)); got != "127.0.0.1" {
		t.Fatalf("header mode none trusted a forwarded address: %q", got)
	}
}

func TestWrapGivesForwardedClientsSeparateBuckets(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 8,
		ClientRequestsPerWindow: 1, Window: time.Minute, MaxClients: 8, ClientAddressHeader: HeaderXForwardedFor})
	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	send := func(client string) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, proxiedRequest("127.0.0.1:443", map[string][]string{"X-Forwarded-For": {client}}))
		return recorder.Code
	}
	if send("203.0.113.1") != http.StatusNoContent {
		t.Fatal("first forwarded client refused")
	}
	if send("203.0.113.1") != http.StatusTooManyRequests {
		t.Fatal("first forwarded client exceeded its own allowance")
	}
	if send("203.0.113.2") != http.StatusNoContent {
		t.Fatal("a second client behind the same terminator was refused because of the first")
	}
}

func TestWrapHintsShortRetryForGlobalSaturation(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 1, ClientConcurrent: 1,
		ClientRequestsPerWindow: 100, Window: time.Minute, MaxClients: 8})
	held, outcome := limiter.acquire("other")
	if outcome != admitted {
		t.Fatal("setup request refused")
	}
	defer held()
	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxiedRequest("192.0.2.5:1", nil))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("global saturation: status %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
}

func TestWrapCutsOffSlowBodies(t *testing.T) {
	limiter, _ := newTestLimiter(t, DefaultLimits())
	limiter.bodyTimeout = 200 * time.Millisecond
	readErr := make(chan error, 1)
	server := httptest.NewServer(limiter.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		readErr <- err
	})))
	defer server.Close()
	body, writer := io.Pipe()
	defer writer.Close()
	go func() { _, _ = writer.Write([]byte("partial")) }()
	request, err := http.NewRequest(http.MethodPost, server.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if response, err := server.Client().Do(request); err == nil {
			response.Body.Close()
		}
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("a body that stalled past the deadline was read without error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled body held the request past the body read deadline")
	}
}
