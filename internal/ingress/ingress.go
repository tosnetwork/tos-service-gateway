// Package ingress bounds the work a client can make the public gateway do
// before any handler runs: request size, body read time, global concurrency,
// and per-client concurrency and request rate.
package ingress

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
)

// MaxRequestBytes is the largest request the public Connect services accept.
// The same value is advertised in the gateway discovery document, so the
// advertised and enforced bounds cannot drift apart.
const MaxRequestBytes = 1 << 20

// BodyReadTimeout bounds how long one request may take to deliver its body
// once admitted, so slow senders cannot hold global slots for the server's
// whole read timeout.
const BodyReadTimeout = 10 * time.Second

// Client address headers a trusted TLS terminator may set. HeaderNone keys
// every request by its peer address.
const (
	HeaderNone           = "none"
	HeaderXForwardedFor  = "X-Forwarded-For"
	HeaderXRealIP        = "X-Real-IP"
	HeaderCFConnectingIP = "CF-Connecting-IP"
)

// overflowKey is the shared bucket for clients that arrive while the client
// table is full: they are served with one shared allowance instead of being
// refused outright.
const overflowKey = "\x00overflow"

// Limits configures the request limiter.
type Limits struct {
	// GlobalConcurrent bounds requests in flight across all clients.
	GlobalConcurrent int
	// ClientConcurrent bounds requests in flight from one client.
	ClientConcurrent int
	// ClientRequestsPerWindow bounds requests one client may start per Window.
	ClientRequestsPerWindow int
	// Window is the fixed rate-limit window.
	Window time.Duration
	// MaxClients bounds the number of individually tracked clients. Clients
	// arriving while it is full share one overflow bucket.
	MaxClients int
	// ClientAddressHeader names the header a loopback TLS terminator uses to
	// pass the original client address, or HeaderNone.
	ClientAddressHeader string
}

// DefaultLimits are the public Connect service limits.
func DefaultLimits() Limits {
	return Limits{GlobalConcurrent: 64, ClientConcurrent: 8, ClientRequestsPerWindow: 600,
		Window: time.Minute, MaxClients: 4096, ClientAddressHeader: HeaderXForwardedFor}
}

// ValidClientAddressHeader reports whether name is a supported header choice.
func ValidClientAddressHeader(name string) bool {
	switch name {
	case HeaderNone, HeaderXForwardedFor, HeaderXRealIP, HeaderCFConnectingIP:
		return true
	default:
		return false
	}
}

// Validate reports whether the limits are usable.
func (l Limits) Validate() error {
	if l.GlobalConcurrent <= 0 || l.ClientConcurrent <= 0 || l.ClientRequestsPerWindow <= 0 ||
		l.Window <= 0 || l.MaxClients <= 0 {
		return errors.New("ingress limits must all be positive")
	}
	if l.ClientConcurrent > l.GlobalConcurrent {
		return errors.New("per-client concurrency cannot exceed global concurrency")
	}
	if !ValidClientAddressHeader(l.ClientAddressHeader) {
		return errors.New("unsupported client address header")
	}
	return nil
}

type clientWindow struct {
	started  time.Time
	requests int
	active   int
}

// refusal says why a request was not admitted.
type refusal int

const (
	admitted refusal = iota
	refusedGlobal
	refusedClient
)

// Limiter enforces Limits for one listener.
type Limiter struct {
	limits      Limits
	bodyTimeout time.Duration
	now         func() time.Time
	global      chan struct{}
	mu          sync.Mutex
	clients     map[string]clientWindow
}

// NewLimiter returns a limiter, or an error for invalid limits. A nil clock
// uses the system clock.
func NewLimiter(limits Limits, now func() time.Time) (*Limiter, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{limits: limits, bodyTimeout: BodyReadTimeout, now: now, global: make(chan struct{}, limits.GlobalConcurrent),
		clients: make(map[string]clientWindow)}, nil
}

func (l *Limiter) expired(window clientWindow, now time.Time) bool {
	return window.started.IsZero() || now.Sub(window.started) >= l.limits.Window || now.Before(window.started)
}

// acquire admits one request from client, returning its release function.
func (l *Limiter) acquire(client string) (func(), refusal) {
	select {
	case l.global <- struct{}{}:
	default:
		return nil, refusedGlobal
	}
	l.mu.Lock()
	now := l.now()
	key := client
	if _, tracked := l.clients[key]; !tracked && l.trackedLocked() >= l.limits.MaxClients {
		l.evictIdleLocked(now)
		if l.trackedLocked() >= l.limits.MaxClients {
			key = overflowKey
		}
	}
	window := l.clients[key]
	if l.expired(window, now) {
		window = clientWindow{started: now, active: window.active}
	}
	if window.active >= l.limits.ClientConcurrent || window.requests >= l.limits.ClientRequestsPerWindow {
		l.clients[key] = window
		l.mu.Unlock()
		<-l.global
		return nil, refusedClient
	}
	window.requests++
	window.active++
	l.clients[key] = window
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			current := l.clients[key]
			if current.active > 0 {
				current.active--
			}
			l.clients[key] = current
			l.mu.Unlock()
			<-l.global
		})
	}, admitted
}

// trackedLocked counts individually tracked clients, excluding the overflow
// bucket.
func (l *Limiter) trackedLocked() int {
	if _, ok := l.clients[overflowKey]; ok {
		return len(l.clients) - 1
	}
	return len(l.clients)
}

// evictIdleLocked drops clients with no request in flight whose window has
// expired. Clients with requests in flight are kept so their release still
// finds their entry.
func (l *Limiter) evictIdleLocked(now time.Time) {
	for client, window := range l.clients {
		if client != overflowKey && window.active == 0 && l.expired(window, now) {
			delete(l.clients, client)
		}
	}
}

// clientKey identifies the client a request is charged to. The listener only
// binds loopback behind a TLS terminator, so the peer is normally that
// terminator; its configured header is trusted only when the peer really is
// loopback. X-Forwarded-For contributes only its right-most entry, the one the
// terminator appended: entries to its left are client-supplied. A missing or
// malformed header falls back to the peer address.
func (l *Limiter) clientKey(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if l.limits.ClientAddressHeader == HeaderNone || peerIP == nil || !peerIP.IsLoopback() {
		return normalize(peer)
	}
	values := r.Header.Values(l.limits.ClientAddressHeader)
	if len(values) == 0 {
		return normalize(peer)
	}
	value := values[len(values)-1]
	if l.limits.ClientAddressHeader == HeaderXForwardedFor {
		entries := strings.Split(value, ",")
		value = entries[len(entries)-1]
	}
	candidate := strings.TrimSpace(value)
	if net.ParseIP(candidate) == nil {
		return normalize(peer)
	}
	return normalize(candidate)
}

func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// normalize keys IPv4 clients by address and IPv6 clients by their /64, so
// one host cannot rotate through its own prefix to escape the per-client
// limits. Non-IP peers keep their literal value.
func normalize(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return address
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Wrap bounds next: each request must be admitted by the limiter, its raw
// body is capped at MaxRequestBytes and must arrive within BodyReadTimeout.
// Refused requests receive 429 with a Retry-After hint and never reach next.
func (l *Limiter) Wrap(next http.Handler) http.Handler {
	windowRetry := strconv.Itoa(int((l.limits.Window + time.Second - 1) / time.Second))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, outcome := l.acquire(l.clientKey(r))
		if outcome != admitted {
			retry := windowRetry
			if outcome == refusedGlobal {
				// Global slots free up as soon as any request finishes.
				retry = "1"
			}
			w.Header().Set("Retry-After", retry)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		defer release()
		if r.ContentLength > MaxRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(l.bodyTimeout)); err != nil &&
			!errors.Is(err, http.ErrNotSupported) {
			http.Error(w, "request deadline unavailable", http.StatusInternalServerError)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

// HandlerOptions bounds the decoded Connect message as well as the wire body,
// so a small compressed body cannot expand past MaxRequestBytes.
func HandlerOptions() []connect.HandlerOption {
	return []connect.HandlerOption{connect.WithReadMaxBytes(MaxRequestBytes)}
}
