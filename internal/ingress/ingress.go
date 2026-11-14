// Package ingress bounds the work an unauthenticated or token-holding client
// can make the public gateway do before any handler runs: request size,
// global concurrency, and per-client concurrency and request rate.
package ingress

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
)

// MaxRequestBytes is the largest request the public Connect services accept.
// The same value is advertised in the gateway discovery document, so the
// advertised and enforced bounds cannot drift apart.
const MaxRequestBytes = 1 << 20

// Limits configures the request limiter. Every field must be positive.
type Limits struct {
	// GlobalConcurrent bounds requests in flight across all clients.
	GlobalConcurrent int
	// ClientConcurrent bounds requests in flight from one client.
	ClientConcurrent int
	// ClientRequestsPerWindow bounds requests one client may start per Window.
	ClientRequestsPerWindow int
	// Window is the fixed rate-limit window.
	Window time.Duration
	// MaxClients bounds the number of tracked clients. When it is reached and
	// no tracked window has expired, new clients are refused rather than
	// letting the table grow without limit.
	MaxClients int
}

// DefaultLimits are the public Connect service limits.
func DefaultLimits() Limits {
	return Limits{GlobalConcurrent: 64, ClientConcurrent: 8, ClientRequestsPerWindow: 600,
		Window: time.Minute, MaxClients: 4096}
}

func (l Limits) validate() error {
	if l.GlobalConcurrent <= 0 || l.ClientConcurrent <= 0 || l.ClientRequestsPerWindow <= 0 ||
		l.Window <= 0 || l.MaxClients <= 0 {
		return errors.New("ingress limits must all be positive")
	}
	if l.ClientConcurrent > l.GlobalConcurrent {
		return errors.New("per-client concurrency cannot exceed global concurrency")
	}
	return nil
}

type clientWindow struct {
	started  time.Time
	requests int
	active   int
}

// Limiter enforces Limits for one listener.
type Limiter struct {
	limits  Limits
	now     func() time.Time
	global  chan struct{}
	mu      sync.Mutex
	clients map[string]clientWindow
}

// NewLimiter returns a limiter, or an error for invalid limits. A nil clock
// uses the system clock.
func NewLimiter(limits Limits, now func() time.Time) (*Limiter, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{limits: limits, now: now, global: make(chan struct{}, limits.GlobalConcurrent),
		clients: make(map[string]clientWindow)}, nil
}

// acquire admits one request from client, returning its release function.
func (l *Limiter) acquire(client string) (func(), bool) {
	select {
	case l.global <- struct{}{}:
	default:
		return nil, false
	}
	l.mu.Lock()
	now := l.now()
	window, tracked := l.clients[client]
	if !tracked && len(l.clients) >= l.limits.MaxClients {
		l.evictIdleLocked(now)
		if len(l.clients) >= l.limits.MaxClients {
			l.mu.Unlock()
			<-l.global
			return nil, false
		}
	}
	if window.started.IsZero() || now.Sub(window.started) >= l.limits.Window || now.Before(window.started) {
		window = clientWindow{started: now, active: window.active}
	}
	if window.active >= l.limits.ClientConcurrent || window.requests >= l.limits.ClientRequestsPerWindow {
		l.clients[client] = window
		l.mu.Unlock()
		<-l.global
		return nil, false
	}
	window.requests++
	window.active++
	l.clients[client] = window
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			current := l.clients[client]
			if current.active > 0 {
				current.active--
			}
			l.clients[client] = current
			l.mu.Unlock()
			<-l.global
		})
	}, true
}

// evictIdleLocked drops clients with no request in flight whose window has
// expired. Clients with requests in flight are kept so their release still
// finds their entry.
func (l *Limiter) evictIdleLocked(now time.Time) {
	for client, window := range l.clients {
		if window.active == 0 && (now.Sub(window.started) >= l.limits.Window || now.Before(window.started)) {
			delete(l.clients, client)
		}
	}
}

// clientKey identifies the connecting peer. Forwarding headers are ignored on
// purpose: they are client-controlled unless a trusted proxy rewrites them,
// and trusting them would let one client rotate identities freely.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Wrap bounds next: the raw request body is capped at MaxRequestBytes and each
// request must be admitted by the limiter. Refused requests receive 429 with a
// Retry-After hint and never reach next.
func (l *Limiter) Wrap(next http.Handler) http.Handler {
	retryAfter := strconv.Itoa(int((l.limits.Window + time.Second - 1) / time.Second))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, ok := l.acquire(clientKey(r))
		if !ok {
			w.Header().Set("Retry-After", retryAfter)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		defer release()
		if r.ContentLength > MaxRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
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
