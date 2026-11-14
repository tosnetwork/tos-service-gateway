package ingress

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestLimiter(t *testing.T, limits Limits) (*Limiter, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	limiter, err := NewLimiter(limits, clock.Now)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	return limiter, clock
}

func TestNewLimiterRejectsInvalidLimits(t *testing.T) {
	valid := DefaultLimits()
	cases := map[string]func(*Limits){
		"zero global":            func(l *Limits) { l.GlobalConcurrent = 0 },
		"zero client concurrent": func(l *Limits) { l.ClientConcurrent = 0 },
		"zero client rate":       func(l *Limits) { l.ClientRequestsPerWindow = 0 },
		"zero window":            func(l *Limits) { l.Window = 0 },
		"zero max clients":       func(l *Limits) { l.MaxClients = 0 },
		"negative global":        func(l *Limits) { l.GlobalConcurrent = -1 },
		"client above global":    func(l *Limits) { l.ClientConcurrent = l.GlobalConcurrent + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			limits := valid
			mutate(&limits)
			if _, err := NewLimiter(limits, nil); err == nil {
				t.Fatalf("NewLimiter accepted %+v", limits)
			}
		})
	}
	if _, err := NewLimiter(valid, nil); err != nil {
		t.Fatalf("NewLimiter rejected default limits: %v", err)
	}
}

func TestLimiterEnforcesPerClientRateAndResetsAfterWindow(t *testing.T) {
	limiter, clock := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 8,
		ClientRequestsPerWindow: 3, Window: time.Minute, MaxClients: 16})
	for i := 0; i < 3; i++ {
		release, ok := limiter.acquire("a")
		if !ok {
			t.Fatalf("request %d refused within rate", i)
		}
		release()
	}
	if _, ok := limiter.acquire("a"); ok {
		t.Fatal("request above the per-window rate was admitted")
	}
	if release, ok := limiter.acquire("b"); !ok {
		t.Fatal("another client was refused because of client a's rate")
	} else {
		release()
	}
	clock.Advance(time.Minute)
	if release, ok := limiter.acquire("a"); !ok {
		t.Fatal("request refused after the window expired")
	} else {
		release()
	}
}

func TestLimiterTreatsBackwardClockAsNewWindow(t *testing.T) {
	limiter, clock := newTestLimiter(t, Limits{GlobalConcurrent: 4, ClientConcurrent: 4,
		ClientRequestsPerWindow: 1, Window: time.Minute, MaxClients: 4})
	release, ok := limiter.acquire("a")
	if !ok {
		t.Fatal("first request refused")
	}
	release()
	clock.Advance(-time.Hour)
	if release, ok := limiter.acquire("a"); !ok {
		t.Fatal("a clock step backwards must not lock the client out until the clock catches up")
	} else {
		release()
	}
}

func TestLimiterEnforcesPerClientConcurrency(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 2,
		ClientRequestsPerWindow: 100, Window: time.Minute, MaxClients: 16})
	first, ok1 := limiter.acquire("a")
	second, ok2 := limiter.acquire("a")
	if !ok1 || !ok2 {
		t.Fatal("requests within client concurrency refused")
	}
	if _, ok := limiter.acquire("a"); ok {
		t.Fatal("request above per-client concurrency admitted")
	}
	first()
	third, ok := limiter.acquire("a")
	if !ok {
		t.Fatal("request refused after a slot was released")
	}
	second()
	third()
}

func TestLimiterEnforcesGlobalConcurrency(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 2, ClientConcurrent: 2,
		ClientRequestsPerWindow: 100, Window: time.Minute, MaxClients: 16})
	first, ok1 := limiter.acquire("a")
	second, ok2 := limiter.acquire("b")
	if !ok1 || !ok2 {
		t.Fatal("requests within global concurrency refused")
	}
	if _, ok := limiter.acquire("c"); ok {
		t.Fatal("request above global concurrency admitted")
	}
	first()
	third, ok := limiter.acquire("c")
	if !ok {
		t.Fatal("request refused after a global slot was released")
	}
	second()
	third()
}

func TestLimiterRefusesNewClientsWhenTableIsFull(t *testing.T) {
	limiter, clock := newTestLimiter(t, Limits{GlobalConcurrent: 8, ClientConcurrent: 2,
		ClientRequestsPerWindow: 100, Window: time.Minute, MaxClients: 2})
	held, ok := limiter.acquire("a")
	if !ok {
		t.Fatal("first client refused")
	}
	release, ok := limiter.acquire("b")
	if !ok {
		t.Fatal("second client refused")
	}
	release()
	if _, ok := limiter.acquire("c"); ok {
		t.Fatal("a new client was admitted while the table is full of live windows")
	}
	if len(limiter.clients) != 2 {
		t.Fatalf("client table grew to %d entries", len(limiter.clients))
	}
	clock.Advance(time.Minute)
	release, ok = limiter.acquire("c")
	if !ok {
		t.Fatal("new client refused after an idle window expired")
	}
	release()
	if _, tracked := limiter.clients["a"]; !tracked {
		t.Fatal("a client with a request in flight was evicted")
	}
	held()
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 1, ClientConcurrent: 1,
		ClientRequestsPerWindow: 100, Window: time.Minute, MaxClients: 4})
	release, ok := limiter.acquire("a")
	if !ok {
		t.Fatal("request refused")
	}
	release()
	release()
	held, ok := limiter.acquire("b")
	if !ok {
		t.Fatal("request refused after release")
	}
	if _, ok := limiter.acquire("c"); ok {
		t.Fatal("a repeated release freed a global slot it did not hold")
	}
	held()
}

func TestLimiterConcurrentUseKeepsCountsBalanced(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 4, ClientConcurrent: 2,
		ClientRequestsPerWindow: 1_000_000, Window: time.Minute, MaxClients: 8})
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(client string) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if release, ok := limiter.acquire(client); ok {
					release()
				}
			}
		}(string(rune('a' + worker%4)))
	}
	wg.Wait()
	if len(limiter.global) != 0 {
		t.Fatalf("%d global slots leaked", len(limiter.global))
	}
	for client, window := range limiter.clients {
		if window.active != 0 {
			t.Fatalf("client %s left %d active requests", client, window.active)
		}
	}
}

func TestWrapRejectsOversizedBodies(t *testing.T) {
	limiter, _ := newTestLimiter(t, DefaultLimits())
	var reached bool
	var readErr error
	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, readErr = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))

	declared := httptest.NewRequest(http.MethodPost, "/svc", bytes.NewReader(make([]byte, MaxRequestBytes+1)))
	declared.RemoteAddr = "192.0.2.1:1000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, declared)
	if recorder.Code != http.StatusRequestEntityTooLarge || reached {
		t.Fatalf("declared oversized body: status %d, handler reached %v", recorder.Code, reached)
	}

	undeclared := httptest.NewRequest(http.MethodPost, "/svc", io.MultiReader(bytes.NewReader(make([]byte, MaxRequestBytes+1))))
	undeclared.ContentLength = -1
	undeclared.RemoteAddr = "192.0.2.1:1001"
	handler.ServeHTTP(httptest.NewRecorder(), undeclared)
	if readErr == nil {
		t.Fatal("an undeclared oversized body was read to the end")
	}

	reached, readErr = false, nil
	exact := httptest.NewRequest(http.MethodPost, "/svc", bytes.NewReader(make([]byte, MaxRequestBytes)))
	exact.RemoteAddr = "192.0.2.1:1002"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, exact)
	if recorder.Code != http.StatusNoContent || !reached || readErr != nil {
		t.Fatalf("body at the limit: status %d, reached %v, read error %v", recorder.Code, reached, readErr)
	}
}

func TestWrapRefusesRateLimitedClientWithRetryAfter(t *testing.T) {
	limiter, _ := newTestLimiter(t, Limits{GlobalConcurrent: 4, ClientConcurrent: 4,
		ClientRequestsPerWindow: 1, Window: 90 * time.Second, MaxClients: 4})
	calls := 0
	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	send := func(remote string, forwarded string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/svc", nil)
		request.RemoteAddr = remote
		if forwarded != "" {
			request.Header.Set("X-Forwarded-For", forwarded)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	if code := send("198.51.100.7:1", "").Code; code != http.StatusNoContent {
		t.Fatalf("first request status %d", code)
	}
	refused := send("198.51.100.7:2", "203.0.113.9")
	if refused.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from the same host (new port, forged forwarding header) status %d", refused.Code)
	}
	if refused.Header().Get("Retry-After") != "90" {
		t.Fatalf("Retry-After = %q", refused.Header().Get("Retry-After"))
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times", calls)
	}
}
