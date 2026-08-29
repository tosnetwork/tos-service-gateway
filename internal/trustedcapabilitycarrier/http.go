package trustedcapabilitycarrier

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPAuthorizer func(*http.Request, bool) (canonicalPrincipal string, err error)

type principalWindow struct {
	started time.Time
	reads   uint32
	writes  uint32
	active  uint16
}

type requestLimiter struct {
	mu         sync.Mutex
	principals map[string]principalWindow
	global     chan struct{}
	now        func() time.Time
}

func newRequestLimiter(now func() time.Time) *requestLimiter {
	return &requestLimiter{principals: map[string]principalWindow{}, global: make(chan struct{}, 32), now: now}
}

func (l *requestLimiter) acquire(principal string, write bool) (func(), bool) {
	select {
	case l.global <- struct{}{}:
	default:
		return nil, false
	}
	l.mu.Lock()
	now := l.now().UTC()
	window := l.principals[principal]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = principalWindow{started: now}
	}
	allowed := window.active < 4
	if write {
		allowed = allowed && window.writes < 60
		window.writes++
	} else {
		allowed = allowed && window.reads < 240
		window.reads++
	}
	if allowed {
		window.active++
	}
	l.principals[principal] = window
	l.mu.Unlock()
	if !allowed {
		<-l.global
		return nil, false
	}
	return func() {
		l.mu.Lock()
		window := l.principals[principal]
		if window.active > 0 {
			window.active--
		}
		l.principals[principal] = window
		l.mu.Unlock()
		<-l.global
	}, true
}

func Handler(store *Store, authorize HTTPAuthorizer) http.Handler {
	if store == nil || !store.ProductionReady() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "durable Carrier unavailable", http.StatusServiceUnavailable)
		})
	}
	limiter := newRequestLimiter(store.now)
	auth := func(w http.ResponseWriter, r *http.Request, write bool) (string, func(), bool) {
		if authorize == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return "", nil, false
		}
		principal, err := authorize(r, write)
		if err != nil || principal == "" || len(principal) > 256 || strings.TrimSpace(principal) != principal {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return "", nil, false
		}
		release, ok := limiter.acquire(principal, write)
		if !ok {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return "", nil, false
		}
		return principal, release, true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/capability-objects", func(w http.ResponseWriter, r *http.Request) {
		principal, release, ok := auth(w, r, true)
		if !ok {
			return
		}
		defer release()
		reader := http.MaxBytesReader(w, r.Body, MaxObjectBytes*2)
		decoder := json.NewDecoder(reader)
		decoder.DisallowUnknownFields()
		var request struct {
			Canonical     []byte   `json:"canonical"`
			Keywords      []string `json:"keywords"`
			PublisherHint string   `json:"publisher_hint"`
		}
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		record, err := store.PublishForPrincipal(principal, request.Canonical, request.Keywords, request.PublisherHint)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, record)
	})
	mux.HandleFunc("GET /v1/capability-objects", func(w http.ResponseWriter, r *http.Request) {
		_, release, ok := auth(w, r, false)
		if !ok {
			return
		}
		defer release()
		after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if err != nil && r.URL.Query().Get("after") != "" {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		page, err := store.Search(r.URL.Query().Get("q"), after, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("GET /v1/capability-objects/{digest}", func(w http.ResponseWriter, r *http.Request) {
		_, release, ok := auth(w, r, false)
		if !ok {
			return
		}
		defer release()
		record, err := store.Exact(r.PathValue("digest"))
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "invalid digest", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
