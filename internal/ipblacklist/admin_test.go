package ipblacklist

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAdminCRUDUsesBrowserAdminAndRauthyShape(t *testing.T) {
	now := func() time.Time { return fixedTime(1_000_000_000) }
	s := newTestStoreWithClock(t, now, 100)
	h := NewAdminHandler(s, nil, func(w http.ResponseWriter, r *http.Request, mutation bool) bool { return true })
	h.now = now

	for _, prefix := range []string{"10.0.0.0/8", "192.0.2.1/32"} {
		post := httptest.NewRequest(http.MethodPost, adminPath, strings.NewReader(`{"ip":"`+prefix+`","exp":1000000100}`))
		post.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, post)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip":"`+prefix+`"`) {
			t.Fatalf("POST %s: code=%d body=%q", prefix, rec.Code, rec.Body.String())
		}
	}

	get := httptest.NewRequest(http.MethodGet, adminPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"10.0.0.0/8"`) || !strings.Contains(rec.Body.String(), `"192.0.2.1/32"`) {
		t.Fatalf("GET: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAdminRejectsAmbiguousRequests(t *testing.T) {
	s := newTestStore(t)
	called := false
	h := NewAdminHandler(s, nil, func(w http.ResponseWriter, r *http.Request, mutation bool) bool { called = true; return true })
	for _, tc := range []struct {
		name string
		make func() *http.Request
	}{
		{"query", func() *http.Request { return httptest.NewRequest(http.MethodGet, adminPath+"?x=1", nil) }},
		{"encoded path", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, adminPath+"/10.0.0.0%2F8", nil)
			r.URL.RawPath = adminPath + "/10.0.0.0%2F8"
			return r
		}},
		{"cross site browser", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, adminPath, nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.make())
			if rec.Code == http.StatusOK || called {
				t.Fatalf("code=%d browser callback called=%v", rec.Code, called)
			}
		})
	}
}

func TestAdminAPIKeyIgnoresBrowserFetchMetadata(t *testing.T) {
	// A malformed key must still stop at API-key auth; it must never invoke the
	// browser callback, even when the request carries browser metadata.
	s := newTestStore(t)
	called := false
	h := NewAdminHandler(s, nil, func(w http.ResponseWriter, r *http.Request, mutation bool) bool { called = true; return true })
	r := httptest.NewRequest(http.MethodGet, adminPath, nil)
	r.Header.Set("Authorization", "Bearer browser-fallback")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("code=%d browser callback called=%v", rec.Code, called)
	}
}

func TestAdminServeHTTPNilHandlerAndRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    *AdminHandler
		r    *http.Request
	}{
		{name: "nil handler", r: httptest.NewRequest(http.MethodGet, adminPath, nil)},
		{name: "nil request", h: NewAdminHandler(nil, nil, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.h.ServeHTTP(rec, tc.r)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestAdminRejectsNonCanonicalAddPrefixes(t *testing.T) {
	now := func() time.Time { return fixedTime(1_000_000_000) }
	h := NewAdminHandler(newTestStoreWithClock(t, now, 100), nil, func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.now = now
	for _, prefix := range []string{"203.0.113.10/24", "::ffff:203.0.113.10/120"} {
		t.Run(prefix, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, adminPath, strings.NewReader(`{"ip":"`+prefix+`","exp":1000000100}`))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

// TestAdminDeleteWithoutRequestIDIsANewOperation reproduces GA-BR-12: without
// an explicit request ID every DELETE must be its own operation, so delete,
// recreate and delete actually removes the prefix instead of replaying the
// first delete's receipt.
func TestAdminDeleteWithoutRequestIDIsANewOperation(t *testing.T) {
	now := func() time.Time { return fixedTime(1_000_000_000) }
	s := newTestStoreWithClock(t, now, 100)
	h := NewAdminHandler(s, nil, func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.now = now

	next := Middleware(s, func(*http.Request) (netip.Addr, error) { return netip.ParseAddr("10.0.0.1") })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	admission := func(stage string, want int) {
		t.Helper()
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != want {
			t.Fatalf("%s: admission status=%d, want %d", stage, rec.Code, want)
		}
	}
	add := func(body string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, adminPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: status=%d body=%q", body, rec.Code, rec.Body.String())
		}
	}
	remove := func(header string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodDelete, adminPath+"/10.0.0.0/8", nil)
		if header != "" {
			r.Header.Set("X-Request-ID", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE with X-Request-ID %q: status=%d body=%q", header, rec.Code, rec.Body.String())
		}
	}

	add(`{"ip":"10.0.0.0/8","exp":1000000100}`)
	admission("before delete", http.StatusForbidden)

	remove("")
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("delete: stored prefix err=%v, want %v", err, ErrNotFound)
	}
	admission("after delete", http.StatusOK)

	// Recreate with a different expiry so only the DELETE path is under test.
	add(`{"ip":"10.0.0.0/8","exp":1000000200}`)
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	admission("after recreate", http.StatusForbidden)

	remove("")
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("delete after recreate: stored prefix err=%v, want %v", err, ErrNotFound)
	}
	admission("after delete of recreated prefix", http.StatusOK)
}

// TestAdminDeleteRequestIDReplay pins the request-ID contract: a valid explicit
// X-Request-ID is an idempotency key whose recorded outcome is replayed, and a
// key the server does not accept is ignored, making the request a new operation.
func TestAdminDeleteRequestIDReplay(t *testing.T) {
	now := func() time.Time { return fixedTime(1_000_000_000) }
	s := newTestStoreWithClock(t, now, 100)
	h := NewAdminHandler(s, nil, func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.now = now

	add := func(body string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, adminPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: status=%d body=%q", body, rec.Code, rec.Body.String())
		}
	}
	remove := func(header string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodDelete, adminPath+"/10.0.0.0/8", nil)
		r.Header.Set("X-Request-ID", header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE with X-Request-ID %q: status=%d body=%q", header, rec.Code, rec.Body.String())
		}
	}

	add(`{"ip":"10.0.0.0/8","exp":1000000100}`)
	remove("delete-op-1")
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("keyed delete: stored prefix err=%v, want %v", err, ErrNotFound)
	}

	// An exact retry of the same key replays the recorded outcome: success, and
	// the recreated prefix is left untouched because the delete is not re-executed.
	add(`{"ip":"10.0.0.0/8","exp":1000000200}`)
	remove("delete-op-1")
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != nil {
		t.Fatalf("replayed key must not re-execute the delete: %v", err)
	}

	// An unusable key is not an idempotency key: the request is a new operation and
	// does remove the prefix.
	remove(strings.Repeat("x", 65))
	if _, err := s.Get(t.Context(), "10.0.0.0/8"); err != ErrNotFound {
		t.Fatalf("invalid key: stored prefix err=%v, want %v", err, ErrNotFound)
	}
}
