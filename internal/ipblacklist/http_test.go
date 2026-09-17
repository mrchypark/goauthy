package ipblacklist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func fixedResolver(addr netip.Addr) Resolver {
	return func(r *http.Request) (netip.Addr, error) {
		return addr, nil
	}
}

func errResolver() Resolver {
	return func(r *http.Request) (netip.Addr, error) {
		return netip.Addr{}, fmt.Errorf("resolver failure")
	}
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
}

func TestMiddlewareIPv4ExactMatch(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }
	if _, err := s.Add(context.Background(), "10.1.2.3/32", "exact-ipv4", nil, "req-mw-exact4"); err != nil {
		t.Fatal(err)
	}

	h := Middleware(s, fixedResolver(netip.MustParseAddr("10.1.2.3")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareIPv6ExactMatch(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }
	if _, err := s.Add(context.Background(), "2001:db8::1/128", "exact-ipv6", nil, "req-mw-exact6"); err != nil {
		t.Fatal(err)
	}

	h := Middleware(s, fixedResolver(netip.MustParseAddr("2001:db8::1")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareCIDRMatch(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }
	if _, err := s.Add(context.Background(), "192.168.0.0/16", "cidr-block", nil, "req-mw-cidr"); err != nil {
		t.Fatal(err)
	}

	h := Middleware(s, fixedResolver(netip.MustParseAddr("192.168.1.100")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareNoMatchPassthrough(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }
	if _, err := s.Add(context.Background(), "192.168.0.0/16", "", nil, "req-mw-passthru"); err != nil {
		t.Fatal(err)
	}

	h := Middleware(s, fixedResolver(netip.MustParseAddr("10.1.2.3")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestMiddlewareExpiredEntryPassthrough(t *testing.T) {
	s := newTestStore(t)
	fixed := fixedTime(1000000)
	s.now = func() time.Time { return fixed }

	expires := fixed.Add(time.Millisecond)
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "expires", &expires, "req-mw-exp"); err != nil {
		t.Fatal(err)
	}

	s.now = func() time.Time { return expires }

	h := Middleware(s, fixedResolver(netip.MustParseAddr("10.1.2.3")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want %d (expired entry should pass through)", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareResolverFailure(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	h := Middleware(s, errResolver())(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want %d (resolver failure should fail closed)", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareClosedDBFailure(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-mw-closed", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-mw-schema",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
				prefix TEXT PRIMARY KEY NOT NULL,
				note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
				expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
				created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
				updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
			) STRICT`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db, 100)
	s.now = func() time.Time { return fixedTime(1000000) }

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	h := Middleware(s, fixedResolver(netip.MustParseAddr("10.1.2.3")))(echoHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want %d (closed DB should fail closed)", rec.Code, http.StatusForbidden)
	}
}

// TestMiddlewareIdenticalRejection proves that matched entry, resolver error,
// closed DB error, nil store, and nil resolver all produce byte-for-byte
// identical status code, body, and Content-Type. No detail leakage.
func TestMiddlewareIdenticalRejection(t *testing.T) {
	capture := func(s *Store, resolve Resolver) (int, string, string) {
		h := Middleware(s, resolve)(echoHandler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		return rec.Code, rec.Body.String(), rec.Header().Get("Content-Type")
	}

	// Seed a matched entry and capture the canonical rejection.
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }
	if _, err := s.Add(context.Background(), "10.0.0.0/8", "blocked", nil, "req-ident-1"); err != nil {
		t.Fatal(err)
	}
	wantCode, wantBody, wantCT := capture(s, fixedResolver(netip.MustParseAddr("10.1.2.3")))

	// Closed-DB store (closed after setup, no cleanup registered).
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-ident-closed", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-ident-schema",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
				prefix TEXT PRIMARY KEY NOT NULL,
				note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
				expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
				created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
				updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
			) STRICT`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sClosed := NewStore(db, 100)
	sClosed.now = func() time.Time { return fixedTime(1000000) }
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		s       *Store
		resolve Resolver
	}{
		{"matched", s, fixedResolver(netip.MustParseAddr("10.1.2.3"))},
		{"resolver error", s, errResolver()},
		{"closed DB", sClosed, fixedResolver(netip.MustParseAddr("10.1.2.3"))},
		{"nil store", nil, fixedResolver(netip.MustParseAddr("10.1.2.3"))},
		{"nil resolver", s, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body, ct := capture(tt.s, tt.resolve)
			if code != wantCode {
				t.Errorf("status = %d, want %d", code, wantCode)
			}
			if body != wantBody {
				t.Errorf("body = %q, want %q", body, wantBody)
			}
			if ct != wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, wantCT)
			}
		})
	}
}

// TestMiddlewareConcurrentAddDeleteRequest exercises concurrent store mutation
// and middleware request handling with a deterministic barrier. No sleeps,
// timeouts, elapsed assertions, or t calls inside goroutines.
func TestMiddlewareConcurrentAddDeleteRequest(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return fixedTime(1000000) }

	const total = 200
	ready := make(chan struct{}, total)
	start := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(total)
	errs := make(chan error, total)

	// 50 concurrent adds.
	for i := 0; i < 50; i++ {
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			p := fmt.Sprintf("10.%d.0.0/16", i)
			if _, err := s.Add(context.Background(), p, "", nil, fmt.Sprintf("req-conc-add-%d", i)); err != nil && err != ErrAlreadyExists {
				errs <- fmt.Errorf("add %s: %w", p, err)
			}
		}(i)
	}

	// 50 concurrent deletes.
	for i := 0; i < 50; i++ {
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			p := fmt.Sprintf("10.%d.0.0/16", i)
			if err := s.Delete(context.Background(), p, fmt.Sprintf("req-conc-del-%d", i)); err != nil {
				errs <- fmt.Errorf("delete %s: %w", p, err)
			}
		}(i)
	}

	// Pre-build 100 middleware handlers outside goroutines.
	type handlerPair struct {
		h   http.Handler
		rec *httptest.ResponseRecorder
	}
	pairs := make([]handlerPair, 100)
	for i := 0; i < 100; i++ {
		addr := netip.MustParseAddr(fmt.Sprintf("10.%d.1.1", i%50))
		pairs[i].h = Middleware(s, fixedResolver(addr))(echoHandler())
		pairs[i].rec = httptest.NewRecorder()
	}

	// 100 concurrent requests using pre-built handlers.
	for i := 0; i < 100; i++ {
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			pairs[i].h.ServeHTTP(pairs[i].rec, httptest.NewRequest("GET", "/", nil))
			code := pairs[i].rec.Code
			if code != http.StatusOK && code != http.StatusForbidden {
				errs <- fmt.Errorf("request %d: code = %d, want 200 or 403", i, code)
			}
		}(i)
	}

	// Coordinator: wait for all goroutines to be ready, then release them.
	for i := 0; i < total; i++ {
		<-ready
	}
	close(start)

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
