package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func apiKeyFailureTestStore(t *testing.T) (*rhiza.DB, *apikey.Store, string) {
	t.Helper()
	ctx := t.Context()
	nodeID := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: nodeID, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := store.Create(ctx, nil, apikey.Request{Name: "svc-backend", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	return db, store, token
}

func wrongAPIKeySecret(token string) string {
	name, secret, _ := strings.Cut(token, "$")
	replacement := "A"
	if secret[0] == 'A' {
		replacement = "B"
	}
	return name + "$" + replacement + secret[1:]
}

func assertAPIKeyFailureEvent(t *testing.T, db *rhiza.DB, wantIP any) {
	t.Helper()
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT ip,text FROM event_log WHERE typ='SuspiciousApiScan'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != wantIP || rows.Rows[0][1] != "svc-backend" {
		t.Fatalf("event rows=%#v err=%v, want ip=%v and key name", rows.Rows, err, wantIP)
	}
}

func TestAPIKeyAuthFailureCallbackPersistsWrongSecretAndUnknownIP(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	handler := newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default())
	keys.OnAuthFailure = handler
	if _, err := keys.Authenticate(t.Context(), "API-Key "+wrongAPIKeySecret(token)); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	assertAPIKeyFailureEvent(t, db, nil)
}

func TestAPIKeyAuthFailureCallbackPersistsExpiredKey(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default())
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "expire-api-key", Statements: []rhiza.SQLStatement{{SQL: `UPDATE api_keys SET expires_at_unix_ms=? WHERE name=?`, Args: []any{time.Now().Add(-time.Second).UnixMilli(), "svc-backend"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Authenticate(t.Context(), "API-Key "+token); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("expired key err=%v", err)
	}
	assertAPIKeyFailureEvent(t, db, nil)
}

func TestAPIKeyAuthFailureUsesTrustedCanonicalPeerIP(t *testing.T) {
	for _, test := range []struct {
		name       string
		remoteAddr string
		forwarded  string
		wantIP     string
	}{
		{name: "ignore forwarded header from untrusted peer", remoteAddr: "198.51.100.8:443", forwarded: "for=203.0.113.99", wantIP: "198.51.100.8"},
		{name: "use forwarded address from trusted proxy", remoteAddr: "192.0.2.8:443", forwarded: "for=203.0.113.9", wantIP: "203.0.113.9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, keys, token := apiKeyFailureTestStore(t)
			keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default())
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := keys.Authenticate(r.Context(), "API-Key "+wrongAPIKeySecret(token)); err == nil {
					t.Error("wrong secret authenticated")
				}
				w.WriteHeader(http.StatusUnauthorized)
			})
			trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("Forwarded", test.forwarded)
			response := httptest.NewRecorder()
			peerIPMiddleware(inner, trusted).ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			assertAPIKeyFailureEvent(t, db, test.wantIP)
		})
	}
}

func TestAPIKeyAuthFailureEventsBoundWritesAndReportStorageErrors(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	now := time.Unix(1_800_005_000, 0).UTC()
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, func() time.Time { return now }, logger)
	badHeader := "API-Key " + wrongAPIKeySecret(token)
	for range 20 {
		if _, err := keys.Authenticate(t.Context(), badHeader); !errors.Is(err, apikey.ErrUnauthorized) {
			t.Fatalf("wrong secret err=%v", err)
		}
	}
	assertAPIKeyFailureEvent(t, db, nil)
	now = now.Add(apiKeyAuthFailureEventInterval)
	if _, err := keys.Authenticate(t.Context(), badHeader); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='SuspiciousApiScan'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("bounded event count rows=%#v err=%v", rows.Rows, err)
	}
	if !strings.Contains(log.String(), "API key authentication failure events suppressed") || !strings.Contains(log.String(), "count=19") || strings.Contains(log.String(), badHeader) {
		t.Fatalf("suppression was not safely reported: %s", log.String())
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "reject-api-key-failure-event", Statements: []rhiza.SQLStatement{{SQL: `CREATE TRIGGER reject_api_key_failure_event BEFORE INSERT ON event_log WHEN NEW.typ='SuspiciousApiScan' BEGIN SELECT RAISE(ABORT, 'test event failure'); END`}}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(apiKeyAuthFailureEventInterval)
	peerIP := "203.0.113.55"
	failedCtx := browser.ContextWithPeerIP(t.Context(), peerIP)
	if _, err := keys.Authenticate(failedCtx, badHeader); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("rejected secret err=%v", err)
	}
	if !strings.Contains(log.String(), "API key authentication failure event was not written") || strings.Contains(log.String(), badHeader) || strings.Contains(log.String(), peerIP) {
		t.Fatalf("storage error was not safely reported: %s", log.String())
	}
}

func TestAPIKeyAuthFailureFloodDoesNotAddWritesWhileStorageStalls(t *testing.T) {
	_, keys, token := apiKeyFailureTestStore(t)
	var clock atomic.Int64
	clock.Store(time.Unix(1_800_005_000, 0).UnixNano())
	firstWrite := make(chan struct{}, 1)
	secondWrite := make(chan struct{}, 1)
	callbackEntered := make(chan struct{}, 21)
	completed := make(chan error, 20)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseStorage := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStorage()
	var writeCalls atomic.Int32
	recorder := &apiKeyAuthFailureRecorder{
		ctx: t.Context(), now: func() time.Time { return time.Unix(0, clock.Load()) },
		logger: slog.Default(), writeTimeout: time.Minute,
		execute: func(ctx context.Context, _ rhiza.ExecuteRequest) error {
			if writeCalls.Add(1) == 1 {
				firstWrite <- struct{}{}
			} else {
				secondWrite <- struct{}{}
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	keys.OnAuthFailure = func(ctx context.Context, keyName string) {
		callbackEntered <- struct{}{}
		recorder.record(ctx, keyName)
	}
	badHeader := "API-Key " + wrongAPIKeySecret(token)
	firstDone := make(chan error, 1)
	go func() {
		_, err := keys.Authenticate(t.Context(), badHeader)
		firstDone <- err
	}()
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("first failure callback did not start")
	}
	select {
	case <-firstWrite:
	case <-time.After(time.Second):
		t.Fatal("first audit write did not start")
	}
	clock.Add(int64(2 * time.Second))
	for range 20 {
		go func() {
			_, err := keys.Authenticate(t.Context(), badHeader)
			completed <- err
		}()
	}
	for range 20 {
		select {
		case <-callbackEntered:
		case <-time.After(5 * time.Second):
			t.Fatal("flood did not reach all failure callbacks")
		}
	}
	if got := writeCalls.Load(); got != 1 {
		t.Fatalf("writes while storage stalled=%d, want 1", got)
	}
	for range 20 {
		select {
		case err := <-completed:
			if !errors.Is(err, apikey.ErrUnauthorized) {
				t.Fatalf("wrong secret err=%v", err)
			}
		case <-secondWrite:
			t.Fatal("a second audit write started while the first was still in flight")
		case <-time.After(5 * time.Second):
			t.Fatal("flood did not complete while audit storage was stalled")
		}
	}
	recorder.mu.Lock()
	suppressed := recorder.suppressed
	recorder.mu.Unlock()
	if suppressed != 20 {
		t.Fatalf("suppressed=%d, want 20", suppressed)
	}
	releaseStorage()
	if err := <-firstDone; !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("first authentication result err=%v", err)
	}
	if got := writeCalls.Load(); got != 1 {
		t.Fatalf("writes after releasing storage=%d, want 1", got)
	}
}

func TestAPIKeyAuthFailureWriteTimesOut(t *testing.T) {
	_, keys, token := apiKeyFailureTestStore(t)
	var log bytes.Buffer
	deadline := make(chan error, 1)
	recorder := &apiKeyAuthFailureRecorder{
		ctx: t.Context(), now: time.Now, logger: slog.New(slog.NewTextHandler(&log, nil)), writeTimeout: 30 * time.Millisecond,
		execute: func(ctx context.Context, _ rhiza.ExecuteRequest) error {
			<-ctx.Done()
			deadline <- ctx.Err()
			return ctx.Err()
		},
	}
	keys.OnAuthFailure = recorder.record
	badHeader := "API-Key " + wrongAPIKeySecret(token)
	if _, err := keys.Authenticate(t.Context(), badHeader); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	if err := <-deadline; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("audit write deadline err=%v", err)
	}
	if !strings.Contains(log.String(), "API key authentication failure event was not written") || strings.Contains(log.String(), badHeader) {
		t.Fatalf("write timeout was not safely observable: %s", log.String())
	}
}

func TestAPIKeyAuthFailureCallbackReadsCanonicalIPFromContext(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default())
	ctx := browser.ContextWithPeerIP(t.Context(), "203.0.113.9")
	if _, err := keys.Authenticate(ctx, "API-Key "+wrongAPIKeySecret(token)); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	assertAPIKeyFailureEvent(t, db, "203.0.113.9")
}
