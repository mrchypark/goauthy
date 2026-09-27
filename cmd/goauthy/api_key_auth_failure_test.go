package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/metrics"
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

func assertAPIKeyFailureMetric(t *testing.T, registry *metrics.Registry, name string, want float64) float64 {
	t.Helper()
	response := httptest.NewRecorder()
	registry.Handler("").ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(response.Body.String(), "\n") {
		if strings.HasPrefix(line, name+" ") {
			fields := strings.Fields(line)
			got, err := strconv.ParseFloat(fields[1], 64)
			if err != nil || got != want {
				t.Fatalf("metric %s=%v err=%v, want %v", name, got, err, want)
			}
			return got
		}
	}
	t.Fatalf("metric %s not exposed", name)
	return 0
}

func TestAPIKeyAuthFailureCallbackPersistsWrongSecretAndUnknownIP(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	registry := metrics.NewRegistry()
	handler := newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default(), registry)
	keys.OnAuthFailure = handler
	if _, err := keys.Authenticate(t.Context(), "API-Key "+wrongAPIKeySecret(token)); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	assertAPIKeyFailureEvent(t, db, nil)
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_interval_total", 0)
}

func TestAPIKeyAuthFailureStatementConstructionFailureIsCounted(t *testing.T) {
	_, keys, token := apiKeyFailureTestStore(t)
	registry := metrics.NewRegistry()
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), nil, func() time.Time { return time.Unix(-1, 0) }, slog.Default(), registry)
	if _, err := keys.Authenticate(t.Context(), "API-Key "+wrongAPIKeySecret(token)); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_statement_failed_total", 1)
}

func TestAPIKeyAuthFailureCallbackPersistsExpiredKey(t *testing.T) {
	db, keys, token := apiKeyFailureTestStore(t)
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default(), nil)
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
			keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default(), nil)
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
	registry := metrics.NewRegistry()
	now := time.Unix(1_800_005_000, 0).UTC()
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, func() time.Time { return now }, logger, registry)
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
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_write_success_total", 2)
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='SuspiciousApiScan'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("bounded event count rows=%#v err=%v", rows.Rows, err)
	}
	if !strings.Contains(log.String(), "API key authentication failure events suppressed") || !strings.Contains(log.String(), "count=19") || strings.Contains(log.String(), badHeader) {
		t.Fatalf("suppression was not safely reported: %s", log.String())
	}
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_interval_total", 19)
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
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_storage_failed_total", 1)
	intervalSuppressed := assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_interval_total", 19)
	busySuppressed := assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_busy_total", 0)
	statementFailed := assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_statement_failed_total", 0)
	writeSuccess := assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_write_success_total", 2)
	storageFailed := assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_storage_failed_total", 1)
	if got := intervalSuppressed + busySuppressed + statementFailed + writeSuccess + storageFailed; got != 22 {
		t.Fatalf("settled failure outcomes sum=%v, want 22", got)
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
	registry := metrics.NewRegistry()
	recorder := &apiKeyAuthFailureRecorder{
		ctx: t.Context(), now: func() time.Time { return time.Unix(0, clock.Load()) },
		logger: slog.Default(), metrics: registry, writeTimeout: time.Minute,
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
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_busy_total", 20)
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_interval_total", 0)
	releaseStorage()
	if err := <-firstDone; !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("first authentication result err=%v", err)
	}
	if got := writeCalls.Load(); got != 1 {
		t.Fatalf("writes after releasing storage=%d, want 1", got)
	}
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_suppressed_busy_total", 20)
	assertAPIKeyFailureMetric(t, registry, "goauthy_api_key_auth_failure_write_success_total", 1)
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
	keys.OnAuthFailure = newAPIKeyAuthFailureHandler(t.Context(), db, time.Now, slog.Default(), nil)
	ctx := browser.ContextWithPeerIP(t.Context(), "203.0.113.9")
	if _, err := keys.Authenticate(ctx, "API-Key "+wrongAPIKeySecret(token)); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("wrong secret err=%v", err)
	}
	assertAPIKeyFailureEvent(t, db, "203.0.113.9")
}
