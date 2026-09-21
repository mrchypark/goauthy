package backchannel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestWorkerHTTPSUsesConfiguredRoot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "request did not use TLS", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	w, db := newTestWorker(t)
	w.RootCAs = roots
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "event-tls", "client-1", "sid-tls", server.URL, true, false, now)
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, done, failed, _ := deliveryState(t, db, "event-tls", "client-1")
	if !done || failed {
		t.Fatalf("TLS delivery done=%v failed=%v", done, failed)
	}
}

func TestWorkerReloadsRootCAsAndRetainsLastKnownGood(t *testing.T) {
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer second.Close()

	path := t.TempDir() + "/ca.pem"
	writeRootCertificate(t, path, first.Certificate())
	reloader, err := NewRootCAReloader(path)
	if err != nil {
		t.Fatal(err)
	}
	w, db := newTestWorker(t)
	w.RootCAReloader = reloader
	var reloadErrors atomic.Int64
	w.OnError = func(error) { reloadErrors.Add(1) }
	now := time.Unix(1_800_000_000, 0).UTC()

	insertDelivery(t, db, "event-ca-first", "client-1", "sid-first", first.URL, true, false, now)
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, done, failed, _ := deliveryState(t, db, "event-ca-first", "client-1")
	if !done || failed {
		t.Fatalf("first CA delivery done=%v failed=%v", done, failed)
	}

	writeRootCertificate(t, path, second.Certificate())
	insertDelivery(t, db, "event-ca-second", "client-1", "sid-second", second.URL, true, false, now.Add(time.Second))
	if err := w.Step(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, done, failed, _ = deliveryState(t, db, "event-ca-second", "client-1")
	if !done || failed {
		t.Fatalf("rotated CA delivery done=%v failed=%v", done, failed)
	}

	if err := os.WriteFile(path, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertDelivery(t, db, "event-ca-last-good", "client-1", "sid-last-good", second.URL, true, false, now.Add(2*time.Second))
	if err := w.Step(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	_, done, failed, _ = deliveryState(t, db, "event-ca-last-good", "client-1")
	if !done || failed {
		t.Fatalf("last-known-good CA delivery done=%v failed=%v", done, failed)
	}
	if reloadErrors.Load() != 1 {
		t.Fatalf("reload errors=%d, want one", reloadErrors.Load())
	}
}

func writeRootCertificate(t *testing.T, path string, certificate *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRootCAsRequiresPrivatePEMCertificateFile(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadRootCAs(path)
	if err != nil || pool == nil || len(pool.Subjects()) != 1 {
		t.Fatalf("loaded roots=%v subjects=%d err=%v", pool, len(pool.Subjects()), err)
	}
	if _, err := LoadRootCAs(""); err != nil {
		t.Fatal(err)
	}
	for _, permission := range []os.FileMode{0o640, 0o620, 0o604, 0o602, 0o601} {
		if err := os.Chmod(path, permission); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRootCAs(path); err == nil {
			t.Fatalf("accepted non-owner-only CA file mode %o", permission)
		}
	}
}

func TestWorkerCurrentNetworkPolicyCeilingBlocksPermissiveSnapshots(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		w, db := newTestWorker(t)
		w.AllowHTTP = false
		insertDelivery(t, db, "event-policy-http", "client-1", "sid-policy-http", server.URL, true, true, time.Unix(1_800_000_000, 0).UTC())
		if err := w.Step(context.Background(), time.Unix(1_800_000_000, 0).UTC()); err != nil {
			t.Fatal(err)
		}
		_, _, failed, _ := deliveryState(t, db, "event-policy-http", "client-1")
		if calls.Load() != 0 || !failed {
			t.Fatalf("permissive HTTP snapshot escaped current policy: calls=%d failed=%v", calls.Load(), failed)
		}
	})

	t.Run("private address", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		w, db := newTestWorker(t)
		w.RootCAs = x509.NewCertPool()
		w.RootCAs.AddCert(server.Certificate())
		w.AllowPrivate = false
		now := time.Unix(1_800_000_000, 0).UTC()
		insertDelivery(t, db, "event-policy-private", "client-1", "sid-policy-private", server.URL, true, false, now)
		if err := w.Step(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		_, _, failed, _ := deliveryState(t, db, "event-policy-private", "client-1")
		if calls.Load() != 0 || !failed {
			t.Fatalf("permissive private snapshot escaped current policy: calls=%d failed=%v", calls.Load(), failed)
		}
	})

	t.Run("snapshot deny is not expanded", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		w, db := newTestWorker(t)
		now := time.Unix(1_800_000_000, 0).UTC()
		insertDelivery(t, db, "event-policy-snapshot", "client-1", "sid-policy-snapshot", server.URL, true, false, now)
		if err := w.Step(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		_, _, failed, _ := deliveryState(t, db, "event-policy-snapshot", "client-1")
		if calls.Load() != 0 || !failed {
			t.Fatalf("current policy expanded a denying snapshot: calls=%d failed=%v", calls.Load(), failed)
		}
	})
}

func TestWorkerDeliveryStates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		name       string
		status     int
		wantTry    int
		wantDone   bool
		wantFailed bool
	}{
		{"2xx", http.StatusNoContent, 1, true, false},
		{"retry", http.StatusServiceUnavailable, 1, false, false},
		{"terminal", http.StatusBadRequest, 1, false, true},
		{"redirect", http.StatusFound, 1, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil || r.Form.Get("logout_token") == "" {
					t.Errorf("bad form: %v", err)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			w, db := newTestWorker(t)
			insertDelivery(t, db, "event-1", "client-1", "sid-1", server.URL, true, true, now)
			if err := w.Step(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			attempts, done, failed, next := deliveryState(t, db, "event-1", "client-1")
			if attempts != int64(tc.wantTry) || done != tc.wantDone || failed != tc.wantFailed {
				t.Fatalf("state attempts=%d done=%v failed=%v", attempts, done, failed)
			}
			if tc.status == http.StatusServiceUnavailable && !next.After(now) {
				t.Fatalf("retry time=%v", next)
			}
		})
	}
}

func TestWorkerConditionalClaimRaceAndLeaseExpiry(t *testing.T) {
	// The due and expiry predicates run on the caller's reconciliation time while
	// the recorded lease is read from the worker clock, so a concurrency fixture
	// must sit in that same current time domain.
	now := time.Now().UTC()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	w, db := newTestWorker(t)
	insertDelivery(t, db, "event-race", "client-1", "sid-1", server.URL, true, true, now)

	load := w.LoadSigningKey
	winnerRead := make(chan struct{})
	release := make(chan struct{})
	var holding atomic.Bool
	w.LoadSigningKey = func(ctx context.Context) (oidc.SigningKey, error) {
		// Hold the winner directly after its linearizable winner read, so the
		// competing step below meets a lease that is still live.
		if holding.CompareAndSwap(false, true) {
			close(winnerRead)
			select {
			case <-release:
			case <-ctx.Done():
				return oidc.SigningKey{}, ctx.Err()
			}
		}
		return load(ctx)
	}
	lease := func() (string, int64) {
		row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT lease_token, lease_until_unix_ms FROM oidc_backchannel_deliveries WHERE event_id = ? AND client_id = ?`, Args: []any{"event-race", "client-1"}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 {
			t.Fatalf("claim row=%#v err=%v", row.Rows, err)
		}
		token, _ := row.Rows[0][0].(string)
		until, _ := row.Rows[0][1].(int64)
		return token, until
	}

	winner := make(chan error, 1)
	go func() { winner <- w.Step(context.Background(), now) }()
	select {
	case <-winnerRead:
	case <-time.After(30 * time.Second):
		t.Fatal("no step reached a post-election delivery")
	}
	// The local candidate read may be shared or stale; only the conditional
	// replicated UPDATE may elect a sender, and its lease must outlive the
	// reconciliation time of every caller in the same time domain.
	claimed, leaseUntil := lease()
	if !strings.HasPrefix(claimed, w.WorkerID+".") || leaseUntil <= now.UnixMilli() {
		t.Fatalf("winner lease token=%q until=%d reconciliation=%d", claimed, leaseUntil, now.UnixMilli())
	}
	// A step that loses the election must neither replace the live lease nor
	// deliver, and the winner must keep ownership of its own completion.
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if token, _ := lease(); token != claimed {
		t.Fatalf("competing step replaced live lease %q with %q", claimed, token)
	}
	if calls.Load() != 0 {
		t.Fatalf("calls=%d, want no delivery while the winner is in flight", calls.Load())
	}
	close(release)
	if err := <-winner; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want one claim winner", calls.Load())
	}
	if attempts, done, failed, _ := deliveryState(t, db, "event-race", "client-1"); attempts != 1 || !done || failed {
		t.Fatalf("winner state attempts=%d done=%v failed=%v", attempts, done, failed)
	}

	insertDelivery(t, db, "event-lease", "client-1", "sid-2", server.URL, true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "test-lease", SQL: `UPDATE oidc_backchannel_deliveries SET lease_token='lost', lease_until_unix_ms=? WHERE event_id=? AND client_id=?`, Args: []any{now.Add(time.Minute).UnixMilli(), "event-lease", "client-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpired lease was claimed")
	}
	if err := w.Step(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired lease was not reclaimed")
	}
}

func TestWorkerDispatchJTIAndFreshTime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	var tokens []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, jwtClaims(t, r.Form.Get("logout_token")))
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	w, db := newTestWorker(t)
	insertDelivery(t, db, "event-fresh", "client-1", "sid-1", server.URL, true, true, now)
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	next := now.Add(w.retryDelay(delivery{eventID: "event-fresh", clientID: "client-1", attempts: 0}))
	if err := w.Step(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0]["jti"] == tokens[1]["jti"] || tokens[0]["iat"] == tokens[1]["iat"] || tokens[0]["exp"] == tokens[1]["exp"] {
		t.Fatalf("retry tokens did not have distinct jti/fresh time: %#v", tokens)
	}
}

func TestEndpointPolicyAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		raw           string
		private, http bool
		ok            bool
	}{
		{"https://8.8.8.8/logout", false, false, true},
		{"http://8.8.8.8/logout", false, false, false},
		{"http://8.8.8.8/logout", false, true, true},
		{"https://127.0.0.1/logout", false, false, false},
		{"https://127.0.0.1/logout", true, false, true},
		{"https://169.254.1.1/logout", false, false, false},
		{"https://169.254.1.1/logout", true, false, true},
		{"https://0.0.0.0/logout", true, false, false},
		{"https://224.0.0.1/logout", true, false, false},
	} {
		err := ValidateEndpoint(tc.raw, tc.private, tc.http)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateEndpoint(%q) err=%v", tc.raw, err)
		}
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	}))
	w, db := newTestWorker(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	insertDelivery(t, db, "event-cancel", "client-1", "sid", server.URL, true, true, now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Step(ctx, now) }()
	<-started
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled delivery succeeded")
	}
	close(release)
	server.Close()
	if attempts, done, failed, _ := deliveryState(t, db, "event-cancel", "client-1"); attempts != 0 || done || failed {
		t.Fatalf("cancelled state mutated")
	}
}

func TestWorkerMaxAttempts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	w, db := newTestWorker(t)
	w.MaxAttempts = 2
	insertDelivery(t, db, "event-max", "client-1", "sid", server.URL, true, true, now)
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, _, _, retryAt := deliveryState(t, db, "event-max", "client-1")
	if err := w.Step(context.Background(), retryAt); err != nil {
		t.Fatal(err)
	}
	attempts, done, failed, _ := deliveryState(t, db, "event-max", "client-1")
	if attempts != 2 || done || !failed {
		t.Fatalf("max-attempt state attempts=%d done=%v failed=%v", attempts, done, failed)
	}
}

// TestWorkerAgedTickKeepsAttemptWithinRecordedLease covers a tick that was
// buffered during a slow pass: the lease stored by the claim must cover the
// attempt's own deadline, so a competing worker cannot reclaim the job while
// the request is still inside the window that lease authorised.
func TestWorkerAgedTickKeepsAttemptWithinRecordedLease(t *testing.T) {
	w, db := newTestWorker(t)
	competing := w
	competing.WorkerID = "competing"
	var competingLoads atomic.Int64
	competing.LoadSigningKey = func(context.Context) (oidc.SigningKey, error) {
		competingLoads.Add(1)
		return oidc.SigningKey{}, context.DeadlineExceeded
	}

	aged := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Millisecond)
	insertDelivery(t, db, "event-aged-tick", "client-1", "sid-aged", "https://8.8.8.8/logout", false, false, aged)

	var recordedLease, attemptDeadline time.Time
	var deadlineSet bool
	w.LoadSigningKey = func(ctx context.Context) (oidc.SigningKey, error) {
		attemptDeadline, deadlineSet = ctx.Deadline()
		row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT lease_until_unix_ms FROM oidc_backchannel_deliveries WHERE event_id=? AND client_id=?`, Args: []any{"event-aged-tick", "client-1"}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] == nil {
			t.Errorf("recorded lease unavailable: rows=%#v err=%v", row.Rows, err)
			return oidc.SigningKey{}, context.DeadlineExceeded
		}
		recordedLease = time.UnixMilli(row.Rows[0][0].(int64))
		// A competing worker polling while this request is in flight must not take
		// over a job that is still inside its recorded lease.
		if err := competing.Step(context.Background(), time.Now().UTC()); err != nil {
			t.Errorf("competing step: %v", err)
		}
		return oidc.SigningKey{}, context.DeadlineExceeded
	}

	stepStart := time.Now()
	err := w.Step(context.Background(), aged)
	if got := competingLoads.Load(); got != 0 {
		t.Fatalf("competing worker reclaimed the job inside its lease: %d loads", got)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !deadlineSet {
		t.Fatal("attempt context has no deadline")
	}
	if !recordedLease.After(stepStart) {
		t.Fatalf("recorded lease %v does not outlive attempt start %v", recordedLease, stepStart)
	}
	// The lease is stored at millisecond resolution, so allow its truncation.
	if attemptDeadline.After(recordedLease.Add(2 * time.Millisecond)) {
		t.Fatalf("attempt deadline %v outlives recorded lease %v", attemptDeadline, recordedLease)
	}
}

func TestWorkerBoundsKeyLoadToLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	w, db := newTestWorker(t)
	w.LeaseDuration = time.Minute
	w.RequestTimeout = 100 * time.Millisecond
	insertDelivery(t, db, "event-lease-bound", "client-1", "sid", "https://8.8.8.8/logout", false, false, now)
	stepStart := time.Now()
	var loaderCalled bool
	w.LoadSigningKey = func(ctx context.Context) (oidc.SigningKey, error) {
		loaderCalled = true
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("loader context has no deadline")
		} else if dl.After(stepStart.Add(w.LeaseDuration + 100*time.Millisecond)) {
			t.Errorf("loader deadline %v exceeds lease bound %v", dl, stepStart.Add(w.LeaseDuration))
		}
		return oidc.SigningKey{}, context.DeadlineExceeded
	}
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if !loaderCalled {
		t.Fatal("LoadSigningKey was not called; lease guard skipped the loader")
	}
	attempts, done, failed, _ := deliveryState(t, db, "event-lease-bound", "client-1")
	if attempts != 1 || done || failed {
		t.Fatalf("lease-bounded failure state attempts=%d done=%v failed=%v", attempts, done, failed)
	}
}

func TestRemainingLeaseIncludesClaimTime(t *testing.T) {
	if remaining := remainingLease(time.Unix(0, 0).UTC().Add(-time.Second), 10*time.Millisecond); remaining >= 0 {
		t.Fatalf("remaining lease=%s, want expired", remaining)
	}
}

func TestStableJTIBindsLease(t *testing.T) {
	if stableJTI("event", "client", "lease-a") != stableJTI("event", "client", "lease-a") {
		t.Fatal("same dispatch did not retain its jti")
	}
	if stableJTI("event", "client", "lease-a") == stableJTI("event", "client", "lease-b") {
		t.Fatal("different dispatch leases reused jti")
	}
}

func newTestWorker(t *testing.T) (Worker, *rhiza.DB) {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "backchannel-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "backchannel-test-schema", SQL: `CREATE TABLE IF NOT EXISTS oidc_backchannel_deliveries (
		event_id TEXT NOT NULL, client_id TEXT NOT NULL, sid TEXT NOT NULL, logout_uri TEXT NOT NULL, allow_private INTEGER NOT NULL, allow_http INTEGER NOT NULL,
		attempts INTEGER NOT NULL, next_attempt_at_unix_ms INTEGER NOT NULL, lease_token TEXT, lease_until_unix_ms INTEGER, delivered_at_unix_ms INTEGER, failed_at_unix_ms INTEGER,
		last_error TEXT, created_at_unix_ms INTEGER NOT NULL, PRIMARY KEY (event_id, client_id), UNIQUE (sid, client_id)) STRICT`}); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "test-key", Algorithm: "EdDSA", Use: "sig"}}
	return Worker{DB: db, Issuer: "https://id.example.test", LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }, WorkerID: "test", TickInterval: time.Second, RetryBase: time.Second, LeaseDuration: time.Minute, RequestTimeout: time.Second, MaxAttempts: 3, TokenLifetime: time.Minute, AllowPrivate: true, AllowHTTP: true}, db
}

func insertDelivery(t *testing.T, db *rhiza.DB, eventID, clientID, sid, endpoint string, private, httpAllowed bool, now time.Time) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "insert-" + eventID, SQL: `INSERT INTO oidc_backchannel_deliveries (event_id,client_id,sid,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,0,?,?)`, Args: []any{eventID, clientID, testSID(sid), endpoint, boolInt(private), boolInt(httpAllowed), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
}

func testSID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func deliveryState(t *testing.T, db *rhiza.DB, eventID, clientID string) (int64, bool, bool, time.Time) {
	t.Helper()
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT attempts, delivered_at_unix_ms, failed_at_unix_ms, next_attempt_at_unix_ms FROM oidc_backchannel_deliveries WHERE event_id=? AND client_id=?`, Args: []any{eventID, clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("delivery row=%#v err=%v", r.Rows, err)
	}
	return r.Rows[0][0].(int64), r.Rows[0][1] != nil, r.Rows[0][2] != nil, time.UnixMilli(r.Rows[0][3].(int64))
}

func jwtClaims(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("bad JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
