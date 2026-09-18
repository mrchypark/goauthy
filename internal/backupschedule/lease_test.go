package backupschedule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestWithLeaseSameScopeHasOneOwner(t *testing.T) {
	db := leaseTestDB(t)
	started := make(chan struct{})
	release := make(chan struct{})
	first := make(chan leaseResult, 1)
	go func() {
		acquired, err := WithLease(t.Context(), db, "backup", time.Second, func(ctx context.Context) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		first <- leaseResult{acquired, err}
	}()
	waitLease(t, started)

	called := false
	acquired, err := WithLease(t.Context(), db, "backup", time.Second, func(context.Context) error {
		called = true
		return nil
	})
	if err != nil || acquired || called {
		t.Fatalf("second acquired=%t called=%t err=%v", acquired, called, err)
	}
	close(release)
	result := waitLeaseResult(t, first)
	if !result.acquired || result.err != nil {
		t.Fatalf("first acquired=%t err=%v", result.acquired, result.err)
	}
}

func TestWithLeaseRenewsPastOriginalTTL(t *testing.T) {
	db := leaseTestDB(t)
	const (
		scope = "renewed-backup"
		ttl   = time.Second
	)
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan leaseResult, 1)
	jobContext := make(chan context.Context, 1)
	go func() {
		acquired, err := WithLease(t.Context(), db, scope, ttl, func(ctx context.Context) error {
			jobContext <- ctx
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		result <- leaseResult{acquired, err}
	}()
	waitLease(t, started)

	// The first lease was granted before started closed, so this crosses its
	// original one-second TTL and observes the native renewed value directly.
	timer := time.NewTimer(ttl + 100*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	jobCtx := <-jobContext
	select {
	case <-jobCtx.Done():
		t.Fatalf("winner context ended: %v", context.Cause(jobCtx))
	default:
	}
	current, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: leaseKey(scope), Consistency: "linearizable"})
	if err != nil || !current.Found {
		t.Fatalf("renewed native lease found=%t err=%v", current.Found, err)
	}
	called := false
	acquired, err := WithLease(t.Context(), db, scope, ttl, func(context.Context) error {
		called = true
		return nil
	})
	if err != nil || acquired || called {
		t.Fatalf("contender acquired=%t called=%t err=%v", acquired, called, err)
	}
	close(release)
	got := waitLeaseResult(t, result)
	if !got.acquired || got.err != nil {
		t.Fatalf("winner acquired=%t err=%v", got.acquired, got.err)
	}
}

func TestWithLeaseSeparateScopesAreIndependent(t *testing.T) {
	db := leaseTestDB(t)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan leaseResult, 2)
	for _, scope := range []string{"backup-a", "backup-b"} {
		go func(scope string) {
			acquired, err := WithLease(t.Context(), db, scope, time.Second, func(ctx context.Context) error {
				started <- struct{}{}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			results <- leaseResult{acquired, err}
		}(scope)
	}
	waitLease(t, started)
	waitLease(t, started)
	close(release)
	for range 2 {
		result := waitLeaseResult(t, results)
		if !result.acquired || result.err != nil {
			t.Fatalf("acquired=%t err=%v", result.acquired, result.err)
		}
	}
}

func TestWithLeaseReturnsJobAndParentCancellation(t *testing.T) {
	db := leaseTestDB(t)
	want := errors.New("job failed")
	acquired, err := WithLease(context.Background(), db, "job-error", time.Second, func(context.Context) error { return want })
	if !acquired || !errors.Is(err, want) {
		t.Fatalf("acquired=%t err=%v", acquired, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan leaseResult, 1)
	go func() {
		acquired, err := WithLease(ctx, db, "parent-cancel", time.Second, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
		result <- leaseResult{acquired, err}
	}()
	waitLease(t, started)
	cancel()
	got := waitLeaseResult(t, result)
	if !got.acquired || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("acquired=%t err=%v", got.acquired, got.err)
	}
}

func TestWithLeaseRejectsInvalidArguments(t *testing.T) {
	db := leaseTestDB(t)
	for _, tc := range []struct {
		name  string
		db    *rhiza.DB
		scope string
		ttl   time.Duration
	}{
		{"nil db", nil, "scope", time.Second},
		{"empty scope", db, "", time.Second},
		{"too short", db, "scope", time.Second - time.Nanosecond},
		{"too long", db, "scope", time.Hour + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			acquired, err := WithLease(context.Background(), tc.db, tc.scope, tc.ttl, func(context.Context) error {
				called = true
				return nil
			})
			if err == nil || acquired || called {
				t.Fatalf("acquired=%t called=%t err=%v", acquired, called, err)
			}
		})
	}
}

func TestWithLeaseCanceledAcquireHasStageAndCause(t *testing.T) {
	db := leaseTestDB(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	acquired, err := WithLease(ctx, db, "canceled-acquire", time.Second, func(context.Context) error {
		called = true
		return nil
	})
	if acquired || called || !errors.Is(err, ErrLeaseAcquire) || !errors.Is(err, context.Canceled) {
		t.Fatalf("acquired=%t called=%t err=%v", acquired, called, err)
	}
}

func TestWithLeaseLosesOwnershipWithoutDeletingSuccessor(t *testing.T) {
	db := leaseTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{})
	jobCanceled := make(chan struct{})
	result := make(chan leaseResult, 1)
	const scope = "forced-loss"
	go func() {
		acquired, err := WithLease(ctx, db, scope, time.Second, func(jobCtx context.Context) error {
			close(started)
			<-jobCtx.Done()
			close(jobCanceled)
			return jobCtx.Err()
		})
		result <- leaseResult{acquired, err}
	}()
	waitLease(t, started)

	key := leaseKey(scope)
	successor := []byte("successor-owner")
	response, err := db.KVPut(ctx, rhiza.KVMutationRequest{
		RequestID: "backup-lease-test-force-loss", Key: key, Value: successor, TTLMS: 60_000,
	})
	if err != nil || response.Status != rhiza.MutationCommitted {
		t.Fatalf("replace lease response=%+v err=%v", response, err)
	}
	waitLease(t, jobCanceled)
	got := waitLeaseResult(t, result)
	if !got.acquired || !errors.Is(got.err, ErrLeaseLost) {
		t.Fatalf("acquired=%t err=%v", got.acquired, got.err)
	}
	current, err := db.KVGet(ctx, rhiza.KVGetRequest{Key: key, Consistency: "linearizable"})
	if err != nil || !current.Found || string(current.Value) != string(successor) {
		t.Fatalf("successor found=%t value=%q err=%v", current.Found, current.Value, err)
	}
}

func TestWithLeasePanicReleasesOwner(t *testing.T) {
	db := leaseTestDB(t)
	const scope = "panic-release"
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was not propagated")
			}
		}()
		_, _ = WithLease(context.Background(), db, scope, time.Second, func(context.Context) error {
			panic("test panic")
		})
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		acquired, err := WithLease(ctx, db, scope, time.Second, func(context.Context) error { return nil })
		if acquired && err == nil {
			return
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("panic holder was not released")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type leaseResult struct {
	acquired bool
	err      error
}

func leaseTestDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "backup-lease-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func leaseKey(scope string) string {
	digest := sha256.Sum256([]byte(scope))
	return "goauthy/backup-lease/" + hex.EncodeToString(digest[:])
}

func waitLease(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lease")
	}
}

func waitLeaseResult(t *testing.T, result <-chan leaseResult) leaseResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lease result")
		return leaseResult{}
	}
}
