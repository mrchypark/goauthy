package loginpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestClearAccountLockSubmitsOnlyForExistingRows(t *testing.T) {
	// This test changes the global tracer provider and must not run in parallel.
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	defer func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	}()
	ctx, parent := otel.Tracer("goauthy/test").Start(t.Context(), "clear")
	defer parent.End()
	count := func() int {
		n := 0
		for _, span := range recorder.Ended() {
			if span.InstrumentationScope().Name == "goauthy/auth-stage" && span.Name() == "storage_submit" {
				n++
			}
		}
		return n
	}
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	seed := func(subject string, until time.Time) string {
		account := AccountStuffingDigest(subject)
		if _, err := db.Execute(t.Context(), rhiza.ExecuteRequest{
			RequestID: "clear-seed-" + subject,
			SQL:       `INSERT INTO login_account_locks(account_hash, locked_until_unix_ms, reason, created_at_unix_ms) VALUES (?, ?, 'clear_test', ?)`,
			Args:      []any{account, until.UnixMilli(), now.UnixMilli()},
		}); err != nil {
			t.Fatal(err)
		}
		return account
	}
	rows := func(account string) int {
		result, err := db.Query(t.Context(), rhiza.QueryRequest{
			SQL:  `SELECT locked_until_unix_ms FROM login_account_locks WHERE account_hash = ?`,
			Args: []any{account}, Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(result.Rows)
	}
	clear := func(account string, want int) {
		t.Helper()
		before := count()
		if err := store.ClearAccountLock(ctx, account); err != nil {
			t.Fatal(err)
		}
		if got := count() - before; got != want {
			t.Fatalf("clear submitted %d mutations, want %d", got, want)
		}
		if got := rows(account); got != 0 {
			t.Fatalf("lock row survived: %d", got)
		}
	}
	account := AccountStuffingDigest("absent")
	if rows(account) != 0 {
		t.Fatal("absent account already has a lock")
	}
	clear(account, 0)
	// Reuse the same account: an earlier absence cannot be cached. This also
	// positively verifies that the recorder observes real mutation submissions.
	clear(seed("absent", now.Add(AccountLockDuration)), 1)
	stale := seed("stale", now.Add(-time.Minute))
	if locked, _, err := store.CheckAccountLock(t.Context(), stale, now); err != nil || locked || rows(stale) != 1 {
		t.Fatalf("expired physical lock precondition: locked=%v err=%v", locked, err)
	}
	clear(stale, 1)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before := count()
	if err := store.ClearAccountLock(canceled, account); err == nil || count() != before {
		t.Fatalf("canceled clear: err=%v submissions=%d", err, count()-before)
	}
	for _, invalid := range []struct {
		store   *Store
		account string
	}{{nil, account}, {NewStore(nil), account}, {store, ""}} {
		if err := invalid.store.ClearAccountLock(ctx, invalid.account); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid clear: %v", err)
		}
	}
	if _, err := db.Execute(t.Context(), rhiza.ExecuteRequest{RequestID: "clear-drop", SQL: `DROP TABLE login_account_locks`}); err != nil {
		t.Fatal(err)
	}
	before = count()
	if err := store.ClearAccountLock(ctx, account); err == nil || count() != before {
		t.Fatalf("failed query: err=%v submissions=%d", err, count()-before)
	}
}

func TestRecordAccountFailureTracksDistinctIPs(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("alice")

	// Record failures from 3 distinct IPs - should not lock.
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		status, locked, err := store.RecordAccountFailure(context.Background(), account, ip, now)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatalf("locked after %d IPs", i+1)
		}
		if status.DistinctIPs != i+1 {
			t.Fatalf("DistinctIPs=%d want=%d", status.DistinctIPs, i+1)
		}
	}
}

func TestRecordAccountFailureLocksAtThreshold(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("bob")

	// Record failures from StuffingThreshold distinct IPs.
	for i := 0; i < StuffingThreshold; i++ {
		ip := "10.0.0." + string(rune('1'+i))
		status, locked, err := store.RecordAccountFailure(context.Background(), account, ip, now)
		if err != nil {
			t.Fatal(err)
		}
		if i < StuffingThreshold-1 && locked {
			t.Fatalf("locked prematurely at %d IPs", i+1)
		}
		if i == StuffingThreshold-1 {
			if !locked {
				t.Fatal("not locked at threshold")
			}
			if status.LockedUntil.IsZero() {
				t.Fatal("LockedUntil is zero")
			}
			if status.LockedUntil != now.Add(AccountLockDuration) {
				t.Fatalf("LockedUntil=%v want=%v", status.LockedUntil, now.Add(AccountLockDuration))
			}
		}
	}
}

func TestRecordAccountFailureSameIPDoesNotDoubleCount(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("charlie")

	// Record 10 failures from the same IP - should count as 1 distinct IP.
	for i := 0; i < 10; i++ {
		status, locked, err := store.RecordAccountFailure(context.Background(), account, "192.0.2.50", now)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatal("locked from single IP")
		}
		if status.DistinctIPs != 1 {
			t.Fatalf("DistinctIPs=%d want=1", status.DistinctIPs)
		}
	}
}

func TestCheckAccountLockReturnsLockStatus(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("dave")

	// Not locked initially.
	locked, remaining, err := store.CheckAccountLock(context.Background(), account, now)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Fatal("locked before any failures")
	}
	if remaining != 0 {
		t.Fatalf("remaining=%v want=0", remaining)
	}

	// Trigger lockout.
	for i := 0; i < StuffingThreshold; i++ {
		ip := "10.0.1." + string(rune('1'+i))
		store.RecordAccountFailure(context.Background(), account, ip, now)
	}

	// Should be locked now.
	locked, remaining, err = store.CheckAccountLock(context.Background(), account, now)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("not locked after threshold")
	}
	if remaining <= 0 || remaining > AccountLockDuration {
		t.Fatalf("remaining=%v want between 0 and %v", remaining, AccountLockDuration)
	}

	// Should still be locked 1 minute later.
	locked, _, err = store.CheckAccountLock(context.Background(), account, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("not locked 1 minute later")
	}

	// Should be unlocked after lock duration.
	locked, _, err = store.CheckAccountLock(context.Background(), account, now.Add(AccountLockDuration+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Fatal("still locked after duration")
	}
}

func TestClearAccountLockRemovesLock(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("eve")

	// Trigger lockout.
	for i := 0; i < StuffingThreshold; i++ {
		ip := "10.0.2." + string(rune('1'+i))
		store.RecordAccountFailure(context.Background(), account, ip, now)
	}

	// Verify locked.
	locked, _, _ := store.CheckAccountLock(context.Background(), account, now)
	if !locked {
		t.Fatal("not locked")
	}

	// Clear lock.
	if err := store.ClearAccountLock(context.Background(), account); err != nil {
		t.Fatal(err)
	}

	// Should be unlocked.
	locked, _, _ = store.CheckAccountLock(context.Background(), account, now)
	if locked {
		t.Fatal("still locked after clear")
	}
}

func TestCleanupStuffingEntriesRemovesExpired(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("frank")

	// Record some failures.
	for i := 0; i < 3; i++ {
		ip := "10.0.3." + string(rune('1'+i))
		store.RecordAccountFailure(context.Background(), account, ip, now)
	}

	// Cleanup should not remove anything yet (entries not expired).
	cleaned, err := store.CleanupStuffingEntries(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned=%d want=0", cleaned)
	}

	// Cleanup after TTL should remove entries.
	cleaned, err = store.CleanupStuffingEntries(context.Background(), now.Add(StuffingEntryTTL+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 3 {
		t.Fatalf("cleaned=%d want=3", cleaned)
	}
}

func TestDifferentAccountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	alice := AccountStuffingDigest("alice-isolated")
	bob := AccountStuffingDigest("bob-isolated")

	// Lock alice.
	for i := 0; i < StuffingThreshold; i++ {
		ip := "10.0.4." + string(rune('1'+i))
		store.RecordAccountFailure(context.Background(), alice, ip, now)
	}

	// Bob should not be affected.
	locked, _, _ := store.CheckAccountLock(context.Background(), bob, now)
	if locked {
		t.Fatal("bob locked by alice's attack")
	}

	// Record one failure for bob - should not lock.
	_, locked, _ = store.RecordAccountFailure(context.Background(), bob, "192.0.2.99", now)
	if locked {
		t.Fatal("bob locked from single IP")
	}
}

func TestAccountStuffingDigestIsConsistent(t *testing.T) {
	t.Parallel()
	d1 := AccountStuffingDigest("test-user")
	d2 := AccountStuffingDigest("test-user")
	if d1 != d2 {
		t.Fatalf("digests differ: %q vs %q", d1, d2)
	}
	d3 := AccountStuffingDigest("other-user")
	if d1 == d3 {
		t.Fatal("different subjects produced same digest")
	}
}

func TestRecordAccountFailureRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	for _, tc := range []struct {
		name        string
		accountHash string
		ip          string
	}{
		{"empty account", "", "192.0.2.1"},
		{"empty ip", "hash", ""},
		{"both empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := store.RecordAccountFailure(context.Background(), tc.accountHash, tc.ip, now)
			if err != ErrInvalid {
				t.Fatalf("err=%v want=%v", err, ErrInvalid)
			}
		})
	}
}

func TestCheckAccountLockRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	_, _, err := store.CheckAccountLock(context.Background(), "", now)
	if err != ErrInvalid {
		t.Fatalf("err=%v want=%v", err, ErrInvalid)
	}
}

func TestRecordAccountFailureCountsReturningSourcesInLaterWindows(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	store := NewStore(db)
	ctx := context.Background()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	account := AccountStuffingDigest("returning-sources")
	sources := []string{"192.0.2.21", "192.0.2.22", "192.0.2.23", "192.0.2.24"}

	// Four distinct sources in the first window: below the five-source
	// threshold, and a repeated source is not counted twice.
	for i, ip := range sources {
		status, locked, err := store.RecordAccountFailure(ctx, account, ip, now)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatalf("locked after %d sources in the first window", i+1)
		}
		if status.DistinctIPs != i+1 {
			t.Fatalf("first window DistinctIPs=%d want=%d", status.DistinctIPs, i+1)
		}
	}
	if _, locked, err := store.RecordAccountFailure(ctx, account, sources[0], now); err != nil || locked {
		t.Fatalf("repeated source locked=%v err=%v", locked, err)
	}

	// The same four sources returning in the next window must still count.
	next := now.Add(StuffingWindow)
	for i, ip := range sources {
		status, locked, err := store.RecordAccountFailure(ctx, account, ip, next)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatalf("locked after %d returning sources", i+1)
		}
		if status.DistinctIPs != i+1 {
			t.Fatalf("second window DistinctIPs=%d want=%d", status.DistinctIPs, i+1)
		}
	}

	// A delayed observation from the earlier window stays attributed to that
	// window and cannot inflate the current window's distinct-source count.
	delayed, locked, err := store.RecordAccountFailure(ctx, account, sources[0], now)
	if err != nil {
		t.Fatal(err)
	}
	if !delayed.WindowStart.Before(next) {
		t.Fatalf("delayed observation window start=%v want a window before %v", delayed.WindowStart, next)
	}
	if delayed.DistinctIPs != len(sources) {
		t.Fatalf("delayed observation DistinctIPs=%d want=%d", delayed.DistinctIPs, len(sources))
	}
	if locked {
		t.Fatal("delayed observation locked the account")
	}

	// A fifth source in the current window reaches the configured threshold.
	status, locked, err := store.RecordAccountFailure(ctx, account, "192.0.2.25", next)
	if err != nil {
		t.Fatal(err)
	}
	if !locked || status.DistinctIPs != StuffingThreshold {
		t.Fatalf("fifth source locked=%v DistinctIPs=%d want=%d", locked, status.DistinctIPs, StuffingThreshold)
	}
}
