package loginpolicy

import (
	"context"
	"testing"
	"time"
)

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
