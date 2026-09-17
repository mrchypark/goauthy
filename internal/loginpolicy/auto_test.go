package loginpolicy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAutomaticBlacklistThresholdsAndIPv6(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	var expiry int64

	for attempt := int64(1); attempt <= 25; attempt++ {
		if _, err := store.Failure(context.Background(), "192.0.2.10", now); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		want := map[int64]int64{7: 60_000, 10: 600_000, 15: 900_000, 20: 3_600_000, 25: 86_400_000}[attempt]
		if want == 0 {
			if attempt < 7 {
				continue
			}
			entry, err := blacklist.Get(context.Background(), "192.0.2.10/32")
			if err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != expiry {
				t.Fatalf("intermediate attempt %d entry=%+v err=%v", attempt, entry, err)
			}
			continue
		}
		entry, err := blacklist.Get(context.Background(), "192.0.2.10/32")
		if err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != now.UnixMilli()+want {
			t.Fatalf("attempt %d entry=%+v err=%v", attempt, entry, err)
		}
		expiry = *entry.ExpiresAtUnixMs
	}

	if _, err := store.Failure(context.Background(), "2001:db8::10", now); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := store.Failure(context.Background(), "2001:db8::10", now); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := blacklist.Get(context.Background(), "2001:db8::10/128")
	if err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != now.UnixMilli()+60_000 {
		t.Fatalf("IPv6 entry=%+v err=%v", entry, err)
	}
}

func TestFailureClockRejectsBackwardAndLargeForwardJumps(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if _, err := store.Failure(context.Background(), "192.0.2.40", now); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := store.Failure(context.Background(), "192.0.2.40", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Failure(context.Background(), "192.0.2.40", now.Add(-time.Millisecond)); err != ErrInvalid {
		t.Fatalf("backward failure err=%v, want %v", err, ErrInvalid)
	}
	forward := now.Add(maxTrustedStaleAge + time.Millisecond)
	status, err := store.Failure(context.Background(), "192.0.2.40", forward)
	if err != nil || status.Failures != 7 {
		t.Fatalf("forward observation status=%+v err=%v", status, err)
	}
	status, err = store.Failure(context.Background(), "192.0.2.40", forward)
	if err != nil || status.Failures != 7 {
		t.Fatalf("same-time forward observation status=%+v err=%v", status, err)
	}
	status, err = store.Failure(context.Background(), "192.0.2.40", forward.Add(time.Millisecond))
	if err != nil || status.Failures != 1 {
		t.Fatalf("strictly newer forward confirmation status=%+v err=%v", status, err)
	}
	status, err = store.Check(context.Background(), "192.0.2.40", forward.Add(time.Millisecond))
	if err != nil || status.Failures != 1 {
		t.Fatalf("clock jump altered status=%+v err=%v", status, err)
	}
}

func TestAutomaticBlacklistReclaimsExpiredFiniteEntriesAtCap(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 1)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	oldExpiry := now.Add(-time.Millisecond).UnixMilli()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "auto-test-expired-cap", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"192.0.2.41/32", "expired", oldExpiry, now.Add(-time.Hour).UnixMilli(), now.Add(-time.Hour).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	for range 7 {
		if _, err := store.Failure(context.Background(), "192.0.2.42", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := blacklist.Get(context.Background(), "192.0.2.42/32"); err != nil {
		t.Fatalf("new entry was not admitted after reclamation: %v", err)
	}
	if _, err := blacklist.Get(context.Background(), "192.0.2.41/32"); err != ipblacklist.ErrNotFound {
		t.Fatalf("expired entry remains err=%v", err)
	}
}

func TestAutomaticBlacklistConcurrentCrossStoreAndPermanentManualEntry(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	first, second := NewStoreWithBlacklist(db, blacklist), NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for attempt := 0; attempt < 8; attempt++ {
		store := first
		if attempt%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.Failure(context.Background(), "192.0.2.20", now); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	status, err := first.Check(context.Background(), "192.0.2.20", now)
	if err != nil || status.Failures != 8 {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "auto-test-manual-entry", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"192.0.2.21/32", "manual", nil, now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	manual := NewStoreWithBlacklist(db, blacklist)
	for range 7 {
		if _, err := manual.Failure(context.Background(), "192.0.2.21", now); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := blacklist.Get(context.Background(), "192.0.2.21/32")
	if err != nil || entry.ExpiresAtUnixMs != nil || entry.Note != "manual" {
		t.Fatalf("manual entry=%+v err=%v", entry, err)
	}
}

func TestAutomaticBlacklistStaleFailureResetDoesNotReblacklist(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	for range 7 {
		if _, err := store.Failure(context.Background(), "192.0.2.30", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Failure(context.Background(), "192.0.2.30", now.Add(24*time.Hour+time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	status, err := store.Check(context.Background(), "192.0.2.30", now.Add(24*time.Hour+time.Millisecond))
	if err != nil || status.Failures != 1 {
		t.Fatalf("stale status=%+v err=%v", status, err)
	}
	entry, err := blacklist.Get(context.Background(), "192.0.2.30/32")
	if err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != now.UnixMilli()+60_000 {
		t.Fatalf("stale entry=%+v err=%v", entry, err)
	}
}
