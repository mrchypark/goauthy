package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRecordBrowserLoginLocationSameBrowserIPChange(t *testing.T) {
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()
	bootstrapPassword(t, store, "browser-location-1", "browser-location-1", []byte("Password1"))

	if got, err := store.RecordBrowserLoginLocation(ctx, "browser-location-1", "browser-a", "192.0.2.1", "ua-1", nil); err != nil || !got {
		t.Fatalf("first record got=%t err=%v", got, err)
	}
	store.now = func() time.Time { return time.UnixMilli(1_800_000_001_000) }
	location := "Seoul"
	if got, err := store.RecordBrowserLoginLocation(ctx, "browser-location-1", "browser-a", "192.0.2.2", "ua-2", &location); err != nil || got {
		t.Fatalf("IP change got=%t err=%v", got, err)
	}

	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count,user_agent,location FROM identity_login_locations WHERE subject=?`, Args: []any{"browser-location-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 6 {
		t.Fatalf("stored location rows=%v err=%v", rows.Rows, err)
	}
	row := rows.Rows[0]
	if row[0] != "192.0.2.2" || row[1] != int64(1_800_000_000_000) || row[2] != int64(1_800_000_001_000) || row[3] != int64(2) || row[4] != "ua-1" || row[5] != location {
		t.Fatalf("stored location=%v", row)
	}
}

func TestRecordBrowserLoginLocationNewBrowserSameIPIsNew(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := context.Background()
	bootstrapPassword(t, store, "browser-location-2", "browser-location-2", []byte("Password1"))

	first, err := store.RecordBrowserLoginLocation(ctx, "browser-location-2", "browser-a", "192.0.2.10", "ua", nil)
	if err != nil || !first {
		t.Fatalf("first record got=%t err=%v", first, err)
	}
	second, err := store.RecordBrowserLoginLocation(ctx, "browser-location-2", "browser-b", "192.0.2.10", "ua", nil)
	if err != nil || !second {
		t.Fatalf("new browser same IP got=%t err=%v", second, err)
	}

	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`, Args: []any{"browser-location-2"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("location count rows=%v err=%v", rows.Rows, err)
	}
}

func TestRecordBrowserLoginLocationWithoutBrowserUsesIP(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := context.Background()
	bootstrapPassword(t, store, "browser-location-3", "browser-location-3", []byte("Password1"))

	first, err := store.RecordBrowserLoginLocation(ctx, "browser-location-3", "", "2001:db8::1", "ua", nil)
	if err != nil || !first {
		t.Fatalf("first record got=%t err=%v", first, err)
	}
	second, err := store.RecordBrowserLoginLocation(ctx, "browser-location-3", "", "2001:0db8:0:0:0:0:0:1", "ua", nil)
	if err != nil || second {
		t.Fatalf("same IP without browser got=%t err=%v", second, err)
	}

	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT login_count FROM identity_login_locations WHERE subject=? AND ip_address=?`, Args: []any{"browser-location-3", "2001:db8::1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("login count rows=%v err=%v", rows.Rows, err)
	}
}

func TestRecordBrowserLoginLocationConcurrentOneWinner(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := context.Background()
	bootstrapPassword(t, store, "browser-location-4", "browser-location-4", []byte("Password1"))

	const workers = 8
	start := make(chan struct{})
	results := make(chan bool, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			newLocation, err := store.RecordBrowserLoginLocation(ctx, "browser-location-4", "browser-a", "198.51.100.7", "ua", nil)
			results <- newLocation
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	winners := 0
	for got := range results {
		if got {
			winners++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("new-location winners=%d, want 1", winners)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*),login_count FROM identity_login_locations WHERE subject=?`, Args: []any{"browser-location-4"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != int64(workers) {
		t.Fatalf("concurrent location rows=%v err=%v", rows.Rows, err)
	}
}

func TestRecordBrowserLoginLocationInvalidInput(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := context.Background()
	bootstrapPassword(t, store, "browser-location-5", "browser-location-5", []byte("Password1"))

	for _, tc := range []struct {
		name, subject, ip, userAgent string
		want                         error
	}{
		{name: "subject", subject: " ", ip: "192.0.2.1", userAgent: "ua", want: ErrInvalidSubject},
		{name: "ip", subject: "browser-location-5", ip: "invalid", userAgent: "ua", want: ErrInvalidIPAddress},
		{name: "user agent", subject: "browser-location-5", ip: "192.0.2.1", userAgent: "", want: ErrInvalidUserAgent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.RecordBrowserLoginLocation(ctx, tc.subject, "browser-a", tc.ip, tc.userAgent, nil); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}

	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-location-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"browser-location-5"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordBrowserLoginLocation(ctx, "browser-location-5", "browser-a", "192.0.2.1", "ua", nil); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("inactive subject err=%v", err)
	}
}

func TestRecordBrowserLoginLocationCanonicalIPFamily(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := t.Context()
	const subject = "location-ip-family"
	bootstrapPassword(t, store, subject, subject, []byte("Password1"))
	for _, item := range []struct {
		ip    string
		fresh bool
	}{
		{"2001:0db8:0:0:0:0:0:1", true},
		{"2001:db8::1", false},
		{"::ffff:192.0.2.1", true},
		{"192.0.2.1", true},
	} {
		fresh, err := store.RecordBrowserLoginLocation(ctx, subject, "", item.ip, "Browser", nil)
		if err != nil || fresh != item.fresh {
			t.Fatalf("IP %s fresh=%t err=%v", item.ip, fresh, err)
		}
	}
	if _, err := store.RecordBrowserLoginLocation(ctx, subject, "", "fe80::1%en0", "Browser", nil); !errors.Is(err, ErrInvalidIPAddress) {
		t.Fatalf("scoped address error=%v", err)
	}
}

func TestBrowserLocationEarlierRequestTimeDoesNotRegressLastSeen(t *testing.T) {
	store := testResetStore(t, testRules(3))
	ctx := t.Context()
	bootstrapPassword(t, store, "reordered-location", "reordered-location", []byte("Password1"))
	for _, browserID := range []string{"browser-a", ""} {
		newer := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
		store.now = func() time.Time { return newer }
		if _, err := store.RecordBrowserLoginLocation(ctx, "reordered-location", browserID, "192.0.2.10", "UA", nil); err != nil {
			t.Fatal(err)
		}
		// Request timestamps can arrive out of order even when database writes serialize.
		store.now = func() time.Time { return newer.Add(-time.Second) }
		if fresh, err := store.RecordBrowserLoginLocation(ctx, "reordered-location", browserID, "192.0.2.10", "UA", nil); err != nil || fresh {
			t.Fatalf("older request fresh=%t err=%v", fresh, err)
		}
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT MIN(last_seen_at_unix_ms-first_seen_at_unix_ms),SUM(login_count) FROM identity_login_locations WHERE subject='reordered-location'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(4) {
		t.Fatalf("location timestamps/count=%v err=%v", rows.Rows, err)
	}
}
