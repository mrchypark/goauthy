package loginpolicy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func autoBlacklistEventCount(t *testing.T, db *rhiza.DB) int64 {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='IpBlacklisted'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("event rows=%#v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0].(int64)
}

func TestAutomaticBlacklistNegativePathsEmitNoEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.UnixMilli(1_704_067_200_000).UTC()

	t.Run("disabled", func(t *testing.T) {
		db := testDB(t)
		store := NewStore(db)
		for range 7 {
			if _, err := store.Failure(ctx, "192.0.2.101", now); err != nil {
				t.Fatal(err)
			}
		}
		if got := autoBlacklistEventCount(t, db); got != 0 {
			t.Fatalf("disabled store events=%d", got)
		}
	})

	t.Run("capacity", func(t *testing.T) {
		db := testDB(t)
		blacklist := ipblacklist.NewStore(db, 1)
		store := NewStoreWithBlacklist(db, blacklist)
		expiry := now.Add(time.Hour).UnixMilli()
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "negative-capacity-existing", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"192.0.2.102/32", "existing", expiry, now.UnixMilli(), now.UnixMilli()}}); err != nil {
			t.Fatal(err)
		}
		for range 7 {
			if _, err := store.Failure(ctx, "192.0.2.103", now); err != nil {
				t.Fatal(err)
			}
		}
		if got := autoBlacklistEventCount(t, db); got != 0 {
			t.Fatalf("full capacity events=%d", got)
		}
		if entry, err := blacklist.Get(ctx, "192.0.2.102/32"); err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != expiry || entry.Note != "existing" {
			t.Fatalf("existing finite entry changed: %v", err)
		}
		if _, err := blacklist.Get(ctx, "192.0.2.103/32"); !errors.Is(err, ipblacklist.ErrNotFound) {
			t.Fatalf("new entry admitted err=%v", err)
		}
	})

	t.Run("permanent-manual", func(t *testing.T) {
		db := testDB(t)
		blacklist := ipblacklist.NewStore(db, 1)
		store := NewStoreWithBlacklist(db, blacklist)
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "negative-manual-existing", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"192.0.2.104/32", "manual", nil, now.UnixMilli(), now.UnixMilli()}}); err != nil {
			t.Fatal(err)
		}
		for range 7 {
			if _, err := store.Failure(ctx, "192.0.2.104", now); err != nil {
				t.Fatal(err)
			}
		}
		entry, err := blacklist.Get(ctx, "192.0.2.104/32")
		if err != nil || entry.ExpiresAtUnixMs != nil || entry.Note != "manual" {
			t.Fatalf("manual entry=%+v err=%v", entry, err)
		}
		if got := autoBlacklistEventCount(t, db); got != 0 {
			t.Fatalf("manual capacity events=%d", got)
		}
	})
}

func TestAutomaticBlacklistEventUsesStoredLongerExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	store := NewStoreWithBlacklist(db, ipblacklist.NewStore(db, 1))
	now := time.UnixMilli(1_800_000_000_321)
	expiry := now.Add(2 * time.Hour).UnixMilli()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "longer-finite-entry", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"192.0.2.120/32", "manual", expiry, now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	for range 7 {
		if _, err := store.Failure(ctx, "192.0.2.120", now); err != nil {
			t.Fatal(err)
		}
	}
	if got := autoEventScalar(t, db, `SELECT data FROM event_log WHERE typ='IpBlacklisted'`); got != expiry/1000 {
		t.Fatalf("event expiry=%v, want retained actual expiry=%d", got, expiry/1000)
	}
}

func TestAutomaticBlacklistBackwardInterpositionRejectsWithoutMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 100)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_704_067_210_000).UTC()
	ip := "192.0.2.110"
	for range 6 {
		if _, err := store.Failure(ctx, ip, now); err != nil {
			t.Fatal(err)
		}
	}
	key := digest(ip)
	future := now.Add(time.Hour).UnixMilli()
	insertExpiredAutoEventVictim(t, db, now)
	var called atomic.Bool
	store.beforeFailureMutation = func() {
		if called.CompareAndSwap(false, true) {
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "negative-clock-interposition", SQL: `UPDATE login_ip_failures SET failures=99,blocked_until_unix_ms=?,updated_at_unix_ms=? WHERE key_digest=?`, Args: []any{future, future, key}}); err != nil {
				t.Fatalf("interposition update: %v", err)
			}
		}
	}
	if _, err := store.Failure(ctx, ip, now); err == nil {
		t.Fatal("stale failure accepted after row advanced")
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failures,blocked_until_unix_ms,updated_at_unix_ms FROM login_ip_failures WHERE key_digest=?`, Args: []any{key}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(99) || rows.Rows[0][1] != future || rows.Rows[0][2] != future {
		t.Fatalf("future counter changed rows=%#v err=%v", rows.Rows, err)
	}
	if got := autoBlacklistEventCount(t, db); got != 0 {
		t.Fatalf("interposed failure emitted events=%d", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins'`); got != int64(6) {
		t.Fatalf("stale failure appended invalid-login event, count=%v", got)
	}
	if got := autoEventScalar(t, db, `SELECT seq FROM sqlite_sequence WHERE name='event_log_order'`); got != int64(6) {
		t.Fatalf("stale failure advanced event highwater=%v", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix='192.0.2.41/32'`); got != int64(1) {
		t.Fatal("stale request pruned victim")
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix=?`, ip+"/32"); got != int64(0) {
		t.Fatal("stale request admitted blacklist")
	}
}

func TestAutomaticBlacklistLargeForwardJumpRequiresFreshObservation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 100)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_704_067_220_000).UTC()
	ip := "192.0.2.111"
	for range 7 {
		if _, err := store.Failure(ctx, ip, now); err != nil {
			t.Fatal(err)
		}
	}
	forward := now.Add(maxTrustedStaleAge + time.Millisecond)
	insertExpiredAutoEventVictim(t, db, now)
	if _, err := store.Failure(ctx, ip, forward); err != nil {
		t.Fatal(err)
	}
	if got := autoBlacklistEventCount(t, db); got != 1 {
		t.Fatalf("large forward marker emitted event=%d", got)
	}
	if _, err := store.Failure(ctx, ip, forward); err != nil {
		t.Fatal(err)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins' AND timestamp=? AND data=7 AND level=1`, forward.UnixMilli()); got != int64(2) {
		t.Fatalf("accepted marker observations=%v, want 2 events retaining count 7", got)
	}
	if entry, err := blacklist.Get(ctx, ip+"/32"); err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != now.Add(time.Minute).UnixMilli() {
		t.Fatalf("large forward marker changed blacklist=%v err=%v", entry, err)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix='192.0.2.41/32'`); got != int64(1) {
		t.Fatal("large forward marker pruned victim")
	}
	status, err := store.Failure(ctx, ip, forward.Add(time.Millisecond))
	if err != nil || status.Failures != 1 {
		t.Fatalf("fresh observation status=%+v err=%v", status, err)
	}
	if got := autoBlacklistEventCount(t, db); got != 1 {
		t.Fatalf("fresh reset emitted event=%d", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins' AND timestamp=? AND data=1 AND level=0`, forward.Add(time.Millisecond).UnixMilli()); got != int64(1) {
		t.Fatalf("fresh observation reset event=%v, want 1", got)
	}
}
