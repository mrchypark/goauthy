package loginpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func execAutoEventTestSQL(t *testing.T, db *rhiza.DB, requestID, sql string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql}); err != nil {
		t.Fatal(err)
	}
}

func autoEventScalar(t *testing.T, db *rhiza.DB, sql string, args ...any) any {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("scalar rows=%#v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0]
}

func seedSixFailures(t *testing.T, store *Store, now time.Time, ip string) {
	t.Helper()
	for attempt := 1; attempt <= 6; attempt++ {
		status, err := store.Failure(context.Background(), ip, now)
		if err != nil || status.Failures != int64(attempt) {
			t.Fatalf("seed attempt=%d status=%+v err=%v", attempt, status, err)
		}
	}
}

func insertExpiredAutoEventVictim(t *testing.T, db *rhiza.DB, now time.Time) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "auto-event-expired-victim",
		SQL:       `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`,
		Args:      []any{"192.0.2.41/32", "expired", now.Add(-time.Millisecond).UnixMilli(), now.Add(-time.Hour).UnixMilli(), now.Add(-time.Hour).UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticBlacklistEventAbortRollsBackAllState(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 1)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	const ip = "192.0.2.42"

	seedSixFailures(t, store, now, ip)
	insertExpiredAutoEventVictim(t, db, now)
	beforeEvents := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	execAutoEventTestSQL(t, db, "auto-event-abort-create", `CREATE TRIGGER auto_event_abort BEFORE INSERT ON event_log WHEN NEW.typ='IpBlacklisted' BEGIN SELECT RAISE(ABORT, 'event sink unavailable'); END`)
	t.Cleanup(func() {
		execAutoEventTestSQL(t, db, "auto-event-abort-drop", `DROP TRIGGER IF EXISTS auto_event_abort`)
	})

	if _, err := store.Failure(context.Background(), ip, now); err == nil {
		t.Fatal("failure succeeded despite event abort trigger")
	}
	if got := autoEventScalar(t, db, `SELECT failures FROM login_ip_failures WHERE key_digest=?`, digest(ip)); got != int64(6) {
		t.Fatalf("failure counter=%v, want 6", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix=?`, "192.0.2.42/32"); got != int64(0) {
		t.Fatalf("attempted blacklist rows=%v, want 0", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix=?`, "192.0.2.41/32"); got != int64(1) {
		t.Fatalf("expired victim rows=%v, want 1", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v, before=%v", got, beforeEvents)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins'`); got != int64(6) {
		t.Fatalf("invalid-login events=%v, want 6", got)
	}
	if got := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event order highwater=%v, before=%v", got, beforeOrder)
	}

	execAutoEventTestSQL(t, db, "auto-event-abort-drop-now", `DROP TRIGGER auto_event_abort`)
	status, err := store.Failure(context.Background(), ip, now)
	if err != nil || status.Failures != 7 {
		t.Fatalf("post-trigger failure status=%+v err=%v", status, err)
	}
	entry, err := blacklist.Get(context.Background(), "192.0.2.42/32")
	if err != nil || entry.ExpiresAtUnixMs == nil || *entry.ExpiresAtUnixMs != now.Add(time.Minute).UnixMilli() {
		t.Fatalf("new blacklist entry=%+v err=%v", entry, err)
	}
	if _, err := blacklist.Get(context.Background(), "192.0.2.41/32"); err != ipblacklist.ErrNotFound {
		t.Fatalf("expired victim err=%v, want not found", err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ='IpBlacklisted'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(2) || rows.Rows[0][2] != ip || rows.Rows[0][3] != now.Add(time.Minute).Unix() || rows.Rows[0][4] != nil {
		t.Fatalf("event rows=%#v err=%v", rows.Rows, err)
	}
	if got := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder+2 {
		t.Fatalf("event order highwater=%v, want %v", got, beforeOrder+2)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log`); got != beforeEvents+2 {
		t.Fatalf("event count=%v, want %v", got, beforeEvents+2)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins'`); got != int64(7) {
		t.Fatalf("invalid-login events=%v, want 7", got)
	}
}

func TestAutomaticBlacklistEventOrderAbortRollsBackAllState(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 1)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1_800_000_000_000).UTC()
	const ip = "192.0.2.43"
	seedSixFailures(t, store, now, ip)
	insertExpiredAutoEventVictim(t, db, now)
	beforeEvents := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`)
	execAutoEventTestSQL(t, db, "auto-event-order-abort-create", `CREATE TRIGGER auto_event_order_abort AFTER INSERT ON event_log_order WHEN EXISTS (SELECT 1 FROM event_log WHERE id=NEW.event_id AND typ='IpBlacklisted') BEGIN SELECT RAISE(ABORT, 'event order unavailable'); END`)
	t.Cleanup(func() {
		execAutoEventTestSQL(t, db, "auto-event-order-abort-drop", `DROP TRIGGER IF EXISTS auto_event_order_abort`)
	})

	if _, err := store.Failure(context.Background(), ip, now); err == nil {
		t.Fatal("failure succeeded despite event-order abort trigger")
	}
	if got := autoEventScalar(t, db, `SELECT failures FROM login_ip_failures WHERE key_digest=?`, digest(ip)); got != int64(6) {
		t.Fatalf("failure counter=%v, want 6", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix=?`, "192.0.2.43/32"); got != int64(0) {
		t.Fatalf("attempted blacklist rows=%v, want 0", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM ip_blacklist_entries WHERE prefix=?`, "192.0.2.41/32"); got != int64(1) {
		t.Fatalf("expired victim rows=%v, want 1", got)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v, before=%v", got, beforeEvents)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins'`); got != int64(6) {
		t.Fatalf("invalid-login events=%v, want 6", got)
	}
	if got := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event order highwater=%v, before=%v", got, beforeOrder)
	}
}
