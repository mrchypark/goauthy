package backchannel

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func backchannelRollbackSQL(t *testing.T, db *rhiza.DB, requestID, sql string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql}); err != nil {
		t.Fatal(err)
	}
}

func backchannelScalar(t *testing.T, db *rhiza.DB, sql string, args ...any) any {
	t.Helper()
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		t.Fatalf("scalar rows=%#v err=%v", r.Rows, err)
	}
	return r.Rows[0][0]
}

func backchannelFullState(t *testing.T, db *rhiza.DB, eventID, clientID string) []any {
	t.Helper()
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT attempts,lease_token,lease_until_unix_ms,delivered_at_unix_ms,failed_at_unix_ms,last_error,next_attempt_at_unix_ms FROM oidc_backchannel_deliveries WHERE event_id=? AND client_id=?`, Args: []any{eventID, clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("delivery state=%#v err=%v", r.Rows, err)
	}
	return append([]any(nil), r.Rows[0]...)
}

func TestCompleteTerminalBackchannelEventBeforeInsertAbortRollsBack(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "rollback-before", "client-1", "sid", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rollback-before-lease", SQL: `UPDATE oidc_backchannel_deliveries SET attempts=2,lease_token='lease',lease_until_unix_ms=? WHERE event_id=? AND client_id=?`, Args: []any{now.Add(time.Minute).UnixMilli(), "rollback-before", "client-1"}}); err != nil {
		t.Fatal(err)
	}
	before := backchannelFullState(t, db, "rollback-before", "client-1")
	beforeEvents := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	backchannelRollbackSQL(t, db, "rollback-before-trigger", `CREATE TRIGGER rollback_before_event BEFORE INSERT ON event_log WHEN NEW.typ='BackchannelLogoutFailed' BEGIN SELECT RAISE(ABORT, 'event sink unavailable'); END`)
	t.Cleanup(func() {
		backchannelRollbackSQL(t, db, "rollback-before-drop", `DROP TRIGGER IF EXISTS rollback_before_event`)
	})

	if err := w.complete(context.Background(), delivery{eventID: "rollback-before", clientID: "client-1", attempts: 2, leaseToken: "lease"}, now, false, false, "transport failed"); err == nil {
		t.Fatal("complete succeeded despite event abort")
	}
	got := backchannelFullState(t, db, "rollback-before", "client-1")
	if len(got) != len(before) {
		t.Fatalf("state shape=%#v before=%#v", got, before)
	}
	for i := range got {
		if got[i] != before[i] {
			t.Fatalf("state[%d]=%v before=%v", i, got[i], before[i])
		}
	}
	if got := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v before=%v", got, beforeEvents)
	}
	if got := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event highwater=%v before=%v", got, beforeOrder)
	}
	backchannelRollbackSQL(t, db, "rollback-before-drop-now", `DROP TRIGGER rollback_before_event`)
	verifyBackchannelCompletionAfterAbort(t, w, db, "rollback-before", now, beforeOrder)
}

func TestCompleteTerminalBackchannelEventOrderAbortRollsBack(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "rollback-order", "client-1", "sid", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rollback-order-lease", SQL: `UPDATE oidc_backchannel_deliveries SET attempts=2,lease_token='lease',lease_until_unix_ms=? WHERE event_id=? AND client_id=?`, Args: []any{now.Add(time.Minute).UnixMilli(), "rollback-order", "client-1"}}); err != nil {
		t.Fatal(err)
	}
	before := backchannelFullState(t, db, "rollback-order", "client-1")
	beforeEvents := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	backchannelRollbackSQL(t, db, "rollback-order-trigger", `CREATE TRIGGER rollback_order_event AFTER INSERT ON event_log_order WHEN EXISTS (SELECT 1 FROM event_log WHERE id=NEW.event_id AND typ='BackchannelLogoutFailed') BEGIN SELECT RAISE(ABORT, 'event order unavailable'); END`)
	t.Cleanup(func() {
		backchannelRollbackSQL(t, db, "rollback-order-drop", `DROP TRIGGER IF EXISTS rollback_order_event`)
	})

	if err := w.complete(context.Background(), delivery{eventID: "rollback-order", clientID: "client-1", attempts: 2, leaseToken: "lease"}, now, false, false, "transport failed"); err == nil {
		t.Fatal("complete succeeded despite event-order abort")
	}
	got := backchannelFullState(t, db, "rollback-order", "client-1")
	for i := range got {
		if got[i] != before[i] {
			t.Fatalf("state[%d]=%v before=%v", i, got[i], before[i])
		}
	}
	if got := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v before=%v", got, beforeEvents)
	}
	if got := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event highwater=%v before=%v", got, beforeOrder)
	}
	backchannelRollbackSQL(t, db, "rollback-order-drop-now", `DROP TRIGGER rollback_order_event`)
	verifyBackchannelCompletionAfterAbort(t, w, db, "rollback-order", now, beforeOrder)
}

func verifyBackchannelCompletionAfterAbort(t *testing.T, w Worker, db *rhiza.DB, eventID string, now time.Time, beforeOrder int64) {
	t.Helper()
	if got := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log_order`); got != int64(0) {
		t.Fatalf("rolled-back event order rows=%v", got)
	}
	d := delivery{eventID: eventID, clientID: "client-1", attempts: 2, leaseToken: "lease"}
	if err := w.complete(context.Background(), d, now, false, false, "transport failed"); err != nil {
		t.Fatal(err)
	}
	state := backchannelFullState(t, db, eventID, "client-1")
	if state[0] != int64(3) || state[1] != nil || state[2] != nil || state[3] != nil || state[4] != now.UnixMilli() {
		t.Fatalf("post-abort completion state=%#v", state)
	}
	if got := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='BackchannelLogoutFailed' AND timestamp=? AND level=3 AND ip IS NULL AND data=3 AND text='client-1 / '`, now.UnixMilli()); got != int64(1) {
		t.Fatalf("post-abort event=%v", got)
	}
	if err := w.complete(context.Background(), d, now, false, false, "stale"); err == nil {
		t.Fatal("stale lease accepted after retry")
	}
	if got := backchannelScalar(t, db, `SELECT seq FROM sqlite_sequence WHERE name='event_log_order'`); got != beforeOrder+1 {
		t.Fatalf("post-abort highwater=%v want=%d", got, beforeOrder+1)
	}
}

func TestCompleteTerminalBackchannelEventSuccessAndStaleLease(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "rollback-success", "client-1", "sid", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rollback-success-lease", SQL: `UPDATE oidc_backchannel_deliveries SET attempts=2,lease_token='lease',lease_until_unix_ms=? WHERE event_id=? AND client_id=?`, Args: []any{now.Add(time.Minute).UnixMilli(), "rollback-success", "client-1"}}); err != nil {
		t.Fatal(err)
	}
	beforeOrder := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	if err := w.complete(context.Background(), delivery{eventID: "rollback-success", clientID: "client-1", attempts: 2, leaseToken: "lease"}, now, false, false, "transport failed"); err != nil {
		t.Fatal(err)
	}
	state, done, failed, _ := deliveryState(t, db, "rollback-success", "client-1")
	if state != 3 || done || !failed {
		t.Fatalf("terminal state attempts=%d done=%v failed=%v", state, done, failed)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(3) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(3) || rows.Rows[0][4] != "client-1 / " {
		t.Fatalf("event=%#v err=%v", rows.Rows, err)
	}
	if got := backchannelScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder+1 {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder+1)
	}
	if err := w.complete(context.Background(), delivery{eventID: "rollback-success", clientID: "client-1", attempts: 2, leaseToken: "lease"}, now, false, false, "stale lease"); err == nil {
		t.Fatal("stale lease unexpectedly completed")
	}
	state, done, failed, _ = deliveryState(t, db, "rollback-success", "client-1")
	if state != 3 || done || !failed {
		t.Fatalf("stale lease altered state attempts=%d done=%v failed=%v", state, done, failed)
	}
	if got := backchannelScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='BackchannelLogoutFailed'`); got != int64(1) {
		t.Fatalf("stale lease event count=%v", got)
	}
}
