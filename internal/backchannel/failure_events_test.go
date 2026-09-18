package backchannel

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCompleteEmitsTerminalBackchannelFailureEvent(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "failure-event", "client-1", "sid", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "failure-event-lease", SQL: `UPDATE oidc_backchannel_deliveries SET attempts=2,lease_token='lease',lease_until_unix_ms=? WHERE event_id='failure-event' AND client_id='client-1'`, Args: []any{now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	d := delivery{eventID: "failure-event", clientID: "client-1", attempts: 2, leaseToken: "lease"}
	if err := w.complete(context.Background(), d, now, false, false, "transport failed"); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(3) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(3) || rows.Rows[0][4] != "client-1 / " {
		t.Fatalf("event=%#v err=%v", rows.Rows, err)
	}
	state, _, failed, _ := deliveryState(t, db, "failure-event", "client-1")
	if state != 3 || !failed {
		t.Fatalf("terminal state attempts=%d failed=%t", state, failed)
	}
}

func TestCompleteBackchannelRetryAndSuccessEmitNoFailureEvent(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "retry-event", "client-1", "sid-r", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "retry-event-lease", SQL: `UPDATE oidc_backchannel_deliveries SET lease_token='retry-lease',lease_until_unix_ms=? WHERE event_id='retry-event'`, Args: []any{now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := w.complete(context.Background(), delivery{eventID: "retry-event", clientID: "client-1", attempts: 0, leaseToken: "retry-lease"}, now, false, false, "temporary"); err != nil {
		t.Fatal(err)
	}
	insertDelivery(t, db, "early-permanent", "client-1", "sid-p", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "early-permanent-lease", SQL: `UPDATE oidc_backchannel_deliveries SET lease_token='permanent-lease',lease_until_unix_ms=? WHERE event_id='early-permanent'`, Args: []any{now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := w.complete(context.Background(), delivery{eventID: "early-permanent", clientID: "client-1", attempts: 0, leaseToken: "permanent-lease"}, now, false, true, "permanent"); err != nil {
		t.Fatal(err)
	}
	insertDelivery(t, db, "success-event", "client-1", "sid-s", "http://127.0.0.1/logout", true, true, now)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "success-event-lease", SQL: `UPDATE oidc_backchannel_deliveries SET lease_token='success-lease',lease_until_unix_ms=? WHERE event_id='success-event'`, Args: []any{now.Add(time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := w.complete(context.Background(), delivery{eventID: "success-event", clientID: "client-1", attempts: 0, leaseToken: "success-lease"}, now, true, false, ""); err != nil {
		t.Fatal(err)
	}
	if rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable}); err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("retry event=%#v err=%v", rows.Rows, err)
	}
}

func TestCompleteBackchannelLostLeaseDoesNotEmitFailureEvent(t *testing.T) {
	w, db := newTestWorker(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	insertDelivery(t, db, "lost-lease", "client-1", "sid-l", "http://127.0.0.1/logout", true, true, now)
	if err := w.complete(context.Background(), delivery{eventID: "lost-lease", clientID: "client-1", attempts: 2, leaseToken: "missing-lease"}, now, false, false, "transport"); err == nil {
		t.Fatal("lost lease unexpectedly completed")
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("lost-lease events=%#v err=%v", rows.Rows, err)
	}
}
