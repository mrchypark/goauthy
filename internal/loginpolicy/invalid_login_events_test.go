package loginpolicy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestFailureEmitsInvalidLoginEventsWithCounterPayload(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.Unix(1_800_000_000, 0).UTC()
	for i := 1; i <= 27; i++ {
		if _, err := store.Failure(context.Background(), "192.0.2.101", now); err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT e.timestamp,e.data,e.level,e.ip,e.text FROM event_log e JOIN event_log_order o ON o.event_id=e.id WHERE e.typ='InvalidLogins' ORDER BY o.sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 27 {
		t.Fatalf("invalid events=%#v err=%v", rows.Rows, err)
	}
	for i, row := range rows.Rows {
		wantLevel := int64(0)
		if i+1 >= 7 {
			wantLevel = 1
		}
		if i+1 >= 10 {
			wantLevel = 2
		}
		if i+1 >= 20 {
			wantLevel = 3
		}
		if row[0] != now.UnixMilli() || row[1] != int64(i+1) || row[2] != wantLevel || row[3] != "192.0.2.101" || row[4] != nil {
			t.Fatalf("event %d=%#v", i+1, row)
		}
	}
}

func TestFailureConcurrentInvalidLoginEventsHaveContiguousCounts(t *testing.T) {
	db := testDB(t)
	first, second := NewStore(db), NewStore(db)
	now := time.Unix(1_800_000_000, 0).UTC()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 7; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.Failure(context.Background(), "2001:db8::101", now); err != nil {
				t.Errorf("failure: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*),COUNT(DISTINCT id),MIN(data),MAX(data),COUNT(DISTINCT data) FROM event_log WHERE typ='InvalidLogins' AND ip='2001:db8::101'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(7) || rows.Rows[0][1] != int64(7) || rows.Rows[0][2] != int64(1) || rows.Rows[0][3] != int64(7) || rows.Rows[0][4] != int64(7) {
		t.Fatalf("concurrent events=%#v err=%v", rows.Rows, err)
	}
}

func TestFailureSuccessDoesNotEmitInvalidLoginEvents(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := store.Failure(context.Background(), "192.0.2.103", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Success(context.Background(), "192.0.2.103", time.Second); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(1) {
		t.Fatalf("events=%#v err=%v", rows.Rows, err)
	}
}

func TestFailureInvalidLoginEventInsertFailureRollsBackCounter(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "invalid-event-fail", SQL: `CREATE TRIGGER invalid_login_event_fail BEFORE INSERT ON event_log BEGIN SELECT RAISE(ABORT,'event failure'); END`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Failure(context.Background(), "192.0.2.102", now); err == nil {
		t.Fatal("failure unexpectedly succeeded")
	}
	status, err := store.Check(context.Background(), "192.0.2.102", now)
	if err != nil || status.Failures != 0 {
		t.Fatalf("rollback status=%+v err=%v", status, err)
	}
	for _, sql := range []string{
		`SELECT COUNT(*) FROM event_log`,
		`SELECT COUNT(*) FROM event_log_order`,
		`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`,
	} {
		if got := autoEventScalar(t, db, sql); got != int64(0) {
			t.Fatalf("rollback %s = %v, want 0", sql, got)
		}
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "invalid-event-drop", SQL: `DROP TRIGGER invalid_login_event_fail`}); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Failure(context.Background(), "192.0.2.102", now); err != nil || status.Failures != 1 {
		t.Fatalf("retry status=%+v err=%v", status, err)
	}
	if got := autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ='InvalidLogins' AND ip='192.0.2.102' AND timestamp=? AND level=0 AND data=1 AND text IS NULL`, now.UnixMilli()); got != int64(1) {
		t.Fatalf("retry event=%v, want 1", got)
	}
	if got := autoEventScalar(t, db, `SELECT seq FROM sqlite_sequence WHERE name='event_log_order'`); got != int64(1) {
		t.Fatalf("retry highwater=%v, want 1", got)
	}
}

func TestFailureInvalidLoginEventCapsWireCountAtUint32(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.Unix(1_800_000_000, 0).UTC()
	ip := "192.0.2.104"
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "invalid-event-max", SQL: `INSERT INTO login_ip_failures(key_digest,failures,blocked_until_unix_ms,updated_at_unix_ms) VALUES(?,?,0,?)`, Args: []any{digest(ip), int64(4294967295), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Failure(context.Background(), ip, now); err != nil || status.Failures != int64(4294967296) {
		t.Fatalf("uncapped counter=%+v err=%v", status, err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT data,level FROM event_log WHERE typ='InvalidLogins' AND ip=?`, Args: []any{ip}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(4294967295) || rows.Rows[0][1] != int64(3) {
		t.Fatalf("capped event=%#v err=%v", rows.Rows, err)
	}
}
