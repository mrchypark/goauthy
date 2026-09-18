package notify

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func queueFixture(t *testing.T) (*rhiza.DB, context.Context, time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "notify-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db, ctx, time.UnixMilli(2_000_000_000_000).UTC()
}
func putEvent(t *testing.T, db *rhiza.DB, e eventlog.Event) {
	s, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-" + e.ID, Statements: []rhiza.SQLStatement{s}}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationQueueSnapshotLeaseRetryAndRestart(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://hooks.one.test/a")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}})
	if err != nil {
		t.Fatal(err)
	}
	e := eventlog.TestEvent("queue-event", "", now)
	putEvent(t, db, e)
	one, err := q.Claim(ctx, id, now, 1, time.Minute)
	if err != nil || len(one) != 1 {
		t.Fatalf("claim=%#v err=%v", one, err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-source", SQL: `DELETE FROM event_log WHERE id=?`, Args: []any{e.ID}}); err != nil {
		t.Fatal(err)
	}
	q2 := &RhizaQueue{DB: db, allowed: map[string]bool{id: true}}
	if got, err := q2.Claim(ctx, id, now, 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("lease claim=%#v err=%v", got, err)
	}
	if err := q2.Ack(ctx, id, e.ID, one[0].Lease, now); err != nil {
		t.Fatal(err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(2*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("acked reclaim=%#v err=%v", got, err)
	}

	e2 := eventlog.TestEvent("queue-event-2", "", now)
	putEvent(t, db, e2)
	d, err := q2.Claim(ctx, id, now.Add(3*time.Minute), 1, time.Minute)
	if err != nil || len(d) != 1 {
		t.Fatalf("second claim=%#v err=%v", d, err)
	}
	if err := q2.Fail(ctx, id, e2.ID, d[0].Lease, now.Add(3*time.Minute), time.Second, "ignored"); err != nil {
		t.Fatal(err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(3*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("early retry=%#v err=%v", got, err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(3*time.Minute+time.Second), 1, time.Minute); err != nil || len(got) != 1 {
		t.Fatalf("boundary retry=%#v err=%v", got, err)
	}
}

func TestNotificationDestinationDoesNotBackfill(t *testing.T) {
	db, ctx, now := queueFixture(t)
	old := Identity("slack", "https://hooks.old.test/a")
	newID := Identity("slack", "https://hooks.new.test/a")
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: old, Kind: "slack", Level: eventlog.Info}}); err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("old", "", now))
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: newID, Kind: "slack", Level: eventlog.Info}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.Claim(ctx, newID, now, 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("backfill=%#v err=%v", got, err)
	}
	putEvent(t, db, eventlog.TestEvent("new", "", now.Add(time.Second)))
	got, err := q.Claim(ctx, newID, now.Add(time.Second), 10, time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("new=%#v err=%v", got, err)
	}
	ts, err := q.Targets(ctx)
	if err != nil || len(ts) != 1 || ts[0].Name != newID {
		t.Fatalf("targets=%#v err=%v", ts, err)
	}
}

func TestNotificationQueueConcurrentClaimReclaimAndColdRestart(t *testing.T) {
	ctx := t.Context()
	config := rhiza.Config{NodeID: "notify-restart", DataDir: t.TempDir()}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(2_000_000_000_000).UTC()
	id := Identity("slack", "https://hooks.example.test/restart")
	targets := []Target{{Name: id, Kind: "slack", Level: eventlog.Info}}
	q, err := NewRhizaQueue(ctx, db, targets)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := NewRhizaQueue(ctx, db, targets)
	if err != nil {
		t.Fatal(err)
	}
	event := eventlog.TestEvent("cold-restart", "", now)
	putEvent(t, db, event)
	type result struct {
		deliveries []Delivery
		err        error
	}
	start, done := make(chan struct{}), make(chan result, 2)
	for _, queue := range []*RhizaQueue{q, q2} {
		go func() {
			<-start
			d, err := queue.Claim(ctx, id, now, 1, time.Minute)
			done <- result{d, err}
		}()
	}
	close(start)
	var claimed []Delivery
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		claimed = append(claimed, r.deliveries...)
	}
	if len(claimed) != 1 {
		t.Fatalf("concurrent claims=%d, want one", len(claimed))
	}
	oldLease := claimed[0].Lease
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "notify-delete-source-restart", SQL: `DELETE FROM event_log WHERE id=?`, Args: []any{event.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRhizaQueue(ctx, db, targets)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Claim(ctx, id, now.Add(30*time.Second), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("restart lost live lease: %v %v", got, err)
	}
	reclaimed, err := restarted.Claim(ctx, id, now.Add(61*time.Second), 1, time.Minute)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim=%v err=%v", reclaimed, err)
	}
	if reclaimed[0].Event.ID != event.ID || reclaimed[0].Event.Text == nil || *reclaimed[0].Event.Text != *event.Text || reclaimed[0].Lease == oldLease {
		t.Fatal("retention/restart lost payload or lease ownership")
	}
	if err := restarted.Ack(ctx, id, event.ID, oldLease, now.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT delivered_at_unix_ms,lease_token FROM event_notification_deliveries WHERE target=? AND event_id=?`, Args: []any{id, event.ID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil || row.Rows[0][1] != reclaimed[0].Lease {
		t.Fatalf("stale acknowledgement changed new lease: %#v err=%v", row, err)
	}
	if err := restarted.Ack(ctx, id, event.ID, reclaimed[0].Lease, now.Add(63*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Claim(ctx, id, now.Add(10*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("acknowledged delivery retried: %v %v", got, err)
	}
}
