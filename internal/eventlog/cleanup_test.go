package eventlog_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/audit"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func cleanupFixture(t *testing.T) (*rhiza.DB, *eventlog.Store, time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-cleanup-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := eventlog.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store, time.UnixMilli(2_000_000_000_000).UTC()
}

func insertEvents(t *testing.T, db *rhiza.DB, events []eventlog.Event) {
	t.Helper()
	for start := 0; start < len(events); start += 64 {
		end := start + 64
		if end > len(events) {
			end = len(events)
		}
		statements := make([]rhiza.SQLStatement, 0, end-start)
		for _, event := range events[start:end] {
			statement, err := event.Statement("1=1")
			if err != nil {
				t.Fatal(err)
			}
			statements = append(statements, statement)
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "event-seed-" + events[start].ID, Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
}

func eventCount(t *testing.T, db *rhiza.DB) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("event count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("event count=%#v", result.Rows)
	}
	return count
}

func TestCleanupStrictCutoffAndBoundedProgress(t *testing.T) {
	db, store, now := cleanupFixture(t)
	sentinel := audit.NewEvent("cleanup-audit", "api_key.created", "create", "browser_admin", "", strings.Repeat("A", 43), now)
	statement, err := sentinel.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "cleanup-audit", Statements: []rhiza.SQLStatement{statement}}); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	cutoff := now.Add(-retention)
	events := make([]eventlog.Event, 0, 1002)
	for i := 0; i < 1001; i++ {
		events = append(events, eventlog.Creation(fmt.Sprintf("old-%d", i), "", "", false, cutoff.Add(-time.Millisecond)))
	}
	events = append(events, eventlog.Creation("boundary", "", "", false, cutoff))
	insertEvents(t, db, events)
	if got := eventCount(t, db); got != 1002 {
		t.Fatalf("initial event count=%d", got)
	}
	removed, err := store.Cleanup(context.Background(), now, retention)
	if err != nil || removed != 1000 {
		t.Fatalf("first cleanup removed=%d err=%v", removed, err)
	}
	if got := eventCount(t, db); got != 2 {
		t.Fatalf("after first cleanup count=%d", got)
	}
	removed, err = store.Cleanup(context.Background(), now, retention)
	if err != nil || removed != 1 {
		t.Fatalf("second cleanup removed=%d err=%v", removed, err)
	}
	if got := eventCount(t, db); got != 1 {
		t.Fatalf("after second cleanup count=%d", got)
	}
	auditRows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM audit_events`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(auditRows.Rows) != 1 || auditRows.Rows[0][0] != int64(1) {
		t.Fatalf("audit sentinel changed rows=%#v err=%v", auditRows.Rows, err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != cutoff.UnixMilli() {
		t.Fatalf("boundary event rows=%#v err=%v", rows.Rows, err)
	}
}

func TestCleanupRejectsCanceledContextWithoutMutation(t *testing.T) {
	db, store, now := cleanupFixture(t)
	event := eventlog.Creation("cancel", "", "", false, now.Add(-time.Hour-time.Millisecond))
	insertEvents(t, db, []eventlog.Event{event})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	removed, err := store.Cleanup(ctx, now, time.Hour)
	if err == nil || removed != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup canceled removed=%d err=%v", removed, err)
	}
	if got := eventCount(t, db); got != 1 {
		t.Fatalf("canceled cleanup count=%d", got)
	}
}
