package eventlog_test

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func streamHistoryFixture(t *testing.T) (*rhiza.DB, *eventlog.Store) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-stream-history", DataDir: t.TempDir()})
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
	return db, store
}

func insertHistoryEvents(t *testing.T, db *rhiza.DB, events []eventlog.Event) {
	t.Helper()
	ctx := context.Background()
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
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "history-" + string(rune(start)), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInitialHistoryUsesNewest100BeforeLevelAndLatestFilters(t *testing.T) {
	db, store := streamHistoryFixture(t)
	base := time.UnixMilli(1_800_001_000_000)
	events := make([]eventlog.Event, 0, 102)
	first := eventlog.Creation("outside", "outside", "1.1.1.1", false, base)
	first.Level = eventlog.Critical
	events = append(events, first)
	for i := 1; i <= 101; i++ {
		events = append(events, eventlog.Creation("info-"+string(rune(i)), "info", "1.1.1.1", false, base.Add(time.Duration(i)*time.Millisecond)))
	}
	insertHistoryEvents(t, db, events)
	page, err := store.StreamPageGuarded(context.Background(), -1, 1000, eventlog.Critical, "1=1")
	if err != nil || !page.Authorized || page.Cursor != 102 || len(page.Events) != 0 {
		t.Fatalf("outside-buffer page=%#v err=%v", page, err)
	}

	db2, store2 := streamHistoryFixture(t)
	criticalOld := eventlog.Creation("critical-old", "old", "1.1.1.1", false, base)
	criticalOld.Level = eventlog.Critical
	info := eventlog.Creation("info-new", "new", "1.1.1.1", false, base.Add(time.Second))
	criticalNew := eventlog.Creation("critical-new", "new", "1.1.1.1", false, base.Add(2*time.Second))
	criticalNew.Level = eventlog.Critical
	insertHistoryEvents(t, db2, []eventlog.Event{criticalOld, criticalNew, info})
	page, err = store2.StreamPageGuarded(context.Background(), -1, 1, eventlog.Critical, "1=1")
	if err != nil || len(page.Events) != 1 || page.Events[0].ID != criticalNew.ID {
		t.Fatalf("latest filtered page=%#v err=%v", page, err)
	}
}

func TestInitialHistoryFollowsCommitSequenceDespiteTimestampOrderAndDeniesCursor(t *testing.T) {
	db, store := streamHistoryFixture(t)
	base := time.UnixMilli(1_800_002_000_000)
	events := []eventlog.Event{
		eventlog.Creation("seq1", "1", "1.1.1.1", false, base.Add(3*time.Second)),
		eventlog.Creation("seq2", "2", "1.1.1.1", false, base.Add(1*time.Second)),
		eventlog.Creation("seq3", "3", "1.1.1.1", false, base),
	}
	insertHistoryEvents(t, db, events)
	page, err := store.StreamPageGuarded(context.Background(), -1, 100, eventlog.Info, "1=1")
	if err != nil || len(page.Events) != 3 || page.Events[0].ID != events[0].ID || page.Events[1].ID != events[1].ID || page.Events[2].ID != events[2].ID {
		t.Fatalf("sequence order page=%#v err=%v", page, err)
	}
	denied, err := store.StreamPageGuarded(context.Background(), -1, 100, eventlog.Info, "0=1")
	if err != nil || denied.Authorized || denied.Cursor != 0 || denied.Events == nil || len(denied.Events) != 0 {
		t.Fatalf("denied page=%#v err=%v", denied, err)
	}
}
