package eventlog_test

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestStreamPagesUseSequenceWatermarkAndAuthorizationMarker(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-stream-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := eventlog.NewStore(db)
	base := time.UnixMilli(1_800_000_000_000)
	for i, admin := range []bool{false, true, false} {
		e := eventlog.Creation("stream-"+string(rune('a'+i)), "u", "1.1.1.1", admin, base.Add(time.Duration(i)*time.Millisecond))
		stmt, _ := e.Statement("1=1")
		if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stream-seed-" + string(rune('a'+i)), Statements: []rhiza.SQLStatement{stmt}}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.StreamPageGuarded(ctx, -1, 1, eventlog.Info, "1=1")
	if err != nil || !first.Authorized || first.Cursor != 3 || len(first.Events) != 1 || first.Events[0].Timestamp != base.Add(2*time.Millisecond).UnixMilli() {
		t.Fatalf("initial=%#v err=%v", first, err)
	}
	next, err := store.StreamPageGuarded(ctx, 1, 1000, eventlog.Info, "1=1")
	if err != nil || !next.Authorized || next.Cursor != 3 || next.More || len(next.Events) != 2 {
		t.Fatalf("next=%#v err=%v", next, err)
	}
	if next.Events[0].Timestamp >= next.Events[1].Timestamp {
		t.Fatalf("continuation not ascending: %#v", next.Events)
	}
	empty, err := store.StreamPageGuarded(ctx, -1, 0, eventlog.Info, "1=1")
	if err != nil || !empty.Authorized || empty.Cursor != 3 || len(empty.Events) != 0 {
		t.Fatalf("latest0=%#v err=%v", empty, err)
	}
	denied, err := store.StreamPageGuarded(ctx, -1, 100, eventlog.Info, "0=1")
	if err != nil || denied.Authorized || denied.Events == nil || len(denied.Events) != 0 {
		t.Fatalf("denied=%#v err=%v", denied, err)
	}
}

func TestStreamContinuationAdvancesAcrossFilteredRowsAndRetainsWatermark(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-stream-progress", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := eventlog.NewStore(db)
	base := time.UnixMilli(1_800_000_100_000)
	statements := make([]rhiza.SQLStatement, 0, 101)
	for i := 0; i < 100; i++ {
		e := eventlog.Creation("low-"+string(rune(i)), "u", "1.1.1.1", false, base.Add(time.Duration(i)*time.Millisecond))
		s, _ := e.Statement("1=1")
		statements = append(statements, s)
	}
	critical := eventlog.Creation("critical", "u", "1.1.1.1", true, base.Add(100*time.Millisecond))
	critical.Level = eventlog.Critical
	s, _ := critical.Statement("1=1")
	statements = append(statements, s)
	for start := 0; start < len(statements); start += 64 {
		end := start + 64
		if end > len(statements) {
			end = len(statements)
		}
		if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stream-progress-seed-" + string(rune(start)), Statements: statements[start:end]}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.StreamPageGuarded(ctx, 0, 100, eventlog.Critical, "1=1")
	if err != nil || !page.Authorized || page.Cursor != 100 || !page.More || len(page.Events) != 0 {
		t.Fatalf("filtered first page=%#v err=%v", page, err)
	}
	page, err = store.StreamPageGuarded(ctx, page.Cursor, 100, eventlog.Critical, "1=1")
	if err != nil || page.Cursor != 101 || page.More || len(page.Events) != 1 || page.Events[0].Type != eventlog.NewRauthyAdmin {
		t.Fatalf("critical next=%#v err=%v", page, err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stream-delete-tail", SQL: `DELETE FROM event_log WHERE id=?`, Args: []any{critical.ID}}); err != nil {
		t.Fatal(err)
	}
	page, err = store.StreamPageGuarded(ctx, -1, 0, eventlog.Info, "1=1")
	if err != nil || page.Cursor != 101 || page.More {
		t.Fatalf("partially deleted watermark=%#v err=%v", page, err)
	}
	page, err = store.StreamPageGuarded(ctx, 100, 0, eventlog.Info, "1=1")
	if err != nil || !page.Authorized || page.Cursor != 101 || page.More || len(page.Events) != 0 {
		t.Fatalf("deleted tail must exhaust snapshot=%#v err=%v", page, err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stream-progress-delete", SQL: `DELETE FROM event_log`}); err != nil {
		t.Fatal(err)
	}
	page, err = store.StreamPageGuarded(ctx, -1, 0, eventlog.Info, "1=1")
	if err != nil || !page.Authorized || page.Cursor != 101 || page.Events == nil || len(page.Events) != 0 {
		t.Fatalf("deleted watermark=%#v err=%v", page, err)
	}
	page, err = store.StreamPageGuarded(ctx, 0, 0, eventlog.Info, "1=1")
	if err != nil || !page.Authorized || page.Cursor != 101 || page.More || len(page.Events) != 0 {
		t.Fatalf("all deleted continuation=%#v err=%v", page, err)
	}
	// A lower wall-clock timestamp after deletion still has a newer commit cursor.
	backdated := eventlog.Creation("backdated", "u", "1.1.1.1", false, base.Add(-time.Hour))
	stmt, err := backdated.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stream-backdated", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
		t.Fatal(err)
	}
	page, err = store.StreamPageGuarded(ctx, page.Cursor, 0, eventlog.Info, "1=1")
	if err != nil || page.Cursor != 102 || page.More || len(page.Events) != 1 || page.Events[0].ID != backdated.ID {
		t.Fatalf("backdated continuation=%#v err=%v", page, err)
	}
}
