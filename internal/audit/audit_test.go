package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	. "github.com/mrchypark/goauthy/internal/audit"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAppendOnlyListIsLinearizableAndBounded(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "audit-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, requestID := range []string{"one", "two"} {
		event := NewEvent(requestID, "api_key.created", "create", "browser_admin", "", Pseudonym(strings.Repeat("A", 43), "target", "target"), time.UnixMilli(100))
		statement, err := event.Statement("1=1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "audit-test-" + requestID, Statements: []rhiza.SQLStatement{statement}}); err != nil {
			t.Fatal(err)
		}
	}
	events, cursor, err := store.List(ctx, nil, 1)
	if err != nil || len(events) != 1 || cursor == nil || events[0].TargetHash == "target" || events[0].ActorHash != "" {
		t.Fatalf("events=%#v cursor=%#v err=%v", events, cursor, err)
	}
	next, _, err := store.List(ctx, cursor, 1)
	if err != nil || len(next) != 1 || next[0].ID == events[0].ID {
		t.Fatalf("next=%#v err=%v", next, err)
	}
	if _, _, err := store.List(ctx, nil, 32); err != nil {
		t.Fatalf("maximum page err=%v", err)
	}
	if _, _, err := store.List(ctx, nil, 33); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded list err=%v", err)
	}
	if Pseudonym(strings.Repeat("A", 43), "actor", "name") == Pseudonym(strings.Repeat("A", 43), "target", "name") || Pseudonym(strings.Repeat("A", 43), "actor", "name") == Pseudonym(strings.Repeat("B", 43), "actor", "name") {
		t.Fatal("audit pseudonym lacks domain/key separation")
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "audit-mutate", SQL: `DELETE FROM audit_events`}); err == nil {
		t.Fatal("append-only audit delete accepted")
	}
}

func TestSequencePaginationIgnoresBackwardClockAndNewRows(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "audit-sequence", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	appendEvent := func(requestID string, occurredAt int64) {
		event := NewEvent(requestID, "api_key.created", "create", "browser_admin", "", Pseudonym(strings.Repeat("A", 43), "target", requestID), time.UnixMilli(occurredAt))
		statement, err := event.Statement("1=1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "audit-sequence-" + requestID, Statements: []rhiza.SQLStatement{statement}}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent("first", 300)
	appendEvent("second", 100)
	first, cursor, err := store.List(ctx, nil, 1)
	if err != nil || len(first) != 1 || cursor == nil || first[0].Sequence != 2 || first[0].OccurredAtUnixMilli != 100 {
		t.Fatalf("first=%#v cursor=%#v err=%v", first, cursor, err)
	}
	appendEvent("interleaved", 200)
	second, next, err := store.List(ctx, cursor, 2)
	if err != nil || len(second) != 1 || next == nil || second[0].Sequence != 1 || second[0].OccurredAtUnixMilli != 300 {
		t.Fatalf("second=%#v next=%#v err=%v", second, next, err)
	}
	other, _, err := store.List(ctx, nil, 32)
	if err != nil || len(other) != 3 || other[0].Sequence != 3 || other[1].Sequence != 2 || other[2].Sequence != 1 {
		t.Fatalf("cross-store=%#v err=%v", other, err)
	}
}

func TestMasterKeyRetirementEventsUseTheAuditChain(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "audit-retirement", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	event := NewEvent("retirement-event", "master_key_retirement.ready", "ready", "api_key", Pseudonym(strings.Repeat("A", 43), "actor", "ops"), Pseudonym(strings.Repeat("A", 43), "target", "epoch:1"), time.UnixMilli(100))
	statement, err := event.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "audit-retirement-event", Statements: []rhiza.SQLStatement{statement}}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	events, _, err := store.List(ctx, nil, 1)
	if err != nil || len(events) != 1 || events[0].Type != "master_key_retirement.ready" || events[0].Action != "ready" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}
