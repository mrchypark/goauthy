package eventlog_test

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func viSealChain(events []eventlog.Event) []eventlog.Event {
	out := make([]eventlog.Event, len(events))
	copy(out, events)
	var prev string
	for i := range out {
		out[i].Seal(prev)
		prev = out[i].IntegrityHash
	}
	return out
}

func viBuildChain(n int, base time.Time) []eventlog.Event {
	events := make([]eventlog.Event, n)
	for i := range events {
		events[i] = eventlog.Creation(
			"op-"+string(rune('a'+i)),
			"user"+string(rune('a'+i))+"@test.example",
			"127.0.0.1",
			false,
			base.Add(time.Duration(i)*time.Second),
		)
	}
	return events
}

func viInsert(t *testing.T, ctx context.Context, db *rhiza.DB, events []eventlog.Event) {
	t.Helper()
	for i, e := range events {
		stmt, err := e.Statement("1=1")
		if err != nil {
			t.Fatalf("event %d statement: %v", i, err)
		}
		if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID:  "vi-test-" + e.ID,
			Statements: []rhiza.SQLStatement{stmt},
		}); err != nil {
			t.Fatalf("event %d insert: %v", i, err)
		}
	}
}

func viOpenDB(t *testing.T, nodeID string) (context.Context, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: nodeID, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return ctx, db
}

func TestVerifyIntegritySealedChainAccepted(t *testing.T) {
	ctx, db := viOpenDB(t, "vi-sealed")
	store, _ := eventlog.NewStore(db)
	events := viSealChain(viBuildChain(5, time.UnixMilli(1_800_000_000_000)))
	viInsert(t, ctx, db, events)
	ok, err := store.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !ok {
		t.Fatal("rejected valid sealed chain")
	}
}

func TestVerifyIntegrityAlteredFieldRejected(t *testing.T) {
	ctx, db := viOpenDB(t, "vi-altered")
	store, _ := eventlog.NewStore(db)
	events := viSealChain(viBuildChain(3, time.UnixMilli(1_800_000_000_000)))
	viInsert(t, ctx, db, events)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID:  "vi-alter-text",
		Statements: []rhiza.SQLStatement{{SQL: "UPDATE event_log SET text='tampered' WHERE id=?", Args: []any{events[0].ID}}},
	}); err != nil {
		t.Fatal(err)
	}
	ok, err := store.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Fatal("accepted chain with altered field")
	}
}

func TestVerifyIntegrityBrokenLinkRejected(t *testing.T) {
	ctx, db := viOpenDB(t, "vi-broken")
	store, _ := eventlog.NewStore(db)
	events := viSealChain(viBuildChain(3, time.UnixMilli(1_800_000_000_000)))
	viInsert(t, ctx, db, events)
	// Reseal middle event with a wrong predecessor so prev_hash and
	// integrity_hash are both internally consistent for that row, but
	// the link between first and second event is broken.
	wrong := events[1]
	wrong.Seal("definitely-not-the-first-hash")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "vi-broken-link",
		Statements: []rhiza.SQLStatement{{
			SQL:  "UPDATE event_log SET prev_hash=?, integrity_hash=? WHERE id=?",
			Args: []any{wrong.PrevHash, wrong.IntegrityHash, wrong.ID},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	ok, err := store.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Fatal("accepted chain with broken link")
	}
}

func TestVerifyIntegrityQueryOrderUsesSequence(t *testing.T) {
	ctx, db := viOpenDB(t, "vi-order")
	store, _ := eventlog.NewStore(db)
	// Build events with deliberately non-monotonic timestamps so
	// chronological order differs from insertion order.
	e1 := eventlog.Creation("op-first", "a@test.example", "127.0.0.1", false, time.UnixMilli(1_800_000_003_000))
	e2 := eventlog.Creation("op-second", "b@test.example", "127.0.0.1", false, time.UnixMilli(1_800_000_001_000))
	e3 := eventlog.Creation("op-third", "c@test.example", "127.0.0.1", false, time.UnixMilli(1_800_000_002_000))
	// Insert in insertion order e1,e2,e3 which differs from timestamp order.
	// Seal in the same order so the chain follows insertion/sequence order.
	preSealed := []eventlog.Event{e1, e2, e3}
	sealed := viSealChain(preSealed)
	viInsert(t, ctx, db, sealed)
	// VerifyIntegrity walks via event_log_order.sequence (insertion order)
	// and should succeed because prev_hash links match insertion order.
	ok, err := store.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !ok {
		t.Fatal("rejected chain whose timestamps are non-monotonic but sequence is valid")
	}
}

func TestVerifyIntegrityUnsealedRowRejected(t *testing.T) {
	ctx, db := viOpenDB(t, "vi-unsealed")
	store, _ := eventlog.NewStore(db)
	raw := eventlog.Creation("unsealed-op", "u@test.example", "127.0.0.1", false, time.UnixMilli(1_800_000_000_000))
	viInsert(t, ctx, db, []eventlog.Event{raw})
	ok, err := store.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Fatal("should not report unsealed row as verified")
	}
}
