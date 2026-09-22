package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func eventSequenceInsert(t *testing.T, db *rhiza.DB, requestID, id string, timestamp int64) {
	t.Helper()
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO event_log(id,timestamp,level,typ) VALUES(?,?,0,'Test')`, Args: []any{id, timestamp}}); err != nil {
		t.Fatal(err)
	}
}

func TestEventLogSequenceBackfillMonotonicAndRetention(t *testing.T) {
	t.Parallel()
	db, ctx := eventSchemaDB(t)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-seq-v59-state", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(59)`},
		{SQL: `CREATE TABLE event_log(id TEXT PRIMARY KEY NOT NULL,timestamp INTEGER NOT NULL,level INTEGER NOT NULL,typ TEXT NOT NULL) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	eventSequenceInsert(t, db, "event-seq-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 20)
	eventSequenceInsert(t, db, "event-seq-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 10)
	if err := migrateSchemaV60(ctx, db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence,event_id FROM event_log_order ORDER BY sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 || rows.Rows[0][1] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || rows.Rows[1][1] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("backfill/order=%#v err=%v", rows.Rows, err)
	}
	last := rows.Rows[1][0].(int64)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-seq-delete", SQL: `DELETE FROM event_log`}); err != nil {
		t.Fatal(err)
	}
	eventSequenceInsert(t, db, "event-seq-c", "ccccccccccccccccccccccccccccccccccccccccccc", 0)
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence FROM event_log_order WHERE event_id='ccccccccccccccccccccccccccccccccccccccccccc'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0].(int64) <= last {
		t.Fatalf("sequence did not retain highwater=%#v last=%d err=%v", row.Rows, last, err)
	}
}

func TestEventLogSequenceDuplicateDoesNotAppendOrder(t *testing.T) {
	t.Parallel()
	db, ctx := eventSchemaDB(t)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	id := "ddddddddddddddddddddddddddddddddddddddddddd"
	eventSequenceInsert(t, db, "event-seq-d", id, 1)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-seq-duplicate", SQL: `INSERT INTO event_log(id,timestamp,level,typ) VALUES(?,?,0,'Test')`, Args: []any{id, 2}}); err == nil {
		t.Fatal("duplicate event accepted")
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log_order WHERE event_id=?`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
		t.Fatalf("order rows=%#v err=%v", row.Rows, err)
	}
}

func TestMigrationV60RejectsPartialTriggerState(t *testing.T) {
	t.Parallel()
	db, ctx := eventSchemaDB(t)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v60-drop-trigger", SQL: `DROP TRIGGER event_log_order_insert`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV60(ctx, db); err == nil {
		t.Fatal("partial trigger state accepted")
	}
}

func TestEventLogSequencePersistsAcrossReopenAndMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "events-v60-reopen", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	eventSequenceInsert(t, db, "event-reopen-a", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 1)
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence FROM event_log_order WHERE event_id='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("first sequence=%#v err=%v", row.Rows, err)
	}
	first := row.Rows[0][0].(int64)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-reopen-delete", SQL: `DELETE FROM event_log`}); err != nil {
		t.Fatal(err)
	}
	eventSequenceInsert(t, db, "event-reopen-b", "fffffffffffffffffffffffffffffffffffffffffff", 0)
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence FROM event_log_order WHERE event_id='fffffffffffffffffffffffffffffffffffffffffff'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0].(int64) <= first {
		t.Fatalf("highwater sequence=%#v first=%d err=%v", row.Rows, first, err)
	}
	second := row.Rows[0][0].(int64)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = rhiza.Open(ctx, rhiza.Config{NodeID: "events-v60-reopen", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	eventSequenceInsert(t, db, "event-reopen-c", "ggggggggggggggggggggggggggggggggggggggggggg", 0)
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence FROM event_log_order WHERE event_id='ggggggggggggggggggggggggggggggggggggggggggg'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0].(int64) <= second {
		t.Fatalf("reopened sequence=%#v second=%d err=%v", row.Rows, second, err)
	}
}
