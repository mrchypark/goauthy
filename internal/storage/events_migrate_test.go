package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func eventSchemaDB(t *testing.T) (*rhiza.DB, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "events-v59-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, ctx
}

func TestMigrationV59CreatesIdempotentEventLogAndPreservesRows(t *testing.T) {
	db, ctx := eventSchemaDB(t)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	id := "1234567890123456789012345678901234567890123"
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v59-row", SQL: `INSERT INTO event_log(id,timestamp,level,typ,text) VALUES(?,?,?,?,?)`, Args: []any{id, int64(42), int64(2), "Test", "kept"}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV59(ctx, db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,timestamp,level,typ,text FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != id || row.Rows[0][4] != "kept" {
		t.Fatalf("row=%#v err=%v", row.Rows, err)
	}
}

func TestEventLogV59StrictConstraints(t *testing.T) {
	db, ctx := eventSchemaDB(t)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	validID := "1234567890123456789012345678901234567890123"
	cases := []struct {
		name, id         string
		timestamp, level any
		typ              string
	}{
		{"short id", "short", int64(0), int64(0), "Test"},
		{"negative timestamp", "2234567890123456789012345678901234567890123", int64(-1), int64(0), "Test"},
		{"high level", "3234567890123456789012345678901234567890123", int64(0), int64(4), "Test"},
		{"unknown type", "4234567890123456789012345678901234567890123", int64(0), int64(0), "NoSuchEvent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v59-invalid-" + tc.name, SQL: `INSERT INTO event_log(id,timestamp,level,typ) VALUES(?,?,?,?)`, Args: []any{tc.id, tc.timestamp, tc.level, tc.typ}}); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v59-valid", SQL: `INSERT INTO event_log(id,timestamp,level,typ) VALUES(?,?,?,?)`, Args: []any{validID, int64(0), int64(0), "Test"}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV59FromV58PreservesPriorTables(t *testing.T) {
	db, ctx := eventSchemaDB(t)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v58-base", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(58)`},
		{SQL: `CREATE TABLE legacy_events(value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO legacy_events(value) VALUES('preserve')`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV59(ctx, db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM legacy_events`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "preserve" {
		t.Fatalf("legacy=%#v err=%v", row.Rows, err)
	}
}

func TestMigrationV59RejectsInconsistentTableAndMarker(t *testing.T) {
	for _, tc := range []struct{ name string }{
		{"marker without table"},
		{"table without marker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := eventSchemaDB(t)
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			if tc.name == "marker without table" {
				if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v59-drop", SQL: `DROP TABLE event_log`}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "event-v59-unmark", SQL: `DELETE FROM goauthy_schema_migrations WHERE version=59`}); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV59(ctx, db); err == nil {
				t.Fatal("inconsistent schema accepted")
			}
		})
	}
}
