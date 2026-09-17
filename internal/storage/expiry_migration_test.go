package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV58ExpiryDefaultsRoundTripAndIdempotence(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "expiry-v58", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Seed a real pre-column row so a new-table default cannot mask broken
	// migration of existing identities.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "expiry-v58-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES (57)`},
		{SQL: `CREATE TABLE identity_users (subject TEXT PRIMARY KEY,username TEXT,password_phc TEXT) STRICT`},
		{SQL: `INSERT INTO identity_users VALUES ('legacy','legacy','')`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV58(ctx, db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT user_expires_at_unix_ms FROM identity_users WHERE subject='legacy'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil {
		t.Fatalf("legacy expiry=%v err=%v", row.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "expiry-v58-set", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='legacy'`, Args: []any{int64(1700000000123)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "expiry-v58-negative", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=-1 WHERE subject='legacy'`}); err == nil {
		t.Fatal("negative expiry accepted")
	}
	if err := migrateSchemaV58(ctx, db); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT user_expires_at_unix_ms FROM identity_users WHERE subject='legacy'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1700000000123) {
		t.Fatalf("expiry not preserved after rejection/replay: rows=%v err=%v", row.Rows, err)
	}
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=58`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || marker.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
}

func TestMigrationV58RejectsPartialMarkedAndUnmarkedExistingColumn(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, setup string }{
		{"marked-missing-column", `ALTER TABLE identity_users DROP COLUMN user_expires_at_unix_ms`},
		{"unmarked-existing-column", `DELETE FROM goauthy_schema_migrations WHERE version=58`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "expiry-v58-" + tc.name, DataDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "expiry-v58-partial-" + tc.name, SQL: tc.setup}); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV58(ctx, db); err == nil {
				t.Fatal("partial schema accepted")
			}
		})
	}
}
