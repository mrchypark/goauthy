package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV83UpstreamSessionBindings(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "upstream-session-v83-fresh", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=83`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
			t.Fatalf("marker=%v err=%v", marker.Rows, err)
		}
		indexes, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name IN ('browser_upstream_session_bindings_subject','browser_upstream_session_bindings_sid') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(indexes.Rows) != 2 {
			t.Fatalf("indexes=%v err=%v", indexes.Rows, err)
		}
	})

	t.Run("rerun preserves binding", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "upstream-session-v83-replay", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "upstream-session-v83-base", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(82)`},
			{SQL: `CREATE TABLE browser_sessions(token_digest TEXT PRIMARY KEY NOT NULL) STRICT`},
			{SQL: `CREATE TABLE v82_preserved(value TEXT NOT NULL) STRICT`},
			{SQL: `INSERT INTO v82_preserved(value) VALUES('keep')`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV83(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "upstream-session-v83-row", SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{"digest", "https://issuer.example.test", "client-1", "upstream-user", "sid", int64(1)}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV83(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms FROM browser_upstream_session_bindings`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 6 || rows.Rows[0][0] != "digest" {
			t.Fatalf("binding rows=%v err=%v", rows.Rows, err)
		}
		preserved, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT value FROM v82_preserved`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(preserved.Rows) != 1 || preserved.Rows[0][0] != "keep" {
			t.Fatalf("preserved=%v err=%v", preserved.Rows, err)
		}
	})
}
