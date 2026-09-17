package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV80DPOPMetadataMigration(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "dpop-metadata-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	defaultValue, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultValue.Rows) != 0 {
		t.Fatalf("unexpected rows in fresh dynamic client table: %v", defaultValue.Rows)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dpop-metadata-default", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"default-dpop-client", nil, "registration", "[]", "[]", "[]", "[]", "[]", "none", "DPOP", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	defaultValue, err = db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients WHERE client_id='default-dpop-client'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(defaultValue.Rows) != 1 || defaultValue.Rows[0][0] != int64(0) {
		t.Fatalf("default dpop metadata=%v err=%v", defaultValue.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dpop-metadata-valid", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,dpop_bound_access_tokens) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"dpop-client", nil, "registration-1", "[]", "[]", "[]", "[]", "[]", "none", "DPOP", int64(1), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients WHERE client_id='dpop-client'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
		t.Fatalf("replay changed true metadata: rows=%v err=%v", row.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dpop-metadata-invalid", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,dpop_bound_access_tokens) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"invalid-dpop-client", nil, "registration-2", "[]", "[]", "[]", "[]", "[]", "none", "DPOP", int64(1), int64(2)}}); err == nil {
		t.Fatal("accepted dpop_bound_access_tokens=2")
	}

	t.Run("legacy rows", func(t *testing.T) {
		legacy, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "dpop-metadata-legacy", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = legacy.Close() })
		if _, err := Execute(t.Context(), legacy, rhiza.ExecuteRequest{RequestID: "dpop-metadata-legacy-schema", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(79)`},
			{SQL: `CREATE TABLE dynamic_oauth_clients(client_id TEXT PRIMARY KEY NOT NULL, secret_hash TEXT, registration_token_digest TEXT NOT NULL UNIQUE, redirect_uris_json TEXT NOT NULL, scopes_json TEXT NOT NULL, grant_types_json TEXT NOT NULL, response_types_json TEXT NOT NULL, audiences_json TEXT NOT NULL, token_endpoint_auth_method TEXT NOT NULL, name TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL) STRICT`},
			{SQL: `INSERT INTO dynamic_oauth_clients VALUES('legacy-client',NULL,'legacy-registration','[]','[]','[]','[]','[]','none','legacy',1)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV80(t.Context(), legacy); err != nil {
			t.Fatal(err)
		}
		row, err := legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients WHERE client_id='legacy-client'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(0) {
			t.Fatalf("legacy default metadata=%v err=%v", row.Rows, err)
		}
		if _, err := Execute(t.Context(), legacy, rhiza.ExecuteRequest{RequestID: "dpop-metadata-legacy-enable", SQL: `UPDATE dynamic_oauth_clients SET dpop_bound_access_tokens=1 WHERE client_id='legacy-client'`}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV80(t.Context(), legacy); err != nil {
			t.Fatal(err)
		}
		row, err = legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT dpop_bound_access_tokens FROM dynamic_oauth_clients WHERE client_id='legacy-client'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
			t.Fatalf("legacy replay metadata=%v err=%v", row.Rows, err)
		}
		// This sparse fixture tests only v80, not the current full schema.
		marker, err := legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT MAX(version) FROM goauthy_schema_migrations`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(80) {
			t.Fatalf("v80 migration marker=%v err=%v", marker.Rows, err)
		}
		if schemaVersion > 80 && Ready(t.Context(), legacy) == nil {
			t.Fatal("legacy-only schema unexpectedly ready for current application")
		}
	})

	t.Run("missing table does not mark", func(t *testing.T) {
		missing, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "dpop-metadata-missing", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = missing.Close() })
		if _, err := Execute(t.Context(), missing, rhiza.ExecuteRequest{RequestID: "dpop-metadata-missing-schema", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(79)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV80(t.Context(), missing); err == nil {
			t.Fatal("migration succeeded without dynamic_oauth_clients")
		}
		marker, err := missing.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=80`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(0) {
			t.Fatalf("schema 80 marker=%v err=%v", marker.Rows, err)
		}
	})
}
