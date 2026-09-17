package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV87BackchannelLogoutURIMigration(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "backchannel-migration", DataDir: t.TempDir()})
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
	defaultValue, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultValue.Rows) != 0 {
		t.Fatalf("unexpected rows in fresh dynamic client table: %v", defaultValue.Rows)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "backchannel-default", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"default-bcl-client", nil, "registration-bcl", "[]", "[]", "[]", "[]", "[]", "none", "BCL", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	defaultValue, err = db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='default-bcl-client'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(defaultValue.Rows) != 1 || defaultValue.Rows[0][0] != nil {
		t.Fatalf("default backchannel metadata=%v err=%v", defaultValue.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "backchannel-valid", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,backchannel_logout_uri) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"bcl-client", nil, "registration-bcl-1", "[]", "[]", "[]", "[]", "[]", "none", "BCL", int64(1), "https://rp.example.test/logout"}}); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='bcl-client'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "https://rp.example.test/logout" {
		t.Fatalf("replay changed valid metadata: rows=%v err=%v", row.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "backchannel-empty", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,backchannel_logout_uri) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"invalid-bcl-client", nil, "registration-bcl-2", "[]", "[]", "[]", "[]", "[]", "none", "BCL", int64(1), ""}}); err == nil {
		t.Fatal("accepted empty backchannel_logout_uri")
	}

	t.Run("legacy rows", func(t *testing.T) {
		legacy, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "backchannel-legacy", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = legacy.Close() })
		if _, err := Execute(t.Context(), legacy, rhiza.ExecuteRequest{RequestID: "backchannel-legacy-schema", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(86)`},
			{SQL: `CREATE TABLE dynamic_oauth_clients(client_id TEXT PRIMARY KEY NOT NULL, secret_hash TEXT, registration_token_digest TEXT NOT NULL UNIQUE, redirect_uris_json TEXT NOT NULL, scopes_json TEXT NOT NULL, grant_types_json TEXT NOT NULL, response_types_json TEXT NOT NULL, audiences_json TEXT NOT NULL, token_endpoint_auth_method TEXT NOT NULL, name TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL, dpop_bound_access_tokens INTEGER NOT NULL DEFAULT 0) STRICT`},
			{SQL: `INSERT INTO dynamic_oauth_clients VALUES('legacy-client',NULL,'legacy-registration','[]','[]','[]','[]','[]','none','legacy',1,0)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV87(t.Context(), legacy); err != nil {
			t.Fatal(err)
		}
		row, err := legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='legacy-client'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil {
			t.Fatalf("legacy default metadata=%v err=%v", row.Rows, err)
		}
		if _, err := Execute(t.Context(), legacy, rhiza.ExecuteRequest{RequestID: "backchannel-legacy-enable", SQL: `UPDATE dynamic_oauth_clients SET backchannel_logout_uri='https://rp.example.test/logout' WHERE client_id='legacy-client'`}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV87(t.Context(), legacy); err != nil {
			t.Fatal(err)
		}
		row, err = legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='legacy-client'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "https://rp.example.test/logout" {
			t.Fatalf("legacy replay metadata=%v err=%v", row.Rows, err)
		}
		marker, err := legacy.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT MAX(version) FROM goauthy_schema_migrations`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(87) {
			t.Fatalf("v87 migration marker=%v err=%v", marker.Rows, err)
		}
		if schemaVersion > 87 && Ready(t.Context(), legacy) == nil {
			t.Fatal("legacy-only schema unexpectedly ready for current application")
		}
	})

	t.Run("missing table does not mark", func(t *testing.T) {
		missing, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "backchannel-missing", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = missing.Close() })
		if _, err := Execute(t.Context(), missing, rhiza.ExecuteRequest{RequestID: "backchannel-missing-schema", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(86)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV87(t.Context(), missing); err == nil {
			t.Fatal("migration succeeded without dynamic_oauth_clients")
		}
		marker, err := missing.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=87`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(0) {
			t.Fatalf("schema 87 marker=%v err=%v", marker.Rows, err)
		}
	})
}
