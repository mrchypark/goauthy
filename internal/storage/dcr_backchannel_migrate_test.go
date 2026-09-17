package storage

import (
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV87PreservesDynamicRegistration(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dcr-backchannel-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v87-dcr-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(86)`},
		{SQL: `CREATE TABLE dynamic_oauth_clients(
			client_id TEXT PRIMARY KEY NOT NULL,
			secret_hash TEXT,
			registration_token_digest TEXT NOT NULL UNIQUE,
			redirect_uris_json TEXT NOT NULL,
			scopes_json TEXT NOT NULL,
			default_scopes_json TEXT NOT NULL,
			grant_types_json TEXT NOT NULL,
			response_types_json TEXT NOT NULL,
			audiences_json TEXT NOT NULL,
			token_endpoint_auth_method TEXT NOT NULL,
			name TEXT NOT NULL,
			force_mfa INTEGER NOT NULL DEFAULT 0,
			anonymous INTEGER NOT NULL DEFAULT 0,
			created_at_unix_ms INTEGER NOT NULL,
			last_used_at_unix_ms INTEGER,
			client_uri TEXT,
			contacts_json TEXT,
			logo_uri TEXT,
			tos_uri TEXT,
			policy_uri TEXT,
			software_statement TEXT,
			dpop_bound_access_tokens INTEGER NOT NULL DEFAULT 0
		) STRICT`},
		{SQL: `INSERT INTO dynamic_oauth_clients(
			client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,
			default_scopes_json,grant_types_json,response_types_json,audiences_json,
			token_endpoint_auth_method,name,force_mfa,anonymous,created_at_unix_ms,
			last_used_at_unix_ms,client_uri,contacts_json,logo_uri,tos_uri,policy_uri,
			software_statement,dpop_bound_access_tokens
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{
			"dynamic-client", "secret-hash", "registration-token", `["https://rp.example.test/callback"]`, `["openid","profile"]`,
			`["openid"]`, `["authorization_code"]`, `["code"]`, `["https://api.example.test"]`,
			"client_secret_basic", "Existing Dynamic RP", int64(1), int64(0), int64(1234),
			int64(5678), "https://rp.example.test", `["mailto:rp@example.test"]`, "https://rp.example.test/logo.svg",
			"https://rp.example.test/terms", "https://rp.example.test/policy", "signed-statement", int64(1),
		}},
	}}); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := migrateSchemaV87(ctx, db); err != nil {
			t.Fatal(err)
		}
	}

	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,default_scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,force_mfa,anonymous,created_at_unix_ms,last_used_at_unix_ms,client_uri,contacts_json,logo_uri,tos_uri,policy_uri,software_statement,dpop_bound_access_tokens,backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='dynamic-client'`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		"dynamic-client", "secret-hash", "registration-token", `["https://rp.example.test/callback"]`, `["openid","profile"]`,
		`["openid"]`, `["authorization_code"]`, `["code"]`, `["https://api.example.test"]`,
		"client_secret_basic", "Existing Dynamic RP", int64(1), int64(0), int64(1234), int64(5678),
		"https://rp.example.test", `["mailto:rp@example.test"]`, "https://rp.example.test/logo.svg", "https://rp.example.test/terms",
		"https://rp.example.test/policy", "signed-statement", int64(1), nil,
	}
	if len(row.Rows) != 1 || !reflect.DeepEqual(row.Rows[0], want) {
		t.Fatalf("dynamic registration after v87=%#v, want=%#v", row.Rows, want)
	}

	marker, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=87`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("v87 migration marker=%#v err=%v", marker.Rows, err)
	}
}
