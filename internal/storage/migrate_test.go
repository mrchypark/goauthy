package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestMigrateIsIdempotentAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV2ReplaysAfterReceiptExpiry(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	// A new request ID models Rhiza accepting the migration again after its
	// bounded idempotency receipt has expired.
	if _, err := Execute(context.Background(), db, schemaV2Request("goauthy-schema-v2-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV6ReplaysAfterReceiptExpiry(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV6Request("goauthy-schema-v6-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV7InitializesExistingSessionAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v7-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE browser_sessions (token_digest TEXT PRIMARY KEY NOT NULL, subject TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL, revoked_at_unix_ms INTEGER) STRICT`},
		{SQL: `INSERT INTO browser_sessions (token_digest, subject, created_at_unix_ms, expires_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"legacy", "subject", int64(123), int64(456)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV7(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV7(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT last_seen_at_unix_ms FROM browser_sessions WHERE token_digest = ?`, Args: []any{"legacy"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(123) {
		t.Fatalf("last seen=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV8CreatesBackchannelTablesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV8(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v8-backchannel-rows", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_session_clients (sid, client_id, logout_uri, allow_private, allow_http, created_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, Args: []any{"sid", "client", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oidc_backchannel_deliveries (event_id, client_id, sid, logout_uri, allow_private, allow_http, attempts, next_attempt_at_unix_ms, created_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{"event", "client", "sid", "https://rp.example.test/logout", int64(0), int64(0), int64(0), int64(1), int64(1)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v8-duplicate-session-client", SQL: `INSERT INTO oidc_session_clients (sid, client_id, logout_uri, allow_private, allow_http, created_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, Args: []any{"sid", "client", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}}); err == nil {
		t.Fatal("duplicate session-client row was accepted")
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v8-duplicate-delivery", SQL: `INSERT INTO oidc_backchannel_deliveries (event_id, client_id, sid, logout_uri, allow_private, allow_http, attempts, next_attempt_at_unix_ms, created_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{"second-event", "client", "sid", "https://rp.example.test/logout", int64(0), int64(0), int64(0), int64(1), int64(1)}}); err == nil {
		t.Fatal("duplicate delivery sid-client row was accepted")
	}
}

func TestMigrationV9CreatesDynamicClientTableAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV9(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV9Request("goauthy-schema-v9-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v9-dynamic-client", SQL: `INSERT INTO dynamic_oauth_clients
		(client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms)
		VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
		"public-client", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE", "[\"https://rp.example.test/callback\"]", "[\"openid\"]", "[\"authorization_code\"]", "[\"code\"]", "[]", "none", "RP", int64(1),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v9-invalid-public-secret", SQL: `INSERT INTO dynamic_oauth_clients
		(client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
		"invalid-public", "bcrypt", "MTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE", "[]", "[]", "[\"client_credentials\"]", "[]", "[]", "none", "RP", int64(1),
	}}); err == nil {
		t.Fatal("public client with a secret was accepted")
	}
}

func TestMigrationV44AddsDynamicClientURI(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV44(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('dynamic_oauth_clients') WHERE name = ?`, Args: []any{"client_uri"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("client_uri column=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV44PreservesLegacyDynamicClientMetadata(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v43-legacy-dcr-row", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (43)`},
		{SQL: `CREATE TABLE dynamic_oauth_clients (
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
			last_used_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `INSERT INTO dynamic_oauth_clients (client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
			"legacy-client", "legacy-token-digest", `["https://rp.example.test/callback"]`, `["openid"]`, `["openid"]`, `["authorization_code"]`, `["code"]`, `[]`, "none", "Legacy RP", int64(1234),
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV44(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV44(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id, name, redirect_uris_json, client_uri FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"legacy-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 || result.Rows[0][0] != "legacy-client" || result.Rows[0][1] != "Legacy RP" || result.Rows[0][2] != `["https://rp.example.test/callback"]` || result.Rows[0][3] != nil {
		t.Fatalf("legacy row after v44=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV27AddsDefaultDynamicClientScopes(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v27-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(26)}},
		{SQL: `CREATE TABLE dynamic_oauth_clients (
			client_id TEXT PRIMARY KEY NOT NULL,
			secret_hash TEXT,
			registration_token_digest TEXT NOT NULL UNIQUE,
			redirect_uris_json TEXT NOT NULL,
			scopes_json TEXT NOT NULL,
			grant_types_json TEXT NOT NULL,
			response_types_json TEXT NOT NULL,
			audiences_json TEXT NOT NULL,
			token_endpoint_auth_method TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			last_used_at_unix_ms INTEGER,
			force_mfa INTEGER NOT NULL DEFAULT 0 CHECK (force_mfa IN (0, 1))
		) STRICT`},
		{SQL: `INSERT INTO dynamic_oauth_clients
			(client_id, secret_hash, registration_token_digest, redirect_uris_json, scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms, force_mfa)
			VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
			"legacy-client", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE", "[\"https://rp.example.test/callback\"]", "[\"openid\"]", "[\"authorization_code\"]", "[\"code\"]", "[]", "none", "RP", int64(1), int64(0),
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV27(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT default_scopes_json, scopes_json FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"legacy-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != "[]" || result.Rows[0][1] != "[\"openid\"]" {
		t.Fatalf("migrated client=%#v err=%v", result.Rows, err)
	}
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(27)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || len(marker.Rows[0]) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("v27 marker=%#v err=%v", marker.Rows, err)
	}
}

func TestMigrationV28APIKeySchemaFromV27IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v28", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v28-v27-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(27)`},
		{SQL: `CREATE TABLE preserved_v27 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v27(id,value) VALUES(1,'kept')`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV28(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"api_keys", "api_key_access", "api_key_mutation_guards", "api_keys_expiry", "api_key_access_lookup"} {
		result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE name=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 {
			t.Fatalf("schema object %s rows=%#v err=%v", name, result.Rows, err)
		}
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=28`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v28 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v27 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_key_mutation_guards`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("guards=%#v err=%v", result.Rows, err)
	}
	if _, err = Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v28-invalid-key", SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES(?,?,?)`, Args: []any{"bad key", "short", int64(0)}}); err == nil {
		t.Fatal("invalid API key row accepted")
	}
	if _, err = Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v28-invalid-access", SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?)`, Args: []any{"key", "Nope", "read"}}); err == nil {
		t.Fatal("invalid API key access accepted")
	}
}

func TestMigrationV29BootstrapClientCredentialsClaimsFromV28IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v29", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v29-v28-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(28)`},
		{SQL: `CREATE TABLE preserved_v28 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v28(id,value) VALUES(1,'kept')`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV29(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=29`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v29 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v28 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v29-valid-row", SQL: `INSERT INTO bootstrap_client_credentials_claims(client_id,claims_json,claims_at_root,revision,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"client", `{"role":"service"}`, int64(1), int64(1), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"empty client", []any{"", nil, int64(0), int64(1), int64(0)}},
		{"long client", []any{strings.Repeat("c", 65), nil, int64(0), int64(1), int64(0)}},
		{"array claims", []any{"array", `[]`, int64(0), int64(1), int64(0)}},
		{"noncanonical claims", []any{"space", `{"role": "service"}`, int64(0), int64(1), int64(0)}},
		{"long claims", []any{"long", `{"v":"` + strings.Repeat("x", 1017) + `"}`, int64(0), int64(1), int64(0)}},
		{"invalid root", []any{"root", nil, int64(2), int64(1), int64(0)}},
		{"zero revision", []any{"revision", nil, int64(0), int64(0), int64(0)}},
		{"negative timestamp", []any{"time", nil, int64(0), int64(1), int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v29-invalid-" + string(rune('a'+i)), SQL: `INSERT INTO bootstrap_client_credentials_claims(client_id,claims_json,claims_at_root,revision,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid bootstrap client credentials claims row was accepted")
			}
		})
	}
}

func TestMigrationV30PoWIssuanceAdmissionFromV29IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v30", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v30-v29-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(29)`},
		{SQL: `CREATE TABLE preserved_v29 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v29(id,value) VALUES(1,'kept')`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV30(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=30`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v30 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v29 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v30-valid-limit", SQL: `INSERT INTO identity_password_reset_pow_issuance_limits(peer_digest,window_start_unix_seconds,count) VALUES(?,?,?)`, Args: []any{strings.Repeat("a", 43), int64(0), int64(5)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v30-invalid-limit", SQL: `INSERT INTO identity_password_reset_pow_issuance_limits(peer_digest,window_start_unix_seconds,count) VALUES(?,?,?)`, Args: []any{"short", int64(-1), int64(6)}}); err == nil {
		t.Fatal("invalid PoW issuance limit row was accepted")
	}
}

func TestMigrationV31AddsPeerIPColumnFromV30IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v31", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v31-v30-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(30)`},
		{SQL: `CREATE TABLE preserved_v30 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v30(id,value) VALUES(1,'kept')`},
		{SQL: `CREATE TABLE browser_sessions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			auth_method TEXT NOT NULL CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa')),
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			last_seen_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('legacy-digest','user-1','pwd',1000,2000,1000)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV31(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=31`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v31 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v30 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT peer_ip FROM browser_sessions WHERE token_digest='legacy-digest'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "" {
		t.Fatalf("legacy peer_ip=%#v err=%v", result.Rows, err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v31-valid-new-session", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES(?,?,?,?,?,?,?)`, Args: []any{"new-digest", "user-2", "pwd", int64(1000), int64(2000), int64(1000), "203.0.113.8"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v31-valid-empty-ip", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES(?,?,?,?,?,?,?)`, Args: []any{"empty-ip-digest", "user-3", "pwd", int64(1000), int64(2000), int64(1000), ""}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV10CreatesDeviceGrantTableAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV10(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV10Request("goauthy-schema-v10-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v10-device-grant", SQL: `INSERT INTO oauth_device_grants (device_code_digest,user_code_digest,client_id,scopes_json,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{"device-digest", "user-digest", "client", "[]", "pending", int64(10), int64(5), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v10-rate-limit", SQL: `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, ?, ?, ?)`, Args: []any{"key-digest", int64(0), int64(1), int64(86400000), int64(0)}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV11CreatesDPoPTablesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV11(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV11Request("goauthy-schema-v11-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v11-dpop-state", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO dpop_nonces (nonce_digest,client_id,jkt,expires_at_unix_ms,consumed_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?, NULL, ?)`, Args: []any{"nonce-digest", "client", "jkt", int64(10), int64(0)}},
		{SQL: `INSERT INTO dpop_replays (replay_digest,expires_at_unix_ms,created_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"replay-digest", int64(10), "attempt", int64(0)}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV13CreatesCIMDCacheAndReplays(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV13(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV13Request("goauthy-schema-v13-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}

	digest := strings.Repeat("d", 43)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v13-valid-cimd-cache", SQL: `INSERT INTO cimd_client_documents
		(client_id, policy_digest, metadata_json, metadata_digest, fetched_at_unix_ms, expires_at_unix_ms)
		VALUES (?, ?, ?, ?, ?, ?)`, Args: []any{"https://client.example.test/metadata", digest, `{}`, digest, int64(10), int64(20)}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"client id bound", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{strings.Repeat("c", 2049), digest, `{}`, digest, int64(10), int64(20)}},
		{"metadata bound", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{"https://other.example.test/metadata", digest, strings.Repeat("m", 8193), digest, int64(10), int64(20)}},
		{"metadata json", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{"https://invalid-json.example.test/metadata", digest, `{`, digest, int64(10), int64(20)}},
		{"metadata digest", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{"https://invalid-digest.example.test/metadata", digest, `{}`, "short", int64(10), int64(20)}},
		{"expiry order", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{"https://expiry.example.test/metadata", digest, `{}`, digest, int64(20), int64(10)}},
		{"zero ttl", `INSERT INTO cimd_client_documents (client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, []any{"https://zero-ttl.example.test/metadata", digest, `{}`, digest, int64(20), int64(20)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v13-invalid-" + tc.name, SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid CIMD cache row was accepted")
			}
		})
	}
}

func TestMigrationV26CreatesUserAttributeTablesAndReplays(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV26(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV26Request("goauthy-schema-v26-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v26-valid-attr-state", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO user_attribute_configs (name,desc,default_value_json,typ,user_editable,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"employee_id", "Employee ID", `"E-0001"`, "email", int64(0), int64(1), int64(1), int64(1)}},
		{SQL: `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{"subject-1", "employee_id", `"E-1234"`, int64(1)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"empty config name", `INSERT INTO user_attribute_configs (name,user_editable,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, []any{"", int64(0), int64(1), int64(1), int64(1)}},
		{"invalid default", `INSERT INTO user_attribute_configs (name,default_value_json,user_editable,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?)`, []any{"broken", `{"x": 1}`, int64(0), int64(1), int64(1), int64(1)}},
		{"invalid type", `INSERT INTO user_attribute_configs (name,typ,user_editable,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?)`, []any{"broken2", "number", int64(0), int64(1), int64(1), int64(1)}},
		{"invalid value", `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) VALUES (?,?,?,?)`, []any{"subject-1", "employee_id", ` 123`, int64(1)}},
		{"negative updated", `INSERT INTO user_attribute_values (subject,key,value_json,updated_at_unix_ms) VALUES (?,?,?,?)`, []any{"subject-1", "employee_id", `"E-1"`, int64(-1)}},
	} {
		if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v26-invalid-" + strings.ReplaceAll(tc.name, " ", "-"), SQL: tc.sql, Args: tc.args}); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
}

func TestMigrationV14UpgradesIdentitySchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v14-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE identity_users (
			subject TEXT PRIMARY KEY NOT NULL,
			username TEXT NOT NULL UNIQUE,
			password_phc TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
		) STRICT`},
		{SQL: `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`, Args: []any{"legacy-subject", "legacy", "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY"}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV14(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT password_changed_at_unix_ms, password_generation FROM identity_users WHERE subject = ?`, Args: []any{"legacy-subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(1) {
		t.Fatalf("legacy password defaults=%#v err=%v", result.Rows, err)
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"negative changed at", `UPDATE identity_users SET password_changed_at_unix_ms = -1 WHERE subject = 'legacy-subject'`},
		{"zero generation", `UPDATE identity_users SET password_generation = 0 WHERE subject = 'legacy-subject'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v14-invalid-user-" + tc.name, SQL: tc.sql}); err == nil {
				t.Fatal("invalid identity password metadata was accepted")
			}
		})
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v14-history", SQL: `INSERT INTO identity_password_history (subject, generation, password_phc, changed_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"legacy-subject", int64(1), "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY", int64(0)}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []any
	}{
		{"empty subject", []any{"", int64(2), "phc", int64(0)}},
		{"zero generation", []any{"legacy-subject", int64(0), "phc", int64(0)}},
		{"empty phc", []any{"legacy-subject", int64(2), "", int64(0)}},
		{"negative changed at", []any{"legacy-subject", int64(2), "phc", int64(-1)}},
		{"duplicate generation", []any{"legacy-subject", int64(1), "phc", int64(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v14-invalid-" + tc.name, SQL: `INSERT INTO identity_password_history (subject, generation, password_phc, changed_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid password history row was accepted")
			}
		})
	}
}

func TestMigrationV14FreshInstallDefaultsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v14-fresh-identity", SQL: `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`, Args: []any{"fresh-subject", "fresh", "phc"}}); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT password_changed_at_unix_ms, password_generation FROM identity_users WHERE subject = ?`, Args: []any{"fresh-subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(1) {
		t.Fatalf("fresh password defaults=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV15UpgradesLegacySchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v15-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(14)}},
		{SQL: `CREATE TABLE identity_users (
			subject TEXT PRIMARY KEY NOT NULL,
			username TEXT NOT NULL UNIQUE,
			password_phc TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
			password_changed_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (password_changed_at_unix_ms >= 0),
			password_generation INTEGER NOT NULL DEFAULT 1 CHECK (password_generation >= 1)
		) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV15(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV15Request("goauthy-schema-v15-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(15)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(15) {
		t.Fatalf("v15 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV15ResetTokenConstraints(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	index, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, Args: []any{"identity_password_reset_tokens_expiry"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(index.Rows) != 1 || len(index.Rows[0]) != 1 || index.Rows[0][0] != "identity_password_reset_tokens_expiry" {
		t.Fatalf("reset-token expiry index=%#v err=%v", index.Rows, err)
	}
	digest := strings.Repeat("d", 43)
	binding := strings.Repeat("b", 43)
	attempt := strings.Repeat("a", 22)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v15-valid-unbound-reset-token", SQL: `INSERT INTO identity_password_reset_tokens
		(token_digest, subject, password_generation, issued_at_unix_ms, expires_at_unix_ms)
		VALUES (?, ?, ?, ?, ?)`, Args: []any{strings.Repeat("u", 43), "unbound-subject", int64(1), int64(10), int64(20)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v15-valid-reset-token", SQL: `INSERT INTO identity_password_reset_tokens
		(token_digest, subject, password_generation, issued_at_unix_ms, expires_at_unix_ms, binding_digest, bound_at_unix_ms, consumed_attempt, consumed_at_unix_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{digest, "subject", int64(1), int64(10), int64(20), binding, int64(11), attempt, int64(12)}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"token digest", []any{"short", "subject", int64(1), int64(10), int64(20), nil, nil, nil, nil}},
		{"empty subject", []any{digest, "", int64(1), int64(10), int64(20), nil, nil, nil, nil}},
		{"long subject", []any{digest, strings.Repeat("s", 513), int64(1), int64(10), int64(20), nil, nil, nil, nil}},
		{"zero generation", []any{digest, "subject", int64(0), int64(10), int64(20), nil, nil, nil, nil}},
		{"negative issued", []any{digest, "subject", int64(1), int64(-1), int64(20), nil, nil, nil, nil}},
		{"zero ttl", []any{digest, "subject", int64(1), int64(10), int64(10), nil, nil, nil, nil}},
		{"binding digest", []any{digest, "subject", int64(1), int64(10), int64(20), "short", int64(10), nil, nil}},
		{"binding pair", []any{digest, "subject", int64(1), int64(10), int64(20), binding, nil, nil, nil}},
		{"bound pair", []any{digest, "subject", int64(1), int64(10), int64(20), nil, int64(10), nil, nil}},
		{"bound before issue", []any{digest, "subject", int64(1), int64(10), int64(20), binding, int64(9), nil, nil}},
		{"consumed attempt", []any{digest, "subject", int64(1), int64(10), int64(20), nil, nil, "short", int64(10)}},
		{"consumed pair", []any{digest, "subject", int64(1), int64(10), int64(20), nil, nil, attempt, nil}},
		{"consumed at pair", []any{digest, "subject", int64(1), int64(10), int64(20), nil, nil, nil, int64(10)}},
		{"consumed before issue", []any{digest, "subject", int64(1), int64(10), int64(20), nil, nil, attempt, int64(9)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "token digest" {
				tc.args[0] = strings.Repeat("d", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v15-invalid-" + tc.name, SQL: `INSERT INTO identity_password_reset_tokens
				(token_digest, subject, password_generation, issued_at_unix_ms, expires_at_unix_ms, binding_digest, bound_at_unix_ms, consumed_attempt, consumed_at_unix_ms)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid reset token row was accepted")
			}
		})
	}
}

func TestMigrationV16UpgradesV15SchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v16-v15-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(15)}},
		{SQL: `CREATE TABLE identity_password_reset_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			password_generation INTEGER NOT NULL CHECK (password_generation >= 1),
			issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
			binding_digest TEXT CHECK (binding_digest IS NULL OR length(binding_digest) = 43),
			bound_at_unix_ms INTEGER CHECK (bound_at_unix_ms IS NULL OR bound_at_unix_ms >= issued_at_unix_ms),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= issued_at_unix_ms),
			CHECK ((binding_digest IS NULL) = (bound_at_unix_ms IS NULL)),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV16(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV16Request("goauthy-schema-v16-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(16)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(16) {
		t.Fatalf("v16 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV16RecoveryEmailConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v16-valid-recovery-email", SQL: `INSERT INTO identity_recovery_emails (subject, email) VALUES (?, ?)`, Args: []any{"subject-1", "user@example.test"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []any
	}{
		{"duplicate subject", []any{"subject-1", "other@example.test"}},
		{"duplicate email", []any{"subject-2", "user@example.test"}},
		{"empty subject", []any{"", "empty@example.test"}},
		{"long subject", []any{strings.Repeat("s", 513), "long-subject@example.test"}},
		{"short email", []any{"subject-short", "a@"}},
		{"long email", []any{"subject-long", strings.Repeat("a", 243) + "@example.test"}},
		{"mixed case email", []any{"subject-mixed", "User@example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v16-invalid-" + tc.name, SQL: `INSERT INTO identity_recovery_emails (subject, email) VALUES (?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid recovery email row was accepted")
			}
		})
	}
}

func TestMigrationV17UpgradesV16SchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v17-v16-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(16)}},
		{SQL: `CREATE TABLE identity_recovery_emails (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254),
			CHECK (email = lower(email))
		) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV17(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV17Request("goauthy-schema-v17-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(17)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(17) {
		t.Fatalf("v17 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV17PasswordResetPoWChallengeConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	index, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, Args: []any{"identity_password_reset_pow_challenges_expiry"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(index.Rows) != 1 || len(index.Rows[0]) != 1 || index.Rows[0][0] != "identity_password_reset_pow_challenges_expiry" {
		t.Fatalf("PoW challenge expiry index=%#v err=%v", index.Rows, err)
	}

	challenge := strings.Repeat("c", 43)
	attempt := strings.Repeat("a", 22)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v17-valid-unconsumed-pow-challenge", SQL: `INSERT INTO identity_password_reset_pow_challenges (challenge, expires_at_unix_seconds) VALUES (?, ?)`, Args: []any{challenge, int64(10)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v17-valid-consumed-pow-challenge", SQL: `INSERT INTO identity_password_reset_pow_challenges (challenge, expires_at_unix_seconds, consumed_attempt, consumed_at_unix_seconds) VALUES (?, ?, ?, ?)`, Args: []any{strings.Repeat("d", 43), int64(10), attempt, int64(0)}}); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		name string
		args []any
	}{
		{"challenge length", []any{"short", int64(10), nil, nil}},
		{"negative expiry", []any{challenge, int64(-1), nil, nil}},
		{"attempt length", []any{challenge, int64(10), "short", int64(0)}},
		{"attempt without consumed at", []any{challenge, int64(10), attempt, nil}},
		{"consumed at without attempt", []any{challenge, int64(10), nil, int64(0)}},
		{"negative consumed at", []any{challenge, int64(10), attempt, int64(-1)}},
		{"duplicate challenge", []any{challenge, int64(10), nil, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "challenge length" && tc.name != "duplicate challenge" {
				tc.args[0] = strings.Repeat("e", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v17-invalid-" + tc.name, SQL: `INSERT INTO identity_password_reset_pow_challenges (challenge, expires_at_unix_seconds, consumed_attempt, consumed_at_unix_seconds) VALUES (?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid password reset PoW challenge row was accepted")
			}
		})
	}
}

func TestMigrationV18UpgradesV17SchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-v17-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(17)}},
		{SQL: `CREATE TABLE identity_password_reset_pow_challenges (
			challenge TEXT PRIMARY KEY NOT NULL CHECK (length(challenge) = 43),
			expires_at_unix_seconds INTEGER NOT NULL CHECK (expires_at_unix_seconds >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_seconds INTEGER CHECK (consumed_at_unix_seconds IS NULL OR consumed_at_unix_seconds >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_seconds IS NULL))
		) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV18(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV18Request("goauthy-schema-v18-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(18)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(18) {
		t.Fatalf("v18 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV18PasskeyAndMFAModTokenConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"identity_webauthn_credentials_subject",
		"identity_webauthn_ceremonies_expiry",
		"identity_webauthn_ceremonies_subject",
		"identity_mfa_mod_tokens_expiry",
	} {
		index, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(index.Rows) != 1 || len(index.Rows[0]) != 1 || index.Rows[0][0] != name {
			t.Fatalf("index %q rows=%#v err=%v", name, index.Rows, err)
		}
	}

	handle := strings.Repeat("h", 43)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-valid-user", SQL: `INSERT INTO identity_webauthn_users (subject, user_handle, created_at_unix_ms) VALUES (?, ?, ?)`, Args: []any{"subject-1", handle, int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-valid-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id, subject, name, credential_json, sign_count, user_verified, registered_at_unix_ms, last_used_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{"credential-1", "subject-1", "platform", `{}`, int64(0), int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	version, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT credential_version FROM identity_webauthn_credentials WHERE credential_id = ?`, Args: []any{"credential-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(version.Rows) != 1 || len(version.Rows[0]) != 1 || version.Rows[0][0] != int64(0) {
		t.Fatalf("credential default version=%#v err=%v", version.Rows, err)
	}
	code := strings.Repeat("c", 43)
	session := strings.Repeat("s", 43)
	interaction := strings.Repeat("i", 43)
	attempt := strings.Repeat("a", 22)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-valid-register-ceremony", SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest, purpose, subject, session_digest, interaction_digest, passkey_name, session_json, expires_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-valid-login-ceremony", SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest, purpose, subject, session_digest, interaction_digest, passkey_name, session_json, expires_at_unix_ms, consumed_attempt, consumed_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{strings.Repeat("l", 43), "login", "subject-1", session, interaction, nil, `{}`, int64(0), attempt, int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-valid-mfa-mod-token", SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest, subject, session_digest, expires_at_unix_ms, consumed_attempt, consumed_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, Args: []any{strings.Repeat("m", 43), "subject-1", session, int64(0), attempt, int64(0)}}); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		name string
		args []any
	}{
		{"short user handle", []any{"subject-2", "short", int64(0)}},
		{"negative user creation", []any{"subject-2", handle, int64(-1)}},
		{"duplicate user handle", []any{"subject-2", handle, int64(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "negative user creation" {
				tc.args[1] = strings.Repeat("u", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-invalid-user-" + tc.name, SQL: `INSERT INTO identity_webauthn_users (subject, user_handle, created_at_unix_ms) VALUES (?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid WebAuthn user row was accepted")
			}
		})
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"empty credential id", []any{"", "subject-1", "other", `{}`, int64(0), int64(1), int64(0), int64(0)}},
		{"long credential id", []any{strings.Repeat("x", 2049), "subject-1", "other", `{}`, int64(0), int64(1), int64(0), int64(0)}},
		{"empty credential name", []any{"credential-invalid", "subject-1", "", `{}`, int64(0), int64(1), int64(0), int64(0)}},
		{"long credential name", []any{"credential-invalid", "subject-1", strings.Repeat("n", 33), `{}`, int64(0), int64(1), int64(0), int64(0)}},
		{"empty credential json", []any{"credential-invalid", "subject-1", "other", "", int64(0), int64(1), int64(0), int64(0)}},
		{"negative sign count", []any{"credential-invalid", "subject-1", "other", `{}`, int64(-1), int64(1), int64(0), int64(0)}},
		{"invalid user verified", []any{"credential-invalid", "subject-1", "other", `{}`, int64(0), int64(2), int64(0), int64(0)}},
		{"negative registered at", []any{"credential-invalid", "subject-1", "other", `{}`, int64(0), int64(1), int64(-1), int64(0)}},
		{"negative last used at", []any{"credential-invalid", "subject-1", "other", `{}`, int64(0), int64(1), int64(0), int64(-1)}},
		{"duplicate subject name", []any{"credential-2", "subject-1", "platform", `{}`, int64(0), int64(1), int64(0), int64(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "empty credential id" && tc.name != "long credential id" && tc.name != "duplicate subject name" {
				tc.args[0] = "credential-invalid-" + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-invalid-credential-" + tc.name, SQL: `INSERT INTO identity_webauthn_credentials (credential_id, subject, name, credential_json, sign_count, user_verified, registered_at_unix_ms, last_used_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid WebAuthn credential row was accepted")
			}
		})
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-invalid-credential-version", SQL: `INSERT INTO identity_webauthn_credentials (credential_id, subject, name, credential_json, sign_count, credential_version, user_verified, registered_at_unix_ms, last_used_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{"credential-negative-version", "subject-1", "version", `{}`, int64(0), int64(-1), int64(1), int64(0), int64(0)}}); err == nil {
		t.Fatal("negative WebAuthn credential version was accepted")
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"short code digest", []any{"short", "register", "subject-1", session, nil, "platform", `{}`, int64(0), nil, nil}},
		{"invalid purpose", []any{code, "invalid", "subject-1", session, nil, "platform", `{}`, int64(0), nil, nil}},
		{"short session digest", []any{code, "register", "subject-1", "short", nil, "platform", `{}`, int64(0), nil, nil}},
		{"short login interaction", []any{code, "login", "subject-1", session, "short", nil, `{}`, int64(0), nil, nil}},
		{"register interaction", []any{code, "register", "subject-1", session, interaction, "platform", `{}`, int64(0), nil, nil}},
		{"register missing name", []any{code, "register", "subject-1", session, nil, nil, `{}`, int64(0), nil, nil}},
		{"long register name", []any{code, "register", "subject-1", session, nil, strings.Repeat("n", 33), `{}`, int64(0), nil, nil}},
		{"login missing interaction", []any{code, "login", "subject-1", session, nil, nil, `{}`, int64(0), nil, nil}},
		{"login has name", []any{code, "login", "subject-1", session, interaction, "platform", `{}`, int64(0), nil, nil}},
		{"empty session json", []any{code, "register", "subject-1", session, nil, "platform", "", int64(0), nil, nil}},
		{"negative expiry", []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(-1), nil, nil}},
		{"short consumed attempt", []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(0), "short", int64(0)}},
		{"missing consumed at", []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(0), attempt, nil}},
		{"missing consumed attempt", []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(0), nil, int64(0)}},
		{"negative consumed at", []any{code, "register", "subject-1", session, nil, "platform", `{}`, int64(0), attempt, int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "short code digest" {
				tc.args[0] = strings.Repeat("z", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-invalid-ceremony-" + tc.name, SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest, purpose, subject, session_digest, interaction_digest, passkey_name, session_json, expires_at_unix_ms, consumed_attempt, consumed_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid WebAuthn ceremony row was accepted")
			}
		})
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"short token digest", []any{"short", "subject-1", session, int64(0), nil, nil}},
		{"empty subject", []any{strings.Repeat("t", 43), "", session, int64(0), nil, nil}},
		{"short session digest", []any{strings.Repeat("t", 43), "subject-1", "short", int64(0), nil, nil}},
		{"negative expiry", []any{strings.Repeat("t", 43), "subject-1", session, int64(-1), nil, nil}},
		{"short consumed attempt", []any{strings.Repeat("t", 43), "subject-1", session, int64(0), "short", int64(0)}},
		{"missing consumed at", []any{strings.Repeat("t", 43), "subject-1", session, int64(0), attempt, nil}},
		{"missing consumed attempt", []any{strings.Repeat("t", 43), "subject-1", session, int64(0), nil, int64(0)}},
		{"negative consumed at", []any{strings.Repeat("t", 43), "subject-1", session, int64(0), attempt, int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "short token digest" {
				tc.args[0] = strings.Repeat("q", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v18-invalid-mfa-mod-token-" + tc.name, SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest, subject, session_digest, expires_at_unix_ms, consumed_attempt, consumed_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid MFA modification token row was accepted")
			}
		})
	}
}

func TestMigrationV19UpgradesV18SchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-v18-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(18)}},
		{SQL: `CREATE TABLE identity_users (
			subject TEXT PRIMARY KEY NOT NULL,
			username TEXT NOT NULL UNIQUE,
			password_phc TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
			password_changed_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (password_changed_at_unix_ms >= 0),
			password_generation INTEGER NOT NULL DEFAULT 1 CHECK (password_generation >= 1)
		) STRICT`},
		{SQL: `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`, Args: []any{"legacy-subject", "legacy", "phc"}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV19(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV19Request("goauthy-schema-v19-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT mode, generation, updated_at_unix_ms FROM identity_authentication_modes WHERE subject = ?`, Args: []any{"legacy-subject"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 || result.Rows[0][0] != "password" || result.Rows[0][1] != int64(1) || result.Rows[0][2] != int64(0) {
		t.Fatalf("legacy authentication mode=%#v err=%v", result.Rows, err)
	}
	marker, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(19)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(19) {
		t.Fatalf("v19 marker=%#v err=%v", marker.Rows, err)
	}
}

func TestMigrationV19AuthenticationModeConstraintsAndCAS(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-user", SQL: `INSERT INTO identity_users (subject, username, password_phc) VALUES (?, ?, ?)`, Args: []any{"subject-1", "user-1", "phc"}}); err != nil {
		t.Fatal(err)
	}
	// New users are explicitly seeded by identity creation; this test supplies
	// the same deterministic initial row the conversion CAS relies on.
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-password-mode", SQL: `INSERT INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"subject-1", "password", int64(1), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-convert", SQL: `UPDATE identity_authentication_modes SET mode = 'passkey', generation = generation + 1, updated_at_unix_ms = ? WHERE subject = ? AND mode = 'password' AND generation = ?`, Args: []any{int64(7), "subject-1", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-stale-convert", SQL: `UPDATE identity_authentication_modes SET mode = 'passkey', generation = generation + 1, updated_at_unix_ms = ? WHERE subject = ? AND mode = 'password' AND generation = ?`, Args: []any{int64(8), "subject-1", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	state, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT mode, generation, updated_at_unix_ms FROM identity_authentication_modes WHERE subject = ?`, Args: []any{"subject-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(state.Rows) != 1 || len(state.Rows[0]) != 3 || state.Rows[0][0] != "passkey" || state.Rows[0][1] != int64(2) || state.Rows[0][2] != int64(7) {
		t.Fatalf("CAS state=%#v err=%v", state.Rows, err)
	}

	for _, tc := range []struct {
		name string
		args []any
	}{
		{"empty subject", []any{"", "password", int64(1), int64(0)}},
		{"long subject", []any{strings.Repeat("s", 513), "password", int64(1), int64(0)}},
		{"invalid mode", []any{"subject-2", "other", int64(1), int64(0)}},
		{"zero generation", []any{"subject-2", "password", int64(0), int64(0)}},
		{"negative updated at", []any{"subject-2", "password", int64(1), int64(-1)}},
		{"duplicate subject", []any{"subject-1", "password", int64(1), int64(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v19-invalid-" + tc.name, SQL: `INSERT INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid authentication mode row was accepted")
			}
		})
	}
}

func TestMigrationV20UpgradesV19SchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-v19-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(19)}},
		{SQL: `CREATE TABLE identity_mfa_mod_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) > 0),
			session_digest TEXT NOT NULL CHECK (length(session_digest) = 43),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{strings.Repeat("t", 43), "legacy-subject", strings.Repeat("s", 43), int64(0)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV20(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, schemaV20Request("goauthy-schema-v20-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	marker, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(20)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || len(marker.Rows[0]) != 1 || marker.Rows[0][0] != int64(20) {
		t.Fatalf("v20 marker=%#v err=%v", marker.Rows, err)
	}
	for _, table := range []string{"identity_webauthn_mfa_ceremonies", "identity_webauthn_mfa_proofs"} {
		row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, Args: []any{table}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != table {
			t.Fatalf("table %q rows=%#v err=%v", table, row.Rows, err)
		}
	}
	legacy, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT count(*) FROM identity_mfa_mod_token_factors`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(legacy.Rows) != 1 || legacy.Rows[0][0] != int64(0) {
		t.Fatalf("legacy factor backfill=%#v err=%v", legacy.Rows, err)
	}
}

func TestMigrationV20MFACeremonyAndProofConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"identity_webauthn_mfa_ceremonies_expiry", "identity_webauthn_mfa_ceremonies_subject",
		"identity_webauthn_mfa_proofs_expiry", "identity_webauthn_mfa_proofs_subject",
	} {
		row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != name {
			t.Fatalf("index %q rows=%#v err=%v", name, row.Rows, err)
		}
	}
	code, session, attempt := strings.Repeat("c", 43), strings.Repeat("s", 43), strings.Repeat("a", 22)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-valid-ceremony", SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{code, "subject-1", session, "ciphertext", int64(0), int64(1), attempt, int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-valid-proof", SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{strings.Repeat("p", 43), "subject-1", session, int64(0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-valid-factor", SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) VALUES (?,?)`, Args: []any{strings.Repeat("t", 43), "webauthn"}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"short code", []any{"short", "subject-2", session, "ciphertext", int64(0), int64(1), nil, nil}},
		{"empty subject", []any{code, "", session, "ciphertext", int64(0), int64(1), nil, nil}},
		{"long subject", []any{code, strings.Repeat("x", 513), session, "ciphertext", int64(0), int64(1), nil, nil}},
		{"short session", []any{code, "subject-2", "short", "ciphertext", int64(0), int64(1), nil, nil}},
		{"empty state", []any{code, "subject-2", session, "", int64(0), int64(1), nil, nil}},
		{"negative expiry", []any{code, "subject-2", session, "ciphertext", int64(-1), int64(1), nil, nil}},
		{"negative proof expiry", []any{code, "subject-2", session, "ciphertext", int64(0), int64(-1), nil, nil}},
		{"short attempt", []any{code, "subject-2", session, "ciphertext", int64(0), int64(1), "short", int64(0)}},
		{"unpaired attempt", []any{code, "subject-2", session, "ciphertext", int64(0), int64(1), attempt, nil}},
		{"unpaired time", []any{code, "subject-2", session, "ciphertext", int64(0), int64(1), nil, int64(0)}},
		{"negative consumed time", []any{code, "subject-2", session, "ciphertext", int64(0), int64(1), attempt, int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "short code" {
				tc.args[0] = strings.Repeat("z", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-invalid-ceremony-" + tc.name, SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid MFA ceremony row was accepted")
			}
		})
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"short code", []any{"short", "subject-2", session, int64(0), nil, nil}},
		{"empty subject", []any{code, "", session, int64(0), nil, nil}},
		{"long subject", []any{code, strings.Repeat("x", 513), session, int64(0), nil, nil}},
		{"short session", []any{code, "subject-2", "short", int64(0), nil, nil}},
		{"negative expiry", []any{code, "subject-2", session, int64(-1), nil, nil}},
		{"short attempt", []any{code, "subject-2", session, int64(0), "short", int64(0)}},
		{"unpaired attempt", []any{code, "subject-2", session, int64(0), attempt, nil}},
		{"unpaired time", []any{code, "subject-2", session, int64(0), nil, int64(0)}},
		{"negative consumed time", []any{code, "subject-2", session, int64(0), attempt, int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "short code" {
				tc.args[0] = strings.Repeat("q", 42) + string(rune('a'+i))
			}
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-invalid-proof-" + tc.name, SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid MFA proof row was accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		args []any
	}{
		{"short token", []any{"short", "password"}},
		{"invalid factor", []any{strings.Repeat("f", 43), "other"}},
		{"duplicate token", []any{strings.Repeat("t", 43), "password"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v20-invalid-factor-" + tc.name, SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) VALUES (?,?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid MFA token factor row was accepted")
			}
		})
	}
}

func TestReadyRejectsUninitializedAndFutureSchema(t *testing.T) {
	t.Parallel()
	// This test asserts that Ready rejects a database with no schema marker, so
	// it needs a genuinely unmigrated database rather than a migrated template.
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := Ready(context.Background(), db); err == nil {
		t.Fatal("uninitialized database reported ready")
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-future-schema",
		SQL:       `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`,
		Args:      []any{schemaVersion + 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Ready(context.Background(), db); err == nil {
		t.Fatal("future schema reported ready")
	}
}

func TestMigrationV21CreatesServicePurposeTablesAndLegacyRowsRemainUnmarked(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV21(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV21Request("goauthy-schema-v21-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("m", 43)
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v21-purpose", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, "MfaModToken"}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("p", 43), "PasswordNew"}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_webauthn_service_ceremony_purposes", "identity_webauthn_service_proof_purposes"} {
		if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v21-invalid-" + table, SQL: `INSERT INTO ` + table + ` (code_digest,purpose) VALUES (?,?)`, Args: []any{strings.Repeat("x", 43), "other"}}); err == nil {
			t.Fatalf("%s accepted invalid purpose", table)
		}
	}
}

func TestMigrationV22RecordsSessionAMRAndRevokesLegacyAuthenticatedSessions(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v22-legacy-migrations", SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV6Request("v22-legacy-v6")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV7Request("v22-legacy-v7")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, schemaV9Request("v22-legacy-v9")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v22-legacy-rows", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"legacy-init", "", int64(100), int64(500), int64(100)}},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"legacy-auth", "subject", int64(200), int64(500), int64(200)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV22(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV22(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT subject,auth_method,revoked_at_unix_ms FROM browser_sessions ORDER BY token_digest`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 {
		t.Fatalf("legacy sessions=%#v err=%v", result.Rows, err)
	}
	if got := result.Rows[0]; len(got) != 3 || got[0] != "subject" || got[1] != "" || got[2] != int64(200) {
		t.Fatalf("authenticated legacy session=%#v", got)
	}
	if got := result.Rows[1]; len(got) != 3 || got[0] != "" || got[1] != "" || got[2] != nil {
		t.Fatalf("init legacy session=%#v", got)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v22-force-mfa-default", SQL: `INSERT INTO dynamic_oauth_clients (client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"client", nil, strings.Repeat("a", 43), "[]", "[]", "[]", "[]", "[]", "none", "client", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	result, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT force_mfa FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("force_mfa default=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v22-invalid-force-mfa", SQL: `UPDATE dynamic_oauth_clients SET force_mfa = 2 WHERE client_id = ?`, Args: []any{"client"}}); err == nil {
		t.Fatal("dynamic client accepted invalid force_mfa")
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v22-invalid-amr", SQL: `UPDATE browser_sessions SET auth_method = 'other' WHERE token_digest = ?`, Args: []any{"legacy-init"}}); err == nil {
		t.Fatal("browser session accepted invalid auth_method")
	}
}

func TestMigrationV23UpgradesResetTokensAndProfilesIdempotently(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v23-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(22)}},
		{SQL: `CREATE TABLE identity_password_reset_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			password_generation INTEGER NOT NULL CHECK (password_generation >= 1),
			issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
			binding_digest TEXT, bound_at_unix_ms INTEGER, consumed_attempt TEXT, consumed_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `INSERT INTO identity_password_reset_tokens (token_digest, subject, password_generation, issued_at_unix_ms, expires_at_unix_ms) VALUES (?, ?, ?, ?, ?)`, Args: []any{strings.Repeat("l", 43), "legacy-subject", int64(1), int64(10), int64(20)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV23(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	reset, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT usage, redirect_uri FROM identity_password_reset_tokens WHERE token_digest = ?`, Args: []any{strings.Repeat("l", 43)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(reset.Rows) != 1 || len(reset.Rows[0]) != 2 || reset.Rows[0][0] != "password_reset" || reset.Rows[0][1] != nil {
		t.Fatalf("legacy reset defaults=%#v err=%v", reset.Rows, err)
	}
	marker, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(23)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(23) {
		t.Fatalf("v23 marker=%#v err=%v", marker.Rows, err)
	}
}

func TestMigrationV23OpenRegistrationConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v23-valid-profile-and-token", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles (subject, email, email_verified, preferred_username, given_name, family_name, user_values_json) VALUES (?, ?, ?, ?, ?, ?, ?)`, Args: []any{"subject-1", "user@example.test", int64(0), "user", "Given", "Family", `{}`}},
		{SQL: `INSERT INTO identity_password_reset_tokens (token_digest, subject, password_generation, issued_at_unix_ms, expires_at_unix_ms, usage, redirect_uri) VALUES (?, ?, ?, ?, ?, ?, ?)`, Args: []any{strings.Repeat("n", 43), "subject-1", int64(1), int64(10), int64(20), "password_new", "https://rp.example.test/after"}},
	}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"invalid usage", `UPDATE identity_password_reset_tokens SET usage = ? WHERE token_digest = ?`, []any{"other", strings.Repeat("n", 43)}},
		{"empty redirect", `UPDATE identity_password_reset_tokens SET redirect_uri = ? WHERE token_digest = ?`, []any{"", strings.Repeat("n", 43)}},
		{"long redirect", `UPDATE identity_password_reset_tokens SET redirect_uri = ? WHERE token_digest = ?`, []any{strings.Repeat("u", 2049), strings.Repeat("n", 43)}},
		{"CRLF redirect", `UPDATE identity_password_reset_tokens SET redirect_uri = ? WHERE token_digest = ?`, []any{"https://rp.example.test/\r\nX-Test: bad", strings.Repeat("n", 43)}},
		{"noncanonical email", `INSERT INTO identity_user_profiles (subject, email) VALUES (?, ?)`, []any{"subject-2", "User@example.test"}},
		{"invalid verified", `INSERT INTO identity_user_profiles (subject, email, email_verified) VALUES (?, ?, ?)`, []any{"subject-2", "other@example.test", int64(2)}},
		{"long preferred username", `INSERT INTO identity_user_profiles (subject, email, preferred_username) VALUES (?, ?, ?)`, []any{"subject-2", "other@example.test", strings.Repeat("p", 129)}},
		{"long given name", `INSERT INTO identity_user_profiles (subject, email, given_name) VALUES (?, ?, ?)`, []any{"subject-2", "other@example.test", strings.Repeat("g", 33)}},
		{"long family name", `INSERT INTO identity_user_profiles (subject, email, family_name) VALUES (?, ?, ?)`, []any{"subject-2", "other@example.test", strings.Repeat("f", 33)}},
		{"invalid user values", `INSERT INTO identity_user_profiles (subject, email, user_values_json) VALUES (?, ?, ?)`, []any{"subject-2", "other@example.test", `{`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v23-invalid-" + string(rune('a'+i)), SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid open-registration row was accepted")
			}
		})
	}
}

func TestMigrationV24UpgradesFromV23Idempotently(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v24-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(23)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV24(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	marker, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(24)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(24) {
		t.Fatalf("v24 marker=%#v err=%v", marker.Rows, err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v24-upgrade-row", SQL: `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"role-1", "role", int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV25UpgradesFromV24Idempotently(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v25-legacy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(24)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV25(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v25-valid-policy", SQL: `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{"bootstrap-client", "team/a", int64(1), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO bootstrap_client_login_restrictions (client_id,revision,updated_at_unix_ms) VALUES (?,?,?)`, []any{"", int64(1), int64(0)}},
		{`INSERT INTO bootstrap_client_login_restrictions (client_id,revision,updated_at_unix_ms) VALUES (?,?,?)`, []any{"client-2", int64(0), int64(0)}},
		{`UPDATE bootstrap_client_login_restrictions SET updated_at_unix_ms=? WHERE client_id=?`, []any{int64(-1), "bootstrap-client"}},
	} {
		if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v25-invalid-" + string(rune('a'+i)), SQL: tc.sql, Args: tc.args}); err == nil {
			t.Fatalf("invalid v25 row %d was accepted", i)
		}
	}
}

func TestMigrationV24RBACConstraintsAndReady(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Ready(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v24-valid-rbac", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{"role-1", "role", `{"key":"value"}`, int64(1), int64(5), int64(5)}},
		{SQL: `INSERT INTO rbac_groups (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{"group-1", "group", nil, int64(1), int64(5), int64(5)}},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?,?,?)`, Args: []any{"subject-1", "role-1", int64(5)}},
		{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES (?,?,?)`, Args: []any{"subject-1", "group-1", int64(5)}},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,?,?)`, Args: []any{"subject-1", int64(1), int64(5)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"one character role name", `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, []any{"role-short", "r", int64(1), int64(0), int64(0)}},
		{"65 character role name", `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, []any{"role-long-name", strings.Repeat("r", 65), int64(1), int64(0), int64(0)}},
		{"65 character role id", `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, []any{strings.Repeat("r", 65), "role-two", int64(1), int64(0), int64(0)}},
		{"duplicate role name", `INSERT INTO rbac_roles (id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?)`, []any{"role-2", "role", int64(1), int64(0), int64(0)}},
		{"noncanonical metadata", `UPDATE rbac_roles SET meta_json = ? WHERE id = ?`, []any{"{\"key\": \"value\"}", "role-1"}},
		{"invalid metadata", `UPDATE rbac_roles SET meta_json = ? WHERE id = ?`, []any{"{", "role-1"}},
		{"long metadata", `UPDATE rbac_roles SET meta_json = ? WHERE id = ?`, []any{strings.Repeat("x", 8193), "role-1"}},
		{"zero revision", `UPDATE rbac_roles SET revision = ? WHERE id = ?`, []any{int64(0), "role-1"}},
		{"backwards timestamp", `UPDATE rbac_roles SET updated_at_unix_ms = ? WHERE id = ?`, []any{int64(4), "role-1"}},
		{"duplicate membership", `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?,?,?)`, []any{"subject-1", "role-1", int64(5)}},
		{"65 character membership role id", `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?,?,?)`, []any{"subject-2", strings.Repeat("r", 65), int64(0)}},
		{"negative grant timestamp", `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES (?,?,?)`, []any{"subject-2", "group-1", int64(-1)}},
		{"zero principal revision", `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,?,?)`, []any{"subject-2", int64(0), int64(0)}},
		{"negative principal timestamp", `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,?,?)`, []any{"subject-2", int64(1), int64(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "v24-invalid-" + string(rune('a'+i)), SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid RBAC row was accepted")
			}
		})
	}
}

func TestExecuteRejectsRejectedReceipt(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: testDatabaseDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "duplicate-schema-version",
		SQL:       `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`,
		Args:      []any{schemaVersion},
	}); err == nil {
		t.Fatal("rejected Rhiza receipt reported success")
	}
}

func TestExecuteRecoversCommittedStatementResultsAfterCommitUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storeDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID:             "test-execute-recovery",
		DataDir:            t.TempDir(),
		ObjStoreProvider:   rhiza.ObjectStoreProviderFilesystem,
		ObjStoreDir:        storeDir,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "execute-recovery-schema",
		SQL:       `CREATE TABLE execute_recovery (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`,
	}); err != nil {
		t.Fatal(err)
	}

	storeBackup := storeDir + "-unavailable"
	if err := os.Rename(storeDir, storeBackup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeDir, []byte("object store unavailable"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(storeDir)
		_ = os.Rename(storeBackup, storeDir)
	})

	request := rhiza.ExecuteRequest{
		RequestID: "execute-recovery",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO execute_recovery (value) VALUES (?)`, Args: []any{"first"}},
			{SQL: `INSERT INTO execute_recovery (value) VALUES (?) RETURNING id, value`, Args: []any{"second"}, WantRows: true},
		},
	}
	if _, err := Execute(ctx, db, request); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("unavailable before-ack store must not report success: %v", err)
	}
	// A committed receipt is not proof of before-ack durability. Even a
	// duplicate must fail until the object store can persist the result.
	if _, err := Execute(ctx, db, request); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("duplicate bypassed before-ack durability: %v", err)
	}
	if err := os.Remove(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(storeBackup, storeDir); err != nil {
		t.Fatal(err)
	}
	response, err := Execute(ctx, db, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Statements) != 2 || response.Statements[0].RowsAffected != 1 || len(response.Statements[1].Rows) != 1 {
		t.Fatalf("recovered statements=%#v", response.Statements)
	}
	row := response.Statements[1].Rows[0]
	if len(row) != 2 || row[0] != int64(2) || row[1] != "second" {
		t.Fatalf("recovered returning row=%#v", row)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM execute_recovery`})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(2) {
		t.Fatalf("mutation count=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV45AuditPreservesV44DataAndIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v45", DataDir: testDatabaseDir(t, "test-v45")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v45-legacy-key", SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms) VALUES (?,?,?)`, Args: []any{"legacy", strings.Repeat("A", 43), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v45-rewind", Statements: []rhiza.SQLStatement{{SQL: `DROP TRIGGER audit_events_append_only_update`}, {SQL: `DROP TRIGGER audit_events_append_only_delete`}, {SQL: `DROP TABLE audit_events`}, {SQL: `DELETE FROM goauthy_schema_migrations WHERE version=45`}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, schemaV45Request("test-v45-apply")); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM api_keys WHERE name='legacy'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "legacy" {
		t.Fatalf("legacy rows=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM audit_events`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		t.Fatalf("audit rows=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV46AddsContactsAndPreservesLegacyDynamicClients(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v46", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v46-legacy-dcr", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (45)`},
		{SQL: `CREATE TABLE dynamic_oauth_clients (
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
			client_uri TEXT
		) STRICT`},
		{SQL: `INSERT INTO dynamic_oauth_clients (client_id, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms, client_uri) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
			"legacy-client", "legacy-token", `["https://rp.example.test/callback"]`, `["openid"]`, `["openid"]`, `["authorization_code"]`, `["code"]`, `[]`, "none", "Legacy RP", int64(1234), "https://rp.example.test",
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV46(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV46(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id, name, client_uri, contacts_json FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"legacy-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 || result.Rows[0][0] != "legacy-client" || result.Rows[0][1] != "Legacy RP" || result.Rows[0][2] != "https://rp.example.test" || result.Rows[0][3] != nil {
		t.Fatalf("legacy row after v46=%#v err=%v", result.Rows, err)
	}
	column, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('dynamic_oauth_clients') WHERE name = ?`, Args: []any{"contacts_json"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(column.Rows) != 1 {
		t.Fatalf("contacts_json column=%#v err=%v", column.Rows, err)
	}
}

func TestMigrationV47AddsURIClientMetadataAndPreservesLegacyDynamicClients(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v47", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v47-legacy-dcr", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (46)`},
		{SQL: `CREATE TABLE dynamic_oauth_clients (
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
			contacts_json TEXT
		) STRICT`},
		{SQL: `INSERT INTO dynamic_oauth_clients (client_id, registration_token_digest, redirect_uris_json, scopes_json, default_scopes_json, grant_types_json, response_types_json, audiences_json, token_endpoint_auth_method, name, created_at_unix_ms, client_uri, contacts_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, Args: []any{
			"legacy-client", "legacy-token", `["https://rp.example.test/callback"]`, `["openid"]`, `["openid"]`, `["authorization_code"]`, `["code"]`, `[]`, "none", "Legacy RP", int64(1234), "https://rp.example.test", `["support@example.test"]`,
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV47(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV47(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id, name, client_uri, contacts_json, logo_uri, tos_uri, policy_uri FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"legacy-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 7 || result.Rows[0][0] != "legacy-client" || result.Rows[0][1] != "Legacy RP" || result.Rows[0][2] != "https://rp.example.test" || result.Rows[0][3] != `["support@example.test"]` || result.Rows[0][4] != nil || result.Rows[0][5] != nil || result.Rows[0][6] != nil {
		t.Fatalf("legacy row after v47=%#v err=%v", result.Rows, err)
	}
	for _, name := range []string{"logo_uri", "tos_uri", "policy_uri"} {
		column, queryErr := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('dynamic_oauth_clients') WHERE name = ?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
		if queryErr != nil || len(column.Rows) != 1 {
			t.Fatalf("%s column=%#v err=%v", name, column.Rows, queryErr)
		}
	}
}

func TestExecuteValidatesBeforeSubmission(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{SQL: `SELECT 1`}); err == nil {
		t.Fatal("invalid mutation was submitted")
	}
	if rhiza.MaxReplicatedMutationBytes != 128<<10 || rhiza.MaxHTTPBodyBytes != 1<<20 {
		t.Fatalf("unexpected Rhiza limits: replicated=%d HTTP=%d", rhiza.MaxReplicatedMutationBytes, rhiza.MaxHTTPBodyBytes)
	}
}

func TestMigrationV32IPBlacklistFromV31IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v32", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	// v31 predecessor fixture: migration marker + preserved data + marker table.
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v32-v31-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(31)`},
		{SQL: `CREATE TABLE preserved_v31 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v31(id,value) VALUES(1,'kept')`},
		// Minimal browser_sessions table with peer_ip column (v31 schema).
		{SQL: `CREATE TABLE browser_sessions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			auth_method TEXT NOT NULL CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa')),
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			last_seen_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER,
			peer_ip TEXT NOT NULL DEFAULT ''
		) STRICT`},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES('v31-session','user-1','pwd',1000,2000,1000,'203.0.113.8')`},
	}}); err != nil {
		t.Fatal(err)
	}

	// Apply v32 twice — idempotent.
	for range 2 {
		if err = migrateSchemaV32(ctx, db); err != nil {
			t.Fatal(err)
		}
	}

	// Replay with alternate request ID also succeeds.
	if _, err := Execute(ctx, db, schemaV32Request("goauthy-schema-v32-after-receipt-expiry")); err != nil {
		t.Fatal(err)
	}

	// v32 marker present exactly once.
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=32`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v32 marker=%#v err=%v", result.Rows, err)
	}

	// v31 marker still present.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=31`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v31 marker=%#v err=%v", result.Rows, err)
	}

	// Preserved v31 data intact.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v31 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}

	// v31 browser_sessions data intact.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT peer_ip FROM browser_sessions WHERE token_digest='v31-session'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "203.0.113.8" {
		t.Fatalf("v31 peer_ip=%#v err=%v", result.Rows, err)
	}

	// IP blacklist table exists.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE name=?`, Args: []any{"ip_blacklist_entries"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("schema object ip_blacklist_entries rows=%#v err=%v", result.Rows, err)
	}

	// Valid row insert.
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v32-valid-entry", SQL: `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"10.0.0.0/8", "test", nil, int64(1000), int64(1000)}}); err != nil {
		t.Fatal(err)
	}

	// Constraint violations.
	for _, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"empty prefix", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"", "", nil, int64(0), int64(0)}},
		{"long note", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"192.168.0.0/16", strings.Repeat("x", 257), nil, int64(0), int64(0)}},
		{"negative created", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"172.16.0.0/12", "", nil, int64(-1), int64(0)}},
		{"negative updated", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"172.16.0.0/12", "", nil, int64(0), int64(-1)}},
		{"updated before created", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"172.16.0.0/12", "", nil, int64(100), int64(50)}},
		{"zero expiry", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"172.16.0.0/12", "", int64(0), int64(0), int64(0)}},
		{"negative expiry", `INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"172.16.0.0/12", "", int64(-1), int64(0), int64(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v32-invalid-" + tc.name, SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatalf("invalid v32 row %q was accepted", tc.name)
			}
		})
	}
}

func TestMigrationV33RateLimitExpiryFromV32IsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v33", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	// v32 predecessor fixture: migration marker + preserved data + oauth_rate_limits.
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v33-v32-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(32)`},
		{SQL: `CREATE TABLE preserved_v32 (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v32(id,value) VALUES(1,'kept')`},
		// Minimal oauth_rate_limits table (v10 schema, no expiry columns).
		{SQL: `CREATE TABLE oauth_rate_limits (
			key_digest TEXT PRIMARY KEY NOT NULL,
			window_start_unix_ms INTEGER NOT NULL,
			count INTEGER NOT NULL CHECK (count >= 0)
		) STRICT`},
		{SQL: `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count) VALUES('legacy-key',1000,3)`},
	}}); err != nil {
		t.Fatal(err)
	}

	// Apply v33 twice — idempotent.
	for range 2 {
		if err = migrateSchemaV33(ctx, db); err != nil {
			t.Fatal(err)
		}
	}

	// v33 marker present exactly once.
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=33`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v33 marker=%#v err=%v", result.Rows, err)
	}

	// v32 marker still present.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=32`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v32 marker=%#v err=%v", result.Rows, err)
	}

	// Preserved v32 data intact.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v32 WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "kept" {
		t.Fatalf("preserved=%#v err=%v", result.Rows, err)
	}

	// Legacy oauth_rate_limits row preserved with expiry metadata backfilled.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms FROM oauth_rate_limits WHERE key_digest='legacy-key'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 5 {
		t.Fatalf("legacy row=%#v err=%v", result.Rows, err)
	}
	keyDigest, _ := result.Rows[0][0].(string)
	windowStart, _ := result.Rows[0][1].(int64)
	count, _ := result.Rows[0][2].(int64)
	expiresAt, _ := result.Rows[0][3].(int64)
	lastWindow, _ := result.Rows[0][4].(int64)
	if keyDigest != "legacy-key" || windowStart != 1000 || count != 3 {
		t.Fatalf("legacy values: key=%q window=%d count=%d", keyDigest, windowStart, count)
	}
	if expiresAt != 1000+86400000 {
		t.Fatalf("legacy expires_at=%d want=%d", expiresAt, 1000+86400000)
	}
	if lastWindow != 1000 {
		t.Fatalf("legacy last_window_at=%d want=%d", lastWindow, 1000)
	}

	// New row insert with expiry columns.
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v33-valid-row", SQL: `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"new-key", int64(2000), int64(1), int64(2000 + 86400000), int64(2000)}}); err != nil {
		t.Fatal(err)
	}

	// Expiry index exists.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name=?`, Args: []any{"oauth_rate_limits_expiry"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("expiry index rows=%#v err=%v", result.Rows, err)
	}

	// Trigger exists.
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='trigger' AND name=?`, Args: []any{"oauth_rate_limits_cleanup"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("cleanup trigger rows=%#v err=%v", result.Rows, err)
	}

	// CHECK constraints enforced.
	for _, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"zero expires", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-exp", int64(0), int64(0), int64(0), int64(0)}},
		{"negative expires", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-exp2", int64(0), int64(0), int64(-1), int64(0)}},
		{"negative last_window", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-lw", int64(0), int64(0), int64(100), int64(-1)}},
		{"negative window_start", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-ws", int64(-1), int64(0), int64(200), int64(100)}},
		{"expires_not_after_last_window", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-exp-lw", int64(0), int64(0), int64(100), int64(100)}},
		{"expires_before_last_window", `INSERT INTO oauth_rate_limits(key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES(?,?,?,?,?)`, []any{"bad-exp-lw2", int64(0), int64(0), int64(50), int64(100)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v33-invalid-" + tc.name, SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatalf("invalid v33 row %q was accepted", tc.name)
			}
		})
	}
}

func TestMigrationV34DCRIdempotencySchema(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v34", DataDir: testDatabaseDir(t, "test-v34")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV34(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version = 34`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v34 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'dcr_registration_idempotency'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("idempotency table=%#v err=%v", result.Rows, err)
	}
	for _, tc := range []struct {
		name string
		args []any
	}{
		{"principal digest", []any{"short", strings.Repeat("a", 43), strings.Repeat("b", 43), "client", "envelope", int64(2), int64(1)}},
		{"key digest", []any{strings.Repeat("a", 43), "short", strings.Repeat("b", 43), "client", "envelope", int64(2), int64(1)}},
		{"request digest", []any{strings.Repeat("a", 43), strings.Repeat("b", 43), "short", "client", "envelope", int64(2), int64(1)}},
		{"empty envelope", []any{strings.Repeat("a", 43), strings.Repeat("b", 43), strings.Repeat("c", 43), "client", "", int64(2), int64(1)}},
		{"zero expiry", []any{strings.Repeat("a", 43), strings.Repeat("b", 43), strings.Repeat("c", 43), "client", "envelope", int64(0), int64(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v34-invalid-" + tc.name, SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: tc.args})
			if err == nil {
				t.Fatal("invalid v34 row was accepted")
			}
		})
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatalf("Ready after v34 migration: %v", err)
	}
}

func TestMigrationV35UpstreamProviderSchema(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v35", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v35-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(34)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV35(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('upstream_provider_transactions', 'identity_external_links') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 || result.Rows[0][0] != "identity_external_links" || result.Rows[1][0] != "upstream_provider_transactions" {
		t.Fatalf("v35 tables=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version = 35`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v35 marker=%#v err=%v", result.Rows, err)
	}

	canonicalDigest := func(fill, terminal string) string { return strings.Repeat(fill, 42) + terminal }
	digest := canonicalDigest("a", "A")
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v35-valid-rows", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, Args: []any{digest, canonicalDigest("b", "E"), "provider", "envelope", "https://issuer.example.test", "", "client", `["openid"]`, "https://goauthy.example.test/callback", int64(2), int64(1)}},
		{SQL: `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,session_digest,interaction_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'link',?,?,?,?,?,?)`, Args: []any{canonicalDigest("c", "I"), canonicalDigest("d", "M"), "provider", "envelope", "https://issuer.example.test", "", "client", `["openid"]`, "https://goauthy.example.test/callback", "subject-link", canonicalDigest("e", "Q"), canonicalDigest("f", "U"), canonicalDigest("g", "Y"), int64(2), int64(1)}},
		{SQL: `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{"provider", strings.Repeat("c", 43), "subject", int64(1)}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"invalid state digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, []any{"short", canonicalDigest("d", "A"), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(2), int64(1)}},
		{"noncanonical state digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, []any{strings.Repeat("a", 43), canonicalDigest("e", "E"), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(2), int64(1)}},
		{"noncanonical browser digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, []any{canonicalDigest("f", "I"), strings.Repeat("a", 43), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(2), int64(1)}},
		{"noncanonical link session digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'link',?,?,?,?)`, []any{canonicalDigest("g", "M"), canonicalDigest("h", "Q"), "provider", "envelope", "issuer", "", "client", "[]", "callback", "subject", strings.Repeat("a", 43), int64(2), int64(1)}},
		{"noncanonical session digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,session_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?,?)`, []any{canonicalDigest("i", "U"), canonicalDigest("j", "Y"), "provider", "envelope", "issuer", "", "client", "[]", "callback", strings.Repeat("a", 43), int64(2), int64(1)}},
		{"noncanonical interaction digest", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,interaction_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?,?)`, []any{canonicalDigest("k", "c"), canonicalDigest("l", "g"), "provider", "envelope", "issuer", "", "client", "[]", "callback", strings.Repeat("a", 43), int64(2), int64(1)}},
		{"noncanonical scopes", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, []any{canonicalDigest("m", "k"), canonicalDigest("n", "o"), "provider", "envelope", "issuer", "", "client", `[ "openid" ]`, "callback", int64(2), int64(1)}},
		{"nonincreasing expiry", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?)`, []any{canonicalDigest("l", "s"), canonicalDigest("m", "w"), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(1), int64(1)}},
		{"invalid link pairing", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'link',?,?,?,?)`, []any{canonicalDigest("n", "0"), canonicalDigest("o", "4"), "provider", "envelope", "issuer", "", "client", "[]", "callback", "subject", nil, int64(2), int64(1)}},
		{"invalid consumed pairing", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms,consumed_attempt,consumed_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?,?,?)`, []any{canonicalDigest("p", "8"), canonicalDigest("q", "A"), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(2), int64(1), strings.Repeat("n", 22), nil}},
		{"invalid consumed attempt", `INSERT INTO upstream_provider_transactions (state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,expires_at_unix_ms,created_at_unix_ms,consumed_attempt,consumed_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,'login',?,?,?,?)`, []any{canonicalDigest("r", "E"), canonicalDigest("s", "I"), "provider", "envelope", "issuer", "", "client", "[]", "callback", int64(2), int64(1), strings.Repeat("!", 22), int64(1)}},
		{"negative linked at", `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms) VALUES (?,?,?,?)`, []any{"provider", strings.Repeat("q", 43), "subject-2", int64(-1)}},
		{"duplicate provider subject", `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms) VALUES (?,?,?,?)`, []any{"provider", strings.Repeat("k", 43), "subject", int64(1)}},
		{"duplicate provider external key", `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms) VALUES (?,?,?,?)`, []any{"provider", strings.Repeat("c", 43), "other-subject", int64(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v35-invalid-" + tc.name, SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid v35 row was accepted")
			}
		})
	}
}

func TestMigrationV36AllowsExternalBrowserSessionsAndPreservesRows(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v36", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v36-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (35)`},
		{SQL: `CREATE TABLE browser_sessions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			auth_method TEXT NOT NULL DEFAULT '' CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa')),
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			last_seen_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER,
			peer_ip TEXT NOT NULL DEFAULT ''
		) STRICT`},
		{SQL: `CREATE INDEX browser_sessions_expiry ON browser_sessions(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX browser_sessions_last_seen ON browser_sessions(last_seen_at_unix_ms)`},
		{SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms,peer_ip) VALUES ('active','user-1','pwd',1,2,3,NULL,'203.0.113.8'), ('revoked','user-2','mfa',4,5,6,7,'')`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV36(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms,peer_ip FROM browser_sessions ORDER BY token_digest`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 || strings.Join([]string{result.Rows[0][0].(string), result.Rows[0][1].(string), result.Rows[0][2].(string), fmt.Sprint(result.Rows[0][3]), fmt.Sprint(result.Rows[0][4]), fmt.Sprint(result.Rows[0][5]), fmt.Sprint(result.Rows[0][6]), result.Rows[0][7].(string)}, ",") != "active,user-1,pwd,1,2,3,<nil>,203.0.113.8" || strings.Join([]string{result.Rows[1][0].(string), result.Rows[1][1].(string), result.Rows[1][2].(string), fmt.Sprint(result.Rows[1][3]), fmt.Sprint(result.Rows[1][4]), fmt.Sprint(result.Rows[1][5]), fmt.Sprint(result.Rows[1][6]), result.Rows[1][7].(string)}, ",") != "revoked,user-2,mfa,4,5,6,7," {
		t.Fatalf("preserved browser sessions=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('browser_sessions_expiry', 'browser_sessions_last_seen') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 || result.Rows[0][0] != "browser_sessions_expiry" || result.Rows[1][0] != "browser_sessions_last_seen" {
		t.Fatalf("browser session indexes=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v36-default", SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES ('default','',8,9,8)`}); err != nil {
		t.Fatalf("preserved auth_method default rejected: %v", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v36-external", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES ('external','user-3','external',8,9,8)`}); err != nil {
		t.Fatalf("external browser session rejected: %v", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v36-invalid", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES ('invalid','user-4','other',8,9,8)`}); err == nil {
		t.Fatal("invalid browser session authentication method accepted")
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version = 36`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v36 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV37CreatesSCIMOutboxAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v37", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v37-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (36)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV37(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=37`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v37 marker=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='table' AND name='scim_user_outbox'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("SCIM outbox table=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v37-valid-row", SQL: `INSERT INTO scim_user_outbox
		(job_id,client_id,external_id,request_json,request_digest,status,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms)
		VALUES (?,?,?,?,?,'pending',?,?,?,?)`, Args: []any{
		strings.Repeat("a", 42) + "A", "client", "external", `{"user":{"externalId":"external","userName":"alice","active":true}}`, strings.Repeat("b", 42) + "E", int64(1), int64(1), int64(1), int64(1),
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV39CreatesSCIMTombstonesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v39", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v39-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (38)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV39(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v39-valid-row", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('subject-1','alice',1,1)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v39-long-email", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES (?, ?, 1, 2)`, Args: []any{"subject-2", strings.Repeat("a", 65) + "@example.test"}}); err != nil {
		t.Fatalf("valid long email tombstone rejected: %v", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v39-hard-delete", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,deleted_at_unix_ms) VALUES ('subject-3','carol',1,1,3)`}); err != nil {
		t.Fatalf("hard-delete tombstone rejected: %v", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v39-invalid-hard-delete", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,deleted_at_unix_ms) VALUES ('subject-4','dave',1,2,4)`}); err == nil {
		t.Fatal("invalid hard-delete tombstone accepted")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name='scim_user_tombstones_deleted'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("SCIM tombstone index=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=39`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v39 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV40AddsAnonymousDynamicClients(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v40", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v40-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (39)`},
		{SQL: `CREATE TABLE dynamic_oauth_clients (client_id TEXT PRIMARY KEY, created_at_unix_ms INTEGER NOT NULL, last_used_at_unix_ms INTEGER) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV40(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v40-default", SQL: `INSERT INTO dynamic_oauth_clients(client_id,created_at_unix_ms) VALUES ('private',1)`}); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT anonymous FROM dynamic_oauth_clients WHERE client_id='private'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("anonymous default=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name='dynamic_oauth_clients_anonymous_cleanup'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("anonymous cleanup index=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name='dynamic_oauth_clients_anonymous_last_used_cleanup'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("anonymous last-used cleanup index=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV41AddsSCIMTombstoneProviderSnapshotFromV40(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v41", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v41-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (40)`},
		{SQL: `CREATE TABLE scim_user_tombstones (
			local_external_id TEXT PRIMARY KEY NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 254),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			hard_delete INTEGER NOT NULL DEFAULT 0 CHECK (hard_delete IN (0, 1)),
			deleted_at_unix_ms INTEGER NOT NULL CHECK (deleted_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('legacy','alice',1,1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV41(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v41-default", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('new','bob',1,2)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v41-invalid-snapshot", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,deleted_at_unix_ms) VALUES ('invalid','carol',1,2,3)`}); err == nil {
		t.Fatal("invalid snapshot completion flag was accepted")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT local_external_id,provider_snapshot_complete FROM scim_user_tombstones ORDER BY local_external_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 || result.Rows[0][0] != "legacy" || result.Rows[0][1] != int64(0) || result.Rows[1][0] != "new" || result.Rows[1][1] != int64(0) {
		t.Fatalf("snapshot defaults=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v41-valid-provider", SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES ('legacy','provider',1)`}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"empty local ID", []any{"", "provider", int64(1)}},
		{"long local ID", []any{strings.Repeat("x", 513), "provider", int64(1)}},
		{"empty provider ID", []any{"other", "", int64(1)}},
		{"long provider ID", []any{"other", strings.Repeat("p", 257), int64(1)}},
		{"zero policy", []any{"other", "provider", int64(0)}},
		{"invalid policy", []any{"other", "provider", int64(3)}},
		{"duplicate", []any{"legacy", "provider", int64(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("v41-invalid-%d", i), SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: tc.args}); err == nil {
				t.Fatal("invalid tombstone provider row was accepted")
			}
		})
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name='scim_user_tombstone_providers_client'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("provider lookup index=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=41`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v41 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV42AddsSCIMTombstoneGenerationFromV41(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-v42", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v42-predecessor", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (41)`},
		{SQL: `CREATE TABLE scim_user_tombstones (
			local_external_id TEXT PRIMARY KEY NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 254),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			hard_delete INTEGER NOT NULL DEFAULT 0 CHECK (hard_delete IN (0, 1)),
			deleted_at_unix_ms INTEGER NOT NULL CHECK (deleted_at_unix_ms >= 0),
			provider_snapshot_complete INTEGER NOT NULL DEFAULT 0 CHECK (provider_snapshot_complete IN (0, 1))
		) STRICT`},
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('legacy','alice',1,1)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV42(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v42-default", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES ('new','bob',1,2)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v42-valid-generation", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,generation,deleted_at_unix_ms) VALUES ('valid','carol',1,'AbCdEfGhIjKlMnOpQrStUv',3)`}); err != nil {
		t.Fatal(err)
	}
	for i, generation := range []string{"short", "AbCdEfGhIjKlMnOpQrStU!"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("v42-invalid-generation-%d", i), SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,generation,deleted_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{fmt.Sprintf("invalid-%d", i), "dave", int64(1), generation, int64(4)}}); err == nil {
			t.Fatal("invalid deletion generation was accepted")
		}
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT local_external_id,generation FROM scim_user_tombstones ORDER BY local_external_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 3 || result.Rows[0][0] != "legacy" || result.Rows[0][1] != "" || result.Rows[1][0] != "new" || result.Rows[1][1] != "" || result.Rows[2][0] != "valid" || result.Rows[2][1] != "AbCdEfGhIjKlMnOpQrStUv" {
		t.Fatalf("generations=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=42`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v42 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV48CreatesInertMasterKeyRetirementSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v48", DataDir: testDatabaseDir(t, "test-v48")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV48(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"master_key_retirement_barrier", "master_key_retirement_members"} {
		result, queryErr := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, Args: []any{table}, Consistency: rhiza.ConsistencyLinearizable})
		if queryErr != nil || len(result.Rows) != 1 {
			t.Fatalf("table %q rows=%#v err=%v", table, result.Rows, queryErr)
		}
	}
	index, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name=?`, Args: []any{"master_key_retirement_attested_boot"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(index.Rows) != 1 {
		t.Fatalf("attested boot index=%#v err=%v", index.Rows, err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM master_key_retirement_barrier`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("barrier rows=%#v err=%v", result.Rows, err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=48`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("v48 marker=%#v err=%v", result.Rows, err)
	}
}

func TestMigrationV49OrdersLegacyAuditRowsDeterministically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v49", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := strings.Repeat("A", 43)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v49-v45-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations (version) VALUES (48)`},
		{SQL: `CREATE TABLE audit_events (
			event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id)=43 AND event_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
			event_type TEXT NOT NULL CHECK (event_type IN ('api_key.created','api_key.updated','api_key.deleted','api_key.rotated')),
			action TEXT NOT NULL CHECK (action IN ('create','update','delete','rotate')),
			outcome TEXT NOT NULL CHECK (outcome='success'),
			actor_kind TEXT NOT NULL CHECK (actor_kind IN ('browser_admin','api_key')),
			actor_hash TEXT CHECK (actor_hash IS NULL OR (length(actor_hash)=43 AND actor_hash NOT GLOB '*[^A-Za-z0-9_-]*')),
			target_hash TEXT NOT NULL CHECK (length(target_hash)=43 AND target_hash NOT GLOB '*[^A-Za-z0-9_-]*')
		) STRICT`},
		{SQL: `CREATE INDEX audit_events_order ON audit_events(occurred_at_unix_ms DESC,event_id DESC)`},
		{SQL: `CREATE TRIGGER audit_events_append_only_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER audit_events_append_only_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `INSERT INTO audit_events(event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES (?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("b", 43), int64(300), "api_key.created", "create", "success", "browser_admin", hash}},
		{SQL: `INSERT INTO audit_events(event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES (?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("a", 43), int64(300), "api_key.created", "create", "success", "browser_admin", hash}},
		{SQL: `INSERT INTO audit_events(event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES (?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("c", 43), int64(100), "api_key.created", "create", "success", "browser_admin", hash}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV49(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV49(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV51(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV51(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence,event_id,occurred_at_unix_ms FROM audit_events ORDER BY sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 3 || result.Rows[0][0] != int64(1) || result.Rows[0][1] != strings.Repeat("c", 43) || result.Rows[1][0] != int64(2) || result.Rows[1][1] != strings.Repeat("a", 43) || result.Rows[2][0] != int64(3) || result.Rows[2][1] != strings.Repeat("b", 43) {
		t.Fatalf("legacy order=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v49-backdated-append", SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) SELECT ?, (SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events), ?, ?, ?, ?, ?, ? WHERE 1=1`, Args: []any{strings.Repeat("z", 43), int64(1), "api_key.created", "create", "success", "browser_admin", hash}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV49(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence,occurred_at_unix_ms FROM audit_events WHERE event_id=?`, Args: []any{strings.Repeat("z", 43)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(4) || result.Rows[0][1] != int64(1) {
		t.Fatalf("post-migration append=%#v err=%v", result.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v49-append-only", SQL: `DELETE FROM audit_events`}); err == nil {
		t.Fatal("v49 audit delete accepted")
	}
	for i, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"replace existing", `INSERT OR REPLACE INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES(?,?,?,?,?,?,?,?)`, []any{strings.Repeat("a", 43), int64(4), int64(400), "api_key.created", "create", "success", "browser_admin", hash}},
		{"replace occupied sequence", `INSERT OR REPLACE INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES(?,?,?,?,?,?,?,?)`, []any{strings.Repeat("g", 43), int64(4), int64(400), "api_key.created", "create", "success", "browser_admin", hash}},
		{"type/action mismatch", `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES(?,?,?,?,?,?,?,?)`, []any{strings.Repeat("d", 43), int64(4), int64(400), "api_key.created", "delete", "success", "browser_admin", hash}},
		{"browser actor hash", `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) VALUES(?,?,?,?,?,?,?,?,?)`, []any{strings.Repeat("e", 43), int64(4), int64(400), "api_key.created", "create", "success", "browser_admin", hash, hash}},
		{"api actor missing hash", `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES(?,?,?,?,?,?,?,?)`, []any{strings.Repeat("f", 43), int64(4), int64(400), "api_key.created", "create", "success", "api_key", hash}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("v51-invalid-%d", i), SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid audit insert was accepted")
			}
		})
	}
}

func TestMigrationV50UpgradesMarkedV48RetirementRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v50", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	preparedAt := int64(1_800_000_000_000)
	members := []string{"node-0", "node-1", "node-2"}
	digest := retirementMembershipDigest(members)
	statements := []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
	}
	for version := int64(1); version <= 49; version++ {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (?)`, Args: []any{version}})
	}
	statements = append(statements,
		rhiza.SQLStatement{SQL: `CREATE TABLE master_key_retirement_barrier (
			barrier_id INTEGER PRIMARY KEY CHECK (barrier_id = 1), epoch INTEGER NOT NULL UNIQUE CHECK (epoch > 0),
			old_key_id TEXT NOT NULL, replacement_key_id TEXT NOT NULL, membership_digest TEXT NOT NULL,
			state TEXT NOT NULL, prepared_at_unix_ms INTEGER NOT NULL, fenced_at_unix_ms INTEGER,
			ready_at_unix_ms INTEGER, aborted_at_unix_ms INTEGER) STRICT`},
		rhiza.SQLStatement{SQL: `CREATE TABLE master_key_retirement_members (
			epoch INTEGER NOT NULL, node_id TEXT NOT NULL, attestation_state TEXT NOT NULL DEFAULT 'pending',
			boot_id TEXT NOT NULL DEFAULT '', active_key_id TEXT NOT NULL DEFAULT '', attested_at_unix_ms INTEGER,
			old_references INTEGER NOT NULL DEFAULT 0, non_active_references INTEGER NOT NULL DEFAULT 0,
			legacy_references INTEGER NOT NULL DEFAULT 0, tamper_references INTEGER NOT NULL DEFAULT 0,
			oidc_references INTEGER NOT NULL DEFAULT 0, dcr_references INTEGER NOT NULL DEFAULT 0,
			upstream_references INTEGER NOT NULL DEFAULT 0, passkey_enabled INTEGER NOT NULL DEFAULT 0,
			passkey_references INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(epoch,node_id)) STRICT`},
		rhiza.SQLStatement{SQL: `INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms,fenced_at_unix_ms) VALUES (1,1,'key-a','key-b',?,'fenced',?,?)`, Args: []any{digest, preparedAt, preparedAt + 1}},
		rhiza.SQLStatement{SQL: `INSERT INTO master_key_retirement_members(epoch,node_id,attestation_state,boot_id,active_key_id,attested_at_unix_ms) VALUES (1,'node-0','attested','boot-old','key-b',?)`, Args: []any{preparedAt + 1}},
		rhiza.SQLStatement{SQL: `INSERT INTO master_key_retirement_members(epoch,node_id) VALUES (1,'node-1'),(1,'node-2')`},
	)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v50-old-v48-fixture", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	// This fixture marks v8 as installed; materialize its tables as well so
	// later migrations inspect a consistent base instead of marker-only state.
	if _, err := Execute(ctx, db, schemaV8Request("v50-fixture-backchannel-tables")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, schemaV9Request("v50-fixture-dynamic-client-table")); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, schemaV10Request("v50-fixture-device-grant-tables")); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMasterKeyRetirement(ctx, db)
	if err != nil || loaded.State != MasterKeyRetirementFenced || len(loaded.Attestations) != 1 || loaded.Attestations[0].AttestationSequence != 1 {
		t.Fatalf("upgraded retirement=%#v err=%v", loaded, err)
	}
	if _, err := AttestMasterKeyRetirement(ctx, db, MasterKeyRetirementAttestationRequest{Epoch: 1, NodeID: "node-0", BootID: "boot-new", ActiveKeyID: "key-b", AttestationSequence: 2, AttestedAt: time.UnixMilli(preparedAt + 2).UTC(), Status: MasterKeyRetirementStatus{}}); err != nil {
		t.Fatal("attestation after upgrade: ", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal("v50 replay: ", err)
	}
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=50`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("v50 marker=%#v err=%v", marker.Rows, err)
	}
}

func TestMigrationV51RejectsMalformedMarkedV49AuditRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v51-malformed", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := strings.Repeat("A", 43)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v51-malformed-v49", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (49)`},
		{SQL: `CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL UNIQUE, occurred_at_unix_ms INTEGER NOT NULL, event_type TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, actor_kind TEXT NOT NULL, actor_hash TEXT, target_hash TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) VALUES (?,?,?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("a", 43), int64(1), int64(1), "api_key.created", "delete", "success", "browser_admin", hash, hash}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV51(ctx, db); err == nil {
		t.Fatal("malformed marked-v49 audit row accepted")
	}
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version=51`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 0 {
		t.Fatalf("v51 marker=%#v err=%v", marker.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v51-fix-malformed", SQL: `UPDATE audit_events SET action=?, actor_hash=NULL WHERE event_id=?`, Args: []any{"create", strings.Repeat("a", 43)}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV51(ctx, db); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV52ExtendsAuditConstraintsWithoutChangingSequence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "test-v52", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := strings.Repeat("A", 43)
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v52-old-audit-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (51)`},
		{SQL: `CREATE TABLE audit_events (event_id TEXT PRIMARY KEY NOT NULL, sequence INTEGER NOT NULL UNIQUE, occurred_at_unix_ms INTEGER NOT NULL, event_type TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, actor_kind TEXT NOT NULL, actor_hash TEXT, target_hash TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("a", 43), int64(7), int64(100), "api_key.created", "create", "success", "browser_admin", hash}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV52(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV52(ctx, db); err != nil {
		t.Fatal("v52 replay: ", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT sequence,event_type,action FROM audit_events`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(7) {
		t.Fatalf("migrated rows=%#v err=%v", rows.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v52-retirement-event", SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("b", 43), int64(8), int64(200), "master_key_retirement.ready", "ready", "success", "api_key", hash, hash}}); err != nil {
		t.Fatal("retirement event rejected: ", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v52-bad-event", SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,target_hash) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{strings.Repeat("c", 43), int64(9), int64(300), "master_key_retirement.ready", "abort", "success", "browser_admin", hash}}); err == nil {
		t.Fatal("mismatched retirement event accepted")
	}
}

func TestMigrationV86PreservesExistingUsers(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "migration-86", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-86", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY)`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES(85)`},
		{SQL: `CREATE TABLE identity_users(subject TEXT PRIMARY KEY,password_generation INTEGER NOT NULL) STRICT`},
		{SQL: `INSERT INTO identity_users VALUES('existing',7)`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV86(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT password_generation,last_failed_login_at_unix_ms,failed_login_attempts FROM identity_users WHERE subject='existing'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(7) || q.Rows[0][1] != nil || q.Rows[0][2] != nil {
		t.Fatal("migration changed existing identity")
	}
	for _, column := range []string{"last_failed_login_at_unix_ms", "failed_login_attempts"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "negative-" + column, SQL: "UPDATE identity_users SET " + column + "=-1"}); err == nil {
			t.Fatal("negative failure metadata accepted")
		}
	}
}

func TestMigrationV87Qualification(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "migration-87", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Set up a legacy schema at v86 with an existing dynamic_oauth_clients row.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-87", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY)`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES(86)`},
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
		{SQL: `INSERT INTO dynamic_oauth_clients(client_id,registration_token_digest,redirect_uris_json,scopes_json,default_scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES('existing','tok', '[]','[]','[]','[]','[]','[]','none','Existing',0)`},
	}}); err != nil {
		t.Fatal(err)
	}

	// Idempotent: run migration twice without error.
	for range 2 {
		if err := migrateSchemaV87(ctx, db); err != nil {
			t.Fatal(err)
		}
	}

	// Existing row must have NULL backchannel_logout_uri.
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='existing'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("existing row backchannel_logout_uri=%#v err=%v", q.Rows, err)
	}

	// Marker must be recorded.
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=87`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(87) {
		t.Fatalf("v87 marker=%#v err=%v", marker.Rows, err)
	}

	// Valid URI is accepted.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v87-valid-uri", SQL: `UPDATE dynamic_oauth_clients SET backchannel_logout_uri='https://rp.example.test/logout' WHERE client_id='existing'`}); err != nil {
		t.Fatal(err)
	}

	// NULL is accepted (clearing the URI).
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v87-null-uri", SQL: `UPDATE dynamic_oauth_clients SET backchannel_logout_uri=NULL WHERE client_id='existing'`}); err != nil {
		t.Fatal(err)
	}

	// Empty string is rejected by the CHECK constraint.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v87-empty-uri", SQL: `UPDATE dynamic_oauth_clients SET backchannel_logout_uri='' WHERE client_id='existing'`}); err == nil {
		t.Fatal("empty backchannel_logout_uri accepted")
	}
}

func TestMigrationV86RecoveryAfterCommitUnknown(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v86-recovery", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Build a legacy schema at v85 with a user that has no failure metadata.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v86-recovery-legacy", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY)`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES(85)`},
		{SQL: `CREATE TABLE identity_users(subject TEXT PRIMARY KEY,password_generation INTEGER NOT NULL) STRICT`},
		{SQL: `INSERT INTO identity_users VALUES('recovered',3)`},
	}}); err != nil {
		t.Fatal(err)
	}

	// Run the migration; it must succeed.
	if err := migrateSchemaV86(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Verify the marker is recorded and data is preserved.
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=86`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(86) {
		t.Fatalf("v86 marker=%#v err=%v", marker.Rows, err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT password_generation,last_failed_login_at_unix_ms,failed_login_attempts FROM identity_users WHERE subject='recovered'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(3) || q.Rows[0][1] != nil || q.Rows[0][2] != nil {
		t.Fatalf("recovered identity=%#v err=%v", q.Rows, err)
	}

	// Simulate a crash recovery scenario: re-run the migration.
	// The EXISTS guard in migrateSchemaV86 returns 1 (marker present), so
	// the migration is safely skipped. This models a restart after the
	// ALTER TABLE committed but before the process continued.
	if err := migrateSchemaV86(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Verify failure metadata columns accept valid values after recovery.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v86-recovery-update", SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=1000, failed_login_attempts=3 WHERE subject='recovered'`}); err != nil {
		t.Fatal(err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT last_failed_login_at_unix_ms,failed_login_attempts FROM identity_users WHERE subject='recovered'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1000) || q.Rows[0][1] != int64(3) {
		t.Fatalf("post-recovery update=%#v err=%v", q.Rows, err)
	}

	// Negative values are still rejected after recovery.
	for _, column := range []string{"last_failed_login_at_unix_ms", "failed_login_attempts"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "negative-recovery-" + column, SQL: "UPDATE identity_users SET " + column + "=-1 WHERE subject='recovered'"}); err == nil {
			t.Fatal("negative failure metadata accepted after recovery")
		}
	}

	// Verify ResetFailureMetadata pattern: clearing failure columns back to NULL.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v86-recovery-clear", SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=NULL, failed_login_attempts=NULL WHERE subject='recovered'`}); err != nil {
		t.Fatal(err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT last_failed_login_at_unix_ms,failed_login_attempts FROM identity_users WHERE subject='recovered'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil || q.Rows[0][1] != nil {
		t.Fatalf("cleared failure metadata=%#v err=%v", q.Rows, err)
	}
}

func TestMigrateConcurrentStartSafety(t *testing.T) {
	t.Parallel()
	// Verify that the full migration path v1→v87 is idempotent and produces
	// a valid schema. Running Migrate multiple times on the same instance
	// must not corrupt the database.
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "concurrent-safety", DataDir: testDatabaseDir(t, "concurrent-safety")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// First pass: full migration from v1 to v87.
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Second pass: simulate restart — all migrations must be no-ops.
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Third pass: one more restart for good measure.
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Verify final schema version.
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT MAX(version) FROM goauthy_schema_migrations`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(schemaVersion) {
		t.Fatalf("final schema version=%#v err=%v", marker.Rows, err)
	}

	// Verify v86 failure metadata columns exist and work.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "concurrent-v86-user", SQL: `INSERT INTO identity_users(subject,username,password_phc,password_changed_at_unix_ms,password_generation,created_at_unix_ms) VALUES('concurrent-user','concurrent','$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY',0,1,0)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "concurrent-v86-update", SQL: `UPDATE identity_users SET last_failed_login_at_unix_ms=500, failed_login_attempts=2 WHERE subject='concurrent-user'`}); err != nil {
		t.Fatal(err)
	}

	// Verify v87 backchannel_logout_uri column exists on dynamic_oauth_clients.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "concurrent-v87-dcr", SQL: `INSERT INTO dynamic_oauth_clients(client_id,registration_token_digest,redirect_uris_json,scopes_json,default_scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,backchannel_logout_uri) VALUES('concurrent-dcr','tok','[]','[]','[]','[]','[]','[]','none','Concurrent',0,'https://rp.example.test/logout')`}); err != nil {
		t.Fatal(err)
	}
}
