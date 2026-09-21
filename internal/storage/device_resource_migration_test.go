package storage

import (
	"context"
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV75DeviceResourcePreservesLegacyRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "device-resource-schema", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-v74-device", Statements: []rhiza.SQLStatement{{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY)`}, {SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(1),(69),(70),(71),(72),(73),(74)`}, {SQL: `CREATE TABLE oauth_device_grants(device_code_digest TEXT PRIMARY KEY NOT NULL,user_code_digest TEXT NOT NULL UNIQUE,client_id TEXT NOT NULL,scopes_json TEXT NOT NULL,subject TEXT,state TEXT NOT NULL,decision_attempt TEXT,expires_at_unix_ms INTEGER NOT NULL,interval_seconds INTEGER NOT NULL,next_poll_at_unix_ms INTEGER NOT NULL,claim_token_digest TEXT,claim_until_unix_ms INTEGER,created_at_unix_ms INTEGER NOT NULL,token_request_id TEXT,revoked_at_unix_ms INTEGER,managed_client_generation TEXT) STRICT`}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-device-row", SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,decision_attempt,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,created_at_unix_ms,token_request_id,revoked_at_unix_ms,managed_client_generation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"device", "user", "client", `["openid"]`, "subject", "approved", "attempt", int64(100), int64(5), int64(10), "claim", int64(20), int64(1), "token-request", int64(30), "generation"}}); err != nil {
		t.Fatal(err)
	}
	original, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT device_code_digest,user_code_digest,client_id,scopes_json,subject,state,decision_attempt,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,created_at_unix_ms,token_request_id,revoked_at_unix_ms,managed_client_generation FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(original.Rows) != 1 {
		t.Fatalf("original=%v err=%v", original.Rows, err)
	}
	if err = migrateSchemaV75(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = migrateSchemaV75(ctx, db); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT device_code_digest,user_code_digest,client_id,scopes_json,subject,state,decision_attempt,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,created_at_unix_ms,token_request_id,revoked_at_unix_ms,managed_client_generation,resource FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 17 {
		t.Fatalf("row=%v err=%v", q.Rows, err)
	}
	if !reflect.DeepEqual(q.Rows[0][:16], original.Rows[0]) || q.Rows[0][16] != nil {
		t.Fatalf("legacy changed=%v", q.Rows[0])
	}
	m, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=75`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(m.Rows) != 1 || m.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", m.Rows, err)
	}
}
