package storage

import (
	"context"
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV74ReconnectAuthorizationVersionDefaultAndReplay(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "reconnect-schema-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-foundation", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE auth_collection_definitions(id TEXT PRIMARY KEY,providers_json TEXT NOT NULL) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	// Use the original table migrations so legacy constraints and indexes are real.
	if err := migrateSchemaV69(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV73(ctx, db); err != nil {
		t.Fatal(err)
	}
	blob := []byte{1, 2, 3, 4}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "legacy-auth-row", SQL: `INSERT INTO saas_authorization_requests(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms,verifier_envelope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"state", "verifier", "session", "provider", "owner", "collection", "connection", "provider", "generation", int64(1), int64(2), blob}}); err != nil {
		t.Fatal(err)
	}
	if err = migrateSchemaV74(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = migrateSchemaV74(ctx, db); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms,verifier_envelope,token_version FROM saas_authorization_requests`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 13 {
		t.Fatalf("row=%v err=%v", q.Rows, err)
	}
	want := []any{"state", "verifier", "session", "provider", "owner", "collection", "connection", "provider", "generation", int64(1), int64(2), blob, int64(1)}
	if !reflect.DeepEqual(q.Rows[0], want) {
		t.Fatalf("legacy row changed: %v", q.Rows[0])
	}
	m, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=74`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(m.Rows) != 1 || m.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", m.Rows, err)
	}
}
