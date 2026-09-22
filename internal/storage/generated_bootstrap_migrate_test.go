package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV85GeneratedAPIKeyBootstrapContract(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "generated-bootstrap-v85", DataDir: testDatabaseDir(t, "generated-bootstrap-v85")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("migration rerun: %v", err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=85`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "generated-bootstrap-v85-insert", SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{"digest", []byte{1}, int64(2), int64(3)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "generated-bootstrap-v85-expire", SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=NULL WHERE singleton=1`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "generated-bootstrap-v85-tombstone-ack", SQL: `UPDATE generated_api_key_bootstrap SET created_at_unix_ms=created_at_unix_ms WHERE singleton=1 AND config_digest=? AND payload_envelope IS NULL`, Args: []any{"digest"}}); err != nil {
		t.Fatalf("durable tombstone acknowledgement: %v", err)
	}
	for i, statement := range []rhiza.ExecuteRequest{
		{RequestID: "generated-bootstrap-v85-revive", SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=? WHERE singleton=1`, Args: []any{[]byte{2}}},
		{RequestID: "generated-bootstrap-v85-metadata", SQL: `UPDATE generated_api_key_bootstrap SET deadline_unix_s=4 WHERE singleton=1`},
		{RequestID: "generated-bootstrap-v85-duplicate", SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{"other", []byte{2}, int64(4), int64(5)}},
	} {
		if _, err := Execute(t.Context(), db, statement); err == nil {
			t.Fatalf("invalid mutation %d committed", i)
		}
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "digest" || rows.Rows[0][1] != nil || rows.Rows[0][2] != int64(2) || rows.Rows[0][3] != int64(3) {
		t.Fatalf("row=%v err=%v", rows.Rows, err)
	}
}
