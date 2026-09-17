package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV84UpstreamLogoutReceipts(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "upstream-logout-v84", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=84`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "upstream-logout-v84-receipt", SQL: `INSERT INTO upstream_logout_receipts(issuer,client_id,jti,token_digest,operation_id,upstream_subject,upstream_sid,expires_at_unix_ms,created_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"https://issuer.example.test", "client", "jti", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA", "subject", "sid", int64(2), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV84(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT issuer,client_id,jti FROM upstream_logout_receipts`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "https://issuer.example.test" {
		t.Fatalf("rows=%v err=%v", rows.Rows, err)
	}
}
