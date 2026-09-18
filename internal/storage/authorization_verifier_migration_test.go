package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV73AuthorizationVerifierMigrationReplay(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "schema-v73-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=73`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", q.Rows, err)
	}
	cols, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM pragma_table_info('saas_authorization_requests') WHERE name='verifier_envelope'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(cols.Rows) != 1 || cols.Rows[0][0] != int64(1) {
		t.Fatalf("column=%v err=%v", cols.Rows, err)
	}
}
