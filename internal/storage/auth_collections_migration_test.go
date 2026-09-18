package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV64AuthCollectionsTables(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "auth-collections-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='table' AND name IN ('auth_collection_definitions','auth_collection_connections') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("tables=%#v err=%v", rows.Rows, err)
	}
	version, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=64)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(version.Rows) != 1 || version.Rows[0][0] != int64(1) {
		t.Fatalf("schema v64=%#v err=%v", version.Rows, err)
	}
}
