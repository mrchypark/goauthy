package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV76CreatesUseGrantsFromPre76Fixture(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "migration-v76", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v76-preflight", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(75)`},
		{SQL: `CREATE TABLE oauth_device_grants (device_code_digest TEXT PRIMARY KEY NOT NULL, resource TEXT)`},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,resource) VALUES('device','https://resource.example.test')`},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV76(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v76-use-grant-row", SQL: `INSERT INTO saas_use_grants (id,owner_subject,collection_id,connection_id,consumer_client_id,mode,purpose,resource,generation,consumer_generation,provider_id,connector_digest,provider_revision,expires_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{
		"use-1", "owner", "collection", "connection", "consumer", "proxy", "use", "https://resource.example.test", "gen-1", "consumer-gen-1", "provider", "digest", int64(3), int64(9999),
	}}); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT mode,provider_revision,revision,revoked FROM saas_use_grants WHERE id='use-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "proxy" || row.Rows[0][1] != int64(3) || row.Rows[0][2] != int64(1) || row.Rows[0][3] != int64(0) {
		t.Fatalf("use grant row=%#v err=%v", row.Rows, err)
	}
	device, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT resource FROM oauth_device_grants WHERE device_code_digest='device'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(device.Rows) != 1 || device.Rows[0][0] != "https://resource.example.test" {
		t.Fatalf("device row=%#v err=%v", device.Rows, err)
	}
}
