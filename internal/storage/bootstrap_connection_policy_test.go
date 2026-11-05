package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV113PreservesExistingClients(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "bootstrap-policy-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-policy-v112-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES(112)`},
		{SQL: `CREATE TABLE managed_oauth_clients(id TEXT PRIMARY KEY,generation TEXT,revision INTEGER,enabled INTEGER,deleted INTEGER,metadata_json TEXT) STRICT`},
		{SQL: `INSERT INTO managed_oauth_clients VALUES('existing','original',7,1,0,'{}')`},
		{SQL: `CREATE TABLE managed_oauth_client_bootstrap(singleton INTEGER PRIMARY KEY,id TEXT) STRICT`},
		{SQL: `CREATE TABLE dynamic_oauth_clients(client_id TEXT PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE bootstrap_client_claim_scopes(client_id TEXT PRIMARY KEY,allowed_scopes_json TEXT,revision INTEGER) STRICT`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateBootstrapConnectionPolicy(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation,revision FROM connection_client_policies WHERE id='existing'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "original" || q.Rows[0][1] != int64(7) {
		t.Fatalf("managed client changed: %v %v", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM bootstrap_connection_policy`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatal("migration implicitly pinned bootstrap")
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
}
