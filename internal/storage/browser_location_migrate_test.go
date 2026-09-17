package storage

import (
	"github.com/mrchypark/rhiza"
	"reflect"
	"testing"
)

func TestMigrationV91PreservesLoginLocations(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "browser-location-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "location-migration-table", SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if err = migrateSchemaV88(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "location-migration-fixture", SQL: `INSERT INTO identity_login_locations VALUES('alice','192.0.2.1',100,200,3)`}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV91(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count,browser_id,user_agent,location FROM identity_login_locations`, Consistency: rhiza.ConsistencyLinearizable})
	want := [][]any{{"alice", "192.0.2.1", int64(100), int64(200), int64(3), "", "", nil}}
	if err != nil || !reflect.DeepEqual(rows.Rows, want) {
		t.Fatalf("rows=%v err=%v", rows.Rows, err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "location-second-browser", SQL: `INSERT INTO identity_login_locations(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,browser_id,user_agent,location) VALUES('alice','192.0.2.1',300,300,'browser-2','Browser','City')`}); err != nil {
		t.Fatal(err)
	}
	rows, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_login_locations`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("browser rows=%v err=%v", rows.Rows, err)
	}
}
