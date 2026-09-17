package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV65ManagedDeviceGeneration(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "managed-device-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name,type FROM pragma_table_info('oauth_device_grants') WHERE name='managed_client_generation'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][1] != "TEXT" {
		t.Fatalf("generation column=%v error=%v", result.Rows, err)
	}
	result, err = db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=65`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("migration marker=%v error=%v", result.Rows, err)
	}
}

func TestSchemaV65PreservesExistingDeviceGrant(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "managed-device-upgrade", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The additive migration must preserve pre-existing bootstrap/DCR grants.
	_, err = Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "legacy-device-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE oauth_device_grants(device_code_digest TEXT PRIMARY KEY,client_id TEXT,state TEXT) STRICT`},
		{SQL: `INSERT INTO oauth_device_grants VALUES('legacy-code','bootstrap-client','pending')`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateSchemaV65(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,state,managed_client_generation FROM oauth_device_grants WHERE device_code_digest='legacy-code'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "bootstrap-client" || rows.Rows[0][1] != "pending" || rows.Rows[0][2] != nil {
		t.Fatalf("legacy grant changed rows=%v error=%v", rows.Rows, err)
	}
}

func TestSchemaV66PreservesLegacyRowsAndIndexesTokenRequests(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "managed-device-v66", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "legacy-device-v66-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE oauth_device_grants(device_code_digest TEXT PRIMARY KEY,client_id TEXT,state TEXT) STRICT`},
		{SQL: `INSERT INTO oauth_device_grants VALUES('legacy-code','bootstrap-client','pending')`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV65(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v66-legacy-row", SQL: `INSERT INTO oauth_device_grants(device_code_digest,client_id,state) VALUES('legacy-code-2','bootstrap-client-2','consumed')`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV66(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV66(t.Context(), db); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,state,managed_client_generation,token_request_id,revoked_at_unix_ms FROM oauth_device_grants ORDER BY device_code_digest`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 || rows.Rows[0][0] != "bootstrap-client" || rows.Rows[1][0] != "bootstrap-client-2" {
		t.Fatalf("legacy grants changed rows=%v error=%v", rows.Rows, err)
	}
	for i, row := range rows.Rows {
		if row[1] != []string{"pending", "consumed"}[i] || row[2] != nil || row[3] != nil || row[4] != nil {
			t.Fatalf("legacy grant fields changed rows=%v", rows.Rows)
		}
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v66-token-request", SQL: `UPDATE oauth_device_grants SET token_request_id='request-1' WHERE device_code_digest='legacy-code'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v66-duplicate-token-request", SQL: `UPDATE oauth_device_grants SET token_request_id='request-1' WHERE device_code_digest='legacy-code-2'`}); err == nil {
		t.Fatal("duplicate non-null token_request_id was accepted")
	}
}
