package storage

import (
	"github.com/mrchypark/rhiza"
	"testing"
)

func TestSchemaV110LegacyDeviceApprovalHasNoMFA(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "device-mfa-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "legacy-device-mfa", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE oauth_device_grants(device_code_digest TEXT PRIMARY KEY,state TEXT) STRICT`},
		{SQL: `INSERT INTO oauth_device_grants VALUES('legacy','approved')`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateSchemaV110(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state,mfa_verified FROM oauth_device_grants WHERE device_code_digest='legacy'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != int64(0) {
		t.Fatalf("legacy evidence=%v err=%v", rows.Rows, err)
	}
}
