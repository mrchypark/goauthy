package storage

import (
	"github.com/mrchypark/rhiza"
	"testing"
)

func TestMigrationV93LogoResolutions(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "logo-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "logo-ledger", SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV93(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	for _, res := range []string{"small", "medium", "favicon"} {
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "logo-" + res, SQL: `INSERT INTO client_logos VALUES('client',?,'image/webp',?,1)`, Args: []any{res, []byte{1}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "logo-invalid", SQL: `INSERT INTO client_logos VALUES('client','invalid','image/webp',?,1)`, Args: []any{[]byte{1}}}); err == nil {
		t.Fatal("invalid resolution accepted")
	}
	result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_logos`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || result.Rows[0][0] != int64(3) {
		t.Fatalf("logo rows=%v err=%v", result.Rows, err)
	}
}
