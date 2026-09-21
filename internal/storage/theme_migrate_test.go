package storage

import (
	"github.com/mrchypark/rhiza"
	"testing"
)

func TestMigrationV92ThemeDocumentConstraints(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "theme-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "theme-ledger", SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateSchemaV92(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		id, document string
		valid        bool
	}{
		{"theme-valid", `{"client_id":"theme-valid"}`, true},
		{"theme-array", `[]`, false},
		{"theme-broken", `{`, false},
	} {
		_, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: tc.id, SQL: `INSERT INTO client_themes VALUES(?,1,1,?)`, Args: []any{tc.id, tc.document}})
		if (err == nil) != tc.valid {
			t.Fatalf("theme %s error=%v", tc.id, err)
		}
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_themes`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("rows=%v error=%v", rows.Rows, err)
	}
}
