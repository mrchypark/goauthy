package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV55KVIsIdempotentAndCascades(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "kv-test", DataDir: testDatabaseDir(t, "kv-test")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV55(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "kv-v55-shape", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO kv_namespaces(name,identity,public) VALUES ('test','test-identity',1)`},
		{SQL: `INSERT INTO kv_values(namespace,key,value) VALUES ('test','k',?)`, Args: []any{[]byte(`true`)}},
		{SQL: `INSERT INTO kv_access(id,namespace,secret,secret_digest) VALUES ('a','test',?,?)`, Args: []any{[]byte("secret"), "digest"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "kv-v55-rename", SQL: `UPDATE kv_namespaces SET name='renamed' WHERE name='test'`}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"kv_values", "kv_access"} {
		r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table + ` WHERE namespace='renamed'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != int64(1) {
			t.Fatalf("rename cascade %s=%v err=%v", table, r.Rows, err)
		}
	}
	if _, err := Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "kv-v55-delete", SQL: `DELETE FROM kv_namespaces WHERE name='renamed'`}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"kv_values", "kv_access"} {
		r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != int64(0) {
			t.Fatalf("delete cascade %s=%v err=%v", table, r.Rows, err)
		}
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT name FROM kv_namespaces WHERE name='default'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("default namespace rows=%v err=%v", rows.Rows, err)
	}
}
