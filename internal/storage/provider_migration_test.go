package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV71CreatesSaaSProvidersAndReplays(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "provider-migration", DataDir: testDatabaseDir(t, "provider-migration")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='table' AND name='saas_providers'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("table=%v err=%v", rows.Rows, err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=71`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
	if err := Ready(t.Context(), db); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaV72AddsOAuthIdentityColumnsAndReplays(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "provider-migration-v72", DataDir: testDatabaseDir(t, "provider-migration-v72")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('saas_providers') WHERE name IN ('identity_endpoint','subject_field') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("identity columns=%v err=%v", rows.Rows, err)
	}
	if err := Ready(t.Context(), db); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaV72PreservesExistingProvider(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "provider-migration-preserve", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "provider-migration-marker", SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV71(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	args := []any{"legacy", "Legacy", "oauth2", int64(1), int64(7), "https://auth.example/callback", "client", "https://provider.example/auth", "https://provider.example/token", `["openid"]`, "header", "", "generation-7", []byte("fixed-envelope")}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "provider-migration-row", SQL: `INSERT INTO saas_providers(id,name,kind,enabled,revision,callback_uri,client_id,auth_endpoint,token_endpoint,scopes_json,auth_style,connector_json,generation,secret_envelope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: args}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV72(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV72(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id,name,kind,enabled,revision,callback_uri,client_id,auth_endpoint,token_endpoint,scopes_json,auth_style,identity_endpoint,subject_field,connector_json,generation,secret_envelope FROM saas_providers WHERE id='legacy'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 16 {
		t.Fatalf("provider=%v err=%v", rows.Rows, err)
	}
	row := rows.Rows[0]
	if row[0] != "legacy" || row[1] != "Legacy" || row[2] != "oauth2" || row[3] != int64(1) || row[4] != int64(7) || row[5] != "https://auth.example/callback" || row[6] != "client" || row[7] != "https://provider.example/auth" || row[8] != "https://provider.example/token" || row[9] != `["openid"]` || row[10] != "header" || row[11] != "" || row[12] != "" || row[13] != "" || row[14] != "generation-7" || string(row[15].([]byte)) != "fixed-envelope" {
		t.Fatalf("provider changed: %#v", row)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=72`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
}
