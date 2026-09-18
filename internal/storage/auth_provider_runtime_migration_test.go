package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV96CreatesRuntimeVersionTable(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "runtime-version-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "runtime-version-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}

	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}

	columns, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,type,"notnull",dflt_value,pk FROM pragma_table_info('auth_provider_runtime_versions') ORDER BY cid`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	wantColumns := []struct {
		name, typ           string
		defaultValue        any
		notNull, primaryKey int64
	}{
		{"provider_id", "TEXT", nil, int64(1), int64(1)},
		{"version", "TEXT", nil, int64(1), int64(0)},
	}
	if len(columns.Rows) != len(wantColumns) {
		t.Fatalf("auth_provider_runtime_versions columns=%d want=%d", len(columns.Rows), len(wantColumns))
	}
	for i, want := range wantColumns {
		row := columns.Rows[i]
		if len(row) != 5 || row[0] != want.name || row[1] != want.typ || row[2] != want.notNull || row[3] != want.defaultValue || row[4] != want.primaryKey {
			t.Fatalf("column %d=%#v want=(%q,%q,%d,%v,%d)", i, row, want.name, want.typ, want.notNull, want.defaultValue, want.primaryKey)
		}
	}
	if got := queryInt64(t, db, "SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=96"); got != 1 {
		t.Fatalf("schema 96 markers=%d want=1", got)
	}
}

func TestMigrationV96BackfillsExistingProviders(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "runtime-version-backfill", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "backfill-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"prov-alpha", "prov-beta"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "seed-" + id,
			SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
			Args:      []any{id, int64(1), id, "oidc", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-" + id, "openid", int64(1)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"prov-alpha", "prov-beta"} {
		result, err := db.Query(ctx, rhiza.QueryRequest{
			SQL:         "SELECT version FROM auth_provider_runtime_versions WHERE provider_id=?",
			Args:        []any{id},
			Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatalf("provider %s: version row missing", id)
		}
		ver, ok := result.Rows[0][0].(string)
		if !ok {
			t.Fatalf("provider %s: version not string", id)
		}
		want := "migration-v96/" + id
		if ver != want {
			t.Fatalf("provider %s: version=%q want=%q", id, ver, want)
		}
	}
	total, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM auth_provider_runtime_versions", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if total.Rows[0][0] != int64(2) {
		t.Fatalf("version rows=%v want=2", total.Rows[0][0])
	}
}

func TestMigrationV96FullPathIsIdempotentAndReady(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "runtime-version-full", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for range 2 {
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := Ready(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != int64(schemaVersion) {
		t.Fatalf("schema version=%d want=%d", got, schemaVersion)
	}
}
