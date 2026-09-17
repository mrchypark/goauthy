package storage

import (
	"bytes"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV95CreatesFinalAuthProvidersShape(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "auth-provider-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-provider-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}

	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}

	columns, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,type,"notnull",dflt_value,pk FROM pragma_table_info('auth_providers') ORDER BY cid`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	wantColumns := []struct {
		name, typ           string
		defaultValue        any
		notNull, primaryKey int64
	}{
		{"id", "TEXT", nil, int64(1), int64(1)},
		{"enabled", "INTEGER", nil, int64(1), int64(0)},
		{"name", "TEXT", nil, int64(1), int64(0)},
		{"typ", "TEXT", nil, int64(1), int64(0)},
		{"issuer", "TEXT", nil, int64(1), int64(0)},
		{"authorization_endpoint", "TEXT", nil, int64(1), int64(0)},
		{"token_endpoint", "TEXT", nil, int64(1), int64(0)},
		{"userinfo_endpoint", "TEXT", nil, int64(1), int64(0)},
		{"client_id", "TEXT", nil, int64(1), int64(0)},
		{"secret", "BLOB", nil, int64(0), int64(0)},
		{"scope", "TEXT", nil, int64(1), int64(0)},
		{"admin_claim_path", "TEXT", nil, int64(0), int64(0)},
		{"admin_claim_value", "TEXT", nil, int64(0), int64(0)},
		{"mfa_claim_path", "TEXT", nil, int64(0), int64(0)},
		{"mfa_claim_value", "TEXT", nil, int64(0), int64(0)},
		{"use_pkce", "INTEGER", nil, int64(1), int64(0)},
		{"client_secret_basic", "INTEGER", "1", int64(1), int64(0)},
		{"client_secret_post", "INTEGER", "1", int64(1), int64(0)},
		{"jwks_endpoint", "TEXT", nil, int64(0), int64(0)},
		{"auto_onboarding", "INTEGER", "1", int64(1), int64(0)},
		{"auto_link", "INTEGER", "0", int64(1), int64(0)},
	}
	if len(columns.Rows) != len(wantColumns) {
		t.Fatalf("auth_providers columns=%d want=%d rows=%#v", len(columns.Rows), len(wantColumns), columns.Rows)
	}
	for i, want := range wantColumns {
		row := columns.Rows[i]
		if len(row) != 5 || row[0] != want.name || row[1] != want.typ || row[2] != want.notNull || row[3] != want.defaultValue || row[4] != want.primaryKey {
			t.Fatalf("auth_providers column %d=%#v want=(%q,%q,%d,%v,%d)", i, row, want.name, want.typ, want.notNull, want.defaultValue, want.primaryKey)
		}
	}
	if got := queryInt64(t, db, "SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=95"); got != 1 {
		t.Fatalf("schema 95 markers=%d want=1", got)
	}

	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-provider-defaults", SQL: "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)", Args: []any{
		"defaults", int64(1), "Defaults", "oidc", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "client-default", "openid", int64(1),
	}}); err != nil {
		t.Fatal(err)
	}
	row := queryAuthProvider(t, db, "defaults")
	if row[0] != "defaults" || row[1] != int64(1) || row[2] != "Defaults" || row[3] != "oidc" || row[4] != "https://issuer.example" || row[9] != nil || row[11] != nil || row[12] != nil || row[13] != nil || row[14] != nil || row[18] != nil || row[16] != int64(1) || row[17] != int64(1) || row[19] != int64(1) || row[20] != int64(0) {
		t.Fatalf("default/null auth provider=%#v", row)
	}

	secret := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-provider-opaque", SQL: "INSERT INTO auth_providers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", Args: []any{
		"opaque", int64(0), "Opaque", "custom", "https://opaque.example", "https://opaque.example/auth", "https://opaque.example/token", "https://opaque.example/userinfo", "client-opaque", secret, "openid profile", "$.admin", "yes", "$.mfa", "required", int64(0), int64(0), int64(1), "https://opaque.example/jwks", int64(0), int64(1),
	}}); err != nil {
		t.Fatal(err)
	}
	row = queryAuthProvider(t, db, "opaque")
	if row[0] != "opaque" || row[1] != int64(0) || row[2] != "Opaque" || row[3] != "custom" || row[4] != "https://opaque.example" || row[5] != "https://opaque.example/auth" || row[6] != "https://opaque.example/token" || row[7] != "https://opaque.example/userinfo" || row[8] != "client-opaque" || !bytes.Equal(row[9].([]byte), secret) || row[10] != "openid profile" || row[11] != "$.admin" || row[12] != "yes" || row[13] != "$.mfa" || row[14] != "required" || row[15] != int64(0) || row[16] != int64(0) || row[17] != int64(1) || row[18] != "https://opaque.example/jwks" || row[19] != int64(0) || row[20] != int64(1) {
		t.Fatalf("opaque auth provider=%#v", row)
	}
}

func TestMigrationV95FullPathIsIdempotentAndReady(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "auth-provider-migration-full", DataDir: t.TempDir()})
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

func queryAuthProvider(t *testing.T, db *rhiza.DB, id string) []any {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link FROM auth_providers WHERE id=?", Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 21 {
		t.Fatalf("auth provider %s=%#v err=%v", id, result.Rows, err)
	}
	return result.Rows[0]
}
