package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

// seedAuthProviders creates the auth_providers + runtime_versions tables at
// schema v96 level and inserts two providers so v97 migration can be tested
// against real rows.
func seedAuthProviders(t *testing.T, db *rhiza.DB) {
	t.Helper()
	ctx := t.Context()
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Insert providers before v96 so the backfill picks them up.
	for _, id := range []string{"prov-oidc", "prov-custom"} {
		typ := "oidc"
		if id == "prov-custom" {
			typ = "custom"
		}
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "seed-" + id,
			SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
			Args:      []any{id, int64(1), id, typ, "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-" + id, "openid", int64(1)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationV97TriggerExists(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-trigger", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-trigger-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	seedAuthProviders(t, db)
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT name FROM sqlite_master WHERE type='trigger' AND name='auth_providers_oauth_userinfo_mode_immutable'`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("trigger not found: rows=%d", len(result.Rows))
	}
}

func TestMigrationV97RowsRetained(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-retain", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-retain-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	seedAuthProviders(t, db)
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	count, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM auth_providers", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if count.Rows[0][0] != int64(2) {
		t.Fatalf("provider count=%v want=2", count.Rows[0][0])
	}
	vcount, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM auth_provider_runtime_versions", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if vcount.Rows[0][0] != int64(2) {
		t.Fatalf("runtime version count=%v want=2", vcount.Rows[0][0])
	}
}

func TestMigrationV97CrossModeOauthUserinfoToOidcFails(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-cross-o2o", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-cross-o2o-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Insert a provider with oauth_userinfo type.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-oauth",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"prov-oauth", int64(1), "OAuth", "oauth_userinfo", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-oauth", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Attempting to change oauth_userinfo -> oidc must fail (cross-mode).
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "cross-o2o-1",
		SQL:       "UPDATE auth_providers SET typ='oidc' WHERE id='prov-oauth'",
	})
	if err == nil {
		t.Fatal("expected error for oauth_userinfo->oidc cross-mode update")
	}
	// Verify row unchanged.
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT typ FROM auth_providers WHERE id='prov-oauth'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "oauth_userinfo" {
		t.Fatalf("typ=%v want=oauth_userinfo (unchanged)", row.Rows[0][0])
	}
}

func TestMigrationV97CrossModeOidcToOauthUserinfoFails(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-cross-o2u", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-cross-o2u-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Insert a provider with oidc type.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-oidc",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"prov-oidc", int64(1), "OIDC", "oidc", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-oidc", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Attempting to change oidc -> oauth_userinfo must fail (cross-mode).
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "cross-o2u-1",
		SQL:       "UPDATE auth_providers SET typ='oauth_userinfo' WHERE id='prov-oidc'",
	})
	if err == nil {
		t.Fatal("expected error for oidc->oauth_userinfo cross-mode update")
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT typ FROM auth_providers WHERE id='prov-oidc'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "oidc" {
		t.Fatalf("typ=%v want=oidc (unchanged)", row.Rows[0][0])
	}
}

func TestMigrationV97SameModeUpdateAllowed(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-same-mode", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-same-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	seedAuthProviders(t, db)
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Same-mode oidc -> oidc (name change only).
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "same-oidc",
		SQL:       "UPDATE auth_providers SET name='OIDC-Renamed' WHERE id='prov-oidc'",
	}); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT name,typ FROM auth_providers WHERE id='prov-oidc'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "OIDC-Renamed" || row.Rows[0][1] != "oidc" {
		t.Fatalf("same-mode update failed: row=%v", row.Rows[0])
	}
	// Same-mode custom -> custom.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "same-custom",
		SQL:       "UPDATE auth_providers SET name='Custom-Renamed' WHERE id='prov-custom'",
	}); err != nil {
		t.Fatal(err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT name,typ FROM auth_providers WHERE id='prov-custom'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "Custom-Renamed" || row.Rows[0][1] != "custom" {
		t.Fatalf("same-mode custom update failed: row=%v", row.Rows[0])
	}
}

func TestMigrationV97LegacyCustomToOidcAllowed(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-legacy", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-legacy-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	seedAuthProviders(t, db)
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}
	// custom -> oidc is NOT cross-mode (neither is oauth_userinfo), so allowed.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "legacy-c2o",
		SQL:       "UPDATE auth_providers SET typ='oidc' WHERE id='prov-custom'",
	}); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT typ FROM auth_providers WHERE id='prov-custom'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "oidc" {
		t.Fatalf("typ=%v want=oidc (legacy custom->oidc allowed)", row.Rows[0][0])
	}
}

func TestMigrationV97ReplayMigrateReadyMaxVersion(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-replay", DataDir: t.TempDir()})
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
	if got := queryInt64(t, db, "SELECT MAX(version) FROM goauthy_schema_migrations"); got != 103 {
		t.Fatalf("schema version=%d want=103", got)
	}
}

func TestMigrationV97CrossModeWithinExecuteRollsBack(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-cross-exec", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-cross-exec-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Seed both providers BEFORE v96 so both get runtime version backfill.
	for _, seed := range []struct {
		id, typ string
	}{
		{"prov-oauth-exec", "oauth_userinfo"},
		{"prov-oidc-exec", "oidc"},
	} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "seed-exec-" + seed.id,
			SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
			Args:      []any{seed.id, int64(1), seed.id, seed.typ, "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-" + seed.id, "openid", int64(1)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}

	// 1. oauth_userinfo -> oidc: update version first, then cross-mode typ.
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "cross-exec-o2o",
		Statements: []rhiza.SQLStatement{
			{SQL: "UPDATE auth_provider_runtime_versions SET version='v2' WHERE provider_id='prov-oauth-exec'"},
			{SQL: "UPDATE auth_providers SET typ='oidc' WHERE id='prov-oauth-exec'"},
		},
	})
	if err == nil {
		t.Fatal("expected error for oauth_userinfo->oidc within Execute")
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT typ FROM auth_providers WHERE id='prov-oauth-exec'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "oauth_userinfo" {
		t.Fatalf("typ=%v want=oauth_userinfo (unchanged)", row.Rows[0][0])
	}
	ver, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT version FROM auth_provider_runtime_versions WHERE provider_id='prov-oauth-exec'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if ver.Rows[0][0] != "migration-v96/prov-oauth-exec" {
		t.Fatalf("version=%v want=migration-v96/prov-oauth-exec (unchanged)", ver.Rows[0][0])
	}

	// 2. oidc -> oauth_userinfo: update version first, then cross-mode typ.
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "cross-exec-o2u",
		Statements: []rhiza.SQLStatement{
			{SQL: "UPDATE auth_provider_runtime_versions SET version='v2' WHERE provider_id='prov-oidc-exec'"},
			{SQL: "UPDATE auth_providers SET typ='oauth_userinfo' WHERE id='prov-oidc-exec'"},
		},
	})
	if err == nil {
		t.Fatal("expected error for oidc->oauth_userinfo within Execute")
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT typ FROM auth_providers WHERE id='prov-oidc-exec'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "oidc" {
		t.Fatalf("typ=%v want=oidc (unchanged)", row.Rows[0][0])
	}
	ver, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT version FROM auth_provider_runtime_versions WHERE provider_id='prov-oidc-exec'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if ver.Rows[0][0] != "migration-v96/prov-oidc-exec" {
		t.Fatalf("version=%v want=migration-v96/prov-oidc-exec (unchanged)", ver.Rows[0][0])
	}
}

func TestMigrationV97SameModeSetTypAllowed(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v97-same-settyp", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v97-same-settyp-ledger", SQL: "CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT"}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-oauth-settyp",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"prov-oauth-set", int64(1), "OAuthSet", "oauth_userinfo", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-oauth-set", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	// Also seed an oidc provider.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-oidc-settyp",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"prov-oidc-set", int64(1), "OIDCSet", "oidc", "https://issuer.example", "https://issuer.example/auth", "https://issuer.example/token", "https://issuer.example/userinfo", "cid-oidc-set", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Same-mode oauth_userinfo with typ SET: fires trigger but allows.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "same-oauth-set",
		SQL:       "UPDATE auth_providers SET typ='oauth_userinfo', name='OAuthSet-Renamed' WHERE id='prov-oauth-set'",
	}); err != nil {
		t.Fatalf("same-mode oauth_userinfo SET typ should be allowed: %v", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT name,typ FROM auth_providers WHERE id='prov-oauth-set'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "OAuthSet-Renamed" || row.Rows[0][1] != "oauth_userinfo" {
		t.Fatalf("same-mode oauth_userinfo SET typ failed: row=%v", row.Rows[0])
	}

	// Same-mode oidc with typ SET: fires trigger but allows.
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "same-oidc-set",
		SQL:       "UPDATE auth_providers SET typ='oidc', name='OIDCSet-Renamed' WHERE id='prov-oidc-set'",
	}); err != nil {
		t.Fatalf("same-mode oidc SET typ should be allowed: %v", err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT name,typ FROM auth_providers WHERE id='prov-oidc-set'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if row.Rows[0][0] != "OIDCSet-Renamed" || row.Rows[0][1] != "oidc" {
		t.Fatalf("same-mode oidc SET typ failed: row=%v", row.Rows[0])
	}
}
