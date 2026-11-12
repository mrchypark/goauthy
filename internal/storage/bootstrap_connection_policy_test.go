package storage

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV113PreservesExistingClients(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "bootstrap-policy-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-policy-v112-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES(112)`},
		{SQL: `CREATE TABLE managed_oauth_clients(id TEXT PRIMARY KEY,generation TEXT,revision INTEGER,enabled INTEGER,deleted INTEGER,metadata_json TEXT) STRICT`},
		{SQL: `INSERT INTO managed_oauth_clients VALUES('existing','original',7,1,0,'{}')`},
		{SQL: `CREATE TABLE managed_oauth_client_bootstrap(singleton INTEGER PRIMARY KEY,id TEXT) STRICT`},
		{SQL: `CREATE TABLE dynamic_oauth_clients(client_id TEXT PRIMARY KEY) STRICT`},
		{SQL: `CREATE TABLE bootstrap_client_claim_scopes(client_id TEXT PRIMARY KEY,allowed_scopes_json TEXT,revision INTEGER) STRICT`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateBootstrapConnectionPolicy(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation,revision FROM connection_client_policies WHERE id='existing'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != "original" || q.Rows[0][1] != int64(7) {
		t.Fatalf("managed client changed: %v %v", q.Rows, err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM bootstrap_connection_policy`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || q.Rows[0][0] != int64(0) {
		t.Fatal("migration implicitly pinned bootstrap")
	}
	if err := Ready(ctx, db); err == nil {
		t.Fatal("schema 113 alone must not satisfy schema 114 readiness")
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "branding-v113-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO bootstrap_connection_policy VALUES(1,'existing',?, 'original-pin','{}')`, Args: []any{strings.Repeat("a", 64)}},
		{SQL: `CREATE TABLE client_themes(client_id TEXT PRIMARY KEY,document_json TEXT) STRICT`},
		{SQL: `INSERT INTO client_themes VALUES('goauthy','{"brand":"legacy"}')`},
		{SQL: `CREATE TABLE client_logos(client_id TEXT PRIMARY KEY,data BLOB) STRICT`},
		{SQL: `INSERT INTO client_logos VALUES('goauthy',?)`, Args: []any{[]byte{1, 2, 3}}},
	}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := migrateGlobalBranding(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT generation FROM bootstrap_connection_policy), (SELECT document_json FROM client_themes WHERE client_id='goauthy'), (SELECT hex(data) FROM client_logos WHERE client_id='goauthy'), (SELECT COUNT(*) FROM global_brand_themes), (SELECT COUNT(*) FROM global_brand_logos), (SELECT COUNT(*) FROM branding_legacy_resolution), (SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version IN (113,114,115))`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || !reflect.DeepEqual(q.Rows[0], []any{"original-pin", `{"brand":"legacy"}`, "010203", int64(0), int64(0), int64(0), int64(2)}) {
		t.Fatalf("v114 state changed bootstrap or claimed legacy rows: %v %v", q.Rows, err)
	}
	if err := Ready(ctx, db); err == nil {
		t.Fatal("v114 state must not satisfy v115 readiness")
	}
	for range 2 {
		if err := migrateOTPVerificationLimits(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM identity_email_otp_verification_limits), (SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version IN (113,114,115))`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || !reflect.DeepEqual(q.Rows[0], []any{int64(0), int64(3)}) {
		t.Fatalf("v115 migration state=%v err=%v", q.Rows, err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
}
