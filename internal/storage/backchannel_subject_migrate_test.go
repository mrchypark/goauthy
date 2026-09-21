package storage

import (
	"context"
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV61BackchannelSubjectsPreservesRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v61-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES (60)`},
		{SQL: `CREATE TABLE browser_sessions (token_digest TEXT PRIMARY KEY NOT NULL, subject TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL, revoked_at_unix_ms INTEGER) STRICT`},
		{SQL: `CREATE TABLE oidc_session_clients (sid TEXT NOT NULL, client_id TEXT NOT NULL, logout_uri TEXT NOT NULL, allow_private INTEGER NOT NULL, allow_http INTEGER NOT NULL, created_at_unix_ms INTEGER NOT NULL, PRIMARY KEY(sid,client_id)) STRICT`},
		{SQL: `CREATE TABLE oidc_backchannel_deliveries (event_id TEXT NOT NULL, client_id TEXT NOT NULL, sid TEXT NOT NULL, logout_uri TEXT NOT NULL, allow_private INTEGER NOT NULL, allow_http INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at_unix_ms INTEGER NOT NULL, lease_token TEXT, lease_until_unix_ms INTEGER, delivered_at_unix_ms INTEGER, failed_at_unix_ms INTEGER, last_error TEXT, created_at_unix_ms INTEGER NOT NULL, PRIMARY KEY(event_id,client_id), UNIQUE(sid,client_id)) STRICT`},
		{SQL: `CREATE INDEX oidc_backchannel_deliveries_due ON oidc_backchannel_deliveries(next_attempt_at_unix_ms) WHERE delivered_at_unix_ms IS NULL AND failed_at_unix_ms IS NULL`},
		{SQL: `INSERT INTO browser_sessions VALUES ('sid-a','user-a',10,100,NULL),('sid-b','user-a',10,100,20),('sid-c','user-b',30,100,40)`},
		{SQL: `INSERT INTO oidc_session_clients VALUES ('sid-a','client-a','https://a/logout',0,0,1),('sid-b','client-a','https://other/logout',1,1,2),('sid-c','client-a','https://a/logout',0,0,3)`},
		{SQL: `INSERT INTO oidc_backchannel_deliveries VALUES ('pending','client-a','sid-a','https://a/logout',0,0,1,11,'lease',12,NULL,NULL,NULL,13),('leased','client-b','sid-b','https://b/logout',1,0,2,21,'token',22,NULL,NULL,NULL,23),('delivered','client-c','sid-c','https://c/logout',0,1,3,31,NULL,NULL,32,NULL,'done',33),('failed','client-d','sid-a','https://d/logout',1,1,4,41,NULL,NULL,NULL,42,'bad',43)`},
	}}); err != nil {
		t.Fatal(err)
	}
	before, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT * FROM oidc_backchannel_deliveries ORDER BY event_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV61(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV61(ctx, db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,lease_token,lease_until_unix_ms,delivered_at_unix_ms,failed_at_unix_ms,last_error,created_at_unix_ms FROM oidc_backchannel_deliveries ORDER BY event_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 4 || rows.Rows[0][2] != "sid-c" || rows.Rows[0][11] != int64(32) || rows.Rows[1][12] != int64(42) || rows.Rows[2][9] != "token" || rows.Rows[3][2] != "sid-a" {
		t.Fatalf("delivery rows=%#v err=%v", rows.Rows, err)
	}
	for i, row := range rows.Rows {
		legacy := append(append([]any{}, row[:3]...), row[4:]...)
		if row[3] != "" || !reflect.DeepEqual(before.Rows[i], legacy) {
			t.Fatalf("migration changed legacy delivery %d", i)
		}
	}
	users, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms FROM oidc_user_clients ORDER BY subject`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(users.Rows) != 2 || users.Rows[0][0] != "user-a" || users.Rows[0][2] != "https://a/logout" || users.Rows[1][0] != "user-b" {
		t.Fatalf("user-client rows=%#v err=%v", users.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-new-subject", SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,subject,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES('subject','client-a','user-a','https://a/logout',0,0,1,1)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-other-and-repeat-subject", SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,subject,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES('subject-other','client-a','user-b','https://a/logout',0,0,1,1),('subject-repeat','client-a','user-a','https://a/logout',0,0,1,1)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-old-writer", SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES('old','client-z','sid-a','https://z/logout',0,0,1,1)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-duplicate-sid", SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES('old-duplicate','client-z','sid-a','https://z/logout',0,0,1,1)`}); err == nil {
		t.Fatal("legacy sid/client uniqueness was lost")
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-missing-both", SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES('invalid','client-z','https://z/logout',0,0,1,1)`}); err == nil {
		t.Fatal("delivery without sid and subject was accepted")
	}
}

func TestMigrationV61RejectsMissingObjects(t *testing.T) {
	t.Parallel()
	for _, table := range []string{"oidc_backchannel_deliveries", "oidc_user_clients"} {
		t.Run(table, func(t *testing.T) {
			db, ctx := eventSchemaDB(t)
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-remove-object", SQL: `DROP TABLE ` + table}); err != nil {
				t.Fatal(err)
			}
			if err := migrateSchemaV61(ctx, db); err == nil {
				t.Fatal("schema marker hid a missing table")
			}
		})
	}
	t.Run("no base tables", func(t *testing.T) {
		db, ctx := eventSchemaDB(t)
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-marker-only-base", Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
			{SQL: `INSERT INTO goauthy_schema_migrations VALUES(60)`},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV61(ctx, db); err == nil {
			t.Fatal("migration created incomplete schema from missing base")
		}
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=61`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 0 {
			t.Fatal("failed migration wrote a completion marker")
		}
	})
}

func TestMigrationV61RejectsMarkerShapeMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "v61-mismatch", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v61-bad-marker", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations VALUES (61)`},
		{SQL: `CREATE TABLE oidc_backchannel_deliveries (sid TEXT) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV61(ctx, db); err == nil {
		t.Fatal("inconsistent schema was accepted")
	}
}
