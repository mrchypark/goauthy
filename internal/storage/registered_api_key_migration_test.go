package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV77APIKeyProviderRevocationAndReplay(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "api-key-provider-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "api-key-provider-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(76)`},
		{SQL: `CREATE TABLE auth_collection_definitions(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL,auth_method TEXT NOT NULL,enabled INTEGER NOT NULL,revision INTEGER NOT NULL,generation TEXT NOT NULL,fields_json TEXT NOT NULL,providers_json TEXT NOT NULL DEFAULT '[]') STRICT`},
		{SQL: `CREATE TABLE saas_connection_credentials(connection_id TEXT PRIMARY KEY NOT NULL,owner_subject TEXT NOT NULL,collection_id TEXT NOT NULL,provider_id TEXT NOT NULL,generation TEXT NOT NULL,token_version INTEGER NOT NULL,state TEXT NOT NULL,credential BLOB NOT NULL,refresh_claim TEXT)`},
		{SQL: `CREATE TRIGGER auth_collection_provider_revoke AFTER UPDATE OF providers_json ON auth_collection_definitions WHEN NEW.auth_method='oauth2' BEGIN UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE collection_id=NEW.id AND NOT EXISTS(SELECT 1 FROM json_each(NEW.providers_json) p WHERE p.type='text' AND p.value=saas_connection_credentials.provider_id); END`},
		{SQL: `INSERT INTO auth_collection_definitions VALUES('api-collection','API','api_key',1,1,'g','[]','[]')`},
		{SQL: `INSERT INTO auth_collection_definitions VALUES('legacy-collection','Legacy','api_key',1,1,'g','[]','[]')`},
		{SQL: `INSERT INTO saas_connection_credentials VALUES('api-1','owner','api-collection','managed-api','g',1,'ready',X'01',NULL)`},
		{SQL: `INSERT INTO saas_connection_credentials VALUES('api-2','owner','api-collection','other','g',1,'refreshing',X'01','claim')`},
		{SQL: `INSERT INTO saas_connection_credentials VALUES('legacy-1','owner','legacy-collection','api-key','g',1,'ready',X'01',NULL)`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV77(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "api-key-provider-change", SQL: `UPDATE auth_collection_definitions SET providers_json='["managed-api"]',revision=2 WHERE id='api-collection'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "api-key-provider-same", SQL: `UPDATE auth_collection_definitions SET providers_json='["managed-api"]',revision=3 WHERE id='api-collection'`}); err != nil {
		t.Fatal(err)
	}
	retained, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state,refresh_claim FROM saas_connection_credentials ORDER BY connection_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(retained.Rows) != 3 || retained.Rows[0][0] != "ready" || retained.Rows[1][0] != "revoked" || retained.Rows[1][1] != nil {
		t.Fatalf("provider retention/revocation=%v err=%v", retained.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "api-key-provider-clear", SQL: `UPDATE auth_collection_definitions SET providers_json='[]',revision=4 WHERE id='api-collection'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "api-key-legacy-empty", SQL: `UPDATE auth_collection_definitions SET providers_json='[]',revision=2 WHERE id='legacy-collection'`}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT connection_id,state FROM saas_connection_credentials ORDER BY connection_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 3 || rows.Rows[0][1] != "revoked" || rows.Rows[1][1] != "revoked" || rows.Rows[2][1] != "ready" {
		t.Fatalf("credentials=%v err=%v", rows.Rows, err)
	}
	if err := migrateSchemaV77(t.Context(), db); err != nil {
		t.Fatal(err)
	}
}
