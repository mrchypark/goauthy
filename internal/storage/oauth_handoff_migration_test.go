package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

const legacyUseHandoffsSchema = `CREATE TABLE saas_use_handoffs (
	id_hash TEXT PRIMARY KEY NOT NULL,
	owner_subject TEXT NOT NULL,
	request_client_id TEXT NOT NULL,
	request_client_generation TEXT NOT NULL,
	collection_id TEXT NOT NULL,
	connection_id TEXT NOT NULL,
	generation TEXT NOT NULL,
	consumer_client_id TEXT NOT NULL,
	consumer_generation TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	connector_digest TEXT NOT NULL,
	resource TEXT NOT NULL,
	mode TEXT NOT NULL CHECK (mode IN ('proxy','credential_delivery')),
	purpose TEXT NOT NULL,
	return_uri TEXT NOT NULL,
	return_state TEXT NOT NULL,
	provider_revision INTEGER NOT NULL CHECK (provider_revision > 0),
	grant_expires_at_unix_ms INTEGER NOT NULL,
	expires_at_unix_ms INTEGER NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('pending','approved','denied')),
	grant_id TEXT,
	CHECK ((state='approved' AND grant_id IS NOT NULL) OR (state IN ('pending','denied') AND grant_id IS NULL))
) STRICT`

func TestMigrationV81OAuthHandoffCredentialVersion(t *testing.T) {
	t.Parallel()
	t.Run("fresh and replay preserve versions", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "oauth-handoff-v81", DataDir: testDatabaseDir(t, "oauth-handoff-v81")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		insert := `INSERT INTO saas_use_handoffs(id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id,credential_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
		args := []any{"oauth", "owner", "client", "client-gen", "collection", "connection", "generation", "consumer", "consumer-gen", "provider", "", "resource", "credential_delivery", "purpose", "https://return.example", "state", int64(1), int64(200), int64(300), "pending", nil, int64(7)}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "oauth-handoff-v81-positive", SQL: insert, Args: args}); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT credential_version FROM saas_use_handoffs ORDER BY id_hash`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(7) {
			t.Fatalf("credential versions=%v err=%v", rows.Rows, err)
		}
	})

	t.Run("legacy row defaults to zero", func(t *testing.T) {
		db := openLegacyUseHandoffs(t, "oauth-handoff-v81-legacy")
		if err := migrateSchemaV81(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id_hash,credential_version FROM saas_use_handoffs`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "legacy" || rows.Rows[0][1] != int64(0) {
			t.Fatalf("legacy row=%v err=%v", rows.Rows, err)
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		db := openLegacyUseHandoffs(t, "oauth-handoff-v81-negative")
		if err := migrateSchemaV81(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "oauth-handoff-v81-negative-row", SQL: `INSERT INTO saas_use_handoffs(id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id,credential_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"negative", "owner", "client", "client-gen", "collection", "connection", "generation", "consumer", "consumer-gen", "provider", "digest", "resource", "proxy", "purpose", "https://return.example", "state", int64(1), int64(200), int64(300), "pending", nil, int64(-1)}}); err == nil {
			t.Fatal("negative credential version accepted")
		}
	})

	t.Run("missing table does not mark", func(t *testing.T) {
		db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "oauth-handoff-v81-missing", DataDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "oauth-handoff-v81-missing-schema", Statements: []rhiza.SQLStatement{{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}, {SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(80)`}}}); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV81(t.Context(), db); err == nil {
			t.Fatal("migration succeeded without saas_use_handoffs")
		}
		marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=81`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(0) {
			t.Fatalf("schema 81 marker=%v err=%v", marker.Rows, err)
		}
	})
}

func openLegacyUseHandoffs(t *testing.T, nodeID string) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: nodeID, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: nodeID + "-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(80)`},
		{SQL: legacyUseHandoffsSchema},
		{SQL: `INSERT INTO saas_use_handoffs VALUES('legacy','owner','client','client-gen','collection','connection','generation','consumer','consumer-gen','provider','digest','resource','proxy','purpose','https://return.example','state',1,200,300,'pending',NULL)`},
	}}); err != nil {
		t.Fatal(err)
	}
	return db
}
