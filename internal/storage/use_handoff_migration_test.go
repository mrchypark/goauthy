package storage

import (
	"reflect"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV79UseHandoffsFreshAndReplay(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "use-handoffs-v78", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV78(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV79(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV79(t.Context(), db); err != nil {
		t.Fatal(err)
	}

	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=79`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("marker=%v err=%v", marker.Rows, err)
	}
	indexes, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name IN ('saas_use_handoffs_expiry','saas_use_handoffs_owner_expiry') ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(indexes.Rows) != 2 {
		t.Fatalf("indexes=%v err=%v", indexes.Rows, err)
	}
}

func TestMigrationV79UseHandoffsRebuildsV78Rows(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "use-handoffs-v79-rebuild", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v79-base", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(77)`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV78(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO saas_use_handoffs(id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	for _, row := range [][]any{
		{"pending", "owner-p", "proxy", "pending", nil},
		{"approved", "owner-a", "proxy", "approved", "grant-a"},
		{"denied", "owner-d", "proxy", "denied", nil},
	} {
		args := []any{row[0], row[1], "request-client", "request-generation", "collection", "connection", "generation", "consumer", "consumer-generation", "provider", "digest", "resource", row[2], "purpose", "https://return.example", row[3], int64(4), int64(200), int64(300), row[3], row[4]}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v79-row-" + row[0].(string), SQL: insert, Args: args}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id FROM saas_use_handoffs ORDER BY id_hash`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV79(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	after, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id FROM saas_use_handoffs ORDER BY id_hash`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(before.Rows, after.Rows) {
		t.Fatalf("rows changed before=%v after=%v err=%v", before.Rows, after.Rows, err)
	}
	if err := migrateSchemaV79(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	replayed, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id FROM saas_use_handoffs ORDER BY id_hash`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(before.Rows, replayed.Rows) {
		t.Fatalf("rows changed on replay before=%v replayed=%v err=%v", before.Rows, replayed.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v79-delivery", SQL: insert, Args: []any{"delivery", "owner", "request-client", "request-generation", "collection", "connection", "generation", "consumer", "consumer-generation", "provider", "digest", "resource", "credential_delivery", "purpose", "https://return.example", "state", int64(4), int64(200), int64(300), "pending", nil}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v79-invalid-mode", SQL: insert, Args: []any{"invalid", "owner", "request-client", "request-generation", "collection", "connection", "generation", "consumer", "consumer-generation", "provider", "digest", "resource", "other", "purpose", "https://return.example", "state", int64(4), int64(200), int64(300), "pending", nil}}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	for _, tc := range []struct {
		name  string
		state string
		grant any
		rev   int64
	}{
		{"invalid state", "unknown", nil, 4},
		{"approved without grant", "approved", nil, 4},
		{"pending with grant", "pending", "grant", 4},
		{"zero provider revision", "pending", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v79-invalid-" + tc.name, SQL: insert, Args: []any{tc.name, "owner", "request-client", "request-generation", "collection", "connection", "generation", "consumer", "consumer-generation", "provider", "digest", "resource", "proxy", "purpose", "https://return.example", "state", tc.rev, int64(200), int64(300), tc.state, tc.grant}}); err == nil {
				t.Fatal("invalid handoff accepted")
			}
		})
	}
}

func TestMigrationV78UseHandoffsPreservesV77FixtureAndConstraints(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "use-handoffs-v77-fixture", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-v77-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(77)`},
		{SQL: `CREATE TABLE preserved_v77(value TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO preserved_v77(value) VALUES('keep')`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV78(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV78(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	legacy, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT value FROM preserved_v77`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(legacy.Rows) != 1 || legacy.Rows[0][0] != "keep" {
		t.Fatalf("legacy=%v err=%v", legacy.Rows, err)
	}

	valid := []any{"handoff", "owner", "request-client", "request-generation", "collection", "connection", "generation", "consumer", "consumer-generation", "provider", "digest", "resource", "proxy", "purpose", "https://return.example", "state", int64(1), int64(200), int64(300), "pending", nil}
	insert := `INSERT INTO saas_use_handoffs(id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-valid", SQL: insert, Args: valid}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []any
	}{
		{"bad mode", append(append([]any(nil), valid[:12]...), append([]any{"credential_delivery"}, valid[13:]...)...)},
		{"bad provider revision", append(append([]any(nil), valid[:16]...), append([]any{int64(0)}, valid[17:]...)...)},
		{"approved without grant", append(append([]any(nil), valid[:19]...), append([]any{"approved", nil}, valid[21:]...)...)},
		{"pending with grant", append(append([]any(nil), valid[:19]...), append([]any{"pending", "grant"}, valid[21:]...)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]any{tc.name}, tc.args[1:]...)
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "use-handoffs-invalid-" + tc.name, SQL: insert, Args: args}); err == nil {
				t.Fatal("invalid handoff accepted")
			}
		})
	}
}
