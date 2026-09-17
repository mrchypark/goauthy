package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV67CreatesSaaSCredentialsTableAndReplays(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "saas-credentials-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='table' AND name='saas_connection_credentials'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("credentials table=%v error=%v", rows.Rows, err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=67`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("schema v67 marker=%v error=%v", marker.Rows, err)
	}
	if err := Ready(t.Context(), db); err != nil {
		t.Fatalf("ready after schema v67: %v", err)
	}
}

func TestSchemaV67SaaSCredentialsConstraints(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "saas-credentials-constraints", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	insert := func(requestID, sql string, args ...any) {
		t.Helper()
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args}); err != nil {
			t.Fatal(err)
		}
	}
	insert("saas-ready", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, "conn-ready", "owner", "collection", "github", "generation-1", int64(1), "ready", []byte("credential"))
	insert("saas-refreshing", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim) VALUES(?,?,?,?,?,?,?,?,?)`, "conn-refreshing", "owner", "collection", "github", "generation-2", int64(2), "refreshing", []byte("credential"), "claim-1")
	for i, tc := range []struct {
		name string
		sql  string
		args []any
	}{
		{"token version", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, []any{"conn-zero", "owner", "collection", "github", "generation", int64(0), "ready", []byte("credential")}},
		{"invalid state", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, []any{"conn-state", "owner", "collection", "github", "generation", int64(1), "pending", []byte("credential")}},
		{"refreshing without claim", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, []any{"conn-claim", "owner", "collection", "github", "generation", int64(1), "refreshing", []byte("credential")}},
		{"ready with claim", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim) VALUES(?,?,?,?,?,?,?,?,?)`, []any{"conn-ready-claim", "owner", "collection", "github", "generation", int64(1), "ready", []byte("credential"), "claim"}},
		{"duplicate connection", `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, []any{"conn-ready", "other-owner", "other-collection", "google", "generation-3", int64(1), "ready", []byte("other")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "saas-invalid-" + string(rune('a'+i)), SQL: tc.sql, Args: tc.args}); err == nil {
				t.Fatal("invalid SaaS credential row was accepted")
			}
		})
	}
}
