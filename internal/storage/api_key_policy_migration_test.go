package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV70PreservesAPIKeyCredentialsAndRevokesOAuthProviders(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "api-key-policy-migration", DataDir: testDatabaseDir(t, "api-key-policy-migration")})
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
	insertDefinition := func(requestID, id, method, providers string) {
		t.Helper()
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{id, id, method, int64(1), int64(1), "generation-" + id, "[]", providers}}); err != nil {
			t.Fatal(err)
		}
	}
	insertCredential := func(requestID, connectionID, collectionID, providerID string) {
		t.Helper()
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{connectionID, "owner", collectionID, providerID, "generation", int64(1), "ready", []byte("credential")}}); err != nil {
			t.Fatal(err)
		}
	}
	insertDefinition("v70-api-definition", "api-collection", "api_key", `[]`)
	insertDefinition("v70-oauth-definition", "oauth-collection", "oauth2", `["github"]`)
	insertCredential("v70-api-credential", "api-connection", "api-collection", "api-key")
	insertCredential("v70-oauth-credential", "oauth-connection", "oauth-collection", "github")
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v70-api-provider-update", SQL: `UPDATE auth_collection_definitions SET name=?,providers_json=? WHERE id=?`, Args: []any{"API renamed", `[]`, "api-collection"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v70-oauth-provider-removal", SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{`[]`, "oauth-collection"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT connection_id,state,refresh_claim FROM saas_connection_credentials ORDER BY connection_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 || rows.Rows[0][0] != "api-connection" || rows.Rows[0][1] != "ready" || rows.Rows[1][0] != "oauth-connection" || rows.Rows[1][1] != "revoked" || rows.Rows[1][2] != nil {
		t.Fatalf("credential policy rows=%v error=%v", rows.Rows, err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=70`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("schema v70 marker=%v error=%v", marker.Rows, err)
	}
}
