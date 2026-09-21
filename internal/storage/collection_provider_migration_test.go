package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV68AddsProviderDefaultAndReplays(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "collection-provider-migration", DataDir: testDatabaseDir(t, "collection-provider-migration")})
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
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v68-legacy-definition", SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json) VALUES(?,?,?,?,?,?,?)`, Args: []any{"legacy-provider-default", "Legacy", "oauth2", int64(1), int64(1), "generation", "[]"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT providers_json FROM auth_collection_definitions WHERE id='legacy-provider-default'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "[]" {
		t.Fatalf("legacy providers default=%v error=%v", rows.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v68-malformed-providers", SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{`{"provider":"github"}`, "legacy-provider-default"}}); err == nil {
		t.Fatal("malformed providers JSON was accepted")
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=68`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("schema v68 marker=%v error=%v", marker.Rows, err)
	}
}

func TestSchemaV68RevokesRemovedProviders(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "collection-provider-revoke", DataDir: testDatabaseDir(t, "collection-provider-revoke")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	insertDefinition := func(id string) {
		t.Helper()
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v68-definition-" + id, SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json) VALUES(?,?,?,?,?,?,?)`, Args: []any{id, id, "oauth2", int64(1), int64(1), "generation-" + id, "[]"}}); err != nil {
			t.Fatal(err)
		}
	}
	insertCredential := func(requestID, connectionID, collectionID, providerID, state, claim string) {
		t.Helper()
		sql := `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim) VALUES(?,?,?,?,?,?,?,?,?)`
		if state != "refreshing" {
			sql = `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES(?,?,?,?,?,?,?,?)`
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: []any{connectionID, "owner", collectionID, providerID, "generation", int64(1), state, []byte("credential")}}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: []any{connectionID, "owner", collectionID, providerID, "generation", int64(1), state, []byte("credential"), claim}}); err != nil {
			t.Fatal(err)
		}
	}
	insertDefinition("provider-collection")
	insertDefinition("other-collection")
	insertCredential("v68-credential-removed", "connection-removed", "provider-collection", "removed", "refreshing", "claim-removed")
	insertCredential("v68-credential-kept", "connection-kept", "provider-collection", "kept", "ready", "")
	insertCredential("v68-credential-other", "connection-other", "other-collection", "removed", "refreshing", "claim-other")
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v68-remove-provider", SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{`["kept"]`, "provider-collection"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT connection_id,state,refresh_claim FROM saas_connection_credentials ORDER BY connection_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 3 || rows.Rows[0][1] != "ready" || rows.Rows[0][2] != nil || rows.Rows[1][1] != "refreshing" || rows.Rows[1][2] != "claim-other" || rows.Rows[2][1] != "revoked" || rows.Rows[2][2] != nil {
		t.Fatalf("provider removal rows=%v error=%v", rows.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v68-readd-provider", SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{`["kept","removed"]`, "provider-collection"}}); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state,refresh_claim FROM saas_connection_credentials WHERE connection_id='connection-removed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "revoked" || row.Rows[0][1] != nil {
		t.Fatalf("readded provider resurrected credential=%v error=%v", row.Rows, err)
	}
}
