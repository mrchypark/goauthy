package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestSchemaV69CreatesAuthorizationRequestsAndReplays(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "saas-authorization-migration", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-legacy-provider-definition", SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"v69-legacy-collection", "Legacy", "oauth2", int64(1), int64(1), "generation", "[]", `["github"]`}}); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	columns, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('saas_authorization_requests') ORDER BY cid`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	// Migrate applies the full current schema, including the verifier and target version.
	wantColumns := []string{"state_digest", "verifier_digest", "session_digest", "provider_digest", "owner_subject", "collection_id", "connection_id", "provider_id", "generation", "created_at_unix_ms", "expires_at_unix_ms", "consumed_at_unix_ms", "invalidated", "verifier_envelope", "token_version"}
	if len(columns.Rows) != len(wantColumns) {
		t.Fatalf("authorization columns=%v", columns.Rows)
	}
	for i, want := range wantColumns {
		if columns.Rows[i][0] != want {
			t.Fatalf("authorization column %d=%v want %s", i, columns.Rows[i][0], want)
		}
	}
	index, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM sqlite_master WHERE type='index' AND name='saas_authorization_requests_expires'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(index.Rows) != 1 {
		t.Fatalf("expiry index=%v error=%v", index.Rows, err)
	}
	provider, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT providers_json FROM auth_collection_definitions WHERE id='v69-legacy-collection'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(provider.Rows) != 1 || provider.Rows[0][0] != `["github"]` {
		t.Fatalf("schema68 provider data=%v error=%v", provider.Rows, err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-pending-request", SQL: `INSERT INTO saas_authorization_requests(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"state-pending", "verifier", "session", "provider", "owner", "v69-legacy-collection", "connection", "github", "generation", int64(100), int64(200)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-consumed-request", SQL: `INSERT INTO saas_authorization_requests(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms,consumed_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{"state-consumed", "verifier", "session", "provider", "owner", "v69-legacy-collection", "connection", "github", "generation", int64(100), int64(200), int64(150)}}); err != nil {
		t.Fatal(err)
	}
	for i, providers := range []string{`[]`, `["github"]`} {
		if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-provider-update-" + string(rune('0'+i)), SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{providers, "v69-legacy-collection"}}); err != nil {
			t.Fatal(err)
		}
	}
	invalidated, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state_digest,invalidated FROM saas_authorization_requests ORDER BY state_digest`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(invalidated.Rows) != 2 || invalidated.Rows[0][0] != "state-consumed" || invalidated.Rows[0][1] != int64(1) || invalidated.Rows[1][0] != "state-pending" || invalidated.Rows[1][1] != int64(1) {
		t.Fatalf("readded provider resurrected request=%v error=%v", invalidated.Rows, err)
	}
	marker, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT version FROM goauthy_schema_migrations WHERE version=69`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 {
		t.Fatalf("schema v69 marker=%v error=%v", marker.Rows, err)
	}
}

func TestSchemaV69AuthorizationRequestConstraints(t *testing.T) {
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "saas-authorization-constraints", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO saas_authorization_requests(state_digest,verifier_digest,session_digest,provider_digest,owner_subject,collection_id,connection_id,provider_id,generation,created_at_unix_ms,expires_at_unix_ms,consumed_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
	args := []any{"state-digest", "verifier-digest", "session-digest", "provider-digest", "owner", "collection", "connection", "github", "generation", int64(100), int64(200), nil}
	if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-valid-request", SQL: insert, Args: args}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		args []any
	}{
		{"expired-before-created", []any{"state-expired", "verifier", "session", "provider", "owner", "collection", "connection", "github", "generation", int64(300), int64(300), nil}},
		{"duplicate-state", []any{"state-digest", "other-verifier", "other-session", "other-provider", "owner", "collection", "connection-2", "github", "generation", int64(100), int64(200), nil}},
		{"null-verifier", []any{"state-null-verifier", nil, "session", "provider", "owner", "collection", "connection-3", "github", "generation", int64(100), int64(200), nil}},
		{"null-provider", []any{"state-null-provider", "verifier", "session", nil, "owner", "collection", "connection-4", "github", "generation", int64(100), int64(200), nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "v69-invalid-" + string(rune('a'+i)), SQL: insert, Args: tc.args}); err == nil {
				t.Fatal("invalid authorization request was accepted")
			}
		})
	}
}
