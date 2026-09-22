package storage

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestDCRBackchannelLogoutURIPersistsAcrossCleanReopen(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	dir := t.TempDir()
	const nodeID = "dcr-backchannel-reopen"

	// This exercises local Rhiza DataDir close/reopen persistence only; it does
	// not configure or restore an object store and makes no DR claim.
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: nodeID, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "dcr-backchannel-reopen-create",
		SQL:       `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms,backchannel_logout_uri) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		Args:      []any{"dcr-reopen-client", nil, "dcr-reopen-registration", "[]", `["profile"]`, `["password"]`, "[]", "[]", "none", "DCR reopen", int64(1), "https://rp.example.test/backchannel-logout"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = rhiza.Open(ctx, rhiza.Config{NodeID: nodeID, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, db); err != nil {
		t.Fatal(err)
	}

	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT client_id,backchannel_logout_uri FROM dynamic_oauth_clients WHERE client_id='dcr-reopen-client'`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != "dcr-reopen-client" || row.Rows[0][1] != "https://rp.example.test/backchannel-logout" {
		t.Fatalf("reopened DCR backchannel metadata=%v err=%v", row.Rows, err)
	}
}
