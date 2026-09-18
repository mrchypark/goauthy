package dcr

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeleteRegistrationRemovesAllClientChildren(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-backchannel", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	seedBackchannelChildren(t, ctx, db, "delete-backchannel", created.ClientID)

	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err != nil {
		t.Fatal(err)
	}
	assertClientChildren(t, ctx, db, "delete-backchannel", created.ClientID, 0)
}

func TestCleanupAnonymousClientsRemovesUserAndSessionAssociations(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	clientID := cleanupClient(t, ctx, store, db, "cleanup-backchannel", now.Add(-time.Hour), nil, true)
	seedBackchannelChildren(t, ctx, db, "cleanup-backchannel", clientID)

	if err := CleanupAnonymousClients(ctx, db, AnonymousCleanupConfig{CleanupMinutes: 1, Limit: 1}, now); err != nil {
		t.Fatal(err)
	}
	assertClientChildren(t, ctx, db, "cleanup-backchannel", clientID, 0)
}

func TestDeleteRegistrationWrongAndStaleTokenLeaveChildrenUntouched(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-wrong-token", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	seedBackchannelChildren(t, ctx, db, "delete-wrong-token", created.ClientID)
	if err := store.DeleteRegistration(ctx, created.ClientID, "wrong-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-token delete err=%v", err)
	}
	assertClientChildren(t, ctx, db, "delete-wrong-token", created.ClientID, 1)

	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale-token delete err=%v", err)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, updated.RegistrationAccessToken); err != nil {
		t.Fatalf("stale-token delete changed registration: %v", err)
	}
	assertClientChildren(t, ctx, db, "delete-wrong-token", created.ClientID, 1)
}

func TestDeleteRegistrationParentFailureRollsBackChildren(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-trigger-failure", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	seedBackchannelChildren(t, ctx, db, "delete-trigger-failure", created.ClientID)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "delete-trigger-failure-trigger",
		SQL: `CREATE TRIGGER dcr_delete_trigger_failure
			BEFORE DELETE ON dynamic_oauth_clients
			WHEN OLD.client_id = 'delete-trigger-failure'
			BEGIN SELECT RAISE(ABORT, 'forced parent delete failure'); END`,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err == nil {
		t.Fatal("parent delete unexpectedly succeeded")
	}
	assertClientChildren(t, ctx, db, "delete-trigger-failure", created.ClientID, 1)
}

func seedBackchannelChildren(t *testing.T, ctx context.Context, db *rhiza.DB, prefix, clientID string) {
	t.Helper()
	access := prefix + "-access"
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES (?,?,?,0,1,'[]','[]','[]','[]')`, Args: []any{access, prefix + "-request", clientID}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES (?, '{}')`, Args: []any{access}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES (?,?,?,'{}',1)`, Args: []any{prefix + "-refresh", access, prefix + "-request"}},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,'[]','pending',1,5,0,0)`, Args: []any{prefix + "-device", prefix + "-user", clientID}},
		{SQL: `INSERT INTO dpop_nonces(nonce_digest,client_id,jkt,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,1,0)`, Args: []any{prefix + "-nonce", clientID, prefix + "-jkt"}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES (?,?,?,0,0,0)`, Args: []any{prefix + "-subject", clientID, "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES (?,?,?,0,0,0)`, Args: []any{prefix + "-sid", clientID, "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES (?,?,?, ?,0,0,0,0)`, Args: []any{prefix + "-event", clientID, prefix + "-sid", "https://rp.example.test/logout"}},
		{SQL: `INSERT INTO dcr_registration_idempotency(principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{fmt.Sprintf("%043d", len(prefix)+1), fmt.Sprintf("%043d", len(prefix)+2), fmt.Sprintf("%043d", len(prefix)+3), clientID, "sealed", int64(1), int64(0)}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: prefix + "-seed-children", Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

func assertClientChildren(t *testing.T, ctx context.Context, db *rhiza.DB, prefix, clientID string, want int64) {
	t.Helper()
	checks := []struct {
		table string
		sql   string
		args  []any
	}{
		{"dynamic_oauth_clients", `SELECT COUNT(*) FROM dynamic_oauth_clients WHERE client_id=?`, []any{clientID}},
		{"oauth_access_tokens", `SELECT COUNT(*) FROM oauth_access_tokens WHERE client_id=?`, []any{clientID}},
		{"oauth_token_requests", `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, []any{prefix + "-access"}},
		{"oauth_refresh_tokens", `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE access_signature=?`, []any{prefix + "-access"}},
		{"oauth_device_grants", `SELECT COUNT(*) FROM oauth_device_grants WHERE client_id=?`, []any{clientID}},
		{"dpop_nonces", `SELECT COUNT(*) FROM dpop_nonces WHERE client_id=?`, []any{clientID}},
		{"oidc_user_clients", `SELECT COUNT(*) FROM oidc_user_clients WHERE client_id=?`, []any{clientID}},
		{"oidc_session_clients", `SELECT COUNT(*) FROM oidc_session_clients WHERE client_id=?`, []any{clientID}},
		{"oidc_backchannel_deliveries", `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE client_id=?`, []any{clientID}},
		{"dcr_registration_idempotency", `SELECT COUNT(*) FROM dcr_registration_idempotency WHERE client_id=?`, []any{clientID}},
	}
	for _, check := range checks {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: check.sql, Args: check.args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatalf("count %s: rows=%#v err=%v", check.table, result.Rows, err)
		}
		got, ok := result.Rows[0][0].(int64)
		if !ok || got != want {
			t.Fatalf("%s rows=%v want=%d", check.table, result.Rows[0][0], want)
		}
	}
}
