package dcr

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCleanupAnonymousClientsEligibilityAndChildren(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	unused := cleanupClient(t, ctx, store, db, "cleanup-unused", now.Add(-time.Minute), nil, true)
	used := cleanupClient(t, ctx, store, db, "cleanup-used", now.Add(-48*time.Hour), ptrTime(now.AddDate(0, 0, -7)), true)
	newUnused := cleanupClient(t, ctx, store, db, "cleanup-new", now, nil, true)
	disabledUsed := cleanupClient(t, ctx, store, db, "cleanup-disabled", now.Add(-48*time.Hour), ptrTime(now.AddDate(0, 0, -6)), true)
	private := cleanupClient(t, ctx, store, db, "cleanup-private", now.Add(-48*time.Hour), nil, false)
	seedCleanupChildren(t, ctx, db, unused)
	config := AnonymousCleanupConfig{CleanupMinutes: 1, InactiveDays: 7, Limit: DefaultAnonymousCleanupLimit}
	if err := CleanupAnonymousClients(ctx, db, config, now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"dynamic_oauth_clients", "oauth_access_tokens", "oauth_token_requests", "oauth_refresh_tokens", "oauth_device_grants", "dpop_nonces", "oidc_session_clients", "oidc_backchannel_deliveries", "dcr_registration_idempotency"} {
		if got := cleanupCount(t, ctx, db, table, unused); got != 0 {
			t.Fatalf("%s rows for cleaned client=%d", table, got)
		}
	}
	for _, id := range []string{newUnused, private} {
		if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", id); got != 1 {
			t.Fatalf("retained client %s rows=%d", id, got)
		}
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", used); got != 0 {
		t.Fatalf("used boundary client rows=%d", got)
	}
	if err := CleanupAnonymousClients(ctx, db, AnonymousCleanupConfig{CleanupMinutes: 1, InactiveDays: 0, Limit: DefaultAnonymousCleanupLimit}, now); err != nil {
		t.Fatal(err)
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", disabledUsed); got != 1 {
		t.Fatalf("inactive-days disabled client rows=%d", got)
	}
}

func TestCleanupAnonymousClientsLimitAndConcurrentPasses(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	cleanupClient(t, ctx, store, db, "cleanup-a", now.Add(-48*time.Hour), nil, true)
	cleanupClient(t, ctx, store, db, "cleanup-b", now.Add(-120*time.Hour), ptrTime(now.Add(-25*time.Hour)), true)
	cleanupClient(t, ctx, store, db, "cleanup-c", now.Add(-36*time.Hour), nil, true)
	config := AnonymousCleanupConfig{CleanupMinutes: 1, InactiveDays: 1, Limit: 2}
	if err := CleanupAnonymousClients(ctx, db, config, now); err != nil {
		t.Fatal(err)
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", "cleanup-a"); got != 0 {
		t.Fatalf("first limited candidate rows=%d", got)
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", "cleanup-c"); got != 0 {
		t.Fatalf("second limited candidate rows=%d", got)
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", "cleanup-b"); got != 1 {
		t.Fatalf("over-limit candidate rows=%d", got)
	}

	var start sync.WaitGroup
	start.Add(1)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			start.Wait()
			errs <- CleanupAnonymousClients(ctx, db, AnonymousCleanupConfig{CleanupMinutes: 1, InactiveDays: 1, Limit: 2}, now)
		}()
	}
	start.Done()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent cleanup: %v", err)
		}
	}
	if got := cleanupCount(t, ctx, db, "dynamic_oauth_clients", "cleanup-b"); got != 0 {
		t.Fatalf("concurrent final client rows=%d", got)
	}
}

func TestCleanupAnonymousClientsRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	ctx, _, db := testStore(t)
	for _, config := range []AnonymousCleanupConfig{{}, {CleanupMinutes: -1, Limit: 1}, {Limit: 1001}} {
		if err := CleanupAnonymousClients(ctx, db, config, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("accepted config %#v", config)
		}
	}
}

func cleanupClient(t *testing.T, ctx context.Context, store *Store, db *rhiza.DB, id string, created time.Time, used *time.Time, anonymous bool) string {
	t.Helper()
	createdClient, err := store.Create(ctx, validRequest(id, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	var lastUsed any
	if used != nil {
		lastUsed = used.UnixMilli()
	}
	flag := int64(0)
	if anonymous {
		flag = 1
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cleanup-seed/" + id, SQL: `UPDATE dynamic_oauth_clients SET anonymous=?, created_at_unix_ms=?, last_used_at_unix_ms=? WHERE client_id=?`, Args: []any{flag, created.UnixMilli(), lastUsed, createdClient.ClientID}}); err != nil {
		t.Fatal(err)
	}
	return createdClient.ClientID
}

func seedCleanupChildren(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string) {
	t.Helper()
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES ('cleanup-access','request',?,0,1,'[]','[]','[]','[]')`, Args: []any{clientID}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES ('cleanup-access','{}')`},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES ('cleanup-refresh','cleanup-access','request','{}',1)`},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES ('cleanup-device','cleanup-user',?,'[]','pending',1,5,0,0)`, Args: []any{clientID}},
		{SQL: `INSERT INTO dpop_nonces(nonce_digest,client_id,jkt,expires_at_unix_ms,created_at_unix_ms) VALUES ('cleanup-nonce',?,'jkt',1,0)`, Args: []any{clientID}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES ('cleanup-sid',?,'https://rp.example.test/logout',0,0,0)`, Args: []any{clientID}},
		{SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,logout_uri,allow_private,allow_http,next_attempt_at_unix_ms,created_at_unix_ms) VALUES ('cleanup-event',?,'cleanup-sid','https://rp.example.test/logout',0,0,0,0)`, Args: []any{clientID}},
		{SQL: `INSERT INTO dcr_registration_idempotency(principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{fmt.Sprintf("%043d", 1), fmt.Sprintf("%043d", 2), fmt.Sprintf("%043d", 3), clientID, "sealed", int64(1), int64(0)}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cleanup-seed-children", Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

func cleanupCount(t *testing.T, ctx context.Context, db *rhiza.DB, table, clientID string) int64 {
	t.Helper()
	sql, args := `SELECT COUNT(*) FROM `+table+` WHERE client_id=?`, []any{clientID}
	switch table {
	case "oauth_token_requests":
		sql, args = `SELECT COUNT(*) FROM oauth_token_requests WHERE signature='cleanup-access'`, nil
	case "oauth_refresh_tokens":
		sql, args = `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE access_signature='cleanup-access'`, nil
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("count %s: rows=%#v err=%v", table, result.Rows, err)
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("count %s value=%#v", table, result.Rows[0][0])
	}
	return value
}

func ptrTime(value time.Time) *time.Time { return &value }
