package device

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRevokeUserSessionInvalidatesOnlyOneDeviceFamily(t *testing.T) {
	ctx, store, db := testStore(t)
	fixed := time.UnixMilli(1700000000000)
	store.now = func() time.Time { return fixed }
	for i, id := range []string{"request-a", "request-b"} {
		_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "session-seed-" + id, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms,token_request_id) VALUES(?,?,?,?,?,'consumed',?,?,?,?,?)`, Args: []any{"device-" + id, "user-" + id, "same-client", `["goauthy.read"]`, "owner", fixed.Add(time.Hour).UnixMilli(), 5, fixed.UnixMilli(), fixed.UnixMilli() + int64(i), id}},
			{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"access-" + id, id, "same-client", fixed.UnixMilli(), fixed.Add(time.Hour).UnixMilli(), `["goauthy.read"]`, `["goauthy.read"]`, `[]`, `[]`}},
			{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{"access-" + id, `{"id":"` + id + `"}`}},
			{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"refresh-" + id, "access-" + id, id, `{"id":"` + id + `"}`, fixed.Add(time.Hour).UnixMilli()}},
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	authority := func() (string, []any) { return "1=1", nil }
	items, err := store.ListUserSessions(ctx, "owner", authority)
	if err != nil || len(items) != 2 || items[0].ID != "request-a" || items[1].ID != "request-b" {
		t.Fatalf("device list=%v err=%v", items, err)
	}
	if items[0].ClientID != "same-client" || len(items[0].Scopes) != 1 || items[0].Scopes[0] != "goauthy.read" || items[0].CreatedAtUnixMS != fixed.UnixMilli() || items[0].RevokedAtUnixMS != nil {
		t.Fatalf("device fields=%+v", items[0])
	}
	if err := store.RevokeUserSession(ctx, "owner", "request-a", authority); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens WHERE request_id='request-a'),(SELECT COUNT(*) FROM oauth_token_requests WHERE signature='access-request-a'),(SELECT active FROM oauth_refresh_tokens WHERE request_id='request-a'),(SELECT revoked_at_unix_ms FROM oauth_device_grants WHERE token_request_id='request-a'),(SELECT COUNT(*) FROM oauth_access_tokens WHERE request_id='request-b')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if got := rows.Rows[0]; got[0] != int64(0) || got[1] != int64(0) || got[2] != int64(0) || got[3] != int64(1700000000000) || got[4] != int64(1) {
		t.Fatalf("state=%v", got)
	}
	if err := store.RevokeUserSession(ctx, "wrong-owner", "request-b", authority); err == nil {
		t.Fatal("wrong owner revoke succeeded")
	}
	fixed = fixed.Add(time.Hour)
	if err := store.RevokeUserSession(ctx, "owner", "request-a", authority); err != nil {
		t.Fatal(err)
	}
	items, err = store.ListUserSessions(ctx, "owner", authority)
	if err != nil || len(items) != 2 || items[0].RevokedAtUnixMS == nil || *items[0].RevokedAtUnixMS != 1700000000000 || items[1].RevokedAtUnixMS != nil {
		t.Fatalf("repeat revoke list=%v err=%v", items, err)
	}
}
