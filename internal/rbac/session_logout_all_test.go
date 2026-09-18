package rbac

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLogoutAllSessionsRevokesAllBrowserAndOAuthState(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	for _, subject := range []string{"target", "other"} {
		insertActive(t, db, subject)
	}
	sid1, sid2, sid3, sid4 := deleteSessionSID(t, 11), deleteSessionSID(t, 12), deleteSessionSID(t, 13), deleteSessionSID(t, 14)
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms) VALUES(?,?,?,?,?,?,?),(?,?,?,?,?,?,?),(?,?,?,?,?,?,?),(?,?,?,?,?,?,?)`, Args: []any{sid1, "target", "pwd", int64(1), int64(4102444800000), int64(1), nil, sid2, "target", "pwd", int64(1), int64(4102444800000), int64(1), nil, sid3, "other", "pwd", int64(1), int64(4102444800000), int64(1), nil, sid4, "other", "pwd", int64(1), int64(4102444800000), int64(1), int64(123)}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?),(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{sid1, "client-a", "https://rp.example.test/a", int64(0), int64(0), int64(1), sid1, "client-b", "https://rp.example.test/b", int64(0), int64(0), int64(1), sid2, "client-a", "https://rp.example.test/a", int64(0), int64(0), int64(1), sid4, "old-client", "https://rp.example.test/old", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oidc_backchannel_deliveries(event_id,client_id,sid,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"old-event", "old-client", sid4, "https://rp.example.test/old", int64(0), int64(0), int64(0), int64(1), int64(1)}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms)
			SELECT b.subject,c.client_id,c.logout_uri,c.allow_private,c.allow_http,MIN(c.created_at_unix_ms)
			FROM oidc_session_clients c JOIN browser_sessions b ON c.sid=b.token_digest GROUP BY b.subject,c.client_id`},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('other','without-browser','https://rp.example.test/no-browser',0,0,1)`},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{"i1", "i1", sid1, `{}`, int64(1), int64(4102444800000), "i3", "i3", sid3, `{}`, int64(1), int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code1", `{"subject":"target"}`, int64(4102444800000), "code2", `{"subject":"other"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code1", `{}`, int64(4102444800000), "code2", `{}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?),(?,?),(?,?)`, Args: []any{"token1", `{"subject":"target"}`, "token2", `{"subject":"other"}`, "client-credentials", `{}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?)`, Args: []any{"token1", "token1", "client-a", int64(1), int64(4102444800000), "", "", "", "", "token2", "token2", "client-b", int64(1), int64(4102444800000), "", "", "", "", "client-credentials", "client-credentials", "client-a", int64(1), int64(4102444800000), "", "", "", ""}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?),(?,?,?,?,?)`, Args: []any{"refresh1", "token1", "token1", `{"subject":"target"}`, int64(4102444800000), "refresh2", "token2", "token2", `{"subject":"other"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_device_grants(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?,?)`, Args: []any{"device-pending", "user-pending", "client-a", `[]`, "target", "pending", int64(4102444800000), int64(5), int64(1), int64(1), "device-approved", "user-approved", "client-b", `[]`, "other", "approved", int64(4102444800000), int64(5), int64(1), int64(1)}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logout-all-seed", Statements: seed}); err != nil {
		t.Fatal(err)
	}
	preserved := make(map[string][][]any)
	for _, table := range []string{"identity_users", "oauth_device_grants"} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT * FROM ` + table + ` ORDER BY 1`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		preserved[table] = result.Rows
	}
	if err := store.LogoutAllSessions(ctx, "logout-all-denied-rich", "0=1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rich denied logout=%v", err)
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NULL AND ?`, int64(1), 3)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms=?`, int64(123), 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE ?`, int64(1), 4)
	count(t, db, `SELECT COUNT(*) FROM oidc_user_clients WHERE ?`, int64(1), 4)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE ?`, int64(1), 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE ?`, int64(1), 3)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE ?`, 1, 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=0 AND ?`, 1, 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE ?`, 1, 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=1 AND ?`, 1, 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE ?`, 1, 3)
	guard := `EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>?)`
	if err := store.LogoutAllSessions(ctx, "logout-all", guard, sid1, store.now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NULL AND ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms=?`, int64(1700000000000), 3)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms=?`, int64(123), 1)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_user_clients WHERE ?`, 1, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, "target", 2)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND sid IS NULL`, "other", 2)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND client_id='without-browser'`, "other", 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid1, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid2, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid3, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=? AND event_id='old-event'`, sid4, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=? AND next_attempt_at_unix_ms=1700000000000 AND created_at_unix_ms=1700000000000`, "target", 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=1 AND ?`, int64(1), 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE ?`, int64(1), 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=0 AND ?`, int64(1), 2)
	count(t, db, `SELECT COUNT(*) FROM oauth_device_grants WHERE state IN ('pending','approved') AND ?`, int64(1), 2)
	count(t, db, `SELECT COUNT(*) FROM identity_users WHERE ?`, int64(1), 2)
	count(t, db, `SELECT COUNT(*) FROM event_log WHERE typ=?`, "ForcedLogout", 0)
	for table, before := range preserved {
		after, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT * FROM ` + table + ` ORDER BY 1`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || !reflect.DeepEqual(before, after.Rows) {
			t.Fatalf("global logout changed preserved table %s: err=%v", table, err)
		}
	}
	if err := store.LogoutAllSessions(ctx, "logout-all-repeat", "1=1"); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE ?`, int64(1), 5)
}

func TestLogoutAllSessionsBarrierAndRollback(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	if err := store.LogoutAllSessions(ctx, "logout-all-empty", "1=1"); err != nil {
		t.Fatal(err)
	}
	if err := store.LogoutAllSessions(ctx, "logout-all-denied", "0=1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("empty denied=%v", err)
	}
	insertActive(t, db, "target")
	sid := deleteSessionSID(t, 15)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logout-all-rollback-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{sid, "target", "pwd", int64(1), int64(4102444800000), int64(1)}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{sid, "rollback-client", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target','rollback-client','https://rp.example.test/logout',0,0,1)`},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{"rollback-i", "rollback-i", sid, `{}`, int64(1), int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"rollback-code", `{"subject":"target"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"rollback-code", `{}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{"rollback-token", `{"subject":"target"}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"rollback-token", "rollback-token", "rollback-client", int64(1), int64(4102444800000), "", "", "", ""}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"rollback-refresh", "rollback-token", "rollback-token", `{"subject":"target"}`, int64(4102444800000)}},
		{SQL: `CREATE TRIGGER reject_logout_all BEFORE DELETE ON oidc_session_clients BEGIN SELECT RAISE(ABORT,'logout sink unavailable'); END`},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logout-all-trigger-drop", SQL: `DROP TRIGGER reject_logout_all`})
	})
	if err := store.LogoutAllSessions(ctx, "logout-all-rollback", "1=1"); err == nil {
		t.Fatal("trigger failure unexpectedly committed")
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_user_clients WHERE subject=?`, "target", 1)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=? AND invalidated=0`, "rollback-code", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, "rollback-code", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "rollback-token", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "rollback-token", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "rollback-refresh", 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE subject=?`, "target", 0)
}

func TestLogoutSkipsUnregisteredBackchannelEndpoint(t *testing.T) {
	for _, all := range []bool{false, true} {
		name := "subject"
		if all {
			name = "all"
		}
		t.Run(name, func(t *testing.T) {
			ctx, store, db := rbacTestStore(t)
			insertActive(t, db, "target")
			_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "endpoint-seed", SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('target','without-uri','',0,0,1),('target','with-uri','https://rp.example.test/logout',0,0,1)`})
			if err != nil {
				t.Fatal(err)
			}
			if all {
				err = store.LogoutAllSessions(ctx, "endpoint-logout", "1=1")
			} else {
				err = store.ForceLogout(ctx, "endpoint-logout", "target", "1=1")
			}
			if err != nil {
				t.Fatal(err)
			}
			count(t, db, `SELECT COUNT(*) FROM oidc_user_clients WHERE ?`, 1, 0)
			count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE client_id=?`, "without-uri", 0)
			count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE client_id=? AND sid IS NULL`, "with-uri", 1)
		})
	}
}
