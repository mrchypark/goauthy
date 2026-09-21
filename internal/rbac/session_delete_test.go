package rbac

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func deleteSessionSID(t *testing.T, n byte) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = n
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sid, err := browser.CanonicalTokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestDeleteSessionScopesSessionBoundState(t *testing.T) {
	t.Parallel()
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "target")
	insertActive(t, db, "other")
	targetSID := deleteSessionSID(t, 1)
	sameUserSID := deleteSessionSID(t, 2)
	otherSID := deleteSessionSID(t, 3)
	seed := []rhiza.SQLStatement{
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{targetSID, "target", "pwd", int64(1), int64(4102444800000), int64(1), sameUserSID, "target", "pwd", int64(1), int64(4102444800000), int64(1), otherSID, "other", "pwd", int64(1), int64(4102444800000), int64(1)}},
		{SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{targetSID, "https://upstream.example.test", "client", "target", "upstream-target", int64(1), sameUserSID, "https://upstream.example.test", "client", "target", "upstream-same", int64(1), otherSID, "https://upstream.example.test", "client", "other", "upstream-other", int64(1)}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{targetSID, "target-client", "https://rp.example.test/logout", int64(0), int64(0), int64(1), sameUserSID, "same-client", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{"interaction-target", "interaction-target", targetSID, `{}`, int64(1), int64(4102444800000), "interaction-other", "interaction-other", otherSID, `{}`, int64(1), int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code-target", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + targetSID + `"}}`, int64(4102444800000), "code-other", `{"subject":"other"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code-target", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + targetSID + `"}}`, int64(4102444800000), "code-other", `{"subject":"other"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?),(?,?)`, Args: []any{"token-target", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + targetSID + `"}}`, "token-other", `{"subject":"other"}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?)`, Args: []any{"token-target", "token-target", "target-client", int64(1), int64(4102444800000), "", "", "", "", "token-other", "token-other", "other-client", int64(1), int64(4102444800000), "", "", "", ""}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?),(?,?,?,?,?)`, Args: []any{"refresh-target", "token-target", "token-target", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + targetSID + `"}}`, int64(4102444800000), "refresh-other", "token-other", "token-other", `{"subject":"other"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code-same", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sameUserSID + `"}}`, int64(4102444800000), "code-sessionless", `{"subject":"target"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?),(?,?,?)`, Args: []any{"code-same", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sameUserSID + `"}}`, int64(4102444800000), "code-sessionless", `{"subject":"target"}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?),(?,?)`, Args: []any{"token-same", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sameUserSID + `"}}`, "token-sessionless", `{"subject":"target"}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?)`, Args: []any{"token-same", "token-same", "same-client", int64(1), int64(4102444800000), "", "", "", "", "token-sessionless", "token-sessionless", "target-client", int64(1), int64(4102444800000), "", "", "", ""}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?),(?,?,?,?,?)`, Args: []any{"refresh-same", "token-same", "token-same", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sameUserSID + `"}}`, int64(4102444800000), "refresh-sessionless", "token-sessionless", "token-sessionless", `{"subject":"target"}`, int64(4102444800000)}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-seed", Statements: seed}); err != nil {
		t.Fatal(err)
	}
	guard := `EXISTS (SELECT 1 FROM browser_sessions WHERE token_digest=? AND subject=? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>?)`
	if err := store.DeleteSession(ctx, "delete-session", targetSID, guard, targetSID, "target", store.now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, targetSID, 0)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, sameUserSID, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, otherSID, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, targetSID, 0)
	count(t, db, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, sameUserSID, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, otherSID, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest=?`, targetSID, 0)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest=?`, otherSID, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, targetSID, 0)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, sameUserSID, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, targetSID, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=? AND created_at_unix_ms=1700000000000 AND next_attempt_at_unix_ms=1700000000000`, targetSID, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sameUserSID, 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=? AND invalidated=1`, "code-target", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, "code-target", 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "token-target", 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "token-target", 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=0`, "refresh-target", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=?`, "code-other", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "token-other", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "refresh-other", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=? AND invalidated=0`, "code-same", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, "code-same", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "token-same", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "token-same", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "refresh-same", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=? AND invalidated=0`, "code-sessionless", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, "code-sessionless", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "token-sessionless", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "token-sessionless", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "refresh-sessionless", 1)
	count(t, db, `SELECT COUNT(*) FROM event_log WHERE typ=?`, "ForcedLogout", 0)
	count(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject=? AND disabled=0 AND password_phc='phc'`, "target", 1)
	if err := store.DeleteSession(ctx, "delete-session-again", targetSID, "1=1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat delete=%v", err)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, targetSID, 1)
}

func TestDeleteSessionGuardsAndRollback(t *testing.T) {
	t.Parallel()
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "target")
	sid := deleteSessionSID(t, 4)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-guard-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{sid, "target", "pwd", int64(1), int64(4102444800000), int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-binding-seed", SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,created_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{sid, "https://upstream.example.test", "client", "target", int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSession(ctx, "delete-denied", sid, "0=1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("denied delete=%v", err)
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, sid, 1)
	if err := store.DeleteSession(ctx, "delete-missing", deleteSessionSID(t, 5), "1=1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-rollback-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{sid, "target-client", "https://rp.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{"rollback-interaction", "rollback-interaction", sid, `{}`, int64(1), int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"rollback-code", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sid + `"}}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"rollback-code", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sid + `"}}`, int64(4102444800000)}},
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{"rollback-token", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sid + `"}}`}},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES(?,?,?,?,?,?,?,?,?)`, Args: []any{"rollback-token", "rollback-token", "target-client", int64(1), int64(4102444800000), "", "", "", ""}},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{"rollback-refresh", "rollback-token", "rollback-token", `{"subject":"target","extra":{"goauthy_oidc_session_id":"` + sid + `"}}`, int64(4102444800000)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSession(ctx, "delete-rich-denied", sid, "0=1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rich denied delete=%v", err)
	}
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "rollback-token", 1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-trigger", SQL: `CREATE TRIGGER reject_session_delete BEFORE DELETE ON browser_sessions BEGIN SELECT RAISE(ABORT,'session sink unavailable'); END`}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-session-trigger-drop", SQL: `DROP TRIGGER reject_session_delete`})
	})
	if err := store.DeleteSession(ctx, "delete-rollback", sid, "1=1"); err == nil {
		t.Fatal("trigger failure unexpectedly committed")
	}
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid, 0)
	count(t, db, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, sid, 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature=? AND invalidated=0`, "rollback-code", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, "rollback-code", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "rollback-token", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "rollback-token", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "rollback-refresh", 1)
}
