package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestSelfPasswordChangeRevokesOtherSessionsAndOAuthState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(1_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "subject-2", "bob", []byte("OtherPassword1"))
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	current, err := sessions.CreateSession(ctx, "subject-1", "pwd", expires, "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := sessions.CreateSession(ctx, "subject-1", "mfa", expires, "")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := sessions.CreateSession(ctx, "subject-2", "pwd", expires, "")
	if err != nil {
		t.Fatal(err)
	}
	seedPasswordChangeArtifacts(t, store, current.ID, other.ID, "subject-1")

	if err := store.ChangePasswordWithSession(ctx, "subject-1", current.ID, []byte("CurrentPassword1"), []byte("ChangedPassword2")); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.LoadSession(ctx, current.Token); err != nil {
		t.Fatalf("current session revoked: %v", err)
	}
	if _, err := sessions.LoadSession(ctx, other.Token); !errors.Is(err, browser.ErrRevoked) {
		t.Fatalf("other session load error=%v want revoked", err)
	}
	if _, err := sessions.LoadSession(ctx, unrelated.Token); err != nil {
		t.Fatalf("unrelated user session revoked: %v", err)
	}
	assertPasswordChangeCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, 1, current.ID)
	assertPasswordChangeCount(t, store, `SELECT COUNT(*) FROM oidc_session_clients WHERE sid=?`, 0, other.ID)
	assertPasswordChangeCount(t, store, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, 1, other.ID)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=1 AND json_extract(request_json,'$.subject')='subject-1'`, 2)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature IN ('code-one','code-two')`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature IN ('access-direct','access-delegated')`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature IN ('access-direct','access-delegated')`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=0 AND json_extract(request_json,'$.subject')='subject-1'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_device_grants WHERE state='denied' AND subject='subject-1'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='access-unrelated'`, 1)
}

func TestAdminPasswordChangeRevokesAllSubjectSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(2_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice@example.test", []byte("CurrentPassword1"))
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	first, err := sessions.CreateSession(ctx, "subject-1", "pwd", expires, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := sessions.CreateSession(ctx, "subject-1", "mfa", expires, "")
	if err != nil {
		t.Fatal(err)
	}
	seedPasswordChangeArtifacts(t, store, first.ID, second.ID, "subject-1")
	password := "ChangedPassword2"
	if _, err := store.UpdateUserWithGuard(ctx, "subject-1", UserUpdate{Email: "alice@example.test", Password: &password, Enabled: true}, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"first": first.Token, "second": second.Token} {
		if _, err := sessions.LoadSession(ctx, token); !errors.Is(err, browser.ErrRevoked) {
			t.Fatalf("%s session error=%v want revoked", name, err)
		}
	}
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=1`, 2)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature IN ('access-direct','access-delegated')`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_device_grants WHERE state='denied'`, 1)
}

func TestPasswordChangeArtifactRevocationIsAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(3_000) }
	seedDeterministicRandom(store)
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	seedPasswordChangeArtifacts(t, store, issued.ID, "other-session", "subject-1")
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "reject-password-revocation", SQL: `CREATE TRIGGER reject_password_revocation BEFORE DELETE ON oauth_access_tokens BEGIN SELECT RAISE(ABORT,'injected revocation failure'); END`}); err != nil {
		t.Fatal(err)
	}
	if err := store.ChangePasswordWithSession(ctx, "subject-1", issued.ID, []byte("CurrentPassword1"), []byte("ChangedPassword2")); err == nil {
		t.Fatal("password change succeeded despite rejected revocation")
	}
	if err := store.VerifyPassword(ctx, "subject-1", []byte("CurrentPassword1")); err != nil {
		t.Fatalf("old password did not roll back: %v", err)
	}
	assertPasswordChangeCount(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, 1, issued.ID)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE invalidated=0 AND json_extract(request_json,'$.subject')='subject-1'`, 2)
	assertCount(t, store, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature='access-direct'`, 1)
}

func seedPasswordChangeArtifacts(t *testing.T, store *Store, currentSession, otherSession, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "password-change-artifacts", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_session_clients (sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES (?,?,?,?,?,?),(?,?,?,?,?,?)`, Args: []any{currentSession, "current-client", "https://current.example.test/logout", int64(0), int64(0), int64(1), otherSession, "other-client", "https://other.example.test/logout", int64(0), int64(0), int64(1)}},
		{SQL: `INSERT INTO oauth_authorize_codes (signature,request_json,expires_at_unix_ms) VALUES (?,?,?),(?,?,?),(?,?,?)`, Args: []any{"code-one", `{"subject":"` + subject + `"}`, int64(999999), "code-two", `{"subject":"` + subject + `"}`, int64(999999), "code-unrelated", `{"subject":"subject-2"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_pkce_requests (signature,request_json,expires_at_unix_ms) VALUES (?,?,?),(?,?,?),(?,?,?)`, Args: []any{"code-one", `{}`, int64(999999), "code-two", `{}`, int64(999999), "code-unrelated", `{}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_access_tokens (signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES (?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?)`, Args: []any{"access-direct", "access-direct", "client", int64(1), int64(999999), "[]", "[]", "[]", "[]", "access-delegated", "access-delegated", "client", int64(1), int64(999999), "[]", "[]", "[]", "[]", "access-unrelated", "access-unrelated", "client", int64(1), int64(999999), "[]", "[]", "[]", "[]"}},
		{SQL: `INSERT INTO oauth_token_requests (signature,request_json) VALUES (?,?),(?,?),(?,?)`, Args: []any{"access-direct", `{"subject":"` + subject + `"}`, "access-delegated", `{"subject":"delegator","extra":{"act":{"sub":"` + subject + `"}}}`, "access-unrelated", `{"subject":"subject-2"}`}},
		{SQL: `INSERT INTO oauth_refresh_tokens (signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES (?,?,?,?,?)`, Args: []any{"refresh-one", "access-direct", "access-direct", `{"subject":"` + subject + `"}`, int64(999999)}},
		{SQL: `INSERT INTO oauth_device_grants (device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,'approved',?,?,?,?)`, Args: []any{"device-one", "user-one", "client", "[]", subject, int64(999999), int64(5), int64(1), int64(1)}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func assertPasswordChangeCount(t *testing.T, store *Store, query string, want int64, args ...any) {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("count query=%q rows=%#v err=%v want=%d", query, result.Rows, err, want)
	}
}
