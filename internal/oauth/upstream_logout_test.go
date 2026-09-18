package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRevokeUpstreamSessionsDurablyRevokesExactBindings(t *testing.T) {
	db := oauthTestDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := &Store{db: db, now: func() time.Time { return now }}
	issuer, client := "https://upstream.example.test", "upstream-client"
	target, sameSubject, sameSID, otherIssuer := oidcTestSessionID(41), oidcTestSessionID(42), oidcTestSessionID(43), oidcTestSessionID(44)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{
		{session: target, subject: "alice", sid: "upstream-sid"},
		{session: sameSubject, subject: "alice", sid: "other-sid"},
		{session: sameSID, subject: "bob", sid: "upstream-sid"},
		{session: otherIssuer, subject: "alice", sid: "upstream-sid", issuer: "https://other.example.test"},
	})
	logout := upstreamLogoutForTest(issuer, client, "alice", "upstream-sid", "logout-1", "token-one", now.Add(time.Minute))
	if err := store.RevokeUpstreamSessions(context.Background(), logout); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		sid     string
		revoked bool
	}{{target, true}, {sameSubject, false}, {sameSID, false}, {otherIssuer, false}} {
		row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT revoked_at_unix_ms FROM browser_sessions WHERE token_digest=?`, Args: []any{check.sid}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || (row.Rows[0][0] != nil) != check.revoked {
			t.Fatalf("sid=%s revoked=%v rows=%v err=%v", check.sid, check.revoked, row.Rows, err)
		}
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, 1, target)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE signature='upstream-code-`+target+`' AND invalidated=1`, 1)
	fresh := oidcTestSessionID(45)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{{session: fresh, subject: "alice", sid: "upstream-sid"}})
	if err := store.RevokeUpstreamSessions(context.Background(), logout); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM upstream_logout_receipts`, 1)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 0, fresh)

	conflict := upstreamLogoutForTest(issuer, client, "bob", "upstream-sid", "logout-1", "different-token", now.Add(time.Minute))
	if err := store.RevokeUpstreamSessions(context.Background(), conflict); err == nil {
		t.Fatal("same JTI with different verified claims was accepted")
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 0, sameSID)
}

func TestRevokeUpstreamSessionsSubjectOrSIDAndRollback(t *testing.T) {
	db := oauthTestDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := &Store{db: db, now: func() time.Time { return now }}
	issuer, client := "https://upstream.example.test", "upstream-client"
	first, second, third := oidcTestSessionID(51), oidcTestSessionID(52), oidcTestSessionID(53)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{
		{session: first, subject: "alice", sid: "one"},
		{session: second, subject: "alice", sid: "two"},
		{session: third, subject: "bob", sid: "two"},
	})
	if err := store.RevokeUpstreamSessions(context.Background(), upstreamLogoutForTest(issuer, client, "alice", "", "subject-only", "subject-token", now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NOT NULL`, 2)
	if err := store.RevokeUpstreamSessions(context.Background(), upstreamLogoutForTest(issuer, client, "", "two", "sid-only", "sid-token", now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NOT NULL`, 3)

	failing := oidcTestSessionID(54)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{{session: failing, subject: "carol", sid: "three"}})
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "upstream-logout-abort-trigger", SQL: `CREATE TRIGGER upstream_logout_abort BEFORE UPDATE ON browser_sessions WHEN NEW.token_digest='` + failing + `' BEGIN SELECT RAISE(ABORT,'rollback'); END`}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "upstream-logout-abort-drop", SQL: `DROP TRIGGER IF EXISTS upstream_logout_abort`})
	})
	failLogout := upstreamLogoutForTest(issuer, client, "carol", "three", "rollback-jti", "rollback-token", now.Add(time.Minute))
	if err := store.RevokeUpstreamSessions(context.Background(), failLogout); err == nil {
		t.Fatal("transaction abort accepted")
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM upstream_logout_receipts WHERE jti='rollback-jti'`, 0)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 0, failing)
}

func TestRevokeUpstreamSessionsRequiresBeforeAckDurability(t *testing.T) {
	ctx := context.Background()
	objectStore := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "upstream-logout-before-ack", DataDir: t.TempDir(), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objectStore, ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := &Store{db: db, now: func() time.Time { return now }}
	session := oidcTestSessionID(61)
	seedUpstreamLogoutSessions(t, db, now, "https://upstream.example.test", "upstream-client", []upstreamLogoutBinding{{session: session, subject: "alice", sid: "sid"}})
	logout := upstreamLogoutForTest("https://upstream.example.test", "upstream-client", "alice", "sid", "before-ack", "before-ack-token", now.Add(time.Minute))
	backup := objectStore + "-unavailable"
	if err := os.Rename(objectStore, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectStore, []byte("unavailable"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(objectStore)
		_ = os.Rename(backup, objectStore)
	})
	if err := store.RevokeUpstreamSessions(ctx, logout); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("first before-ack error=%v", err)
	}
	if err := store.RevokeUpstreamSessions(ctx, logout); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("retry before restore error=%v", err)
	}
	if err := os.Remove(objectStore); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, objectStore); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeUpstreamSessions(ctx, logout); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 1, session)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
}

type upstreamLogoutBinding struct {
	session, subject, sid, issuer string
}

func seedUpstreamLogoutSessions(t *testing.T, db *rhiza.DB, now time.Time, issuer, client string, bindings []upstreamLogoutBinding) {
	t.Helper()
	for _, binding := range bindings {
		if binding.issuer == "" {
			binding.issuer = issuer
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "upstream-logout-seed-" + binding.session, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?, 'external',?,?,?)`, Args: []any{binding.session, "local-" + binding.session[:8], now.UnixMilli(), now.Add(time.Hour).UnixMilli(), now.UnixMilli()}},
			{SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{binding.session, binding.issuer, client, binding.subject, binding.sid, now.UnixMilli()}},
			{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,0,0,?)`, Args: []any{binding.session, "rp-" + binding.session[:8], "https://rp.example.test/logout", now.UnixMilli()}},
			{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{"upstream-code-" + binding.session, `{"extra":{"goauthy_oidc_session_id":"` + binding.session + `"}}`, now.Add(time.Hour).UnixMilli()}},
		}}); err != nil {
			t.Fatal(err)
		}
	}
}

func upstreamLogoutForTest(issuer, client, subject, sid, jti, raw string, expiresAt time.Time) UpstreamLogout {
	sum := sha256.Sum256([]byte(raw))
	return UpstreamLogout{Issuer: issuer, ClientID: client, Subject: subject, SessionID: sid, JTI: jti, TokenDigest: base64.RawURLEncoding.EncodeToString(sum[:]), ExpiresAt: expiresAt}
}

func assertUpstreamLogoutCount(t *testing.T, db *rhiza.DB, sql string, want int64, args ...any) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("query=%q args=%v rows=%v err=%v", sql, args, result.Rows, err)
	}
}

func TestUpstreamLogoutReceiptSurvivesRestart(t *testing.T) {
	ctx := t.Context()
	cfg := rhiza.Config{NodeID: "upstream-logout-restart", DataDir: t.TempDir()}
	db, err := rhiza.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	issuer, client := "https://upstream.example.test", "upstream-client"
	target, fresh := oidcTestSessionID(71), oidcTestSessionID(72)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{{session: target, subject: "alice", sid: "sid"}})
	logout := upstreamLogoutForTest(issuer, client, "alice", "sid", "restart-jti", "restart-token", now.Add(time.Minute))
	store := &Store{db: db, now: func() time.Time { return now }}
	if err := store.RevokeUpstreamSessions(ctx, logout); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = rhiza.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
	store = &Store{db: db, now: func() time.Time { return now }}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 1, target)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM upstream_logout_receipts WHERE jti=?`, 1, logout.JTI)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{{session: fresh, subject: "alice", sid: "sid"}})
	if err := store.RevokeUpstreamSessions(ctx, logout); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, 1, fresh)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
	conflict := upstreamLogoutForTest(issuer, client, "alice", "sid", logout.JTI, "changed-token", logout.ExpiresAt)
	if err := store.RevokeUpstreamSessions(ctx, conflict); err == nil {
		t.Fatal("restart lost JTI token binding")
	}
	now = logout.ExpiresAt
	if err := store.RevokeUpstreamSessions(ctx, logout); err == nil {
		t.Fatal("expired token replay accepted")
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, 1, fresh)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
}

func TestUpstreamLogoutConcurrentReplayAndConflictingJTI(t *testing.T) {
	db := oauthTestDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := &Store{db: db, now: func() time.Time { return now }}
	issuer, client := "https://upstream.example.test", "upstream-client"
	first, second := oidcTestSessionID(81), oidcTestSessionID(82)
	seedUpstreamLogoutSessions(t, db, now, issuer, client, []upstreamLogoutBinding{{session: first, subject: "alice", sid: "one"}, {session: second, subject: "bob", sid: "two"}})
	alice := upstreamLogoutForTest(issuer, client, "alice", "one", "concurrent-jti", "alice-token", now.Add(time.Minute))
	bob := upstreamLogoutForTest(issuer, client, "bob", "two", "concurrent-jti", "bob-token", now.Add(time.Minute))
	type outcome struct {
		token string
		err   error
	}
	const callers = 8
	start := make(chan struct{})
	results := make(chan outcome, callers)
	for i := 0; i < callers; i++ {
		request := alice
		if i%2 != 0 {
			request = bob
		}
		go func() {
			<-start
			// Each caller uses a separate Store, as separate HTTP handlers would.
			caller := &Store{db: db, now: func() time.Time { return now }}
			results <- outcome{request.TokenDigest, caller.RevokeUpstreamSessions(t.Context(), request)}
		}()
	}
	close(start)
	outcomes := make([]outcome, 0, callers)
	for i := 0; i < callers; i++ {
		outcomes = append(outcomes, <-results)
	}
	receipt, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT token_digest FROM upstream_logout_receipts WHERE issuer=? AND client_id=? AND jti=?`, Args: []any{issuer, client, alice.JTI}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(receipt.Rows) != 1 {
		t.Fatalf("receipt=%v err=%v", receipt.Rows, err)
	}
	winner := receipt.Rows[0][0]
	if winner != alice.TokenDigest && winner != bob.TokenDigest {
		t.Fatal("receipt selected neither token")
	}
	for _, result := range outcomes {
		if (result.token == winner) != (result.err == nil) {
			t.Fatalf("concurrent result token=%s winner=%v err=%v", result.token, winner, result.err)
		}
	}
	target, untouched := first, second
	winningRequest := alice
	if winner == bob.TokenDigest {
		target, untouched = second, first
		winningRequest = bob
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NOT NULL`, 1, target)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, 1, untouched)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM upstream_logout_receipts`, 1)
	if err := store.RevokeUpstreamSessions(t.Context(), winningRequest); err != nil {
		t.Fatal(err)
	}
	assertUpstreamLogoutCount(t, db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, 1)
}
