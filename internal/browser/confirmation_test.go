package browser

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func seedConfirmationCleanup(t *testing.T, s *Store, now time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("seed-expired-%d", i), SQL: "INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,'eA',?,?)", Args: []any{fmt.Sprintf("expired-%d", i), fmt.Sprintf("expired-request-%d", i), "old-session", now.Add(-time.Hour).UnixMilli(), now.UnixMilli()}})
		if err != nil {
			t.Fatal(err)
		}
	}
}
func confirmationCount(t *testing.T, s *Store) int64 {
	t.Helper()
	q, err := s.db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM browser_authorization_interactions", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("count=%+v err=%v", q, err)
	}
	return q.Rows[0][0].(int64)
}
func TestConfirmationCreateCleanup(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		for _, n := range []int{0, 1, 3} {
			t.Run(fmt.Sprintf("authenticated=%v/cleanup=%d", authenticated, n), func(t *testing.T) {
				s := testStore(t)
				now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
				s.now = func() time.Time { return now }
				var session IssuedSession
				var err error
				if authenticated {
					session, err = s.CreateSession(t.Context(), "user-1", "pwd", now.Add(time.Hour), "")
				} else {
					session, err = s.CreateInitSession(t.Context(), now.Add(time.Hour), "")
				}
				if err != nil {
					t.Fatal(err)
				}
				seedConfirmationCleanup(t, s, now, n)
				payload := []byte("request payload")
				issued, err := s.CreateAuthorizationInteraction(t.Context(), session.Token, "new-request", payload, now.Add(time.Minute))
				if err != nil || issued.Token == "" || issued.RequestID != "new-request" || !issued.ExpiresAt.Equal(now.Add(time.Minute)) {
					t.Fatalf("issued=%+v err=%v", issued, err)
				}
				payload[0] = 'X'
				if string(issued.Payload) != "request payload" {
					t.Fatal("payload aliases input")
				}
				if count := confirmationCount(t, s); count != 1 {
					t.Fatalf("cleanup count=%d", count)
				}
				var loaded AuthorizationInteraction
				if authenticated {
					loaded, err = s.LoadAuthorizationInteractionReadOnlyForSession(t.Context(), session.Token, issued.Token)
				} else {
					loaded, err = s.LoadAuthorizationInteractionReadOnly(t.Context(), session.Token, issued.Token)
				}
				if err != nil || loaded.RequestID != "new-request" || string(loaded.Payload) != "request payload" || !loaded.ExpiresAt.Equal(issued.ExpiresAt) {
					t.Fatalf("persisted binding=%+v err=%v", loaded, err)
				}
			})
		}
	}
}

func TestAuthorizationInteractionCleanupMutationCap(t *testing.T) {
	for _, path := range []string{"existing-session", "combined-init-pair"} {
		t.Run(path, func(t *testing.T) {
			s := testStore(t)
			ctx := t.Context()
			base := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
			now := base
			s.now = func() time.Time { return now }
			session, err := s.CreateInitSession(ctx, base.Add(time.Hour), "")
			if err != nil {
				t.Fatal(err)
			}
			expiredReplay, err := s.CreateAuthorizationInteraction(ctx, session.Token, "expired-replay-target", []byte("expired"), base.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			live, err := s.CreateAuthorizationInteraction(ctx, session.Token, "live-control", []byte("live"), base.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}

			now = base.Add(2 * time.Second)
			statements := make([]rhiza.SQLStatement, 0, 40)
			for i := range 40 {
				expiresAt := base.Add(-time.Duration(40-i) * time.Second)
				statements = append(statements, rhiza.SQLStatement{
					SQL:  `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,'eA',?,?)`,
					Args: []any{fmt.Sprintf("cleanup-expired-%02d", i), fmt.Sprintf("cleanup-expired-request-%02d", i), "expired-session", expiresAt.UnixMilli(), expiresAt.UnixMilli()},
				})
			}
			if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-interaction-cleanup-backlog", Statements: statements}); err != nil {
				t.Fatal(err)
			}

			var issued IssuedAuthorizationInteraction
			if path == "existing-session" {
				issued, err = s.CreateAuthorizationInteraction(ctx, session.Token, "cleanup-trigger-existing", []byte("new"), now.Add(time.Minute))
			} else {
				var paired IssuedSession
				paired, issued, err = s.CreateInitSessionWithAuthorizationInteraction(ctx, "", "cleanup-trigger-pair", []byte("new"), now.Add(time.Minute))
				if err == nil && (paired.Token == "" || paired.ID == "") {
					t.Fatal("combined init flow returned an empty session")
				}
			}
			if err != nil || issued.Token == "" {
				t.Fatalf("interaction creation=%+v err=%v", issued, err)
			}

			for i := range 40 {
				want := int64(0)
				if i >= 32 {
					want = 1
				}
				if got := confirmationMatchingCount(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE token_digest=?`, fmt.Sprintf("cleanup-expired-%02d", i)); got != want {
					t.Errorf("expired row %02d count=%d want=%d (oldest rows should be swept first)", i, got, want)
				}
			}
			if got := confirmationMatchingCount(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE expires_at_unix_ms<=?`, now.UnixMilli()); got != 9 {
				t.Errorf("expired rows remaining=%d want=9 (40-row backlog plus retained replay target, minus 32)", got)
			}
			expiredDigest, err := tokenDigest(expiredReplay.Token)
			if err != nil {
				t.Fatal(err)
			}
			if got := confirmationMatchingCount(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE token_digest=?`, expiredDigest); got != 1 {
				t.Errorf("expired replay target row count=%d want=1", got)
			}
			liveDigest, err := tokenDigest(live.Token)
			if err != nil {
				t.Fatal(err)
			}
			if got := confirmationMatchingCount(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE token_digest=? AND expires_at_unix_ms>?`, liveDigest, now.UnixMilli()); got != 1 {
				t.Errorf("live interaction row count=%d want=1", got)
			}
			issuedDigest, err := tokenDigest(issued.Token)
			if err != nil {
				t.Fatal(err)
			}
			if got := confirmationMatchingCount(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE token_digest=? AND expires_at_unix_ms>?`, issuedDigest, now.UnixMilli()); got != 1 {
				t.Errorf("new live interaction row count=%d want=1", got)
			}
			if _, err := s.LoadAuthorizationInteractionReadOnly(ctx, session.Token, expiredReplay.Token); !errors.Is(err, ErrExpired) {
				t.Errorf("retained expired interaction replay error=%v want ErrExpired", err)
			}
		})
	}
}

func confirmationMatchingCount(t *testing.T, s *Store, query string, args ...any) int64 {
	t.Helper()
	result, err := s.db.Query(t.Context(), rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("count query rows=%#v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(int64)
}

func TestConfirmationAuthorityLossRollsBackCleanup(t *testing.T) {
	for _, kind := range []string{"revoke", "delete", "hard-expiry", "idle-expiry", "disable-user", "account-expiry"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			s.now = func() time.Time { return now }
			session, err := s.CreateSession(t.Context(), "user-1", "pwd", now.Add(time.Hour), "")
			if err != nil {
				t.Fatal(err)
			}
			seedConfirmationCleanup(t, s, now, 1)
			calls := 0
			// The second clock read is after authoritative LoadSession and before the
			// creator captures its fixed SQL cutoff. No apply-time wall clock is implied.
			s.now = func() time.Time {
				calls++
				if calls == 2 {
					sql := ""
					var args []any
					switch kind {
					case "revoke":
						sql = "UPDATE browser_sessions SET revoked_at_unix_ms=? WHERE token_digest=?"
						args = []any{now.UnixMilli(), session.ID}
					case "delete":
						sql = "DELETE FROM browser_sessions WHERE token_digest=?"
						args = []any{session.ID}
					case "hard-expiry":
						sql = "UPDATE browser_sessions SET expires_at_unix_ms=? WHERE token_digest=?"
						args = []any{now.UnixMilli(), session.ID}
					case "idle-expiry":
						sql = "UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?"
						args = []any{now.Add(-s.idleTimeout).UnixMilli(), session.ID}
					case "disable-user":
						sql = "UPDATE identity_users SET disabled=1 WHERE subject='user-1'"
					case "account-expiry":
						sql = "UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'"
						args = []any{now.UnixMilli()}
					}
					if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{RequestID: "authority-loss", SQL: sql, Args: args}); err != nil {
						t.Fatal(err)
					}
				}
				return now
			}
			issued, err := s.CreateAuthorizationInteraction(t.Context(), session.Token, "new-request", []byte("payload"), now.Add(time.Minute))
			if !errors.Is(err, ErrNotFound) || issued.Token != "" {
				t.Fatalf("guarded rejection=%+v err=%v", issued, err)
			}
			if count := confirmationCount(t, s); count != 1 {
				t.Fatalf("cleanup must roll back: count=%d", count)
			}
		})
	}
}
func TestConfirmationConstraintFailureIsNotAbsence(t *testing.T) {
	s := testStore(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }
	session, err := s.CreateInitSession(t.Context(), now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAuthorizationInteraction(t.Context(), session.Token, "same-request", []byte("payload"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	issued, err := s.CreateAuthorizationInteraction(t.Context(), session.Token, "same-request", []byte("payload"), now.Add(time.Minute))
	if err == nil || errors.Is(err, ErrNotFound) || issued.Token != "" {
		t.Fatalf("constraint=%+v err=%v", issued, err)
	}
}
