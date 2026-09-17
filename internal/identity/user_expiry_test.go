package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserExpiryBoundaryMatrix(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		offset  int64
		expired bool
	}{
		{"unlimited", 0, false}, {"before", -1, true}, {"equal", 0, true}, {"after", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			now := time.UnixMilli(10_000)
			s.now = func() time.Time { return now }
			phc, err := credential.Hash([]byte("Password1!"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.BootstrapUser(ctx, "expiry-subject", "expiry-user", phc); err != nil {
				t.Fatal(err)
			}
			if tc.name == "unlimited" {
				_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-null", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject=?`, Args: []any{"expiry-subject"}})
			} else {
				_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-set", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli() + tc.offset, "expiry-subject"}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.expired {
				if err := s.ValidateSubject(ctx, "expiry-subject"); !errors.Is(err, ErrInactiveSubject) {
					t.Fatalf("ValidateSubject=%v", err)
				}
				if _, err := s.UserBySubject(ctx, "expiry-subject"); !errors.Is(err, ErrInactiveSubject) {
					t.Fatalf("UserBySubject=%v", err)
				}
				if _, err := s.AccountProfileBySubject(ctx, "expiry-subject"); !errors.Is(err, ErrInactiveSubject) {
					t.Fatalf("AccountProfileBySubject=%v", err)
				}
				if _, err := s.Authenticate(ctx, "expiry-user", []byte("Password1!")); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("Authenticate=%v", err)
				}
				if err := s.VerifyPassword(ctx, "expiry-subject", []byte("Password1!")); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("VerifyPassword=%v", err)
				}
			} else {
				if err := s.ValidateSubject(ctx, "expiry-subject"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.UserBySubject(ctx, "expiry-subject"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AccountProfileBySubject(ctx, "expiry-subject"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Authenticate(ctx, "expiry-user", []byte("Password1!")); err != nil {
					t.Fatal(err)
				}
				if err := s.VerifyPassword(ctx, "expiry-subject", []byte("Password1!")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "after" {
				// Warm reads must not remain valid after time alone expires the account.
				now = now.Add(time.Millisecond)
				if _, err := s.UserBySubject(ctx, "expiry-subject"); !errors.Is(err, ErrInactiveSubject) {
					t.Fatalf("expired warm user=%v", err)
				}
				if _, err := s.AccountProfileBySubject(ctx, "expiry-subject"); !errors.Is(err, ErrInactiveSubject) {
					t.Fatalf("expired warm profile=%v", err)
				}
			}
		})
	}
}

func TestExpiredAccountCannotResetOrActivate(t *testing.T) {
	for _, usage := range []string{"password_reset", "password_new"} {
		t.Run(usage, func(t *testing.T) {
			s := testResetStore(t, credential.DefaultRules())
			ctx := context.Background()
			now := time.UnixMilli(20_000)
			s.now = func() time.Time { return now }
			subject := "subject-1"
			var raw string
			var err error
			if usage == "password_new" {
				pending, createErr := s.RegisterOpenUser(ctx, OpenRegistration{Email: "pending@example.test", TTL: time.Hour})
				if createErr != nil || !pending.Created {
					t.Fatalf("pending registration err=%v created=%t", createErr, pending.Created)
				}
				subject, raw = pending.Subject, pending.Token
			} else {
				bootstrapPassword(t, s, subject, "alice", []byte("original password"))
				raw, _, err = s.IssuePasswordReset(ctx, subject, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			}
			challenge, err := s.BeginPasswordReset(ctx, subject, raw)
			if err != nil {
				t.Fatal(err)
			}
			before, _, err := s.passwordRecord(ctx, subject)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-reset", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli(), subject}}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.IssuePasswordReset(ctx, subject, time.Hour); !errors.Is(err, ErrInvalidPasswordReset) {
				t.Fatalf("IssuePasswordReset=%v", err)
			}
			if _, err := s.BeginPasswordReset(ctx, subject, raw); !errors.Is(err, ErrInvalidPasswordReset) {
				t.Fatalf("BeginPasswordReset=%v", err)
			}
			if _, err := s.ResetPassword(ctx, subject, raw, challenge.CookieToken, challenge.CSRFToken, []byte("replacement password"), ""); !errors.Is(err, ErrInvalidPasswordReset) {
				t.Fatalf("ResetPassword=%v", err)
			}
			after, _, err := s.passwordRecord(ctx, subject)
			if err != nil || before.passwordPHC != after.passwordPHC || before.generation != after.generation {
				t.Fatalf("expired account password changed: err=%v", err)
			}
			token, found, err := s.resetRecord(ctx, s.resetDigest(raw))
			if err != nil || !found || token.consumed || token.binding != s.resetCookieDigest(challenge.CookieToken) {
				t.Fatalf("expired account's reset token changed: err=%v found=%t consumed=%t", err, found, token.consumed)
			}
			if usage == "password_new" {
				result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT email_verified FROM identity_user_profiles WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
					t.Fatalf("expired account email verified: rows=%v err=%v", result.Rows, err)
				}
			}
		})
	}
}
