package identity

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAuthenticationDoesNotRecaptureChangedGenerations(t *testing.T) {
	t.Parallel()
	s := testStoreWithRules(t, testRules(3))
	password := []byte("CurrentPassword1")
	bootstrapPassword(t, s, "snapshot-user", "alice", password)
	now := time.Now().UTC()
	if _, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "snapshot-expiry", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=?`, Args: []any{now.Add(time.Hour).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	changed := false
	s.now = func() time.Time {
		// The first expiry clock read follows the credential SELECT. Commit a
		// new generation at that boundary without sleeps or hash timing races.
		if !changed {
			changed = true
			_, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "snapshot-change", Statements: []rhiza.SQLStatement{
				{SQL: `UPDATE identity_users SET password_generation=2`},
				{SQL: `UPDATE identity_authentication_modes SET generation=2`},
			}})
			if err != nil {
				t.Fatal(err)
			}
		}
		return now
	}
	auth, err := s.Authenticate(t.Context(), "alice", password)
	if err != nil || !changed || auth.PasswordGeneration != 1 || auth.AuthenticationGeneration != 1 {
		t.Fatalf("authenticated snapshot=%+v changed=%t err=%v", auth, changed, err)
	}
}

func TestAuthenticationCapturesCredentialGenerations(t *testing.T) {
	t.Parallel()
	s := testStoreWithRules(t, testRules(3))
	old, next := []byte("CurrentPassword1"), []byte("NextPassword2")
	bootstrapPassword(t, s, "snapshot-user", "alice", old)
	before, err := s.Authenticate(t.Context(), "alice", old)
	if err != nil || before.Subject != "snapshot-user" || before.PasswordGeneration < 1 || before.AuthenticationGeneration < 1 {
		t.Fatalf("initial authentication=%+v err=%v", before, err)
	}
	if err := s.ChangePassword(t.Context(), before.Subject, old, next); err != nil {
		t.Fatal(err)
	}
	after, err := s.Authenticate(t.Context(), "alice", next)
	if err != nil || after.PasswordGeneration != before.PasswordGeneration+1 || after.AuthenticationGeneration != before.AuthenticationGeneration {
		t.Fatalf("changed authentication=%+v prior=%+v err=%v", after, before, err)
	}
	failed, err := s.Authenticate(t.Context(), "alice", old)
	if err != ErrInvalidCredentials || failed != (Authentication{}) {
		t.Fatalf("failed authentication=%+v err=%v", failed, err)
	}
}
