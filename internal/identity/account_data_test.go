package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAccountDataSnapshotMatchesProfileAndMode(t *testing.T) {
	s := testStore(t)
	bootstrapPassword(t, s, "subject-1", "alice@example.test", []byte("CurrentPassword1"))
	now := time.Now().UTC().Truncate(time.Millisecond)
	s.now = func() time.Time { return now }
	for _, tc := range []struct {
		name, sql string
		args      []any
		modeError bool
		inactive  bool
	}{
		{name: "password-null-profile"},
		{name: "profile", sql: `INSERT INTO identity_user_profiles (subject,email,email_verified,preferred_username,given_name,family_name) VALUES ('subject-1','profile@example.test',1,'Alice','Alice','Example')`},
		{name: "passkey", sql: `UPDATE identity_authentication_modes SET mode='passkey' WHERE subject='subject-1'`},
		{name: "missing-mode", sql: `DELETE FROM identity_authentication_modes WHERE subject='subject-1'`, modeError: true},
		{name: "disabled-missing-mode", sql: `UPDATE identity_users SET disabled=1 WHERE subject='subject-1'`, inactive: true},
		{name: "expiry-boundary", sql: `UPDATE identity_users SET disabled=0,user_expires_at_unix_ms=? WHERE subject='subject-1'`, args: []any{now.UnixMilli()}, inactive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sql != "" {
				if _, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "account-data-" + tc.name, SQL: tc.sql, Args: tc.args}); err != nil {
					t.Fatal(err)
				}
			}
			oldProfile, profileErr := s.AccountProfileBySubject(t.Context(), "subject-1")
			oldMode, modeErr := s.IsPasskeyOnly(t.Context(), "subject-1")
			profile, mode, err := s.AccountDataBySubject(t.Context(), "subject-1")
			if tc.inactive {
				if !errors.Is(profileErr, ErrInactiveSubject) || !errors.Is(err, ErrInactiveSubject) || errors.Is(err, ErrAccountDataMode) {
					t.Fatalf("profile rejection changed: old=%v new=%v", profileErr, err)
				}
			} else if tc.modeError {
				if profileErr != nil || !errors.Is(modeErr, ErrInactiveSubject) || !errors.Is(err, ErrAccountDataMode) || !errors.Is(err, modeErr) {
					t.Fatalf("mode rejection changed: old=%v new=%v", modeErr, err)
				}
			} else if profileErr != nil || modeErr != nil || err != nil || profile != oldProfile || mode != oldMode {
				t.Fatalf("snapshot differs from separate reads: profile=%v mode=%v err=%v", profile == oldProfile, mode == oldMode, err)
			}
		})
	}
	if _, _, err := s.AccountDataBySubject(t.Context(), "missing"); !errors.Is(err, ErrInactiveSubject) || errors.Is(err, ErrAccountDataMode) {
		t.Fatalf("missing subject=%v", err)
	}
	if _, _, err := s.AccountDataBySubject(t.Context(), ""); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("invalid subject=%v", err)
	}
}

func TestAccountDataSharedDecodersFailClosed(t *testing.T) {
	valid := []any{"s", "alice@example.test", int64(0), nil, nil, nil, nil, nil}
	profile, err := decodeAccountProfile(valid)
	if err != nil || profile.Email != "alice@example.test" || profile.EmailVerified {
		t.Fatal("null profile fallback changed")
	}
	for _, tc := range []struct {
		index int
		value any
	}{
		{2, "0"}, {3, int64(1)}, {3, "Invalid Email"}, {4, int64(2)}, {4, "1"}, {5, int64(1)}, {6, int64(1)}, {7, int64(1)},
	} {
		row := append([]any(nil), valid...)
		row[tc.index] = tc.value
		if _, err := decodeAccountProfile(row); err == nil {
			t.Fatalf("corrupt profile column %d accepted", tc.index)
		}
	}
	for _, row := range [][]any{{nil, int64(1)}, {"unknown", int64(1)}, {"password", int64(0)}, {"password", nil}, {"password", "1"}} {
		if _, _, err := decodeAuthenticationMode([][]any{row}); err == nil || errors.Is(err, ErrInactiveSubject) {
			t.Fatal("corrupt mode must return a decoding error")
		}
	}
	if _, _, err := decodeAuthenticationMode(nil); !errors.Is(err, ErrInactiveSubject) {
		t.Fatal("absent mode must remain inactive")
	}
}
