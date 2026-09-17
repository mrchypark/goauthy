package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/rhiza"
)

func TestUpdateUserPasswordPolicyVerificationAndHistory(t *testing.T) {
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_123) }
	seedDeterministicRandom(store)
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-update-password", "alice@example.test", []byte("CurrentPassword1"))
	update := func(password string) error {
		input := UserUpdate{Email: "alice@example.test", Password: &password, Enabled: true}
		_, err := store.UpdateUserWithGuard(ctx, "subject-update-password", input, userUpdateTestAuthority)
		return err
	}
	before := userUpdateSnapshot(t, store)
	if err := update("short1A"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("weak password err=%v", err)
	}
	assertUserUpdateSnapshot(t, store, before)
	if err := update("CurrentPassword1"); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("current password err=%v", err)
	}
	assertUserUpdateSnapshot(t, store, before)
	if err := update("NextPassword1"); err != nil {
		t.Fatal(err)
	}
	before = userUpdateSnapshot(t, store)
	if err := update("CurrentPassword1"); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("history password err=%v", err)
	}
	assertUserUpdateSnapshot(t, store, before)
	if err := store.VerifyPassword(ctx, "subject-update-password", []byte("NextPassword1")); err != nil {
		t.Fatalf("new password verification err=%v", err)
	}
	if err := update("ThirdPassword1"); err != nil {
		t.Fatal(err)
	}
	if err := update("FourthPassword1"); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_history WHERE subject=?`, Args: []any{"subject-update-password"}, Consistency: rhiza.ConsistencyLinearizable}); err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) {
		t.Fatalf("history rows=%#v err=%v", rows.Rows, err)
	}
	if err := store.VerifyPassword(ctx, "subject-update-password", []byte("FourthPassword1")); err != nil {
		t.Fatalf("latest password verification err=%v", err)
	}
	var generation int64
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT password_generation FROM identity_users WHERE subject=?`, Args: []any{"subject-update-password"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("generation rows=%#v err=%v", rows.Rows, err)
	}
	var ok bool
	if generation, ok = rows.Rows[0][0].(int64); !ok || generation != 4 {
		t.Fatalf("generation=%v rows=%#v", generation, rows.Rows)
	}
	if err := update("NextPassword1"); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("retained second password not protected: %v", err)
	}
	if err := update("CurrentPassword1"); err != nil {
		t.Fatalf("password outside the configured history was not pruned: %v", err)
	}
}

func TestUpdateUserPendingPasswordNewClearsSetupAndEnablesAdmission(t *testing.T) {
	store := testResetStore(t, testRules(3))
	now := time.UnixMilli(1_800_000_001_000)
	store.now = func() time.Time { return now }
	seedDeterministicRandom(store)
	ctx := context.Background()
	created, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "pending-update@example.test", TTL: time.Hour}}, "1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	password := "PendingPassword1"
	if _, err = store.UpdateUserWithGuard(ctx, created.Subject, UserUpdate{Email: "pending-update@example.test", Password: &password, Enabled: true, EmailVerified: true}, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Authenticate(ctx, "pending-update@example.test", []byte(password)); err != nil || got.Subject != created.Subject {
		t.Fatalf("authentication=%#v err=%v", got, err)
	}
	if rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject=? AND usage='password_new'`, Args: []any{created.Subject}, Consistency: rhiza.ConsistencyLinearizable}); err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("setup token rows=%#v err=%v", rows.Rows, err)
	}
}

func TestUpdateUserPasskeyOnlyAssignmentRestoresPasswordWithoutHistory(t *testing.T) {
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.UnixMilli(1_800_000_002_000) }
	seedDeterministicRandom(store)
	ctx := context.Background()
	makePasskeyOnly(t, store, "subject-update-passkey", "passkey@example.test")
	password := "RestoredPassword1"
	if _, err := store.UpdateUserWithGuard(ctx, "subject-update-passkey", UserUpdate{Email: "passkey@example.test", Password: &password, Enabled: true}, userUpdateTestAuthority); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyPassword(ctx, "subject-update-passkey", []byte(password)); err != nil {
		t.Fatalf("restored password err=%v", err)
	}
	if passkeyOnly, err := store.IsPasskeyOnly(ctx, "subject-update-passkey"); err != nil || passkeyOnly {
		t.Fatalf("passkey-only=%v err=%v", passkeyOnly, err)
	}
	if rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject=?`, Args: []any{"subject-update-passkey"}, Consistency: rhiza.ConsistencyLinearizable}); err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("passkey rows=%#v err=%v", rows.Rows, err)
	}
	if rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_history WHERE subject=?`, Args: []any{"subject-update-passkey"}, Consistency: rhiza.ConsistencyLinearizable}); err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("history rows=%#v err=%v", rows.Rows, err)
	}
}
