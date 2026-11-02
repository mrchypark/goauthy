package identity

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCleanupExpiredAdminCreatedPendingProofDoesNotRequireProfileMatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	base := time.UnixMilli(50_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	const email = "admin-pending@example.test"
	created, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{
		Email: email, TTL: time.Minute,
	}}, "1=1", nil)
	if err != nil || !created.Created || created.Token == "" {
		t.Fatalf("admin-created pending identity=%#v err=%v", created, err)
	}
	// Legacy login names are independent of the profile/recovery email. Admin
	// profile updates preserve that login while they can verify the email.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "cleanup-legacy-login-name",
		SQL:       `UPDATE identity_users SET username='legacy-login' WHERE subject=?`,
		Args:      []any{created.Subject},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateUserWithGuard(ctx, created.Subject, UserUpdate{
		Email: email, Enabled: true, EmailVerified: true,
	}, userUpdateTestAuthority); err != nil {
		t.Fatalf("verify admin-created pending email: %v", err)
	}
	base = base.Add(time.Minute)
	duplicate, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: email, TTL: time.Minute})
	if err != nil || duplicate.Subject != created.Subject || duplicate.Created || duplicate.Token != "" || duplicate.ReissuedPasswordNew {
		t.Fatalf("same-email registration changed verified pending identity: result=%#v err=%v", duplicate, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+created.Subject+`' AND usage='password_new' AND consumed_attempt IS NULL`, 1)
	if err := store.CleanupExpiredOpenRegistrations(ctx, base); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_users", "identity_authentication_modes", "identity_recovery_emails", "identity_user_profiles", "rbac_principal_versions", "identity_password_reset_tokens"} {
		assertCount(t, store, `SELECT COUNT(*) FROM `+table+` WHERE subject='`+created.Subject+`'`, 0)
	}
}
