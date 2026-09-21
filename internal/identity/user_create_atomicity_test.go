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

func TestCreateUserConcurrentPreferredHasOneWinner(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	now := time.Unix(1700000000, 0)
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	store.now = func() time.Time { arrived <- struct{}{}; <-release; return now }
	results := make(chan error, 2)
	for _, email := range []string{"first@example.test", "second@example.test"} {
		go func() {
			_, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: email, PreferredUsername: "same-name", TTL: time.Hour}}, "1=1", nil)
			results <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrCreateConflict)) || (b == nil && errors.Is(a, ErrCreateConflict))) {
		t.Fatalf("creation outcomes=%v,%v", a, b)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE preferred_username='same-name'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE usage='password_new'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM api_key_mutation_guards`, 0)
	_, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "first@example.test", PreferredUsername: "same-name", TTL: time.Hour}}, "0=1", nil)
	if !errors.Is(err, ErrCreateUnauthorized) {
		t.Fatalf("denied caller learned duplicate state: %v", err)
	}
}

func TestCreateUserPendingCleanupRemovesMembershipsButPreservesPasskeys(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	store.now = func() time.Time { return now }
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "pending-cleanup-entities", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('cleanup-role','reader',1,0,0)`},
		{SQL: `INSERT INTO rbac_groups(id,name,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('cleanup-group','team',1,0,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for _, email := range []string{"abandoned@example.test", "passkey@example.test"} {
		result, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: email, TTL: time.Minute}, Roles: []string{"reader"}, Groups: []string{"team"}}, "1=1", nil)
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, result.Subject)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "pending-completed-passkey", SQL: `INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,credential_version,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES('cleanup-retained-key',?,'primary','{}',0,0,1,0,0)`, Args: []any{subjects[1]}}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpiredOpenRegistrations(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_users", "identity_user_profiles", "identity_recovery_emails", "rbac_user_roles", "rbac_user_groups", "rbac_principal_versions", "identity_authentication_modes", "identity_password_reset_tokens"} {
		for i, subject := range subjects {
			rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table + ` WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(i) {
				t.Fatalf("table=%s subject=%d rows=%v err=%v", table, i, rows.Rows, err)
			}
		}
	}
}

func TestCreateUserPreferredUniquenessIncludesPublicRegistration(t *testing.T) {
	t.Parallel()
	for _, publicFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "admin first", true: "public first"}[publicFirst], func(t *testing.T) {
			store := testResetStore(t, credential.DefaultRules())
			store.now = func() time.Time { return time.Unix(1700000000, 0) }
			create := func(public bool, email string) error {
				input := OpenRegistration{Email: email, PreferredUsername: "shared-name", TTL: time.Hour}
				if public {
					_, err := store.RegisterOpenUser(context.Background(), input)
					return err
				}
				_, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: input}, "1=1", nil)
				return err
			}
			if err := create(publicFirst, "owner@example.test"); err != nil {
				t.Fatal(err)
			}
			if err := create(!publicFirst, "other@example.test"); err == nil {
				t.Fatal("second registration reused preferred username")
			}
			assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE preferred_username='shared-name'`, 1)
			assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='other@example.test'`, 0)
		})
	}
}
