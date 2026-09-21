package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCreateUserWithGuardCreatesCompletePendingIdentity(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "create-user-entities", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('role-1','reviewer',NULL,1,0,0)`},
		{SQL: `INSERT INTO rbac_groups(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('group-1','team-a',NULL,1,0,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	expires := store.now().UnixMilli() + int64(time.Hour/time.Millisecond)
	created, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "new@example.test", PreferredUsername: "new-user", GivenName: "한글 이름", TTL: time.Hour}, Roles: []string{"reviewer", "missing"}, Groups: []string{"team-a", "absent"}, UserExpires: &expires}, "1=1", nil)
	if err != nil || !created.Created || created.Subject == "" || created.Token == "" {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+created.Subject+`' AND password_phc=''`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='`+created.Subject+`' AND email='new@example.test' AND preferred_username='new-user'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+created.Subject+`' AND usage='password_new'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject='`+created.Subject+`' AND role_id='role-1'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM rbac_user_groups WHERE subject='`+created.Subject+`' AND group_id='group-1'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+created.Subject+`' AND user_expires_at_unix_ms=`+fmt.Sprint(expires), 1)
	nilExpiry, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "unlimited@example.test", TTL: time.Hour}}, "1=1", nil)
	if err != nil || !nilExpiry.Created {
		t.Fatalf("nil expiry created=%#v err=%v", nilExpiry, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+nilExpiry.Subject+`' AND user_expires_at_unix_ms IS NULL`, 1)
}

func TestCreateUserWithGuardConstraintFailureRollsBackEverything(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "create-rollback-role", SQL: `INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('role-1','reviewer',NULL,1,0,0)`}); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "rollback@example.test", TTL: time.Hour}, Roles: []string{"reviewer", "reviewer"}}, "1=1", nil)
	if err == nil || created.Created {
		t.Fatalf("constraint failure created=%#v err=%v", created, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='rollback@example.test'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE usage='password_new'`, 0)
}

func TestCreateUserWithGuardRejectsRevokedAuthorityWithoutWrites(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	created, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "blocked@example.test", TTL: time.Hour}}, "0=1", nil)
	if err != ErrCreateUnauthorized || created.Created {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='blocked@example.test'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE usage='password_new'`, 0)
}

func TestCreateUserWithGuardDuplicateEmailLeavesExistingRowsUnchanged(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	pending, err := store.RegisterOpenUser(context.Background(), OpenRegistration{Email: "duplicate@example.test", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "duplicate@example.test", TTL: time.Hour}}, "1=1", nil)
	if err != ErrCreateConflict || created.Created {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='duplicate@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE usage='password_new' AND consumed_attempt IS NULL`, 1)
	_ = pending
	preferred, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "preferred@example.test", PreferredUsername: "new-user2", TTL: time.Hour}}, "1=1", nil)
	if err != nil || !preferred.Created {
		t.Fatalf("preferred seed created=%#v err=%v", preferred, err)
	}
	duplicatePreferred, err := store.CreateUserWithGuard(context.Background(), UserCreation{OpenRegistration: OpenRegistration{Email: "other@example.test", PreferredUsername: "new-user2", TTL: time.Hour}}, "1=1", nil)
	if err != ErrCreateConflict || duplicatePreferred.Created {
		t.Fatalf("duplicate preferred created=%#v err=%v", duplicatePreferred, err)
	}
}
