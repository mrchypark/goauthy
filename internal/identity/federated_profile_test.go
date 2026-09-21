package identity

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func testFederatedProfileStore(t *testing.T) *Store {
	t.Helper()
	store := testResetStore(t, credential.DefaultRules())
	ctx := context.Background()
	seedArgs := []any{
		testFederatedProviderID, int64(1), "test-google", "oidc",
		"https://accounts.google.com",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token",
		"https://openidconnect.googleapis.com/v1/userinfo",
		"test-client-id", nil, "openid email profile",
		nil, nil, nil, nil,
		int64(1), int64(1), int64(0), nil, int64(1), int64(0),
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "federated-profile-test-seed",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", Args: seedArgs},
			{SQL: "INSERT INTO auth_provider_runtime_versions(provider_id, version) VALUES(?, ?)", Args: []any{testFederatedProviderID, "v1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "test-seed-admin-role",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT OR IGNORE INTO rbac_roles(id,name,created_at_unix_ms,updated_at_unix_ms) VALUES('rauthy-admin-id','rauthy_admin',0,0)"},
		},
	})
	return store
}

func seedExistingUser(t *testing.T, store *Store, email string) string {
	t.Helper()
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(1_000_000).UTC() }
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         email,
		EmailVerified: true,
		GivenName:     "Old",
		FamilyName:    "User",
		SourceIP:      "10.0.0.1",
	})
	if err != nil || !result.Created {
		t.Fatalf("seedExistingUser: result=%#v err=%v", result, err)
	}
	return result.Subject
}

func seedAdminRole(t *testing.T, store *Store, subject string) {
	t.Helper()
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "test-seed-admin-role-for-user",
		Statements: []rhiza.SQLStatement{
			{SQL: "INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT ?,id,? FROM rbac_roles WHERE name='rauthy_admin'", Args: []any{subject, int64(1_500_000)}},
		},
	}); err != nil {
		t.Fatalf("seedAdminRole: %v", err)
	}
}

func TestFederatedProfileUpdateBasic(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "basic@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "basic@example.test",
		EmailVerified: true,
		GivenName:     "Updated",
		FamilyName:    "Name",
		SourceIP:      "10.0.0.2",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if result.Subject != subject || result.EmailChanged || result.AdminChanged {
		t.Fatalf("result=%#v", result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_user_profiles WHERE subject='"+subject+"' AND email='basic@example.test' AND email_verified=1 AND given_name='Updated' AND family_name='Name'", 1)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='"+subject+"' AND email='basic@example.test'", 1)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_users WHERE subject='"+subject+"' AND last_login_at_unix_ms=2000000 AND last_failed_login_at_unix_ms IS NULL AND failed_login_attempts IS NULL", 1)
}

func TestFederatedProfileUpdateEmailChange(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "old@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "new@example.test",
		EmailVerified: true,
		GivenName:     "New",
		FamilyName:    "Person",
		SourceIP:      "10.0.0.3",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !result.EmailChanged || result.AdminChanged {
		t.Fatalf("result=%#v", result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_user_profiles WHERE subject='"+subject+"' AND email='new@example.test' AND email_verified=1", 1)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_user_profiles WHERE subject='"+subject+"' AND email='old@example.test'", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='"+subject+"' AND email='new@example.test'", 1)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_user_profiles WHERE subject<>'"+subject+"' AND email='new@example.test'", 0)
}

func TestFederatedProfileUpdateDuplicateEmailConflict(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "first@example.test")
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(1_500_000).UTC() }
	second, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "second-subject", IdentityNamespace: testFederatedNamespace},
		Config:        testFederatedProvider,
		Email:         "second@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.4",
	})
	if err != nil || !second.Created {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	_, err = store.UpdateFederatedProfile(ctx, FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "second@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.5",
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestFederatedProfileUpdateAdminGrant(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "admgrant@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	adminTrue := true
	result, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "admgrant@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.6",
		AdminMapping:  &adminTrue,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !result.AdminChanged {
		t.Fatalf("expected AdminChanged=true, got result=%#v", result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subject+"' AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')", 1)
}

func TestFederatedProfileUpdateAdminRevoke(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "admrevoke@example.test")
	seedAdminRole(t, store, subject)
	ctx := context.Background()
	peer, _ := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "admin-peer", IdentityNamespace: testFederatedNamespace},
		Config:        testFederatedProvider,
		Email:         "admin-peer@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.7",
	})
	store.now = func() time.Time { return time.UnixMilli(1_600_000).UTC() }
	adminTrue := true
	store.UpdateFederatedProfile(ctx, FederatedProfileUpdateInput{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "admin-peer", IdentityNamespace: testFederatedNamespace},
		Config:        testFederatedProvider,
		Email:         "admin-peer@example.test",
		EmailVerified: true,
		AdminMapping:  &adminTrue,
	})
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	adminFalse := false
	result, err := store.UpdateFederatedProfile(ctx, FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "admrevoke@example.test",
		EmailVerified: true,
		AdminMapping:  &adminFalse,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !result.AdminChanged {
		t.Fatalf("expected AdminChanged=true, got result=%#v", result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subject+"' AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')", 0)
	_ = peer
}

func TestFederatedProfileUpdateLastAdminProtection(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "lastadmin@example.test")
	seedAdminRole(t, store, subject)
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	adminFalse := false
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "lastadmin@example.test",
		EmailVerified: true,
		AdminMapping:  &adminFalse,
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict, got err=%v", err)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subject+"' AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')", 1)
}

func TestFederatedProfileUpdateAdminNilNoChange(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "niladmin@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "niladmin@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.8",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if result.AdminChanged {
		t.Fatalf("expected AdminChanged=false for nil, got result=%#v", result)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subject+"'", 0)
}

func TestFederatedProfileUpdateProviderChangedRejected(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "provchange@example.test")
	ctx := context.Background()
	storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "test-version-rotate",
		Statements: []rhiza.SQLStatement{
			{SQL: "UPDATE auth_provider_runtime_versions SET version = 'v2' WHERE provider_id = '" + testFederatedProviderID + "'"},
		},
	})
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	_, err := store.UpdateFederatedProfile(ctx, FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "provchange@example.test",
		EmailVerified: true,
	})
	if err != ErrFederatedProfileNotFound {
		t.Fatalf("expected ErrFederatedProfileNotFound, got err=%v", err)
	}
}

func TestFederatedProfileUpdateNotFound(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "nonexistent@example.test",
		EmailVerified: true,
	})
	if err != ErrFederatedProfileNotFound {
		t.Fatalf("expected ErrFederatedProfileNotFound, got err=%v", err)
	}
}

func TestFederatedProfileUpdatePreservesPasswordAndMode(t *testing.T) {
	t.Parallel()
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "preserve@example.test")
	ctx := context.Background()
	before, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT mode, generation FROM identity_authentication_modes WHERE subject=?",
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(before.Rows) != 1 {
		t.Fatalf("before mode query: err=%v rows=%v", err, before.Rows)
	}
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	_, err = store.UpdateFederatedProfile(ctx, FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "preserve@example.test",
		EmailVerified: true,
		GivenName:     "Still",
		FamilyName:    "Old",
		SourceIP:      "10.0.0.9",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	after, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT mode, generation FROM identity_authentication_modes WHERE subject=?",
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(after.Rows) != 1 {
		t.Fatalf("after mode query: err=%v rows=%v", err, after.Rows)
	}
	if before.Rows[0][0] != after.Rows[0][0] || before.Rows[0][1] != after.Rows[0][1] {
		t.Fatalf("mode changed: before=%v after=%v", before.Rows[0], after.Rows[0])
	}
}
