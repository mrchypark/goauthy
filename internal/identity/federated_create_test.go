package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const testFederatedProviderID = "AbCdEfGhIjKlMnOpQrStUvWx"

var testFederatedNamespace = upstreamprovider.ComputeNamespace("https://accounts.google.com", "test-client-id")

func testFederatedStore(t *testing.T) *Store {
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
		RequestID: "federated-test-provider-seed",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: seedArgs},
			{SQL: `INSERT INTO auth_provider_runtime_versions(provider_id, version) VALUES(?, ?)`, Args: []any{testFederatedProviderID, "v1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

var testFederatedProvider = FederatedConfigSnapshot{
	Source:         "registry",
	Version:        "v1",
	Issuer:         "https://accounts.google.com",
	ClientID:       "test-client-id",
	Kind:           "oidc",
	AutoOnboarding: true,
}

func testFederatedSubject(namespace string) upstreamprovider.SubjectResult {
	return upstreamprovider.SubjectResult{
		ProviderID:        testFederatedProviderID,
		Subject:           "upstream-subject-123",
		IdentityNamespace: namespace,
	}
}

func TestFederatedCreateVerifiedProfile(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "verified@example.test",
		EmailVerified: true,
		GivenName:     "Given",
		FamilyName:    "Family",
		SourceIP:      "10.0.0.1",
	})
	if err != nil || !result.Created || result.Subject == "" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+s+`' AND password_phc='' AND disabled=0`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='`+s+`' AND mode='passkey' AND generation=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='`+s+`' AND email='verified@example.test' AND email_verified=1 AND given_name='Given' AND family_name='Family'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_external_links WHERE provider_id='`+testFederatedProviderID+`' AND local_subject='`+s+`'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='`+s+`' AND email='verified@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM rbac_principal_versions WHERE subject='`+s+`' AND revision=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+s+`' AND usage='password_new'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject='`+s+`'`, 0)
}

func TestFederatedCreateUnverifiedProfile(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "unverified@example.test",
		EmailVerified: false,
		SourceIP:      "10.0.0.2",
	})
	if err != nil || !result.Created || result.Subject == "" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='`+s+`' AND email='unverified@example.test' AND email_verified=0`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+s+`'`, 0)
}

func TestFederatedCreateNoResetEnrollmentPasswordLogin(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "noreset@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.3",
	})
	if err != nil || !result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+s+`'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject='`+s+`'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='`+s+`' AND mode='passkey' AND generation=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+s+`' AND password_phc=''`, 1)
}

func TestFederatedCreateAutoOnboardingFalseRejected(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  FederatedConfigSnapshot{Source: "registry", Version: "v1", Issuer: "https://accounts.google.com", ClientID: "test-client-id", Kind: "oidc", AutoOnboarding: false},
		Email:   "onboard-reject@example.test",
		EmailVerified: true,
		SourceIP: "10.0.0.4",
	})
	if err != ErrFederatedProviderChanged || result.Created {
		t.Fatalf("expected provider changed, got result=%#v err=%v", result, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='onboard-reject@example.test'`, 0)
}

func TestFederatedCreateVersionChangedRejected(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "federated-test-version-rotate",
		SQL:       `UPDATE auth_provider_runtime_versions SET version = 'v2' WHERE provider_id = '`+testFederatedProviderID+`'`,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "version-change@example.test",
		EmailVerified: true,
		SourceIP: "10.0.0.5",
	})
	if err != ErrFederatedProviderChanged || result.Created {
		t.Fatalf("expected provider changed, got result=%#v err=%v", result, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='version-change@example.test'`, 0)
}

func TestFederatedCreateDisabledProviderRejected(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: "federated-test-disable-provider",
		SQL:       `UPDATE auth_providers SET enabled = 0 WHERE id = '`+testFederatedProviderID+`'`,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "disabled-provider@example.test",
		EmailVerified: true,
		SourceIP: "10.0.0.6",
	})
	if err != ErrFederatedProviderChanged || result.Created {
		t.Fatalf("expected provider changed, got result=%#v err=%v", result, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='disabled-provider@example.test'`, 0)
}

func TestFederatedCreateDuplicateEmailNoOrphanRows(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	first, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "dup@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.7",
	})
	if err != nil || !first.Created {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='dup@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='dup@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_external_links WHERE provider_id='`+testFederatedProviderID+`'`, 1)
	second, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "different-subject", IdentityNamespace: testFederatedNamespace},
		Config:        testFederatedProvider,
		Email:         "dup@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.8",
	})
	if err != ErrFederatedProviderChanged || second.Created {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='dup@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE email='dup@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_external_links WHERE provider_id='`+testFederatedProviderID+`'`, 1)
}

func TestFederatedCreateDuplicateExternalKeyNoOrphanRows(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	first, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "first-ek@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.9",
	})
	if err != nil || !first.Created {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "second-ek@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.10",
	})
	if err != ErrFederatedProviderChanged || second.Created {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='first-ek@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE username='second-ek@example.test'`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_external_links WHERE provider_id='`+testFederatedProviderID+`'`, 1)
}

func TestFederatedCreateRejectsMissingEmail(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	result, err := store.CreateFederatedIdentity(context.Background(), FederatedCreationInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "",
	})
	if err != ErrFederatedInvalidEmail || result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestFederatedCreateRejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	result, err := store.CreateFederatedIdentity(context.Background(), FederatedCreationInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "not-an-email",
	})
	if err != ErrFederatedInvalidEmail || result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestFederatedCreateRejectsUnverifiedNamespace(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	result, err := store.CreateFederatedIdentity(context.Background(), FederatedCreationInput{
		Subject: upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "s"},
		Config:  testFederatedProvider,
		Email:   "ns@example.test",
	})
	if err != ErrFederatedUnauthorized || result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func boolPtr(b bool) *bool { return &b }

func seedRauthyAdminRole(t *testing.T, store *Store) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "seed-rauthy-admin-role",
		SQL:       "INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('admin-role-id','rauthy_admin',NULL,1,0,0)",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFederatedCreateAdminMappingTrue(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(3_000_000).UTC() }
	seedRauthyAdminRole(t, store)
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "admin-true@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.20",
		AdminMapping:  boolPtr(true),
	})
	if err != nil || !result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+s+"' AND role_id='admin-role-id'", 1)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_users WHERE subject='"+s+"' AND last_login_at_unix_ms = "+fmt.Sprint(store.now().UTC().Truncate(time.Millisecond).UnixMilli()), 1)
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT typ,level FROM event_log ORDER BY id",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{"NewUserRegistered": false, "NewRauthyAdmin": false}
	for _, row := range rows.Rows {
		found[row[0].(string)] = true
	}
	if !found["NewUserRegistered"] || !found["NewRauthyAdmin"] {
		t.Fatalf("expected both creation events, got %#v", found)
	}
}

func TestFederatedCreateAdminMappingFalse(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(3_000_001).UTC() }
	seedRauthyAdminRole(t, store)
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "admin-false@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.21",
		AdminMapping:  boolPtr(false),
	})
	if err != nil || !result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+s+"'", 0)
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT typ FROM event_log ORDER BY id",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows.Rows {
		if row[0].(string) == "NewRauthyAdmin" {
			t.Fatalf("unexpected NewRauthyAdmin event for AdminMapping=false")
		}
	}
}

func TestFederatedCreateAdminMappingNil(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(3_000_002).UTC() }
	seedRauthyAdminRole(t, store)
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "admin-nil@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.22",
		AdminMapping:  nil,
	})
	if err != nil || !result.Created {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	s := result.Subject
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+s+"'", 0)
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT typ FROM event_log ORDER BY id",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows.Rows {
		if row[0].(string) == "NewRauthyAdmin" {
			t.Fatalf("unexpected NewRauthyAdmin event for AdminMapping=nil")
		}
	}
}

func TestFederatedCreateAdminMissingRoleRollback(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.UnixMilli(3_000_003).UTC() }
	// Do NOT seed rauthy_admin role.
	result, err := store.CreateFederatedIdentity(ctx, FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "missing-role@example.test",
		EmailVerified: true,
		SourceIP:      "10.0.0.23",
		AdminMapping:  boolPtr(true),
	})
	if err != ErrFederatedProviderChanged || result.Created {
		t.Fatalf("expected provider changed rollback, got result=%#v err=%v", result, err)
	}
	assertCount(t, store, "SELECT COUNT(*) FROM identity_users WHERE username='missing-role@example.test'", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_external_links WHERE provider_id='"+testFederatedProviderID+"'", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_recovery_emails WHERE subject NOT IN (SELECT subject FROM identity_users)", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_principal_versions WHERE subject NOT IN (SELECT subject FROM identity_users)", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM identity_user_profiles WHERE email='missing-role@example.test'", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles", 0)
	assertCount(t, store, "SELECT COUNT(*) FROM event_log", 0)
}
