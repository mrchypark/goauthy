package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const (
	testPID = "AbCdEfGhIjKlMnOpQrStUvWx"
	testIss = "https://issuer.example.test"
	testCID = "test-client"
)

var testNS = upstreamprovider.ComputeNamespace(testIss, testCID)

func testSetup(t *testing.T) (*identity.Store, *rhiza.DB) {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seedArgs := []any{
		testPID, int64(1), "test-google", "oidc",
		testIss, testIss + "/auth", testIss + "/token", testIss + "/userinfo",
		testCID, nil, "openid email profile",
		nil, nil, nil, nil,
		int64(1), int64(1), int64(0), nil, int64(1), int64(0),
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-provider",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: seedArgs},
			{SQL: `INSERT INTO auth_provider_runtime_versions(provider_id, version) VALUES(?, ?)`, Args: []any{testPID, "v1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store, db
}

func seedAdminRole(t *testing.T, db *rhiza.DB) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID:  "seed-admin-role",
		Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('admin-role-id','rauthy_admin',NULL,1,0,0)`}},
	}); err != nil {
		t.Fatal(err)
	}
}

func createUser(t *testing.T, store *identity.Store, subject, username string) {
	t.Helper()
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.Hash(context.Background(), []byte("TestPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(context.Background(), subject, username, phc); err != nil {
		t.Fatal(err)
	}
}

// seedProfile inserts identity_user_profiles row. BootstrapUser does NOT
// create profile/recovery rows; UpdateFederatedProfile requires baseline
// profile with email to pass its snapshot guard.
func seedProfile(t *testing.T, db *rhiza.DB, subject, email string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID:  "seed-profile-" + subject,
		Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified) VALUES(?,?,1)`, Args: []any{subject, email}}},
	}); err != nil {
		t.Fatal(err)
	}
}

func seedRecovery(t *testing.T, db *rhiza.DB, subject, email string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID:  "seed-recovery-" + subject,
		Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES(?,?)`, Args: []any{subject, email}}},
	}); err != nil {
		t.Fatal(err)
	}
}

func linkUser(t *testing.T, store *identity.Store, localSub, extSub string) {
	t.Helper()
	external := upstreamprovider.SubjectResult{ProviderID: testPID, Subject: extSub, IdentityNamespace: testNS}
	decision, err := store.LinkExternal(context.Background(), localSub, external, time.Now())
	if err != nil {
		t.Fatalf("LinkExternal decision=%v err=%v", decision, err)
	}
}

func grantAdmin(t *testing.T, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID:  "grant-admin-" + subject,
		Statements: []rhiza.SQLStatement{{SQL: `INSERT OR IGNORE INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES(?, 'admin-role-id', 0)`, Args: []any{subject}}},
	}); err != nil {
		t.Fatal(err)
	}
}

func countRows(t *testing.T, db *rhiza.DB, sql string) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("countRows sql=%q err=%v rows=%#v", sql, err, result.Rows)
	}
	return result.Rows[0][0].(int64)
}

// signClaims signs a JWT with the given claims and returns a JWKSVerifier
// plus the compact token. Uses httptest.NewTLSServer for the JWKS endpoint.
func signClaims(t *testing.T, claims map[string]any) (*upstreamprovider.JWKSVerifier, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}},
		})
	}))
	t.Cleanup(srv.Close)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "k1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	cfg := upstreamprovider.Config{
		Kind: upstreamprovider.ProviderKindOIDC, Issuer: testIss,
		AuthorizationEndpoint: testIss + "/auth", TokenEndpoint: testIss + "/token",
		JWKSURI: srv.URL + "/jwks", ClientID: testCID,
		ProviderSource: "registry", RuntimeVersion: "v1",
	}
	insecureClient := srv.Client()
	insecureClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	verifier, err := upstreamprovider.NewJWKSVerifier(map[string]upstreamprovider.Config{testIss: cfg}, insecureClient)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, raw
}

func getClaims(t *testing.T, v *upstreamprovider.JWKSVerifier, raw string) *upstreamprovider.IDTokenClaims {
	t.Helper()
	c, err := v.VerifyIDToken(context.Background(), raw, testIss, testCID)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	return c
}

// --- Tests ---

func TestResolveVerifiedNilCases(t *testing.T) {
	var nilR *FederatedIdentityResolver
	_, err := nilR.resolveVerified(context.Background(), upstreamprovider.VerifiedIdentity{})
	if err == nil || err.Error() != "upstream identity unavailable" {
		t.Fatalf("nil resolver: %v", err)
	}
	r := &FederatedIdentityResolver{}
	_, err = r.resolveVerified(context.Background(), upstreamprovider.VerifiedIdentity{})
	if err == nil || err.Error() != "upstream identity unavailable" {
		t.Fatalf("nil store: %v", err)
	}
}

func TestResolveVerifiedExistingLinked(t *testing.T) {
	store, db := testSetup(t)
	ctx := context.Background()
	seedAdminRole(t, db)
	createUser(t, store, "local-1", "alice")
	seedProfile(t, db, "local-1", "old@example.test")
	seedRecovery(t, db, "local-1", "old@example.test")
	linkUser(t, store, "local-1", "up-1")

	verifier, rawToken := signClaims(t, map[string]any{
		"iss": testIss, "sub": "up-1", "aud": testCID,
		"email": "alice@example.test", "email_verified": true,
		"given_name": "Alice", "family_name": "Wonder",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
	})
	claims := getClaims(t, verifier, rawToken)

	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: "up-1", IdentityNamespace: testNS},
		Config:        upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID},
		IDTokenClaims: claims,
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	subject, err := r.resolveVerified(ctx, vi)
	if err != nil {
		t.Fatalf("resolveVerified: %v", err)
	}
	if subject != "local-1" {
		t.Fatalf("subject = %q, want local-1", subject)
	}
	// Assert profile was synced by UpdateFederatedProfile.
	rows, qerr := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT email,given_name,family_name FROM identity_user_profiles WHERE subject='local-1'`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if qerr != nil || len(rows.Rows) != 1 {
		t.Fatalf("profile query: rows=%#v err=%v", rows.Rows, qerr)
	}
	email := rows.Rows[0][0].(string)
	given := rows.Rows[0][1].(string)
	family := rows.Rows[0][2].(string)
	if email != "alice@example.test" {
		t.Fatalf("email = %q, want alice@example.test", email)
	}
	if given != "Alice" {
		t.Fatalf("given_name = %q, want Alice", given)
	}
	if family != "Wonder" {
		t.Fatalf("family_name = %q, want Wonder", family)
	}
	// Assert last_login_at_unix_ms was refreshed.
	lrows, lerr := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT last_login_at_unix_ms FROM identity_users WHERE subject='local-1'`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if lerr != nil || len(lrows.Rows) != 1 || lrows.Rows[0][0] == nil {
		t.Fatalf("last_login: rows=%#v err=%v", lrows.Rows, lerr)
	}
}

func TestResolveVerifiedAdminGrantRevokeNil(t *testing.T) {
	tests := []struct {
		name       string
		claims     map[string]any
		adminPath  string
		adminValue string
		seedAdmin  bool // seed admin role before resolveVerified
		wantAdmin  int64
	}{
		{
			name:       "grant",
			claims:     map[string]any{"iss": testIss, "sub": "up-g", "aud": testCID, "email": "g@example.test", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "custom": map[string]any{"admin": true}},
			adminPath:  "$.custom.admin",
			adminValue: "true",
			wantAdmin:  1,
		},
		{
			name:       "revoke",
			claims:     map[string]any{"iss": testIss, "sub": "up-r", "aud": testCID, "email": "r@example.test", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "custom": map[string]any{"admin": false}},
			adminPath:  "$.custom.admin",
			adminValue: "true",
			seedAdmin:  true,
			wantAdmin:  0,
		},
		{
			name:      "nil_mapping",
			claims:    map[string]any{"iss": testIss, "sub": "up-n", "aud": testCID, "email": "n@example.test", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix()},
			seedAdmin: true,
			wantAdmin: 1, // preserved
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, db := testSetup(t)
			ctx := context.Background()
			seedAdminRole(t, db)
			subj := "local-" + tt.name
			createUser(t, store, subj, "user-"+tt.name)
			seedProfile(t, db, subj, tt.claims["email"].(string))
			seedRecovery(t, db, subj, tt.claims["email"].(string))
			linkUser(t, store, subj, tt.claims["sub"].(string))

			if tt.seedAdmin {
				grantAdmin(t, db, subj)
			}
			// For revoke: need another active admin to satisfy last-admin guard.
			if tt.name == "revoke" {
				createUser(t, store, "other-admin", "other-admin")
				seedProfile(t, db, "other-admin", "other@admin.test")
				grantAdmin(t, db, "other-admin")
			}

			verifier, rawToken := signClaims(t, tt.claims)
			claims := getClaims(t, verifier, rawToken)

			cfg := upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID}
			if tt.adminPath != "" {
				cfg.AdminClaimPath = &tt.adminPath
				cfg.AdminClaimValue = &tt.adminValue
			}
			vi := upstreamprovider.VerifiedIdentity{
				Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: tt.claims["sub"].(string), IdentityNamespace: testNS},
				Config:        cfg,
				IDTokenClaims: claims,
			}
			r := &FederatedIdentityResolver{IdentityStore: store}
			subject, err := r.resolveVerified(ctx, vi)
			if err != nil {
				t.Fatalf("resolveVerified: %v", err)
			}
			if subject != subj {
				t.Fatalf("subject = %q, want %q", subject, subj)
			}
			got := countRows(t, db, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subj+"' AND role_id='admin-role-id'")
			if got != tt.wantAdmin {
				t.Fatalf("admin roles = %d, want %d", got, tt.wantAdmin)
			}
			// For revoke: other admin must still have role.
			if tt.name == "revoke" {
				other := countRows(t, db, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject='other-admin' AND role_id='admin-role-id'`)
				if other != 1 {
					t.Fatalf("other admin roles = %d, want 1", other)
				}
			}
		})
	}
}

func TestResolveVerifiedMalformedPathAllowed(t *testing.T) {
	store, db := testSetup(t)
	seedAdminRole(t, db)
	createUser(t, store, "local-mal", "malformed")
	seedProfile(t, db, "local-mal", "mal@example.test")
	seedRecovery(t, db, "local-mal", "mal@example.test")
	linkUser(t, store, "local-mal", "up-mal")

	verifier, rawToken := signClaims(t, map[string]any{
		"iss": testIss, "sub": "up-mal", "aud": testCID,
		"email": "mal@example.test", "email_verified": true,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
	})
	claims := getClaims(t, verifier, rawToken)

	badPath := "$.nonexistent["
	cfg := upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID}
	cfg.AdminClaimPath = &badPath
	cfg.AdminClaimValue = ptr("x")

	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: "up-mal", IdentityNamespace: testNS},
		Config:        cfg,
		IDTokenClaims: claims,
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	subject, err := r.resolveVerified(context.Background(), vi)
	if err != nil {
		t.Fatalf("resolveVerified: %v", err)
	}
	if subject != "local-mal" {
		t.Fatalf("subject = %q, want local-mal", subject)
	}
	got := countRows(t, db, `SELECT COUNT(*) FROM rbac_user_roles WHERE subject='local-mal'`)
	if got != 0 {
		t.Fatalf("admin roles = %d, want 0 (malformed path = no change)", got)
	}
}

func TestResolveVerifiedNoRawClaimsRejects(t *testing.T) {
	store, _ := testSetup(t)
	path := "$.admin"
	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: "up-x", IdentityNamespace: testNS},
		Config:        upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID, AdminClaimPath: &path, AdminClaimValue: ptr("true")},
		IDTokenClaims: &upstreamprovider.IDTokenClaims{Email: ptr("x@example.test")},
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	_, err := r.resolveVerified(context.Background(), vi)
	if err == nil || err.Error() != "admin mapping configured but claims unavailable" {
		t.Fatalf("expected claims unavailable, got %v", err)
	}
}

func TestResolveVerifiedNoEmailRejects(t *testing.T) {
	store, _ := testSetup(t)
	verifier, rawToken := signClaims(t, map[string]any{
		"iss": testIss, "sub": "up-noemail", "aud": testCID,
		"email": "x@example.test", "email_verified": true,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
	})
	claims := getClaims(t, verifier, rawToken)
	claims.Email = nil

	path := "$.admin"
	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: "up-noemail", IdentityNamespace: testNS},
		Config:        upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID, AdminClaimPath: &path, AdminClaimValue: ptr("true")},
		IDTokenClaims: claims,
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	_, err := r.resolveVerified(context.Background(), vi)
	if err == nil || err.Error() != "admin mapping configured but claims unavailable" {
		t.Fatalf("expected claims unavailable, got %v", err)
	}
}

func TestResolveVerifiedEvalErrRejects(t *testing.T) {
	store, _ := testSetup(t)
	verifier, rawToken := signClaims(t, map[string]any{
		"iss": testIss, "sub": "up-eval", "aud": testCID,
		"email": "eval@example.test", "email_verified": true,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
	})
	claims := getClaims(t, verifier, rawToken)

	path := "$.admin"
	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testPID, Subject: "up-eval", IdentityNamespace: testNS},
		Config:        upstreamprovider.Config{ProviderSource: "registry", RuntimeVersion: "v1", Issuer: testIss, ClientID: testCID, AdminClaimPath: &path},
		IDTokenClaims: claims,
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	_, err := r.resolveVerified(context.Background(), vi)
	if err == nil || err.Error() != "admin claim mapping failed" {
		t.Fatalf("expected admin claim mapping failed, got %v", err)
	}
}

func TestResolveVerifiedLegacyStatic(t *testing.T) {
	store, _ := testSetup(t)
	createUser(t, store, "legacy-subj", "legacy-user")
	external := upstreamprovider.SubjectResult{ProviderID: "legacy", Subject: "legacy-ext"}
	_, err := store.LinkExternal(context.Background(), "legacy-subj", external, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	vi := upstreamprovider.VerifiedIdentity{
		Subject:       upstreamprovider.SubjectResult{ProviderID: "legacy", Subject: "legacy-ext"},
		Config:        upstreamprovider.Config{},
		IDTokenClaims: &upstreamprovider.IDTokenClaims{Email: ptr("legacy@example.test")},
	}
	r := &FederatedIdentityResolver{IdentityStore: store}
	subject, err := r.resolveVerified(context.Background(), vi)
	if err != nil {
		t.Fatalf("resolveVerified: %v", err)
	}
	if subject != "legacy-subj" {
		t.Fatalf("subject = %q, want legacy-subj", subject)
	}
}

func ptr[T any](v T) *T { return &v }
