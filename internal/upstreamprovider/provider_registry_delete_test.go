package upstreamprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type deleteFixture struct {
	t         *testing.T
	ctx       context.Context
	db        *rhiza.DB
	store     *RegistryStore
	keys      *apikey.Store
	principal *apikey.Principal
}

func newDeleteFixture(t *testing.T) *deleteFixture {
	t.Helper()
	ctx := context.Background()
	db := openTestDB(t, "delete-test")
	store, err := NewRegistryStore(db, &fakeEnvelopeKeyring{})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   "delete-manager",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Create, apikey.Update, apikey.Delete}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return &deleteFixture{t: t, ctx: ctx, db: db, store: store, keys: keys, principal: &p}
}

func (f *deleteFixture) newRequestID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		f.t.Fatal(err)
	}
	return prefix + "/" + base64.RawURLEncoding.EncodeToString(b)
}

func seedIdentityUser(t *testing.T, ctx context.Context, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "seed-user-" + subject,
		SQL:       "INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)",
		Args:      []any{subject, subject, ""},
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *deleteFixture) seedProvider(id string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-provider-" + id,
		SQL:       `INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		Args: []any{id, int64(1), "seed-" + id, "oidc",
			"https://issuer-" + id + ".test", "https://auth-" + id + ".test",
			"https://token-" + id + ".test", "https://userinfo-" + id + ".test",
			"cid-" + id, nil, "openid", "$.admin", "true",
			nil, nil, int64(1), int64(1), int64(0), nil, int64(0), int64(0)},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) seedLogo(providerID, res string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-logo-" + providerID + "-" + res,
		SQL:       "INSERT INTO auth_provider_logos(auth_provider_id,res,content_type,data,updated) VALUES(?,?,?,?,?)",
		Args:      []any{providerID, res, "image/webp", []byte("logo-data"), int64(1000)},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) seedProfile(subject, email string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-profile-" + subject,
		SQL:       "INSERT INTO identity_user_profiles(subject,email,email_verified) VALUES(?,?,1)",
		Args:      []any{subject, email},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) seedRecoveryEmail(subject, email string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-recovery-" + subject,
		SQL:       "INSERT INTO identity_recovery_emails(subject,email) VALUES(?,?)",
		Args:      []any{subject, email},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) seedLink(providerID, extKey, localSubject string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-link-" + providerID + "-" + extKey,
		SQL:       "INSERT INTO identity_external_links(provider_id,external_key,local_subject,linked_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{providerID, extKey, localSubject, int64(2000)},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) disableUser(subject string) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "disable-" + subject,
		SQL:       "UPDATE identity_users SET disabled=1 WHERE subject=?",
		Args:      []any{subject},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *deleteFixture) providerExists(id string) bool {
	f.t.Helper()
	r, err := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT 1 FROM auth_providers WHERE id=?", Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		f.t.Fatal(err)
	}
	return len(r.Rows) > 0
}

func (f *deleteFixture) logoCount(providerID string) int64 {
	f.t.Helper()
	r, err := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM auth_provider_logos WHERE auth_provider_id=?", Args: []any{providerID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		f.t.Fatalf("logoCount: %v", err)
	}
	return r.Rows[0][0].(int64)
}

func (f *deleteFixture) linkCount(providerID string) int64 {
	f.t.Helper()
	r, err := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM identity_external_links WHERE provider_id=?", Args: []any{providerID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		f.t.Fatalf("linkCount: %v", err)
	}
	return r.Rows[0][0].(int64)
}

func testExtKey(suffix string) string {
	base := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	if suffix == "" {
		return base
	}
	return base[:43-len(suffix)] + suffix
}

func TestDeleteAuthorizedProviderLogoAndLinks(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-clean")
	f.seedLogo("del-clean", "small")
	seedIdentityUser(t, f.ctx, f.db, "u-del-1")
	f.seedProfile("u-del-1", "u1@example.test")
	f.seedLink("del-clean", testExtKey("00001"), "u-del-1")

	err := f.store.DeleteAuthorized(f.ctx, "del-clean", f.newRequestID("del"), f.keys, f.principal)
	if err != nil {
		t.Fatalf("DeleteAuthorized: %v", err)
	}
	if f.providerExists("del-clean") {
		t.Fatal("provider should be deleted")
	}
	if f.logoCount("del-clean") != 0 {
		t.Fatal("logos should be deleted")
	}
	if f.linkCount("del-clean") != 0 {
		t.Fatal("links should be deleted")
	}
	r, err := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT 1 FROM identity_users WHERE subject=?", Args: []any{"u-del-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatal("user should be preserved")
	}
	r, err = f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT 1 FROM identity_user_profiles WHERE subject=?", Args: []any{"u-del-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatal("profile should be preserved")
	}
}

func TestDeleteAuthorizedRevokedPrincipal(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-rev")
	f.seedLogo("del-rev", "small")
	seedIdentityUser(t, f.ctx, f.db, "u-rev")
	f.seedProfile("u-rev", "rev@test.test")
	f.seedLink("del-rev", testExtKey("00002"), "u-rev")

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-del-key",
		SQL:       "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args:      []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil {
		t.Fatal(err)
	}

	err := f.store.DeleteAuthorized(f.ctx, "del-rev", f.newRequestID("del-rev"), f.keys, f.principal)
	if !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("err=%v, want ErrForbidden", err)
	}
	if !f.providerExists("del-rev") {
		t.Fatal("provider should be preserved")
	}
	if f.logoCount("del-rev") != 1 {
		t.Fatal("logo should be preserved")
	}
	if f.linkCount("del-rev") != 1 {
		t.Fatal("link should be preserved")
	}
}

func TestDeleteAuthorizedConstraintRollback(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-roll")
	_, token, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name:   "read-only-key",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.keys.Authenticate(f.ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.DeleteAuthorized(f.ctx, "del-roll", f.newRequestID("roll"), f.keys, &p)
	if !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("err=%v, want ErrForbidden", err)
	}
	if !f.providerExists("del-roll") {
		t.Fatal("provider should be preserved after wrong-right rollback")
	}
}

func TestDeleteAuthorizedLinkedUsersCorrect(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-multi")
	seedIdentityUser(t, f.ctx, f.db, "u-multi-a")
	f.seedProfile("u-multi-a", "alice@example.test")
	seedIdentityUser(t, f.ctx, f.db, "u-multi-b")
	f.seedProfile("u-multi-b", "bob@example.test")
	f.seedLink("del-multi", testExtKey("00003"), "u-multi-a")
	f.seedLink("del-multi", testExtKey("00004"), "u-multi-b")

	linked, err := f.store.LinkedUsers(f.ctx, "del-multi")
	if err != nil {
		t.Fatalf("LinkedUsers: %v", err)
	}
	if len(linked) != 2 {
		t.Fatalf("linked count = %d, want 2", len(linked))
	}
	emails := map[string]string{}
	for _, u := range linked {
		emails[u.ID] = u.Email
	}
	if emails["u-multi-a"] != "alice@example.test" {
		t.Fatalf("alice email = %q", emails["u-multi-a"])
	}
	if emails["u-multi-b"] != "bob@example.test" {
		t.Fatalf("bob email = %q", emails["u-multi-b"])
	}
	err = f.store.DeleteAuthorized(f.ctx, "del-multi", f.newRequestID("del"), f.keys, f.principal)
	if err != nil {
		t.Fatalf("DeleteAuthorized: %v", err)
	}
	if f.providerExists("del-multi") {
		t.Fatal("provider should be deleted")
	}
}

func TestDeleteAuthorizedEmpty(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-empty")
	linked, err := f.store.LinkedUsers(f.ctx, "del-empty")
	if err != nil {
		t.Fatalf("LinkedUsers: %v", err)
	}
	if len(linked) != 0 {
		t.Fatalf("linked count = %d, want 0", len(linked))
	}
	err = f.store.DeleteAuthorized(f.ctx, "del-empty", f.newRequestID("del"), f.keys, f.principal)
	if err != nil {
		t.Fatalf("DeleteAuthorized: %v", err)
	}
	if f.providerExists("del-empty") {
		t.Fatal("provider should be deleted")
	}
}

func TestDeleteAuthorizedNonExistent(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	err := f.store.DeleteAuthorized(f.ctx, "del-nope", f.newRequestID("del"), f.keys, f.principal)
	if err != nil {
		t.Fatalf("delete non-existent: %v, want nil", err)
	}
}

func TestDeleteAuthorizedMissingProfile(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-noprof")
	seedIdentityUser(t, f.ctx, f.db, "u-noprof")
	f.seedLink("del-noprof", testExtKey("00005"), "u-noprof")
	linked, err := f.store.LinkedUsers(f.ctx, "del-noprof")
	if err != nil {
		t.Fatalf("LinkedUsers: %v", err)
	}
	if len(linked) != 1 {
		t.Fatalf("linked count = %d, want 1", len(linked))
	}
	if linked[0].ID != "u-noprof" {
		t.Fatalf("id = %q, want u-noprof", linked[0].ID)
	}
	if linked[0].Email != "" {
		t.Fatalf("email = %q, want empty for missing profile", linked[0].Email)
	}
}

func TestDeleteAuthorizedMissingProfileWithRecoveryEmail(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-recov")
	seedIdentityUser(t, f.ctx, f.db, "u-recov")
	f.seedRecoveryEmail("u-recov", "recovery@example.test")
	f.seedLink("del-recov", testExtKey("00006"), "u-recov")
	linked, err := f.store.LinkedUsers(f.ctx, "del-recov")
	if err != nil {
		t.Fatalf("LinkedUsers: %v", err)
	}
	if len(linked) != 1 {
		t.Fatalf("linked count = %d, want 1", len(linked))
	}
	if linked[0].Email != "recovery@example.test" {
		t.Fatalf("email = %q, want recovery fallback", linked[0].Email)
	}
}

func TestDeleteAuthorizedDisabledUserListed(t *testing.T) {
	t.Parallel()
	f := newDeleteFixture(t)
	f.seedProvider("del-dis")
	seedIdentityUser(t, f.ctx, f.db, "u-dis")
	f.seedProfile("u-dis", "dis@test.test")
	f.seedLink("del-dis", testExtKey("00007"), "u-dis")
	f.disableUser("u-dis")

	linked, err := f.store.LinkedUsers(f.ctx, "del-dis")
	if err != nil {
		t.Fatalf("LinkedUsers: %v", err)
	}
	if len(linked) != 1 {
		t.Fatalf("linked count = %d, want 1 (disabled user listed)", len(linked))
	}
	if linked[0].ID != "u-dis" || linked[0].Email != "dis@test.test" {
		t.Fatalf("linked user = %+v", linked[0])
	}
}
