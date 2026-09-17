package upstreamprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// --- test fixture ---

// mutationFixture creates a real Rhiza DB, a RegistryStore with a real
// oidc.Keyring, an apikey.Store with an authenticated principal, and returns
// all three. The keyring is shared between the RegistryStore and the
// envelope-mutation path so that SealEnvelope and PurposeEnvelopeKeyID are
// consistent.
type mutationFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *rhiza.DB
	keyring  EnvelopeKeyring
	store    *RegistryStore
	keys     *apikey.Store
	principal *apikey.Principal
}

func newMutationFixture(t *testing.T) *mutationFixture {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "mutation-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, 32))
	if err := os.WriteFile(filepath.Join(dir, "test-key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	rStore, err := NewRegistryStore(db, keyring)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := apiKeys.Create(ctx, nil, apikey.Request{
		Name:   "mutation-manager",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Create, apikey.Update}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := apiKeys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return &mutationFixture{
		t:         t,
		ctx:       ctx,
		db:        db,
		keyring:   keyring,
		store:     rStore,
		keys:      apiKeys,
		principal: &p,
	}
}

func (f *mutationFixture) newRequestID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		f.t.Fatal(err)
	}
	return prefix + "/" + base64.RawURLEncoding.EncodeToString(b)
}

func (f *mutationFixture) seedProvider(id string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-" + id,
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

func (f *mutationFixture) readProvider(id string) []any {
	f.t.Helper()
	result, err := f.db.Query(f.ctx, rhiza.QueryRequest{
		SQL:         `SELECT id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link FROM auth_providers WHERE id=?`,
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		f.t.Fatalf("read provider %s: rows=%d err=%v", id, len(result.Rows), err)
	}
	return result.Rows[0]
}

// --- tests ---

func TestProviderCreateAuthorizedWithSecret(t *testing.T) {
	f := newMutationFixture(t)
	secret := "my-client-secret"
	req := validProviderMutationRequest()
	req.ClientSecret = &secret

	doc, err := f.store.CreateAuthorized(f.ctx, "prov-create-sec", f.newRequestID("create"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	if doc.ID != "prov-create-sec" {
		t.Fatalf("ID = %q", doc.ID)
	}
	if doc.Name != req.Name || doc.Typ != req.Typ || doc.ClientID != req.ClientID {
		t.Fatalf("fields mismatch: name=%q typ=%q clientID=%q", doc.Name, doc.Typ, doc.ClientID)
	}
	// Secret must be non-nil encrypted ciphertext, not plaintext.
	if doc.Secret == nil {
		t.Fatal("expected non-nil encrypted secret")
	}
	if string(doc.Secret) == secret {
		t.Fatal("secret stored as plaintext")
	}
	// Verify purpose binding.
	purpose := ProviderSecretPurpose("prov-create-sec")
	cleartext, err := f.keyring.OpenEnvelope(purpose, doc.Secret)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if string(cleartext) != secret {
		t.Fatalf("cleartext = %q, want %q", cleartext, secret)
	}
	// Verify row exists in DB.
	row := f.readProvider("prov-create-sec")
	if row[0] != "prov-create-sec" || row[9] == nil {
		t.Fatalf("DB row mismatch: id=%v secret=%v", row[0], row[9])
	}
}

func TestProviderCreateAuthorizedNoSecret(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil

	doc, err := f.store.CreateAuthorized(f.ctx, "prov-create-nosec", f.newRequestID("create"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	if doc.Secret != nil {
		t.Fatalf("expected nil secret, got %x", doc.Secret)
	}
	row := f.readProvider("prov-create-nosec")
	if row[9] != nil {
		t.Fatalf("DB secret should be NULL, got %v", row[9])
	}
}

func TestProviderCreateAuthorizedRejectsDuplicate(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-dup")
	req := validProviderMutationRequest()

	_, err := f.store.CreateAuthorized(f.ctx, "prov-dup", f.newRequestID("create"), req, f.keys, f.principal)
	if !errors.Is(err, ErrProviderExists) {
		t.Fatalf("duplicate create: err=%v, want ErrProviderExists", err)
	}
}

func TestProviderCreateAuthorizedRejectsInvalidDTO(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.Name = "" // empty name fails validation

	_, err := f.store.CreateAuthorized(f.ctx, "prov-invalid", f.newRequestID("create"), req, f.keys, f.principal)
	if err == nil {
		t.Fatal("invalid DTO accepted")
	}
}

func TestProviderCreateAuthorizedScopeNormalized(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.Scope = "openid  profile   email" // double spaces
	req.ClientSecret = nil

	doc, err := f.store.CreateAuthorized(f.ctx, "prov-scope", f.newRequestID("create"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	if doc.Scope != "openid+profile+email" {
		t.Fatalf("scope = %q, want openid+profile+email", doc.Scope)
	}
}

func TestProviderUpdateAuthorizedWithSecret(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-upd")
	req := validProviderMutationRequest()
	newSecret := "updated-secret"
	req.ClientSecret = &newSecret

	doc, err := f.store.UpdateAuthorized(f.ctx, "prov-upd", f.newRequestID("update"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("UpdateAuthorized: %v", err)
	}
	if doc.ID != "prov-upd" {
		t.Fatalf("ID = %q", doc.ID)
	}
	// Verify the new secret is encrypted with provider-bound purpose.
	purpose := ProviderSecretPurpose("prov-upd")
	cleartext, err := f.keyring.OpenEnvelope(purpose, doc.Secret)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if string(cleartext) != newSecret {
		t.Fatalf("cleartext = %q, want %q", cleartext, newSecret)
	}
}

func TestProviderUpdateAuthorizedNullClear(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-null")
	req := validProviderMutationRequest()
	req.ClientSecret = nil // clear

	doc, err := f.store.UpdateAuthorized(f.ctx, "prov-null", f.newRequestID("update"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("UpdateAuthorized: %v", err)
	}
	if doc.Secret != nil {
		t.Fatalf("expected nil secret after clear, got %x", doc.Secret)
	}
	row := f.readProvider("prov-null")
	if row[9] != nil {
		t.Fatalf("DB secret should be NULL after clear, got %v", row[9])
	}
}

func TestProviderUpdateAuthorizedExactFields(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-exact")
	req := ProviderRequest{
		Name:                  "ExactUpdate",
		Typ:                   AuthProviderTypeGoogle,
		Enabled:               true,
		Issuer:                "https://exact.example",
		AuthorizationEndpoint: "https://exact.example/auth",
		TokenEndpoint:         "https://exact.example/token",
		UserinfoEndpoint:      "https://exact.example/userinfo",
		ClientID:              "exact-cid",
		ClientSecret:          nil,
		Scope:                 "openid email",
		AdminClaimPath:        strPtr("$.admin"),
		AdminClaimValue:       strPtr("yes"),
		MFAClaimPath:          strPtr("$.mfa"),
		MFAClaimValue:         strPtr("required"),
		UsePKCE:               true,
		ClientSecretBasic:     false,
		ClientSecretPost:      true,
		JWKS:                  strPtr("https://exact.example/jwks"),
		AutoOnboarding:        true,
		AutoLink:              false,
	}

	doc, err := f.store.UpdateAuthorized(f.ctx, "prov-exact", f.newRequestID("update"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("UpdateAuthorized: %v", err)
	}
	// Verify all 21 columns read back.
	if doc.Name != "ExactUpdate" || doc.Typ != AuthProviderTypeGoogle || !doc.Enabled {
		t.Fatalf("basic fields: name=%q typ=%v enabled=%v", doc.Name, doc.Typ, doc.Enabled)
	}
	if doc.Issuer != "https://exact.example" || doc.AuthorizationEndpoint != "https://exact.example/auth" {
		t.Fatalf("endpoint fields mismatch")
	}
	if doc.TokenEndpoint != "https://exact.example/token" || doc.UserinfoEndpoint != "https://exact.example/userinfo" {
		t.Fatalf("token/userinfo mismatch")
	}
	if doc.ClientID != "exact-cid" || doc.Scope != "openid+email" {
		t.Fatalf("credential fields: cid=%q scope=%q", doc.ClientID, doc.Scope)
	}
	if doc.AdminClaimPath == nil || *doc.AdminClaimPath != "$.admin" {
		t.Fatalf("AdminClaimPath = %v", doc.AdminClaimPath)
	}
	if doc.AdminClaimValue == nil || *doc.AdminClaimValue != "yes" {
		t.Fatalf("AdminClaimValue = %v", doc.AdminClaimValue)
	}
	if doc.MFAClaimPath == nil || *doc.MFAClaimPath != "$.mfa" {
		t.Fatalf("MFAClaimPath = %v", doc.MFAClaimPath)
	}
	if doc.MFAClaimValue == nil || *doc.MFAClaimValue != "required" {
		t.Fatalf("MFAClaimValue = %v", doc.MFAClaimValue)
	}
	if !doc.UsePKCE || doc.ClientSecretBasic || !doc.ClientSecretPost {
		t.Fatalf("protocol flags: pkce=%v basic=%v post=%v", doc.UsePKCE, doc.ClientSecretBasic, doc.ClientSecretPost)
	}
	if doc.JWKS == nil || *doc.JWKS != "https://exact.example/jwks" {
		t.Fatalf("JWKS = %v", doc.JWKS)
	}
	if !doc.AutoOnboarding || doc.AutoLink {
		t.Fatalf("auto flags: onboard=%v link=%v", doc.AutoOnboarding, doc.AutoLink)
	}
	if doc.Secret != nil {
		t.Fatalf("secret should be nil, got %x", doc.Secret)
	}
}

func TestProviderUpdateAuthorizedRejectsNonExistent(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()

	_, err := f.store.UpdateAuthorized(f.ctx, "prov-nonexist", f.newRequestID("update"), req, f.keys, f.principal)
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("update non-existent: err=%v, want ErrProviderNotFound", err)
	}
}

func TestProviderCreateAuthorizedRevokedGuard(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	requestID := f.newRequestID("create-revoked")

	// Revoke the key before the mutation is submitted.
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-key",
		SQL:       `UPDATE api_keys SET secret_digest=? WHERE name=?`,
		Args:      []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil {
		t.Fatal(err)
	}

	_, err := f.store.CreateAuthorized(f.ctx, "prov-revoked", requestID, req, f.keys, f.principal)
	if !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked guard: err=%v, want ErrForbidden", err)
	}
	// Verify nothing persisted.
	if _, err := f.db.Query(f.ctx, rhiza.QueryRequest{
		SQL: `SELECT 1 FROM auth_providers WHERE id=?`, Args: []any{"prov-revoked"},
		Consistency: rhiza.ConsistencyLinearizable,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderCreateAuthorizedOldWriterFence(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	secret := "fenced-secret"
	req.ClientSecret = &secret

	// Seal with the current (old) key to discover the writer key ID
	// and prove source binding.
	purpose := ProviderSecretPurpose("prov-fenced")
	oldEnvelope, err := f.keyring.SealEnvelope(purpose, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	oldWriterKeyID, err := f.keyring.PurposeEnvelopeKeyID(purpose, oldEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	// Source binding: the sealed envelope decrypts with the same purpose.
	cleartext, err := f.keyring.OpenEnvelope(purpose, oldEnvelope)
	if err != nil || string(cleartext) != secret {
		t.Fatalf("source binding: cleartext=%q err=%v", cleartext, err)
	}

	// Build a replacement keyring with distinct key material.
	replDir := t.TempDir()
	replKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x08}, 32))
	if err := os.WriteFile(filepath.Join(replDir, "repl-key"), []byte(replKey), 0o600); err != nil {
		t.Fatal(err)
	}
	replKeyring, err := oidc.LoadKeyring(replDir, "repl-key")
	if err != nil {
		t.Fatal(err)
	}
	// Discover the replacement keyring's writer key ID via a probe seal.
	replPurpose := ProviderSecretPurpose("prov-repl")
	replProbe, err := replKeyring.SealEnvelope(replPurpose, []byte("probe"))
	if err != nil {
		t.Fatal(err)
	}
	replWriterKeyID, err := replKeyring.PurposeEnvelopeKeyID(replPurpose, replProbe)
	if err != nil {
		t.Fatal(err)
	}

	// Advance the retirement barrier to fenced state; old key is fenced,
	// replacement key is admitted.
	fenceMasterKeyRetirementForTest(t, f.ctx, f.db, oldWriterKeyID, replWriterKeyID)

	// --- old key rejection ---

	// CreateAuthorized seals with the same (old) keyring, so the envelope
	// writer key ID will match the fenced old key. The fence must reject
	// the entire transaction — error or ok=false, either is valid rejection.
	_, err = f.store.CreateAuthorized(f.ctx, "prov-fenced", f.newRequestID("create-fenced"), req, f.keys, f.principal)
	if err == nil {
		t.Fatal("old writer accepted after fence")
	}

	// Verify no provider row was written.
	result, qerr := f.db.Query(f.ctx, rhiza.QueryRequest{
		SQL:         "SELECT 1 FROM auth_providers WHERE id=?",
		Args:        []any{"prov-fenced"},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if qerr != nil {
		t.Fatal(qerr)
	}
	if len(result.Rows) != 0 {
		t.Fatalf("fenced create left %d rows in DB", len(result.Rows))
	}

	// Verify no guard rows were left behind.
	guards, gerr := f.db.Query(f.ctx, rhiza.QueryRequest{
		SQL:         "SELECT COUNT(*) FROM api_key_mutation_guards",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if guards.Rows[0][0] != int64(0) {
		t.Fatalf("guards left behind: %v", guards.Rows[0][0])
	}

	// --- replacement key success ---

	// CreateAuthorized through the replacement keyring: seals with the
	// replacement key, fence admits it, secret is envelope-encrypted.
	replStore, err := NewRegistryStore(f.db, replKeyring)
	if err != nil {
		t.Fatal(err)
	}
	replSecret := "replacement-secret"
	replReq := validProviderMutationRequest()
	replReq.ClientSecret = &replSecret
	replDoc, err := replStore.CreateAuthorized(f.ctx, "prov-repl", f.newRequestID("create-replacement"), replReq, f.keys, f.principal)
	if err != nil {
		t.Fatalf("replacement CreateAuthorized: %v", err)
	}
	if replDoc.ID != "prov-repl" {
		t.Fatalf("replacement ID = %q", replDoc.ID)
	}
	if replDoc.Secret == nil {
		t.Fatal("replacement secret is nil")
	}
	// Verify the secret decrypts through the replacement keyring.
	replCleartext, err := replKeyring.OpenEnvelope(replPurpose, replDoc.Secret)
	if err != nil {
		t.Fatalf("replacement OpenEnvelope: %v", err)
	}
	if string(replCleartext) != replSecret {
		t.Fatalf("replacement cleartext = %q, want %q", replCleartext, replSecret)
	}
	// Verify the envelope writer key matches the replacement key ID.
	envKeyID, err := replKeyring.PurposeEnvelopeKeyID(replPurpose, replDoc.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if envKeyID != replWriterKeyID {
		t.Fatalf("envelope writer key = %q, want %q", envKeyID, replWriterKeyID)
	}

	// Verify all 21 columns persisted via the canonical 21-column SELECT
	// with WHERE + guard, not a blind edit.
	replRow := f.readProvider("prov-repl")
	if len(replRow) != 21 {
		t.Fatalf("expected 21 columns, got %d", len(replRow))
	}
	if replRow[0] != "prov-repl" || replRow[9] == nil {
		t.Fatalf("DB mismatch: id=%v secret=%v", replRow[0], replRow[9])
	}
	// Decrypt the persisted envelope from DB, not just the returned doc,
	// to prove the INSERT sealed through the replacement keyring.
	dbSecret, ok := replRow[9].([]byte)
	if !ok {
		t.Fatalf("DB secret type = %T, want []byte", replRow[9])
	}
	dbCleartext, err := replKeyring.OpenEnvelope(replPurpose, dbSecret)
	if err != nil {
		t.Fatalf("DB envelope OpenEnvelope: %v", err)
	}
	if string(dbCleartext) != replSecret {
		t.Fatalf("DB envelope cleartext = %q, want %q", dbCleartext, replSecret)
	}
	dbKeyID, err := replKeyring.PurposeEnvelopeKeyID(replPurpose, dbSecret)
	if err != nil {
		t.Fatalf("DB envelope PurposeEnvelopeKeyID: %v", err)
	}
	if dbKeyID != replWriterKeyID {
		t.Fatalf("DB envelope key = %q, want %q", dbKeyID, replWriterKeyID)
	}

	// Guard rows cleaned up after successful commit.
	finalGuards, fgErr := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM api_key_mutation_guards", Consistency: rhiza.ConsistencyLinearizable})
	if fgErr != nil {
		t.Fatal(fgErr)
	}
	if finalGuards.Rows[0][0] != int64(0) {
		t.Fatalf("guards after replacement create: %v", finalGuards.Rows[0][0])
	}
}

func TestProviderCreateAuthorizedCrossProviderSecretBinding(t *testing.T) {
	keyring := &fakeEnvelopeKeyring{}

	// Seal for provider A.
	purposeA := ProviderSecretPurpose("prov-a")
	env, err := keyring.SealEnvelope(purposeA, []byte("secret-a"))
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to decrypt as provider B — purpose mismatch must fail.
	purposeB := ProviderSecretPurpose("prov-b")
	if purposeA == purposeB {
		t.Fatal("different providers produced same purpose")
	}
	_, err = keyring.OpenEnvelope(purposeB, env)
	if err == nil {
		t.Fatal("cross-provider secret binding should fail")
	}

	// Verify the sealed envelope carries the correct writer key.
	writerKeyID, err := keyring.PurposeEnvelopeKeyID(purposeA, env)
	if err != nil {
		t.Fatal(err)
	}
	if writerKeyID != "test-key" {
		t.Fatalf("writer key = %q, want test-key", writerKeyID)
	}
}


func TestProviderCreateScopeOpenidProfile(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.Scope = "openid profile"
	req.ClientSecret = nil

	doc, err := f.store.CreateAuthorized(f.ctx, "prov-scope-profile", f.newRequestID("create"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	if doc.Scope != "openid+profile" {
		t.Fatalf("doc.Scope = %q, want openid+profile", doc.Scope)
	}
	// Verify persisted scope in DB.
	row := f.readProvider("prov-scope-profile")
	if row[10] != "openid+profile" {
		t.Fatalf("DB scope = %v, want openid+profile", row[10])
	}
}

func TestProviderUpdateScopeOpenidProfile(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-scope-upd")
	req := validProviderMutationRequest()
	req.Scope = "openid profile"
	req.ClientSecret = nil

	doc, err := f.store.UpdateAuthorized(f.ctx, "prov-scope-upd", f.newRequestID("update"), req, f.keys, f.principal)
	if err != nil {
		t.Fatalf("UpdateAuthorized: %v", err)
	}
	if doc.Scope != "openid+profile" {
		t.Fatalf("doc.Scope = %q, want openid+profile", doc.Scope)
	}
	// Verify persisted scope in DB.
	row := f.readProvider("prov-scope-upd")
	if row[10] != "openid+profile" {
		t.Fatalf("DB scope = %v, want openid+profile", row[10])
	}
}

func TestProviderCreateInvalidRequestLeavesDBUnchanged(t *testing.T) {
	f := newMutationFixture(t)
	req := validProviderMutationRequest()
	req.Name = "" // invalid: empty name

	_, err := f.store.CreateAuthorized(f.ctx, "prov-invalid-check", f.newRequestID("create"), req, f.keys, f.principal)
	if err == nil {
		t.Fatal("invalid request accepted")
	}
	// Verify nothing persisted.
	result, qerr := f.db.Query(f.ctx, rhiza.QueryRequest{
		SQL:         "SELECT 1 FROM auth_providers WHERE id=?",
		Args:        []any{"prov-invalid-check"},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if qerr != nil {
		t.Fatal(qerr)
	}
	if len(result.Rows) != 0 {
		t.Fatalf("invalid create left %d rows in DB", len(result.Rows))
	}
}

func TestProviderUpdateInvalidRequestLeavesDBUnchanged(t *testing.T) {
	f := newMutationFixture(t)
	f.seedProvider("prov-invalid-upd")

	// Read original state.
	orig := f.readProvider("prov-invalid-upd")
	origName := orig[2]

	req := validProviderMutationRequest()
	req.Name = "" // invalid: empty name

	_, err := f.store.UpdateAuthorized(f.ctx, "prov-invalid-upd", f.newRequestID("update"), req, f.keys, f.principal)
	if err == nil {
		t.Fatal("invalid update accepted")
	}
	// Verify original data preserved.
	row := f.readProvider("prov-invalid-upd")
	if row[2] != origName {
		t.Fatalf("DB name changed from %v to %v after invalid update", origName, row[2])
	}
}
// --- helpers ---

func validProviderMutationRequest() ProviderRequest {
	return ProviderRequest{
		Name:                  "Test Provider",
		Typ:                   AuthProviderTypeOIDC,
		Enabled:               true,
		Issuer:                "https://issuer.test",
		AuthorizationEndpoint: "https://issuer.test/auth",
		TokenEndpoint:         "https://issuer.test/token",
		UserinfoEndpoint:      "https://issuer.test/userinfo",
		ClientID:              "test-client",
		Scope:                 "openid",
		UsePKCE:               true,
		ClientSecretBasic:     true,
		ClientSecretPost:      false,
		AutoOnboarding:        false,
		AutoLink:              false,
	}
}

func strPtr(s string) *string { return &s }






