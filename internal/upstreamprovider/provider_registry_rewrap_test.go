package upstreamprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// --- helpers ---

func testKeyringDir(t *testing.T, activeID string, keyIDs ...string) (dir string, keyring *oidc.Keyring) {
	t.Helper()
	dir = t.TempDir()
	for _, id := range keyIDs {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(key)
		if err := os.WriteFile(filepath.Join(dir, id), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := oidc.LoadKeyring(dir, activeID)
	if err != nil {
		t.Fatal(err)
	}
	return dir, kr
}

func testRewrapDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "provider-rewrap-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func insertAuthProvSecret(t *testing.T, db *rhiza.DB, id string, secret []byte) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-insert-" + id,
			SQL: `INSERT INTO auth_providers
			(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,
			 userinfo_endpoint,client_id,secret,scope,
			 admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,
			 use_pkce,client_secret_basic,client_secret_post,
			 jwks_endpoint,auto_onboarding,auto_link)
			VALUES (?,?,?,?,?,?, ?,?,?,?, ?,NULL,NULL,NULL,NULL, 1,1,0, NULL,0,0)`,
		Args: []any{id, int64(1), "test-" + id, "oidc",
			"https://issuer-" + id + ".test",
			"https://auth-" + id + ".test",
			"https://token-" + id + ".test",
			"https://userinfo-" + id + ".test",
			"cid-" + id, secret, "openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func insertAuthProvNullSecret(t *testing.T, db *rhiza.DB, id string) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-insert-" + id,
			SQL: `INSERT INTO auth_providers
			(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,
			 userinfo_endpoint,client_id,secret,scope,
			 admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,
			 use_pkce,client_secret_basic,client_secret_post,
			 jwks_endpoint,auto_onboarding,auto_link)
			VALUES (?,?,?,?,?, ?,?,?,?, NULL, ?,NULL,NULL,NULL,NULL, 1,1,0, NULL,0,0)`,
		Args: []any{id, int64(1), "test-" + id, "oidc",
			"https://issuer-" + id + ".test",
			"https://auth-" + id + ".test",
			"https://token-" + id + ".test",
			"https://userinfo-" + id + ".test",
			"cid-" + id, "openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readSecret(t *testing.T, db *rhiza.DB, id string) []byte {
	t.Helper()
	qr, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         "SELECT secret FROM auth_providers WHERE id=?",
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 || len(qr.Rows[0]) != 1 {
		t.Fatalf("expected one row for %s", id)
	}
	if qr.Rows[0][0] == nil {
		return nil
	}
	b, _ := qr.Rows[0][0].([]byte)
	return b
}

// --- test-only keyring wrappers ---

type interposingKeyring struct {
	inner      *oidc.Keyring
	mu         sync.Mutex
	interposed bool
	interpose  func()
}

func (k *interposingKeyring) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	return k.inner.SealEnvelope(purpose, plaintext)
}
func (k *interposingKeyring) OpenEnvelope(purpose string, envelope []byte) ([]byte, error) {
	return k.inner.OpenEnvelope(purpose, envelope)
}
func (k *interposingKeyring) PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error) {
	return k.inner.PurposeEnvelopeKeyID(purpose, envelope)
}
func (k *interposingKeyring) RewrapEnvelope(purpose string, envelope []byte) ([]byte, error) {
	k.mu.Lock()
	if !k.interposed {
		k.interposed = true
		k.mu.Unlock()
		k.interpose()
	} else {
		k.mu.Unlock()
	}
	return k.inner.RewrapEnvelope(purpose, envelope)
}
func (k *interposingKeyring) ActiveMasterKeyID() (string, error) {
	return k.inner.ActiveMasterKeyID()
}

type wrongActiveKey struct {
	inner   *oidc.Keyring
	wrongID string
}

func (k *wrongActiveKey) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	return k.inner.SealEnvelope(purpose, plaintext)
}
func (k *wrongActiveKey) OpenEnvelope(purpose string, envelope []byte) ([]byte, error) {
	return k.inner.OpenEnvelope(purpose, envelope)
}
func (k *wrongActiveKey) PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error) {
	return k.inner.PurposeEnvelopeKeyID(purpose, envelope)
}
func (k *wrongActiveKey) RewrapEnvelope(purpose string, envelope []byte) ([]byte, error) {
	return k.inner.RewrapEnvelope(purpose, envelope)
}
func (k *wrongActiveKey) ActiveMasterKeyID() (string, error) {
	return k.wrongID, nil
}

// --- tests ---

func TestInspectNilArgs(t *testing.T) {
	_, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")
	_, err := InspectAuthProviderSecretReferences(nil, nil, keyring)
	if err == nil {
		t.Fatal("expected error for nil args")
	}
}

func TestInspectNullActiveOldTamper(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	insertAuthProvNullSecret(t, db, "prov-null")

	activeEnv, err := keyring.SealEnvelope(ProviderSecretPurpose("prov-active"), []byte("secret-active"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-active", activeEnv)

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}
	oldEnv, err := oldKeyring.SealEnvelope(ProviderSecretPurpose("prov-old"), []byte("secret-old"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-old", oldEnv)

	tampered := []byte("tampered-data-that-looks-like-an-envelope")
	insertAuthProvSecret(t, db, "prov-tamper", tampered)

	_, err = InspectAuthProviderSecretReferences(ctx, db, keyring)
	if err == nil {
		t.Fatal("expected error for tampered envelope")
	}
}

func TestInspectInventoryDistribution(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	insertAuthProvNullSecret(t, db, "prov-null")

	activeEnv, err := keyring.SealEnvelope(ProviderSecretPurpose("prov-active"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-active", activeEnv)

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}
	oldEnv, err := oldKeyring.SealEnvelope(ProviderSecretPurpose("prov-old"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-old", oldEnv)

	family, err := InspectAuthProviderSecretReferences(ctx, db, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if family.Total != 2 {
		t.Fatalf("expected 2 total, got %d", family.Total)
	}
	if family.ByKeyID["master-active"] != 1 {
		t.Fatalf("expected 1 active-key ref, got %d", family.ByKeyID["master-active"])
	}
	if family.ByKeyID["master-old"] != 1 {
		t.Fatalf("expected 1 old-key ref, got %d", family.ByKeyID["master-old"])
	}
}

func TestInspectProviderPurposeReplay(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	_, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	env, err := keyring.SealEnvelope(ProviderSecretPurpose("prov-a"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-b", env)

	_, err = InspectAuthProviderSecretReferences(ctx, db, keyring)
	if err == nil {
		t.Fatal("expected error for provider-purpose replay")
	}
}

func TestRewrapOldToActiveRetainsPlaintext(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}

	purpose := ProviderSecretPurpose("prov-1")
	wantPlaintext := []byte("my-client-secret")
	oldEnv, err := oldKeyring.SealEnvelope(purpose, wantPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-1", oldEnv)

	result, err := RewrapAuthProviderSecretBatch(ctx, db, keyring, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewrapped != 1 {
		t.Fatalf("expected 1 rewrap, got %d", result.Rewrapped)
	}

	newSecret := readSecret(t, db, "prov-1")
	kid, err := keyring.PurposeEnvelopeKeyID(purpose, newSecret)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "master-active" {
		t.Fatalf("expected active key, got %s", kid)
	}

	gotPlaintext, err := keyring.OpenEnvelope(purpose, newSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", gotPlaintext, wantPlaintext)
	}
}

func TestRewrapAllActiveSkips(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	_, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	activeEnv, err := keyring.SealEnvelope(ProviderSecretPurpose("prov-1"), []byte("s1"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-1", activeEnv)

	result, err := RewrapAuthProviderSecretBatch(ctx, db, keyring, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewrapped != 0 {
		t.Fatalf("expected 0 rewraps, got %d", result.Rewrapped)
	}
	if !result.Done {
		t.Fatal("expected done=true when all active")
	}
}

func TestRewrapCursorSkipsNothing(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 35; i++ {
		id := fmt.Sprintf("prov-%02d", i)
		purpose := ProviderSecretPurpose(id)
		oldEnv, err := oldKeyring.SealEnvelope(purpose, []byte("secret-"+id))
		if err != nil {
			t.Fatal(err)
		}
		insertAuthProvSecret(t, db, id, oldEnv)
	}

	result, err := RewrapAuthProviderSecretBatch(ctx, db, keyring, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewrapped != 32 {
		t.Fatalf("expected 32 rewraps, got %d", result.Rewrapped)
	}
	if result.Done {
		t.Fatal("expected done=false with more rows")
	}

	result2, err := RewrapAuthProviderSecretBatch(ctx, db, keyring, result.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if result2.Rewrapped != 3 {
		t.Fatalf("expected 3 rewraps, got %d", result2.Rewrapped)
	}
	if !result2.Done {
		t.Fatal("expected done=true")
	}

	family, err := InspectAuthProviderSecretReferences(ctx, db, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if family.Total != 35 {
		t.Fatalf("expected 35 total, got %d", family.Total)
	}
	if family.ByKeyID["master-active"] != 35 {
		t.Fatalf("expected 35 active-key refs, got %d", family.ByKeyID["master-active"])
	}
}

func TestRewrapCASInterposition(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"prov-a", "prov-b", "prov-c"} {
		purpose := ProviderSecretPurpose(id)
		env, err := oldKeyring.SealEnvelope(purpose, []byte("secret-"+id))
		if err != nil {
			t.Fatal(err)
		}
		insertAuthProvSecret(t, db, id, env)
	}

	origA := append([]byte(nil), readSecret(t, db, "prov-a")...)
	origB := append([]byte(nil), readSecret(t, db, "prov-b")...)
	origC := append([]byte(nil), readSecret(t, db, "prov-c")...)

	wrapper := &interposingKeyring{
		inner: keyring,
		interpose: func() {
			newOldEnv, err := oldKeyring.SealEnvelope(
				ProviderSecretPurpose("prov-c"), []byte("interposed-secret"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{
				RequestID: "test-cas-interpose",
				SQL:       "UPDATE auth_providers SET secret=? WHERE id=?",
				Args: []any{newOldEnv, "prov-c"},
			})
			if err != nil {
				t.Fatal(err)
			}
		},
	}

	result, err := RewrapAuthProviderSecretBatch(ctx, db, wrapper, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewrapped != 0 {
		t.Fatalf("expected 0 rewraps (CAS all-or-zero), got %d", result.Rewrapped)
	}
	if result.Cursor != "" {
		t.Fatalf("expected empty cursor on CAS failure, got %q", result.Cursor)
	}
	if result.Done {
		t.Fatal("expected done=false")
	}

	if !bytes.Equal(readSecret(t, db, "prov-a"), origA) {
		t.Fatal("prov-a secret changed despite CAS failure")
	}
	if !bytes.Equal(readSecret(t, db, "prov-b"), origB) {
		t.Fatal("prov-b secret changed despite CAS failure")
	}
	interposedC := readSecret(t, db, "prov-c")
	if bytes.Equal(interposedC, origC) {
		t.Fatal("prov-c was not interposed")
	}
	kidC, err := keyring.PurposeEnvelopeKeyID(ProviderSecretPurpose("prov-c"), interposedC)
	if err != nil {
		t.Fatal(err)
	}
	if kidC != "master-old" {
		t.Fatalf("interposed prov-c should still be under old key, got %s", kidC)
	}

	result2, err := RewrapAuthProviderSecretBatch(ctx, db, wrapper, result.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if result2.Rewrapped != 3 {
		t.Fatalf("expected 3 rewraps on retry, got %d", result2.Rewrapped)
	}
	if !result2.Done {
		t.Fatal("expected done=true on retry")
	}

	for _, id := range []string{"prov-a", "prov-b", "prov-c"} {
		kid, err := keyring.PurposeEnvelopeKeyID(ProviderSecretPurpose(id), readSecret(t, db, id))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if kid != "master-active" {
			t.Fatalf("%s: expected active key, got %s", id, kid)
		}
	}
}

func TestRewrapMismatchOutputKeyFail(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, keyring := testKeyringDir(t, "master-active", "master-old", "master-active")

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}

	purpose := ProviderSecretPurpose("prov-1")
	oldEnv, err := oldKeyring.SealEnvelope(purpose, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-1", oldEnv)

	wrapper := &wrongActiveKey{inner: keyring, wrongID: "master-wrong"}
	_, err = RewrapAuthProviderSecretBatch(ctx, db, wrapper, "")
	if err == nil {
		t.Fatal("expected error for mismatching output key")
	}
}

func TestRewrapFencedOldWriterRollback(t *testing.T) {
	db := testRewrapDB(t)
	ctx := context.Background()
	dir, _ := testKeyringDir(t, "master-wrong", "master-old", "master-active", "master-wrong")

	digest := DigestSHA256("membership")
	now := int64(1000)
	_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "test-barrier-insert",
		SQL:       "INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms,fenced_at_unix_ms) VALUES (1,1,?,?,?,'fenced',?,?)",
		Args:      []any{"master-old", "master-active", digest, now, now + 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	keyring, err := oidc.LoadKeyring(dir, "master-wrong")
	if err != nil {
		t.Fatal(err)
	}

	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}

	purpose := ProviderSecretPurpose("prov-1")
	oldEnv, err := oldKeyring.SealEnvelope(purpose, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertAuthProvSecret(t, db, "prov-1", oldEnv)

	_, err = RewrapAuthProviderSecretBatch(ctx, db, keyring, "")
	if err == nil {
		t.Fatal("expected error for fenced old writer rollback")
	}
}

func TestProviderSecretRewrapRequestIDContentAware(t *testing.T) {
	rows1 := []providerSecretRewrapRow{
		{id: "a", secret: []byte("old1"), newEnvelope: []byte("new1")},
	}
	rows2 := []providerSecretRewrapRow{
		{id: "a", secret: []byte("old2"), newEnvelope: []byte("new1")},
	}
	rows3 := []providerSecretRewrapRow{
		{id: "a", secret: []byte("old1"), newEnvelope: []byte("new2")},
	}

	id1 := providerSecretRewrapRequestID(rows1)
	id2 := providerSecretRewrapRequestID(rows2)
	id3 := providerSecretRewrapRequestID(rows3)

	if id1 == id2 {
		t.Fatal("request IDs should differ when old envelopes differ")
	}
	if id1 == id3 {
		t.Fatal("request IDs should differ when new envelopes differ")
	}
}
