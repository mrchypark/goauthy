package upstreamprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// --- helpers ---

func testRegistryRow(id string, enabled bool, name, typ, issuer, authEP, tokenEP, userinfoEP, clientID string, secret []byte, scope string, adminPath, adminValue, mfaPath, mfaValue, jwks string, usePKCE, csBasic, csPost, autoOnboard, autoLink bool) []any {
	return []any{
		id,
		boolToInt64(enabled),
		name,
		typ,
		issuer,
		authEP,
		tokenEP,
		userinfoEP,
		clientID,
		secret,
		scope,
		nullableString(adminPath),
		nullableString(adminValue),
		nullableString(mfaPath),
		nullableString(mfaValue),
		boolToInt64(usePKCE),
		boolToInt64(csBasic),
		boolToInt64(csPost),
		nullableString(jwks),
		boolToInt64(autoOnboard),
		boolToInt64(autoLink),
	}
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// derefOptionalString simulates what a DB driver returns for nullable TEXT:
// plain string when non-nil, untyped nil when nil.
func derefOptionalString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// fakeEnvelopeKeyring is a minimal EnvelopeKeyring for unit tests.
// It XORs plaintext with a fixed key per purpose, which is enough to verify
// purpose-binding without crypto.
type fakeEnvelopeKeyring struct {
	// openErr is returned by OpenEnvelope when non-nil.
	openErr error
}

func (k *fakeEnvelopeKeyring) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	return append([]byte(purpose+":"), plaintext...), nil
}

func (k *fakeEnvelopeKeyring) OpenEnvelope(purpose string, envelope []byte) ([]byte, error) {
	if k.openErr != nil {
		return nil, k.openErr
	}
	prefix := purpose + ":"
	if !strings.HasPrefix(string(envelope), prefix) {
		return nil, fmt.Errorf("purpose mismatch: envelope prefix %q, want %q", string(envelope[:min(len(envelope), len(prefix))]), prefix)
	}
	return envelope[len(prefix):], nil
}

func (k *fakeEnvelopeKeyring) PurposeEnvelopeKeyID(_ string, _ []byte) (string, error) {
	return "test-key", nil
}

func (k *fakeEnvelopeKeyring) RewrapEnvelope(_ string, envelope []byte) ([]byte, error) {
	return envelope, nil
}

func (k *fakeEnvelopeKeyring) ActiveMasterKeyID() (string, error) {
	return "test-key", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


// testRegistryStore creates a real rhiza DB with auth_providers table
// and a fakeEnvelopeKeyring, matching the pattern used by testRhizaStore.
func testRegistryStore(t *testing.T) (*RegistryStore, *rhiza.DB) {
	t.Helper()
	db := openTestDB(t, "registry-store-test")
	store, err := NewRegistryStore(db, &fakeEnvelopeKeyring{})
	if err != nil {
		t.Fatal(err)
	}
	return store, db
}

func insertAuthProvider(t *testing.T, ctx context.Context, db *rhiza.DB, row []any) {
	t.Helper()
	id, _ := row[0].(string)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "test-insert-provider/" + id,
		SQL:       "INSERT INTO auth_providers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		Args:      row,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRegistryStoreGetNullableFields inserts a row with all nullable fields
// populated and verifies Get returns the correct *string pointers.
func TestRegistryStoreGetNullableFields(t *testing.T) {
	t.Parallel()
	store, db := testRegistryStore(t)
	ctx := context.Background()

	adminPath := "roles/admin"
	adminValue := "true"
	mfaPath := "amr"
	mfaValue := "required"
	jwks := "https://issuer.example/.well-known/jwks"
	ciphertext := []byte{0x01, 0x02, 0x03, 0xff}
	insertAuthProvider(t, ctx, db, []any{
		"prov-nullable", int64(1), "Nullable", "oidc",
		"https://issuer.example", "https://issuer.example/auth",
		"https://issuer.example/token", "https://issuer.example/userinfo",
		"cid", ciphertext, "openid",
		adminPath, adminValue, mfaPath, mfaValue,
		int64(1), int64(1), int64(0), jwks, int64(1), int64(0),
	})

	got, err := store.Get(ctx, "prov-nullable")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AdminClaimPath == nil || *got.AdminClaimPath != adminPath {
		t.Fatalf("AdminClaimPath = %v, want %q", got.AdminClaimPath, adminPath)
	}
	if got.AdminClaimValue == nil || *got.AdminClaimValue != adminValue {
		t.Fatalf("AdminClaimValue = %v, want %q", got.AdminClaimValue, adminValue)
	}
	if got.MFAClaimPath == nil || *got.MFAClaimPath != mfaPath {
		t.Fatalf("MFAClaimPath = %v, want %q", got.MFAClaimPath, mfaPath)
	}
	if got.MFAClaimValue == nil || *got.MFAClaimValue != mfaValue {
		t.Fatalf("MFAClaimValue = %v, want %q", got.MFAClaimValue, mfaValue)
	}
	if got.JWKS == nil || *got.JWKS != jwks {
		t.Fatalf("JWKS = %v, want %q", got.JWKS, jwks)
	}
	if !bytes.Equal(got.Secret, ciphertext) {
		t.Fatalf("Secret = %x, want %x", got.Secret, ciphertext)
	}
}

// TestRegistryStoreGetCiphertextOnly inserts a row with a ciphertext secret
// and no nullable fields, then verifies Get returns the opaque bytes.
func TestRegistryStoreGetCiphertextOnly(t *testing.T) {
	t.Parallel()
	store, db := testRegistryStore(t)
	ctx := context.Background()

	ciphertext := []byte{0xde, 0xad, 0xbe, 0xef}
	insertAuthProvider(t, ctx, db, []any{
		"prov-ct", int64(1), "CT Only", "custom",
		"https://ct.example", "https://ct.example/auth",
		"https://ct.example/token", "https://ct.example/userinfo",
		"cid-ct", ciphertext, "openid",
		nil, nil, nil, nil,
		int64(0), int64(0), int64(0), nil, int64(0), int64(0),
	})

	got, err := store.Get(ctx, "prov-ct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Secret, ciphertext) {
		t.Fatalf("Secret = %x, want %x", got.Secret, ciphertext)
	}
	if got.AdminClaimPath != nil || got.AdminClaimValue != nil || got.MFAClaimPath != nil || got.MFAClaimValue != nil || got.JWKS != nil {
		t.Fatalf("expected nil optionals: admin=%v/%v mfa=%v/%v jwks=%v",
			got.AdminClaimPath, got.AdminClaimValue, got.MFAClaimPath, got.MFAClaimValue, got.JWKS)
	}
}

// TestRegistryStoreListReturnsMultiple verifies List returns all inserted
// providers ordered by name,id.
func TestRegistryStoreListReturnsMultiple(t *testing.T) {
	t.Parallel()
	store, db := testRegistryStore(t)
	ctx := context.Background()

	for _, id := range []string{"prov-b", "prov-a"} {
		insertAuthProvider(t, ctx, db, []any{
			id, int64(1), id, "oidc",
			"https://issuer.example", "https://issuer.example/auth",
"https://issuer.example/token", "https://issuer.example/userinfo",
			"cid-" + id, nil, "openid",
			nil, nil, nil, nil,
			int64(0), int64(0), int64(0), nil, int64(0), int64(0),
		})
	}

	docs, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("List returned %d providers, want 2", len(docs))
	}
	// ORDER BY name,id -> prov-a before prov-b
	if docs[0].ID != "prov-a" || docs[1].ID != "prov-b" {
		t.Fatalf("order = [%s, %s], want [prov-a, prov-b]", docs[0].ID, docs[1].ID)
	}
}

// TestRegistryStoreSecretCleartextPurposeBound verifies that SecretCleartext
// decrypts with the correct provider purpose and rejects cross-provider replay.
func TestRegistryStoreSecretCleartextPurposeBound(t *testing.T) {
	t.Parallel()
	keyring := &fakeEnvelopeKeyring{}
	s := &RegistryStore{db: nil, keyring: keyring}

	purpose := ProviderSecretPurpose("google")
	ciphertext, err := keyring.SealEnvelope(purpose, []byte("google-secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Correct provider: decryption succeeds.
	doc := ProviderDocument{ID: "google", Secret: ciphertext}
	got, err := s.SecretCleartext(doc)
	if err != nil {
		t.Fatalf("correct provider: %v", err)
	}
	if got == nil || *got != "google-secret" {
		t.Fatalf("cleartext = %v, want google-secret", got)
	}

	// Cross-provider replay: same ciphertext, different provider -> fail.
	wrongDoc := ProviderDocument{ID: "github", Secret: ciphertext}
	_, err = s.SecretCleartext(wrongDoc)
	if err == nil {
		t.Fatal("cross-provider replay should fail")
	}
}

// --- decodeProviderDocument tests ---

func TestDecodeProviderDocumentExact21Columns(t *testing.T) {
	t.Parallel()
	row := testRegistryRow(
		"prov-1", true, "Google OIDC", "google",
		"https://accounts.google.com", "https://accounts.google.com/o/oauth2/auth",
		"https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo",
		"client-123", []byte("opaque-ciphertext"), "openid+profile+email",
		"roles/admin", "true", "amr", "mfa",
		"https://www.googleapis.com/oauth2/v3/certs", true, true, false, true, false,
	)
	doc, err := decodeProviderDocument(row)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if doc.ID != "prov-1" || !doc.Enabled || doc.Name != "Google OIDC" || doc.Typ != AuthProviderTypeGoogle {
		t.Fatalf("field mismatch: id=%q enabled=%v name=%q typ=%q", doc.ID, doc.Enabled, doc.Name, doc.Typ)
	}
	if doc.ClientID != "client-123" || string(doc.Secret) != "opaque-ciphertext" || doc.Scope != "openid+profile+email" {
		t.Fatalf("credential mismatch: clientID=%q secret=%q scope=%q", doc.ClientID, doc.Secret, doc.Scope)
	}
	if doc.AdminClaimPath == nil || *doc.AdminClaimPath != "roles/admin" || doc.AdminClaimValue == nil || *doc.AdminClaimValue != "true" {
		t.Fatalf("admin claim mismatch: path=%v value=%v", doc.AdminClaimPath, doc.AdminClaimValue)
	}
	if doc.MFAClaimPath == nil || *doc.MFAClaimPath != "amr" || doc.MFAClaimValue == nil || *doc.MFAClaimValue != "mfa" {
		t.Fatalf("mfa claim mismatch: path=%v value=%v", doc.MFAClaimPath, doc.MFAClaimValue)
	}
	if !doc.UsePKCE || !doc.ClientSecretBasic || doc.ClientSecretPost {
		t.Fatalf("protocol flags: pkce=%v basic=%v post=%v", doc.UsePKCE, doc.ClientSecretBasic, doc.ClientSecretPost)
	}
	if doc.JWKS == nil || *doc.JWKS != "https://www.googleapis.com/oauth2/v3/certs" {
		t.Fatalf("jwks = %v", doc.JWKS)
	}
	if !doc.AutoOnboarding || doc.AutoLink {
		t.Fatalf("onboarding flags: auto=%v link=%v", doc.AutoOnboarding, doc.AutoLink)
	}
}

func TestDecodeProviderDocumentWrongColumnCount(t *testing.T) {
	t.Parallel()
	row := make([]any, 20)
	_, err := decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("20 columns: err=%v, want ErrInvalidProviderRow", err)
	}
	row = make([]any, 22)
	_, err = decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("22 columns: err=%v, want ErrInvalidProviderRow", err)
	}
}

func TestDecodeProviderDocumentEmptyID(t *testing.T) {
	t.Parallel()
	row := testRegistryRow("", true, "p", "oidc", "i", "a", "t", "u", "c", nil, "s", "", "", "", "", "", true, false, false, false, false)
	row[0] = ""
	_, err := decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("empty id: err=%v", err)
	}
	row[0] = 12345
	_, err = decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("non-string id: err=%v", err)
	}
}

func TestDecodeProviderDocumentInvalidType(t *testing.T) {
	t.Parallel()
	row := testRegistryRow("p", true, "name", "oidc", "i", "a", "t", "u", "c", nil, "s", "", "", "", "", "", true, false, false, false, false)
	row[3] = "bogus"
	_, err := decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("invalid type: err=%v", err)
	}
}

func TestDecodeProviderDocumentNilOptionals(t *testing.T) {
	t.Parallel()
	// All optional fields (admin*, mfa*, jwks) are nil/empty.
	row := testRegistryRow(
		"prov-nil", false, "Minimal", "custom",
		"https://example.com", "https://example.com/auth", "https://example.com/token", "https://example.com/userinfo",
		"cid", nil, "openid", "", "", "", "", "", false, false, false, false, false,
	)
	doc, err := decodeProviderDocument(row)
	if err != nil {
		t.Fatalf("decode nil optionals: %v", err)
	}
	if doc.AdminClaimPath != nil || doc.AdminClaimValue != nil || doc.MFAClaimPath != nil || doc.MFAClaimValue != nil || doc.JWKS != nil {
		t.Fatalf("nil optionals should be nil: adminPath=%v adminValue=%v mfaPath=%v mfaValue=%v jwks=%v",
			doc.AdminClaimPath, doc.AdminClaimValue, doc.MFAClaimPath, doc.MFAClaimValue, doc.JWKS)
	}
	if doc.Secret != nil {
		t.Fatalf("nil secret should remain nil, got %v", doc.Secret)
	}
}

func TestDecodeProviderDocumentCiphertextOnly(t *testing.T) {
	t.Parallel()
	ciphertext := []byte{0x01, 0x02, 0x03, 0xff}
	row := testRegistryRow(
		"prov-ct", true, "Ciphertext Only", "oidc",
		"https://issuer.example.test", "https://issuer.example.test/auth", "https://issuer.example.test/token", "https://issuer.example.test/userinfo",
		"cid", ciphertext, "openid", "", "", "", "", "", true, false, false, false, false,
	)
	doc, err := decodeProviderDocument(row)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The secret must be a copy, not a reference to the original slice.
	if string(doc.Secret) != string(ciphertext) {
		t.Fatalf("secret = %x, want %x", doc.Secret, ciphertext)
	}
	doc.Secret[0] = 0xfe
	if ciphertext[0] == 0xfe {
		t.Fatal("decodeProviderDocument did not copy secret bytes")
	}
}

func TestProviderBoolRejectsNonInt64(t *testing.T) {
	t.Parallel()
	if _, ok := providerBool("not-an-int"); ok {
		t.Fatal("string should not be accepted as bool")
	}
	if _, ok := providerBool(2); ok {
		t.Fatal("int64(2) should not be accepted as bool")
	}
}

func TestProviderNullableStringRejectsNonString(t *testing.T) {
	t.Parallel()
	if _, ok := providerNullableString(123); ok {
		t.Fatal("non-string should not be accepted")
	}
}

func TestProviderNullableBytesRejectsNonBytes(t *testing.T) {
	t.Parallel()
	if _, ok := providerNullableBytes("string"); ok {
		t.Fatal("string should not be accepted as bytes")
	}
}

// --- ProviderSecretPurpose tests ---

func TestProviderSecretPurposeBinding(t *testing.T) {
	t.Parallel()
	p1 := ProviderSecretPurpose("google")
	p2 := ProviderSecretPurpose("github")
	if p1 == p2 {
		t.Fatal("different providers produced same purpose")
	}
	if !strings.HasPrefix(p1, "upstream-provider-secret/v1/") {
		t.Fatalf("purpose = %q, want upstream-provider-secret/v1/ prefix", p1)
	}
	if !strings.HasSuffix(p1, "google") || !strings.HasSuffix(p2, "github") {
		t.Fatalf("purpose suffixes = %q, %q", p1, p2)
	}
}

func TestValidProviderSecretPurpose(t *testing.T) {
	t.Parallel()
	cases := []struct {
		purpose string
		valid   bool
	}{
		{"", false},
		{strings.Repeat("a", 65), false},
		{"upstream-provider-secret/v1/google", true},
		{"UPPER-case_99", true},
		{"has space", false},
		{"has:colon", false},
		{"has;semicolon", false},
	}
	for _, tc := range cases {
		if got := validProviderSecretPurpose(tc.purpose); got != tc.valid {
			t.Errorf("validProviderSecretPurpose(%q) = %v, want %v", tc.purpose, got, tc.valid)
		}
	}
}

// --- SecretCleartext tests ---

func TestSecretCleartextNilSecret(t *testing.T) {
	t.Parallel()
	s := &RegistryStore{db: nil, keyring: &fakeEnvelopeKeyring{}}
	doc := ProviderDocument{ID: "prov-nil", Secret: nil}
	got, err := s.SecretCleartext(doc)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if got != nil {
		t.Fatalf("nil secret should return nil cleartext, got %q", *got)
	}
}

func TestSecretCleartextPurposeBinding(t *testing.T) {
	t.Parallel()
	keyring := &fakeEnvelopeKeyring{}
	s := &RegistryStore{db: nil, keyring: keyring}

	// Seal a secret for provider "google".
	purpose := ProviderSecretPurpose("google")
	ciphertext, err := keyring.SealEnvelope(purpose, []byte("google-secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with the correct provider document should succeed.
	doc := ProviderDocument{ID: "google", Secret: ciphertext}
	cleartext, err := s.SecretCleartext(doc)
	if err != nil {
		t.Fatalf("correct provider: %v", err)
	}
	if cleartext == nil || *cleartext != "google-secret" {
		t.Fatalf("cleartext = %v, want google-secret", cleartext)
	}

	// Decrypt with a different provider should fail (purpose mismatch).
	wrongDoc := ProviderDocument{ID: "github", Secret: ciphertext}
	_, err = s.SecretCleartext(wrongDoc)
	if err == nil {
		t.Fatal("cross-provider replay should fail")
	}
}

func TestSecretCleartextNilStoreOrKeyring(t *testing.T) {
	t.Parallel()
	doc := ProviderDocument{ID: "p", Secret: []byte("x")}
	// nil store
	var nilStore *RegistryStore
	_, err := nilStore.SecretCleartext(doc)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store: err=%v", err)
	}
	// nil keyring
	s := &RegistryStore{db: nil, keyring: nil}
	_, err = s.SecretCleartext(doc)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil keyring: err=%v", err)
	}
}

func TestSecretCleartextOpenError(t *testing.T) {
	t.Parallel()
	keyring := &fakeEnvelopeKeyring{openErr: errors.New("key missing")}
	s := &RegistryStore{db: nil, keyring: keyring}
	doc := ProviderDocument{ID: "p", Secret: []byte("x")}
	_, err := s.SecretCleartext(doc)
	if err == nil || err.Error() != "key missing" {
		t.Fatalf("open error propagation: %v", err)
	}
}

// --- RegistryStore constructor tests ---

func TestNewRegistryStoreRejectsNilDB(t *testing.T) {
	t.Parallel()
	_, err := NewRegistryStore(nil, &fakeEnvelopeKeyring{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil db: err=%v", err)
	}
}

func TestNewRegistryStoreRejectsNilKeyring(t *testing.T) {
	t.Parallel()
	_, err := NewRegistryStore(&rhiza.DB{}, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil keyring: err=%v", err)
	}
}

// --- Get / List nil-guard tests (no live DB needed) ---

func TestRegistryStoreGetRejectsNilAndEmptyID(t *testing.T) {
	t.Parallel()
	s := &RegistryStore{db: nil, keyring: &fakeEnvelopeKeyring{}}
	_, err := s.Get(context.Background(), "")
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty id: err=%v", err)
	}
	var nilStore *RegistryStore
	_, err = nilStore.Get(context.Background(), "x")
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store: err=%v", err)
	}
}

func TestRegistryStoreListRejectsNilDB(t *testing.T) {
	t.Parallel()
	s := &RegistryStore{db: nil, keyring: &fakeEnvelopeKeyring{}}
	_, err := s.List(context.Background())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil db: err=%v", err)
	}
	var nilStore *RegistryStore
	_, err = nilStore.List(context.Background())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store: err=%v", err)
	}
}

// --- decodeProviderDocument with all bools set ---

func TestDecodeProviderDocumentAllBoolsFalse(t *testing.T) {
	t.Parallel()
	row := testRegistryRow(
		"prov-false", false, "Disabled", "custom",
		"https://example.com", "https://example.com/auth", "https://example.com/token", "https://example.com/userinfo",
		"cid", nil, "", "", "", "", "", "", false, false, false, false, false,
	)
	doc, err := decodeProviderDocument(row)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Enabled || doc.UsePKCE || doc.ClientSecretBasic || doc.ClientSecretPost || doc.AutoOnboarding || doc.AutoLink {
		t.Fatalf("expected all bools false: enabled=%v pkce=%v basic=%v post=%v onboard=%v link=%v",
			doc.Enabled, doc.UsePKCE, doc.ClientSecretBasic, doc.ClientSecretPost, doc.AutoOnboarding, doc.AutoLink)
	}
}

// --- decodeProviderDocument with invalid bool values ---

func TestDecodeProviderDocumentRejectsInvalidBool(t *testing.T) {
	t.Parallel()
	row := testRegistryRow(
		"p", true, "n", "oidc", "i", "a", "t", "u", "c", nil, "s", "", "", "", "", "", true, false, false, false, false,
	)
	// enabled = 2 is not a valid bool
	row[1] = int64(2)
	_, err := decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("invalid bool: err=%v", err)
	}
}

// --- decodeProviderDocument with non-string in string fields ---

func TestDecodeProviderDocumentRejectsNonStringInStringField(t *testing.T) {
	t.Parallel()
	row := testRegistryRow(
		"p", true, "n", "oidc", "i", "a", "t", "u", "c", nil, "s", "", "", "", "", "", true, false, false, false, false,
	)
	// name = int, not string
	row[2] = 12345
	_, err := decodeProviderDocument(row)
	if !errors.Is(err, ErrInvalidProviderRow) {
		t.Fatalf("non-string name: err=%v", err)
	}
}

// --- Round-trip: ToDocument + decode ---

func TestProviderDocumentToDocumentAndDecode(t *testing.T) {
	t.Parallel()
	req := validProviderRequest()
	secret := []byte("encrypted-blob")
	doc, err := req.ToDocument("rt-1", secret)
	if err != nil {
		t.Fatalf("ToDocument: %v", err)
	}
	// Build the row from the document fields.
	row := []any{
		doc.ID,
		boolToInt64(doc.Enabled),
		doc.Name,
		string(doc.Typ),
		doc.Issuer,
		doc.AuthorizationEndpoint,
		doc.TokenEndpoint,
		doc.UserinfoEndpoint,
		doc.ClientID,
		doc.Secret,
		doc.Scope,
		derefOptionalString(doc.AdminClaimPath),
		derefOptionalString(doc.AdminClaimValue),
		derefOptionalString(doc.MFAClaimPath),
		derefOptionalString(doc.MFAClaimValue),
		boolToInt64(doc.UsePKCE),
		boolToInt64(doc.ClientSecretBasic),
		boolToInt64(doc.ClientSecretPost),
		derefOptionalString(doc.JWKS),
		boolToInt64(doc.AutoOnboarding),
		boolToInt64(doc.AutoLink),
	}
	decoded, err := decodeProviderDocument(row)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ID != doc.ID || decoded.Name != doc.Name || decoded.Typ != doc.Typ || decoded.Scope != doc.Scope {
		t.Fatalf("round-trip mismatch: id=%q name=%q typ=%q scope=%q", decoded.ID, decoded.Name, decoded.Typ, decoded.Scope)
	}
	if string(decoded.Secret) != string(doc.Secret) {
		t.Fatalf("secret round-trip: %x != %x", decoded.Secret, doc.Secret)
	}
}
