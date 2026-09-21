package upstreamprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifiedClaimPayloadRetained(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()

	now := jwksTestNow()
	claims := map[string]any{
		"iss":   "issuer",
		"sub":   "subject123",
		"aud":   "client",
		"nonce": "nonce1",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"custom": map[string]any{
			"nested": map[string]any{
				"mfa_level": "strong",
				"roles":     []string{"admin", "user"},
			},
		},
		"email":          "user@example.test",
		"email_verified": true,
		"given_name":     "Ada",
		"family_name":    "Lovelace",
	}

	raw := signTokenFullClaims(t, key, "k1", claims)
	v := newTestJWKSVerifier(server.URL, server.Client())

	result, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if result == nil {
		t.Fatal("nil claims")
	}

	if result.Email == nil || *result.Email != "user@example.test" {
		t.Fatalf("email = %v, want user@example.test", result.Email)
	}
	if result.EmailVerified == nil || !*result.EmailVerified {
		t.Fatalf("email_verified = %v, want true", result.EmailVerified)
	}
	if result.GivenName == nil || *result.GivenName != "Ada" {
		t.Fatalf("given_name = %v, want Ada", result.GivenName)
	}
	if result.FamilyName == nil || *result.FamilyName != "Lovelace" {
		t.Fatalf("family_name = %v, want Lovelace", result.FamilyName)
	}

	rawClaims := result.RawClaims()
	if rawClaims == nil {
		t.Fatal("RawClaims() returned nil")
	}
	var parsed map[string]any
	if err := json.Unmarshal(rawClaims, &parsed); err != nil {
		t.Fatalf("RawClaims unmarshal: %v", err)
	}
	custom, ok := parsed["custom"].(map[string]any)
	if !ok {
		t.Fatalf("custom claim missing from RawClaims, keys: %v", keysOf(parsed))
	}
	nested, ok := custom["nested"].(map[string]any)
	if !ok {
		t.Fatal("custom.nested missing from RawClaims")
	}
	if nested["mfa_level"] != "strong" {
		t.Fatalf("custom.nested.mfa_level = %v, want strong", nested["mfa_level"])
	}
	roles, ok := nested["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "admin" || roles[1] != "user" {
		t.Fatalf("custom.nested.roles = %v, want [admin user]", nested["roles"])
	}
}

func TestVerifiedClaimPayloadInvalidSignatureReturnsNil(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw := signedToken(t, wrongKey, "k1", "issuer", "client")
	v := newTestJWKSVerifier(server.URL, server.Client())

	result, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if result != nil {
		t.Fatalf("expected nil claims for invalid signature, got %+v", result)
	}
	if !errors.Is(err, ErrIDTokenVerification) {
		t.Fatalf("expected ErrIDTokenVerification, got %v", err)
	}
}

// TestDecodeIDTokenClaimsCopiesInputBytes verifies that decodeIDTokenClaims
// copies the payload bytes into rawClaims rather than aliasing the caller
// slice. Mutating rawClaims must not affect the original payload.
func TestDecodeIDTokenClaimsCopiesInputBytes(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"iss":"https://issuer.example.test","sub":"sub1","aud":"aud1","exp":9999999999,"iat":9999999998}`)
	claims, err := decodeIDTokenClaims(payload)
	if err != nil {
		t.Fatalf("decodeIDTokenClaims: %v", err)
	}
	// Mutate the rawClaims slice held by the returned struct.
	for i := range claims.rawClaims {
		claims.rawClaims[i] = "X"[0]
	}
	// Original payload must be untouched.
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("payload unmarshal after mutation: %v", err)
	}
	if parsed["iss"] != "https://issuer.example.test" {
		t.Fatalf("payload iss corrupted: %v", parsed["iss"])
	}
	if parsed["sub"] != "sub1" {
		t.Fatalf("payload sub corrupted: %v", parsed["sub"])
	}
}

// TestRawClaimsAccessorReturnsIndependentCopy proves that successive RawClaims
// calls each return an independent copy.
func TestRawClaimsAccessorReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()

	now := jwksTestNow()
	claims := map[string]any{
		"iss":   "issuer",
		"sub":   "subject456",
		"aud":   "client",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"custom": map[string]any{"deep": "original"},
	}
	raw := signTokenFullClaims(t, key, "k1", claims)
	v := newTestJWKSVerifier(server.URL, server.Client())

	result, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}

	rc := result.RawClaims()
	for i := range rc {
		rc[i] = "X"[0]
	}

	rc2 := result.RawClaims()
	var parsed map[string]any
	if err := json.Unmarshal(rc2, &parsed); err != nil {
		t.Fatalf("second RawClaims unmarshal: %v", err)
	}
	custom, ok := parsed["custom"].(map[string]any)
	if !ok {
		t.Fatal("custom claim lost after mutation of first RawClaims copy")
	}
	if custom["deep"] != "original" {
		t.Fatalf("custom.deep = %v, want original", custom["deep"])
	}
}

func signTokenFullClaims(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
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
	return raw
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
