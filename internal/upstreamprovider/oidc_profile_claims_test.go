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

// signedTokenWithClaims creates a signed JWT with the given claims merged
// into the standard iss/sub/aud/exp/iat/nbf set. Uses test verifier defaults.
func signedTokenWithClaims(t *testing.T, key *rsa.PrivateKey, kid string, extra map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	now := jwksTestNow()
	claims := map[string]any{
		"iss": "issuer",
		"aud": "client",
		"sub": "subject",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProfileClaimsPreservedFromSignedJWT(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())

	raw := signedTokenWithClaims(t, key, "k", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"given_name":     "Alice",
		"family_name":    "Smith",
	})
	claims, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Email == nil || *claims.Email != "alice@example.com" {
		t.Fatalf("email = %v, want alice@example.com", claims.Email)
	}
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		t.Fatalf("email_verified = %v, want true", claims.EmailVerified)
	}
	if claims.GivenName == nil || *claims.GivenName != "Alice" {
		t.Fatalf("given_name = %v, want Alice", claims.GivenName)
	}
	if claims.FamilyName == nil || *claims.FamilyName != "Smith" {
		t.Fatalf("family_name = %v, want Smith", claims.FamilyName)
	}
}

func TestProfileClaimsAbsentWhenOmitted(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())

	raw := signedTokenWithClaims(t, key, "k", nil)
	claims, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Email != nil {
		t.Fatalf("email should be nil when absent, got %v", *claims.Email)
	}
	if claims.EmailVerified != nil {
		t.Fatalf("email_verified should be nil when absent, got %v", *claims.EmailVerified)
	}
	if claims.GivenName != nil {
		t.Fatalf("given_name should be nil when absent, got %v", *claims.GivenName)
	}
	if claims.FamilyName != nil {
		t.Fatalf("family_name should be nil when absent, got %v", *claims.FamilyName)
	}
}

func TestEmailVerifiedFalseDistinctFromAbsent(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())

	// false explicitly present
	rawFalse := signedTokenWithClaims(t, key, "k", map[string]any{"email_verified": false})
	claimsFalse, err := v.VerifyIDToken(context.Background(), rawFalse, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken (false): %v", err)
	}
	if claimsFalse.EmailVerified == nil {
		t.Fatal("email_verified false should produce non-nil *bool")
	}
	if *claimsFalse.EmailVerified {
		t.Fatal("email_verified should be false, not true")
	}

	// absent
	rawAbsent := signedTokenWithClaims(t, key, "k", nil)
	claimsAbsent, err := v.VerifyIDToken(context.Background(), rawAbsent, "issuer", "client")
	if err != nil {
		t.Fatalf("VerifyIDToken (absent): %v", err)
	}
	if claimsAbsent.EmailVerified != nil {
		t.Fatal("absent email_verified should produce nil *bool")
	}
}

func TestProfileClaimsRejectMalformedEmailVerified(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())

	raw := signedTokenWithClaims(t, key, "k", map[string]any{"email_verified": "not-a-bool"})
	_, err = v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if err == nil {
		t.Fatal("expected error for malformed email_verified")
	}
}

func TestProfileClaimsRejectInvalidSignature(t *testing.T) {
	t.Parallel()
	correctKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &correctKey.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())

	// Sign with wrong key but server only serves correctKey's public key
	raw := signedTokenWithClaims(t, wrongKey, "k", map[string]any{"email": "attacker@example.com"})
	_, err = v.VerifyIDToken(context.Background(), raw, "issuer", "client")
	if !errors.Is(err, ErrIDTokenVerification) {
		t.Fatalf("invalid signature should return ErrIDTokenVerification, got %v", err)
	}
}
