package oauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
)

func TestIntrospectionVerifiesJWTOncePerRequest(t *testing.T) {
	key := oidcTestKey(t)
	server := oidcTestServer(t, oauthTestDB(t), randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	verifier := strings.Repeat("v", 43)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, verifier)},
		"redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	strategy := server.accessTokens.(*signedAccessTokenStrategy)
	original := strategy.verifyToken
	verifications := 0
	strategy.verifyToken = func(token string, keys jose.JSONWebKeySet, issuer string, now time.Time) (oidc.AccessTokenClaims, error) {
		verifications++
		return original(token, keys, issuer, now)
	}
	for want := 1; want <= 2; want++ {
		response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
		if response.Code != 200 || !strings.Contains(response.Body.String(), `"active":true`) || verifications != want {
			t.Fatalf("request %d status=%d verifies=%d body=%s", want, response.Code, verifications, response.Body.String())
		}
	}
	strategy.verifyToken = original
	var requests sync.WaitGroup
	for i := 0; i < 8; i++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
			if response.Code != 200 || !strings.Contains(response.Body.String(), `"active":true`) {
				t.Errorf("concurrent introspection status=%d body=%s", response.Code, response.Body.String())
			}
		}()
	}
	requests.Wait()
	revoked := postOAuthForm(server.RevocationHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	if revoked.Code != 200 {
		t.Fatalf("signed token revocation status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret))
}

func TestCachedJWTValidationUsesCurrentStoredClientAndAudience(t *testing.T) {
	key := oidcTestKey(t)
	server := oidcTestServer(t, oauthTestDB(t), randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	verifier := strings.Repeat("c", 43)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, verifier)},
		"redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	strategy := server.accessTokens.(*signedAccessTokenStrategy)
	verifications := 0
	original := strategy.verifyToken
	strategy.verifyToken = func(token string, keys jose.JSONWebKeySet, issuer string, now time.Time) (oidc.AccessTokenClaims, error) {
		verifications++
		return original(token, keys, issuer, now)
	}
	ctx := withAccessTokenVerificationCache(t.Context())
	signature := strategy.AccessTokenSignature(ctx, issued.AccessToken)
	if signature == "" {
		t.Fatal("valid token did not resolve signature")
	}
	stored, err := server.store.GetAccessTokenSession(ctx, signature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	storedRequest, ok := stored.(*fosite.Request)
	if !ok {
		t.Fatalf("stored requester type=%T", stored)
	}
	originalClient := stored.GetClient()
	storedRequest.Client = &clients.Client{ID: "changed-client"}
	if err := strategy.ValidateAccessToken(ctx, stored, issued.AccessToken); !errors.Is(err, fosite.ErrRequestUnauthorized) {
		t.Fatalf("accepted cached claims for changed stored client: %v", err)
	}
	storedRequest.Client = originalClient
	stored.GrantAudience("https://changed.example.test/resource")
	if err := strategy.ValidateAccessToken(ctx, stored, issued.AccessToken); !errors.Is(err, fosite.ErrRequestUnauthorized) || verifications != 1 {
		t.Fatalf("accepted cached claims for changed stored audience: verifies=%d err=%v", verifications, err)
	}
}

func TestAccessTokenVerificationCacheRechecksClockAndSigningKeys(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "cache-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	claims := oidc.AccessTokenClaims{Issuer: "https://issuer.example.test", Subject: "subject", Audience: []string{"client"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Second), ID: "jti", AuthorizedParty: "client", Type: "Bearer"}
	token, err := oidc.SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	activeKey := key.PublicJWK
	verifyCalls := 0
	strategy := &signedAccessTokenStrategy{
		issuer:   claims.Issuer,
		loadKeys: func(context.Context) ([]jose.JSONWebKey, error) { return []jose.JSONWebKey{activeKey}, nil },
		verifyToken: func(token string, keys jose.JSONWebKeySet, issuer string, at time.Time) (oidc.AccessTokenClaims, error) {
			verifyCalls++
			return oidc.VerifyAccessToken(token, keys, issuer, at)
		},
		now: func() time.Time { return now },
	}
	ctx := withAccessTokenVerificationCache(context.Background())
	if _, err := strategy.verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	now = claims.ExpiresAt
	if _, err := strategy.verify(ctx, token); err == nil || verifyCalls != 2 {
		t.Fatalf("expired token reused cached verification: err=%v verifies=%d", err, verifyCalls)
	}

	now = claims.IssuedAt
	ctx = withAccessTokenVerificationCache(context.Background())
	if _, err := strategy.verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	originalByte := public[0]
	public[0] ^= 0xff
	if _, err := strategy.verify(ctx, token); err == nil || verifyCalls != 4 {
		t.Fatalf("mutated signing key reused cached verification: err=%v verifies=%d", err, verifyCalls)
	}

	public[0] = originalByte
	ctx = withAccessTokenVerificationCache(context.Background())
	if _, err := strategy.verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	strategy.issuer = "https://changed-issuer.example.test"
	if _, err := strategy.verify(ctx, token); err == nil || verifyCalls != 6 {
		t.Fatalf("changed issuer reused cached verification: err=%v verifies=%d", err, verifyCalls)
	}
}

func TestAccessTokenVerificationCacheRequiresExactTokenAndStrategy(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "identity-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	claims := oidc.AccessTokenClaims{Issuer: "https://issuer.example.test", Subject: "subject", Audience: []string{"client"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: "first", AuthorizedParty: "client", Type: "Bearer"}
	first, err := oidc.SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	claims.ID = "second"
	second, err := oidc.SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyCalls := 0
	newStrategy := func() *signedAccessTokenStrategy {
		return &signedAccessTokenStrategy{
			issuer:   claims.Issuer,
			loadKeys: func(context.Context) ([]jose.JSONWebKey, error) { return []jose.JSONWebKey{key.PublicJWK}, nil },
			verifyToken: func(token string, keys jose.JSONWebKeySet, issuer string, at time.Time) (oidc.AccessTokenClaims, error) {
				verifyCalls++
				return oidc.VerifyAccessToken(token, keys, issuer, at)
			},
			now: func() time.Time { return now },
		}
	}
	strategy, otherStrategy := newStrategy(), newStrategy()
	ctx := withAccessTokenVerificationCache(context.Background())
	if got, err := strategy.verify(ctx, first); err != nil || got.ID != "first" {
		t.Fatalf("first token verify claims=%#v err=%v", got, err)
	}
	if got, err := otherStrategy.verify(ctx, first); err != nil || got.ID != "first" || verifyCalls != 2 {
		t.Fatalf("strategy identity reused cached verification: claims=%#v verifies=%d err=%v", got, verifyCalls, err)
	}
	if got, err := strategy.verify(ctx, second); err != nil || got.ID != "second" || verifyCalls != 3 {
		t.Fatalf("different token reused cached verification: claims=%#v verifies=%d err=%v", got, verifyCalls, err)
	}
	parts := strings.Split(first, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	if _, err := strategy.verify(ctx, strings.Join(parts, ".")); err == nil || verifyCalls != 4 {
		t.Fatalf("tampered token reused cached verification: verifies=%d err=%v", verifyCalls, err)
	}
}
