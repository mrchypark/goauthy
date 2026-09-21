package oidc

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestActorClaimsValidationAndSignedRoundTrip(t *testing.T) {
	t.Parallel()
	value := map[string]any{"sub": "immediate", "act": map[string]any{"sub": "ancestor"}}
	actor, err := ParseActorClaims(value)
	if err != nil {
		t.Fatal(err)
	}
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := AccessTokenClaims{Actor: actor, Issuer: "https://id.example.com", Subject: "owner", Audience: []string{"client"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: "jti", AuthorizedParty: "client", Type: "Bearer"}
	token, err := SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAccessToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, now)
	if err != nil || !reflect.DeepEqual(got.Actor, actor) {
		t.Fatalf("signed actor mismatch: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key.Private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []any{nil, "actor", map[string]any{}, map[string]any{"sub": ""}, map[string]any{"sub": 1}, map[string]any{"sub": "actor", "extra": true}, map[string]any{"sub": "actor", "act": nil}, map[string]any{"sub": "actor", "act": map[string]any{"sub": "ancestor", "roles": []string{"admin"}}}} {
		if _, err := ParseActorClaims(invalid); err == nil {
			t.Fatal("accepted invalid actor")
		}
		payload["act"] = invalid
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		malformed, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAccessToken(malformed, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, now); err == nil {
			t.Fatal("accepted signed invalid actor")
		}
	}
	var chain any = map[string]any{"sub": "leaf"}
	for i := 1; i < maxCustomJSONDepth; i++ {
		chain = map[string]any{"sub": "actor", "act": chain}
	}
	bounded, err := ParseActorClaims(chain)
	if err != nil {
		t.Fatal(err)
	}
	claims.Actor = bounded
	token, err = SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyAccessToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseActorClaims(map[string]any{"sub": "too-deep", "act": chain}); err == nil {
		t.Fatal("accepted deep actor")
	}
	claims.Actor = actor
	actor.Actor = actor
	if _, err := SignAccessToken(key, claims); err == nil {
		t.Fatal("accepted cyclic actor")
	}
}
