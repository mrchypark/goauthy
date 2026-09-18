package oidc

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestLogoutTokenSignsAndVerifies(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	want := testLogoutTokenClaims(now, time.Minute)
	compact, err := SignLogoutToken(key, want)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(parsed.Headers) != 1 || parsed.Headers[0].Algorithm != string(jose.EdDSA) || parsed.Headers[0].KeyID != key.PublicJWK.KeyID || parsed.Headers[0].ExtraHeaders[jose.HeaderKey("typ")] != "logout+jwt" {
		t.Fatalf("unexpected header: %#v, %v", parsed.Headers, err)
	}
	var raw map[string]any
	if err := parsed.Claims(key.PublicJWK.Key, &raw); err != nil {
		t.Fatal(err)
	}
	if _, found := raw["nonce"]; found || !validLogoutEvents(raw["events"]) {
		t.Fatalf("unexpected payload: %#v", raw)
	}
	got, err := VerifyLogoutToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, want.Issuer, want.Audience, now)
	if err != nil || got.Issuer != want.Issuer || got.Subject != want.Subject || got.Audience != want.Audience || got.JTI != want.JTI || got.SessionID != want.SessionID || !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("VerifyLogoutToken() = %#v, %v; want %#v", got, err, want)
	}
}

func TestLogoutTokenRoundTripsSubjectAndSessionShapes(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	sid := testLogoutTokenClaims(now, time.Minute).SessionID
	for _, want := range []LogoutTokenClaims{
		{Issuer: "https://id.example.test", Subject: "user-1", Audience: "client-1", JTI: "logout-sub", IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
		{Issuer: "https://id.example.test", SessionID: sid, Audience: "client-1", JTI: "logout-sid", IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
		{Issuer: "https://id.example.test", Subject: "user-1", SessionID: sid, Audience: "client-1", JTI: "logout-both", IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
	} {
		compact, err := SignLogoutToken(key, want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyLogoutToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, want.Issuer, want.Audience, now)
		if err != nil || got.Subject != want.Subject || got.SessionID != want.SessionID {
			t.Fatalf("shape %#v: got %#v, %v", want, got, err)
		}
	}
}

func TestLogoutTokenRejectsInvalidClaimsSignatureAndTime(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := testLogoutTokenClaims(now, time.Minute)
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}
	compact, err := SignLogoutToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name, issuer, audience string
		at                     time.Time
		keyset                 jose.JSONWebKeySet
	}{
		{"wrong issuer", "https://other.example.test", claims.Audience, now, keys},
		{"wrong audience", claims.Issuer, "other-client", now, keys},
		{"wrong key", claims.Issuer, claims.Audience, now, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{testTokenSigningKey(t).PublicJWK}}},
		{"expiry boundary", claims.Issuer, claims.Audience, claims.ExpiresAt, keys},
		{"issued in future", claims.Issuer, claims.Audience, now.Add(-time.Second), keys},
	} {
		t.Run(check.name, func(t *testing.T) {
			if _, err := VerifyLogoutToken(compact, check.keyset, check.issuer, check.audience, check.at); err == nil {
				t.Fatal("invalid logout token accepted")
			}
		})
	}
	for _, lifetime := range []time.Duration{0, LogoutTokenMinLifetime - time.Nanosecond, LogoutTokenMaxLifetime + time.Nanosecond} {
		invalid := claims
		invalid.ExpiresAt = invalid.IssuedAt.Add(lifetime)
		if _, err := SignLogoutToken(key, invalid); err == nil {
			t.Fatalf("lifetime %s was accepted", lifetime)
		}
	}
	for _, lifetime := range []time.Duration{LogoutTokenMinLifetime, LogoutTokenMaxLifetime} {
		valid := claims
		valid.ExpiresAt = valid.IssuedAt.Add(lifetime)
		if _, err := SignLogoutToken(key, valid); err != nil {
			t.Fatalf("lifetime %s was rejected: %v", lifetime, err)
		}
	}
	for _, lifetime := range []time.Duration{0, LogoutTokenMaxLifetime + time.Second} {
		forged := claims
		forged.ExpiresAt = forged.IssuedAt.Add(lifetime)
		compact := mustSignedLogoutToken(t, key, logoutTokenMap(forged, map[string]any{backchannelLogoutEvent: map[string]any{}}, ""), jose.EdDSA)
		if _, err := VerifyLogoutToken(compact, keys, claims.Issuer, claims.Audience, now); err == nil {
			t.Fatalf("forged lifetime %s was accepted", lifetime)
		}
	}
}

func TestLogoutTokenRejectsNonceAndMalformedEvents(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := testLogoutTokenClaims(now, time.Minute)
	compat := logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, "")
	compat["typ"] = "logout+jwt"
	if _, err := VerifyLogoutToken(mustSignedLogoutToken(t, key, compat, jose.EdDSA), jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, claims.Audience, now); err != nil {
		t.Fatalf("Rauthy compatibility typ was rejected: %v", err)
	}
	for _, payload := range []map[string]any{
		logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, "nonce-1"),
		logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{"x": "y"}}, ""),
		logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}, "other": map[string]any{}}, ""),
		func() map[string]any {
			p := logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, "")
			p["typ"] = "other"
			return p
		}(),
		func() map[string]any {
			p := logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, "")
			p["sub"] = nil
			return p
		}(),
		func() map[string]any {
			p := logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, "")
			p["sid"] = 7
			return p
		}(),
	} {
		compact := mustSignedLogoutToken(t, key, payload, jose.EdDSA)
		if _, err := VerifyLogoutToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, claims.Audience, now); err == nil {
			t.Fatalf("invalid payload accepted: %#v", payload)
		}
	}
	if compact := mustSignedLogoutToken(t, key, logoutTokenMap(claims, map[string]any{backchannelLogoutEvent: map[string]any{}}, ""), jose.HS256); compact == "" {
		t.Fatal("empty test token")
	} else if _, err := VerifyLogoutToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, claims.Audience, now); err == nil {
		t.Fatal("wrong algorithm accepted")
	}
}

func testLogoutTokenClaims(now time.Time, lifetime time.Duration) LogoutTokenClaims {
	sid := make([]byte, 32)
	sid[0] = 1
	return LogoutTokenClaims{Issuer: "https://id.example.test", Audience: "client-1", JTI: "logout-1", SessionID: base64.RawURLEncoding.EncodeToString(sid), IssuedAt: now, ExpiresAt: now.Add(lifetime)}
}

func logoutTokenMap(claims LogoutTokenClaims, events map[string]any, nonce string) map[string]any {
	payload := map[string]any{"iss": claims.Issuer, "aud": []string{claims.Audience}, "iat": claims.IssuedAt.Unix(), "exp": claims.ExpiresAt.Unix(), "jti": claims.JTI, "events": events}
	if claims.Subject != "" {
		payload["sub"] = claims.Subject
	}
	if claims.SessionID != "" {
		payload["sid"] = claims.SessionID
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	return payload
}

func mustSignedLogoutToken(t *testing.T, key SigningKey, payload map[string]any, algorithm jose.SignatureAlgorithm) string {
	t.Helper()
	signingKey := any(key.Private)
	if algorithm == jose.HS256 {
		signingKey = []byte("0123456789abcdef0123456789abcdef")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: signingKey}, (&jose.SignerOptions{}).WithType("logout+jwt").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
