package oidc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestIDTokenSignsAndVerifiesWithPublicJWKS(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	want := IDTokenClaims{
		Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), NotBefore: now, Nonce: "nonce-1", AuthTime: now.Add(-time.Minute),
		AuthorizedParty: "client-1", SessionID: "session-1", AccessTokenHash: AccessTokenHash("access-token"),
		AuthenticationMethods: []string{"pwd", "mfa"},
		Roles:                 []string{"admin", "reader"}, Groups: []string{"ops", "sales"},
	}
	compact, err := SignIDToken(key, want)
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(key.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), `"d"`) {
		t.Fatal("public JWK exposes private material")
	}
	got, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, want.Issuer, "client-1", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject || len(got.Audience) != 1 || got.Audience[0] != "client-1" || got.Nonce != want.Nonce || !got.AuthTime.Equal(want.AuthTime) || !got.NotBefore.Equal(want.NotBefore) || got.AuthorizedParty != want.AuthorizedParty || got.SessionID != want.SessionID || got.AccessTokenHash != want.AccessTokenHash || strings.Join(got.AuthenticationMethods, ",") != strings.Join(want.AuthenticationMethods, ",") || strings.Join(got.Roles, ",") != strings.Join(want.Roles, ",") || strings.Join(got.Groups, ",") != strings.Join(want.Groups, ",") {
		t.Fatalf("unexpected claims: %#v", got)
	}
}

func TestIDTokenStandardProfileClaimsRoundTrip(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	name, email, given := "team_34", "user@example.test", "Given"
	verified, phoneVerified := true, false
	want := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), NotBefore: now,
		Roles: []string{}, Profile: ProfileClaims{Email: &email, EmailVerified: &verified, PreferredUsername: &name, GivenName: &given, Address: map[string]string{"street_address": "Main", "postal_code": "12345"}, PhoneNumber: &email, PhoneNumberVerified: &phoneVerified, Zoneinfo: &name, Locale: &given}}
	compact, err := SignIDToken(key, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, want.Issuer, "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Profile, want.Profile) {
		t.Fatalf("profile roundtrip=%#v want=%#v", got.Profile, want.Profile)
	}
}

func TestIDTokenCustomClaimsCannotCollideWithProfileNames(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	value := "x"
	_, err := SignIDToken(fixedTokenSigningKey(), IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Roles: []string{}, Profile: ProfileClaims{GivenName: &value}, CustomClaims: CustomClaims{Values: map[string]json.RawMessage{"given_name": json.RawMessage(`"evil"`)}, AtRoot: true}})
	if err == nil {
		t.Fatal("profile claim collision accepted")
	}
}

func TestIDTokenCustomClaimsRoundTripIsCanonicalAndDeterministic(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	base := IDTokenClaims{
		Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		CustomClaims: CustomClaims{Values: map[string]json.RawMessage{
			"profile": json.RawMessage(` { "z" : 2, "a" : [ true, null ] } `),
		}},
	}
	first, err := SignIDToken(key, base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignIDToken(key, base)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("fixed key and claims produced different tokens")
	}
	got, err := VerifyIDToken(first, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.CustomClaims.AtRoot || string(got.CustomClaims.Values["profile"]) != `{"a":[true,null],"z":2}` {
		t.Fatalf("unexpected custom claims: %#v", got.CustomClaims)
	}
}

func TestIDTokenRootCustomClaimsRejectReservedNames(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	base := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	base.CustomClaims = CustomClaims{AtRoot: true, Values: map[string]json.RawMessage{"department": json.RawMessage(`"ops"`)}}
	compact, err := SignIDToken(key, base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CustomClaims.AtRoot || string(got.CustomClaims.Values["department"]) != `"ops"` {
		t.Fatalf("root custom claims did not round-trip: %#v", got.CustomClaims)
	}
	base.CustomClaims = CustomClaims{AtRoot: true, Values: map[string]json.RawMessage{"sub": json.RawMessage(`"other"`)}}
	if _, err := SignIDToken(key, base); err == nil {
		t.Fatal("reserved root claim was accepted")
	}
}

func TestIDTokenMixedCustomClaimsRoundTrip(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	base := IDTokenClaims{
		Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		CustomClaims: CustomClaims{
			Nested: map[string]json.RawMessage{"department": json.RawMessage(`"ops"`)},
			Root:   map[string]json.RawMessage{"tenant": json.RawMessage(` { "id" : 7 } `)},
		},
	}
	compact, err := SignIDToken(key, base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CustomClaims.Nested["department"]) != `"ops"` || string(got.CustomClaims.Root["tenant"]) != `{"id":7}` || got.CustomClaims.Values != nil {
		t.Fatalf("mixed custom claims did not round-trip: %#v", got.CustomClaims)
	}
	base.CustomClaims = CustomClaims{Nested: map[string]json.RawMessage{"department": json.RawMessage(`true`)}, Root: map[string]json.RawMessage{"department": json.RawMessage(`false`)}}
	compact, err = SignIDToken(key, base)
	if err != nil {
		t.Fatalf("same nested/root name was rejected: %v", err)
	}
	got, err = VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now)
	if err != nil || string(got.CustomClaims.Nested["department"]) != "true" || string(got.CustomClaims.Root["department"]) != "false" {
		t.Fatalf("same-name custom claims did not round-trip: %#v, %v", got.CustomClaims, err)
	}
	base.CustomClaims = CustomClaims{Root: map[string]json.RawMessage{"iss": json.RawMessage(`"other"`)}}
	if _, err := SignIDToken(key, base); err == nil {
		t.Fatal("reserved root custom claim was accepted")
	}
}

func TestIDTokenRejectsInvalidCustomClaimPayloads(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	base := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	tooMany := make(map[string]json.RawMessage, maxCustomClaimCount+1)
	for i := range maxCustomClaimCount + 1 {
		tooMany[fmt.Sprintf("claim-%d", i)] = json.RawMessage(`true`)
	}
	for _, custom := range []CustomClaims{
		{AtRoot: true, Values: map[string]json.RawMessage{"bad\nname": json.RawMessage(`true`)}},
		{Values: map[string]json.RawMessage{"profile": json.RawMessage(`{"a":1,"a":2}`)}},
		{Values: tooMany},
		{Values: map[string]json.RawMessage{"profile": json.RawMessage(`[[[[[[[[[0]]]]]]]]]`)}},
	} {
		base.CustomClaims = custom
		if _, err := SignIDToken(key, base); err == nil {
			t.Fatalf("invalid custom claims were signed: %#v", custom)
		}
	}

	raw := []byte(`{"iss":"https://id.example.com","sub":"user-1","aud":["client-1"],"iat":1800000000,"exp":1800003600,"roles":[],"custom":{"profile":1,"profile":2}}`)
	compact := signedRawIDToken(t, key, raw)
	if _, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now); err == nil {
		t.Fatal("duplicate custom JSON key was accepted")
	}
}

func TestAccessTokenHash(t *testing.T) {
	if got, want := AccessTokenHash("access-token"), "Rb10lsqrobcpd02MQ_878ctvfDDbaRese_Z50nFw5Jw"; got != want {
		t.Fatalf("AccessTokenHash() = %q, want %q", got, want)
	}
}

func TestAccessTokenSignsCustomClaimsWithFixedClock(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := AccessTokenClaims{
		Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1", "https://api.example.com"},
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: "opaque-jti", AuthorizedParty: "client-1",
		Scope: []string{"openid", "employee"}, Type: "DPoP", ConfirmationJKT: strings.Repeat("a", 43),
		Roles: []string{"admin"}, Groups: []string{"ops"},
		CustomClaims: CustomClaims{Nested: map[string]json.RawMessage{"department": json.RawMessage(`"ops"`)}, Root: map[string]json.RawMessage{"tenant": json.RawMessage(`{"id":7}`)}},
	}
	first, err := SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignAccessToken(key, claims)
	if err != nil || first != second {
		t.Fatalf("fixed access claims are not deterministic: %v", err)
	}
	got, err := VerifyAccessToken(first, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != claims.Subject || strings.Join(got.Audience, " ") != strings.Join(claims.Audience, " ") || got.ID != claims.ID || got.Type != "DPoP" || got.ConfirmationJKT != claims.ConfirmationJKT || strings.Join(got.Scope, " ") != "openid employee" || string(got.CustomClaims.Nested["department"]) != `"ops"` || string(got.CustomClaims.Root["tenant"]) != `{"id":7}` {
		t.Fatalf("unexpected access claims: %#v", got)
	}
}

func TestAccessTokenRejectsRootScopeCollisionAndInvalidSignature(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := AccessTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: "jti", AuthorizedParty: "client-1", Scope: []string{"openid"}, Type: "Bearer", CustomClaims: CustomClaims{Root: map[string]json.RawMessage{"scope": json.RawMessage(`"admin"`)}}}
	if _, err := SignAccessToken(key, claims); err == nil {
		t.Fatal("root scope collision was accepted")
	}
	claims.CustomClaims = CustomClaims{}
	compact, err := SignAccessToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, claims.ExpiresAt); err == nil {
		t.Fatal("expired access token was accepted")
	}
	if _, err := VerifyAccessToken(compact+"x", jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, claims.Issuer, now); err == nil {
		t.Fatal("modified access token was accepted")
	}
}

func TestVerifyIDTokenRejectsWrongClaimsAlgorithmAndExpiry(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	compact, err := SignIDToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}
	for _, check := range []struct {
		name, issuer, audience string
		at                     time.Time
	}{
		{"issuer", "https://other.example.com", "client-1", now},
		{"audience", claims.Issuer, "other-client", now},
		{"expiry", claims.Issuer, "client-1", claims.ExpiresAt},
	} {
		t.Run(check.name, func(t *testing.T) {
			if _, err := VerifyIDToken(compact, keys, check.issuer, check.audience, check.at); err == nil {
				t.Fatal("invalid token was accepted")
			}
		})
	}
	wrongAlgorithm, err := signedToken(t, jose.HS256, []byte("0123456789abcdef0123456789abcdef"), claims, "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIDToken(wrongAlgorithm, keys, claims.Issuer, "client-1", now); err == nil {
		t.Fatal("non-EdDSA token was accepted")
	}
}

func TestVerifyLogoutIDTokenLeeway(t *testing.T) {
	key := testTokenSigningKey(t)
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}
	now := time.Unix(1_800_000_000, 0).UTC()
	issuer, audience := "https://id.example.com", "client-1"

	expired, err := SignIDToken(key, IDTokenClaims{Issuer: issuer, Subject: "user-1", Audience: []string{audience}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIDToken(expired, keys, issuer, audience, now); err == nil {
		t.Fatal("strict verifier accepted token at expiry")
	}
	for _, check := range []struct {
		name  string
		token string
		at    time.Time
		ok    bool
	}{
		{"expiry boundary", expired, now.Add(logoutIDTokenClockLeeway), true},
		{"expiry beyond leeway", expired, now.Add(logoutIDTokenClockLeeway + time.Second), false},
		{"not-before boundary", signedTestIDToken(t, key, issuer, audience, now, now.Add(logoutIDTokenClockLeeway), now.Add(time.Hour)), now, true},
		{"not-before beyond leeway", signedTestIDToken(t, key, issuer, audience, now, now.Add(logoutIDTokenClockLeeway+time.Second), now.Add(time.Hour)), now, false},
		{"issued-at boundary", signedTestIDToken(t, key, issuer, audience, now.Add(logoutIDTokenClockLeeway), now, now.Add(time.Hour)), now, true},
		{"issued-at beyond leeway", signedTestIDToken(t, key, issuer, audience, now.Add(logoutIDTokenClockLeeway+time.Second), now, now.Add(time.Hour)), now, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			_, err := VerifyLogoutIDToken(check.token, keys, issuer, audience, check.at)
			if (err == nil) != check.ok {
				t.Fatalf("VerifyLogoutIDToken() error = %v, want accepted=%v", err, check.ok)
			}
		})
	}
}

func TestVerifyLogoutIDTokenRetainsNonTimeValidation(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	compact, err := SignIDToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}
	for _, check := range []struct {
		name, token, issuer, audience string
	}{
		{"wrong issuer", compact, "https://other.example.com", "client-1"},
		{"wrong audience", compact, claims.Issuer, "other-client"},
		{"wrong algorithm", mustSignedToken(t, jose.HS256, []byte("0123456789abcdef0123456789abcdef"), claims, "other"), claims.Issuer, "client-1"},
		{"wrong signature", mustSignedIDToken(t, testTokenSigningKey(t), idTokenPayload{Claims: jwt.Claims{Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience), IssuedAt: jwt.NewNumericDate(claims.IssuedAt), Expiry: jwt.NewNumericDate(claims.ExpiresAt)}}), claims.Issuer, "client-1"},
	} {
		t.Run(check.name, func(t *testing.T) {
			if _, err := VerifyLogoutIDToken(check.token, keys, check.issuer, check.audience, now); err == nil {
				t.Fatal("invalid logout hint was accepted")
			}
		})
	}
}

func TestIDTokenOmitsOptionalClaims(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	compact, err := SignIDToken(key, IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := parsed.Claims(key.PublicJWK.Key, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["nonce"]; ok {
		t.Fatal("empty nonce was serialized")
	}
	if _, ok := payload["auth_time"]; ok {
		t.Fatal("zero auth_time was serialized")
	}
	for _, name := range []string{"nbf", "azp", "sid", "at_hash", "amr", "groups"} {
		if _, ok := payload[name]; ok {
			t.Fatalf("empty %s was serialized", name)
		}
	}
	if got := string(payload["roles"]); got != "[]" {
		t.Fatalf("empty roles = %s, want []", got)
	}
	claims, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, "https://id.example.com", "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Roles == nil || len(claims.Roles) != 0 {
		t.Fatalf("empty roles did not round-trip as an array: %#v", claims.Roles)
	}
}

func TestIDTokenRejectsMalformedOptionalClaims(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	valid := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, claims := range []IDTokenClaims{
		func() IDTokenClaims { c := valid; c.AuthorizedParty = "other-client"; return c }(),
		func() IDTokenClaims { c := valid; c.AccessTokenHash = "not-a-hash"; return c }(),
		func() IDTokenClaims { c := valid; c.AuthenticationMethods = []string{""}; return c }(),
		func() IDTokenClaims { c := valid; c.NotBefore = valid.ExpiresAt.Add(time.Second); return c }(),
		func() IDTokenClaims { c := valid; c.Roles = []string{"reader", "admin"}; return c }(),
		func() IDTokenClaims { c := valid; c.Roles = []string{"admin", "admin"}; return c }(),
		func() IDTokenClaims { c := valid; c.Roles = []string{"x"}; return c }(),
		func() IDTokenClaims { c := valid; c.Groups = []string{"sales", "ops"}; return c }(),
		func() IDTokenClaims { c := valid; c.Groups = []string{"ops", "ops"}; return c }(),
		func() IDTokenClaims { c := valid; c.Groups = []string{"a."}; return c }(),
	} {
		if _, err := SignIDToken(key, claims); err == nil {
			t.Fatalf("malformed claims were signed: %#v", claims)
		}
	}

	for _, payload := range []idTokenPayload{
		{Claims: jwt.Claims{Issuer: valid.Issuer, Subject: valid.Subject, Audience: jwt.Audience(valid.Audience), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, AuthorizedParty: "other-client"},
		{Claims: jwt.Claims{Issuer: valid.Issuer, Subject: valid.Subject, Audience: jwt.Audience(valid.Audience), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, AccessTokenHash: "not-a-hash"},
		{Claims: jwt.Claims{Issuer: valid.Issuer, Subject: valid.Subject, Audience: jwt.Audience(valid.Audience), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, Roles: []string{"reader", "admin"}},
		{Claims: jwt.Claims{Issuer: valid.Issuer, Subject: valid.Subject, Audience: jwt.Audience(valid.Audience), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, Roles: []string{}, Groups: []string{"ops", "ops"}},
	} {
		compact, err := signedIDTokenPayload(key, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, valid.Issuer, "client-1", now); err == nil {
			t.Fatalf("malformed token was accepted: %#v", payload)
		}
	}
}

func TestIDTokenRejectsMoreThan64RoleOrGroupClaims(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	valid := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Roles: make([]string, 65)}
	for i := range valid.Roles {
		valid.Roles[i] = fmt.Sprintf("r%02d", i)
	}
	if _, err := SignIDToken(key, valid); err == nil {
		t.Fatal("more than 64 roles were accepted")
	}
	valid.Roles = []string{}
	valid.Groups = make([]string, 65)
	for i := range valid.Groups {
		valid.Groups[i] = fmt.Sprintf("g%02d", i)
	}
	if _, err := SignIDToken(key, valid); err == nil {
		t.Fatal("more than 64 groups were accepted")
	}
}

func TestGroupClaimGrammar(t *testing.T) {
	for _, check := range []struct {
		value string
		valid bool
	}{
		{"ops", true},
		{"team/name:1,*", true},
		{"x", false},
		{"team a", false},
		{"team\nops", false},
		{" team", false},
		{"team ", false},
		{"team\\ops", false},
		{"team.ops", false},
		{"팀", false},
	} {
		t.Run(check.value, func(t *testing.T) {
			if got := validCanonicalClaimValues([]string{check.value}, groupClaimPattern); got != check.valid {
				t.Fatalf("validCanonicalClaimValues(%q) = %v, want %v", check.value, got, check.valid)
			}
		})
	}
}

func TestVerifyIDTokenRejectsNotYetValidToken(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	compact, err := SignIDToken(key, IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, NotBefore: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, "https://id.example.com", "client-1", now); err == nil {
		t.Fatal("not-yet-valid token was accepted")
	}
}

func TestIDTokenRejectsLifetimeBeyondRotationRetentionBound(t *testing.T) {
	key := testTokenSigningKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	_, err := SignIDToken(key, IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(MaxIDTokenLifetime + time.Second)})
	if err == nil {
		t.Fatal("overlong ID token lifetime was accepted")
	}
}

func testTokenSigningKey(t *testing.T) SigningKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "test-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
}

func fixedTokenSigningKey() SigningKey {
	private := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	return SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: private.Public(), KeyID: "fixed-test-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
}

func signedToken(t *testing.T, algorithm jose.SignatureAlgorithm, key any, claims IDTokenClaims, kid string) (string, error) {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(idTokenPayload{Claims: jwt.Claims{Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience), IssuedAt: jwt.NewNumericDate(claims.IssuedAt), Expiry: jwt.NewNumericDate(claims.ExpiresAt)}}).Serialize()
}

func signedIDTokenPayload(key SigningKey, payload idTokenPayload) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key.Private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

func signedRawIDToken(t *testing.T, key SigningKey, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key.Private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func signedTestIDToken(t *testing.T, key SigningKey, issuer, audience string, issuedAt, notBefore, expiresAt time.Time) string {
	t.Helper()
	compact, err := SignIDToken(key, IDTokenClaims{Issuer: issuer, Subject: "user-1", Audience: []string{audience}, IssuedAt: issuedAt, NotBefore: notBefore, ExpiresAt: expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mustSignedToken(t *testing.T, algorithm jose.SignatureAlgorithm, key any, claims IDTokenClaims, kid string) string {
	t.Helper()
	compact, err := signedToken(t, algorithm, key, claims, kid)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mustSignedIDToken(t *testing.T, key SigningKey, payload idTokenPayload) string {
	t.Helper()
	compact, err := signedIDTokenPayload(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// GA-OAUTH-003: locale is a standard profile claim, so a root custom claim of
// that name must not be signable and an ordinary locale must stay a profile
// claim instead of being re-extracted as custom during verification.
func TestIDTokenLocaleIsReservedAndNotReExtractedAsCustomClaim(t *testing.T) {
	key := fixedTokenSigningKey()
	now := time.Unix(1_800_000_000, 0).UTC()
	locale := "de-DE"
	base := IDTokenClaims{Issuer: "https://id.example.com", Subject: "user-1", Audience: []string{"client-1"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Roles: []string{}, Profile: ProfileClaims{Locale: &locale}}

	for name, value := range map[string]string{"string": `"en"`, "non-string": `7`} {
		t.Run(name, func(t *testing.T) {
			claims := base
			claims.CustomClaims = CustomClaims{Root: map[string]json.RawMessage{"locale": json.RawMessage(value)}}
			if _, err := SignIDToken(key, claims); err == nil {
				t.Fatalf("root locale collision %s was signed", value)
			}
		})
	}

	custom := make(map[string]json.RawMessage, maxCustomClaimCount)
	for i := range maxCustomClaimCount {
		custom[fmt.Sprintf("custom_%02d", i)] = json.RawMessage(`"value"`)
	}
	claims := base
	claims.CustomClaims = CustomClaims{Nested: custom}
	compact, err := SignIDToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyIDToken(compact, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, base.Issuer, "client-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.Locale == nil || *got.Profile.Locale != locale {
		t.Fatalf("locale profile claim lost: %#v", got.Profile)
	}
	if len(got.CustomClaims.Values) != maxCustomClaimCount || got.CustomClaims.AtRoot || got.CustomClaims.Nested != nil || len(got.CustomClaims.Root) != 0 {
		t.Fatalf("custom claims alongside a locale round-tripped as %#v", got.CustomClaims)
	}

	// Every claim a fully populated standard payload emits must be reserved, so
	// a future profile claim cannot become a colliding custom claim again.
	text, verified := "value", true
	populated := base
	populated.Profile = ProfileClaims{Email: &text, EmailVerified: &verified, PreferredUsername: &text, GivenName: &text, FamilyName: &text, Birthdate: &text, Address: map[string]string{"street_address": text}, PhoneNumber: &text, PhoneNumberVerified: &verified, Zoneinfo: &text, Locale: &text}
	populated.Nonce, populated.SessionID, populated.AuthorizedParty, populated.AccessTokenHash = "nonce-1", "session-1", "client-1", AccessTokenHash("access-token")
	populated.AuthTime, populated.AuthenticationMethods, populated.Groups = now.Add(-time.Minute), []string{"pwd"}, []string{"ops"}
	compact, err = SignIDToken(key, populated)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if len(parts) != 3 || err != nil {
		t.Fatalf("signed payload %q err=%v", compact, err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(payload, &emitted); err != nil {
		t.Fatal(err)
	}
	for name := range emitted {
		if _, reserved := reservedIDTokenClaimNames[name]; !reserved {
			t.Fatalf("standard ID token claim %q is not reserved against custom claims", name)
		}
	}
}
