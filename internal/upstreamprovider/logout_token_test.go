package upstreamprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	jose "github.com/go-jose/go-jose/v4"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyLogoutToken(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	verifier := newTestJWKSVerifier(server.URL, server.Client())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "key").WithType("logout+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	now := jwksTestNow()
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"both", func(m map[string]any) {}, true},
		{"sid only", func(m map[string]any) { delete(m, "sub") }, true},
		{"sub only", func(m map[string]any) { delete(m, "sid") }, true},
		{"audience array", func(m map[string]any) { m["aud"] = []string{"other", "client"} }, true},
		{"neither", func(m map[string]any) { delete(m, "sub"); delete(m, "sid") }, false},
		{"wrong issuer", func(m map[string]any) { m["iss"] = "other" }, false},
		{"wrong audience", func(m map[string]any) { m["aud"] = "other" }, false},
		{"nonce empty", func(m map[string]any) { m["nonce"] = "" }, false},
		{"nonce null", func(m map[string]any) { m["nonce"] = nil }, false},
		{"missing event", func(m map[string]any) { delete(m, "events") }, false},
		{"null event", func(m map[string]any) { m["events"] = map[string]any{logoutEvent: nil} }, false},
		{"array event", func(m map[string]any) { m["events"] = map[string]any{logoutEvent: []any{}} }, false},
		{"nonempty event", func(m map[string]any) { m["events"] = map[string]any{logoutEvent: map[string]any{"x": 1}} }, false},
		{"missing jti", func(m map[string]any) { delete(m, "jti") }, false},
		{"missing exp", func(m map[string]any) { delete(m, "exp") }, false},
		{"expired", func(m map[string]any) { m["exp"] = now.Unix() }, false},
		{"missing iat", func(m map[string]any) { delete(m, "iat") }, false},
		{"future iat", func(m map[string]any) { m["iat"] = now.Unix() + 1 }, false},
		{"stale iat", func(m map[string]any) { m["iat"] = now.Add(-3 * time.Minute).Unix() }, false},
		{"future nbf", func(m map[string]any) { m["nbf"] = now.Unix() + 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": "issuer", "aud": "client", "sub": "subject", "sid": "upstream-session", "jti": "unique", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "events": map[string]any{logoutEvent: map[string]any{}}}
			tc.change(claims)
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := verifier.VerifyLogoutToken(context.Background(), raw, "issuer", "client", now, 2*time.Minute)
			if !tc.valid {
				if got != nil || !errors.Is(err, ErrLogoutTokenVerification) {
					t.Fatalf("accepted invalid claims: %+v, %v", got, err)
				}
				return
			}
			if err != nil || got == nil || got.JTI != "unique" || got.Issuer != "issuer" || !got.ReplayUntil.Equal(now.Add(time.Minute)) {
				t.Fatalf("valid claims: %+v, %v", got, err)
			}
			if _, err := verifier.VerifyLogoutToken(context.Background(), raw, "unconfigured", "client", now, 2*time.Minute); !errors.Is(err, ErrLogoutTokenVerification) {
				t.Fatal("unconfigured issuer accepted")
			}
		})
	}
}

func TestDecodeIDTokenPreservesUpstreamSID(t *testing.T) {
	t.Parallel()
	claims, err := decodeIDTokenClaims([]byte(`{"iss":"issuer","aud":"client","sub":"subject","sid":"upstream-session"}`))
	if err != nil || claims.SessionID != "upstream-session" {
		t.Fatalf("sid discarded: %+v, %v", claims, err)
	}
}

func TestLogoutTokenRejectsUnauthenticatedAndBoundaryInputs(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	verifier := newTestJWKSVerifier(server.URL, server.Client())
	now := jwksTestNow()
	sign := func(signingKey *rsa.PrivateKey) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithHeader("kid", "key"))
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{"iss": "issuer", "aud": "client", "sid": "session", "jti": "jti", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "events": map[string]any{logoutEvent: map[string]any{}}})
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
	valid := sign(key)
	for _, tc := range []struct {
		name, raw string
		at        time.Time
		age       time.Duration
		audience  string
	}{
		{"wrong signing key", sign(attacker), now, time.Minute, "client"},
		{"unsigned", "eyJhbGciOiJub25lIn0.e30.", now, time.Minute, "client"},
		{"malformed", "not-a-jwt", now, time.Minute, "client"},
		{"oversized", string(make([]byte, (16<<10)+1)), now, time.Minute, "client"},
		{"empty audience", valid, now, time.Minute, ""},
		{"zero age policy", valid, now, 0, "client"},
		{"negative age policy", valid, now, -time.Minute, "client"},
		{"expired at boundary", valid, now.Add(5 * time.Minute), 10 * time.Minute, "client"},
		{"stale by nanosecond", valid, now.Add(time.Minute + time.Nanosecond), time.Minute, "client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := verifier.VerifyLogoutToken(context.Background(), tc.raw, "issuer", tc.audience, tc.at, tc.age)
			if claims != nil || !errors.Is(err, ErrLogoutTokenVerification) {
				t.Fatalf("untrusted token accepted: %v", err)
			}
		})
	}
	claims, err := verifier.VerifyLogoutToken(context.Background(), valid, "issuer", "client", now.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("max age boundary: %v", err)
	}
	if !claims.ReplayUntil.Equal(now.Add(time.Minute+time.Millisecond)) || !claims.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("replay retention does not bound long token expiry: %+v", claims)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyLogoutToken(ctx, valid, "issuer", "client", now, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := verifier.VerifyLogoutToken(nil, valid, "issuer", "client", now, time.Minute); !errors.Is(err, ErrLogoutTokenVerification) {
		t.Fatalf("nil context: %v", err)
	}
	var absent *JWKSVerifier
	if _, err := absent.VerifyLogoutToken(context.Background(), valid, "issuer", "client", now, time.Minute); !errors.Is(err, ErrLogoutTokenVerification) {
		t.Fatalf("nil verifier: %v", err)
	}
}
