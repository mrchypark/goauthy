package dpop

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestValidate(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	raw, key := signedProof(t, "POST", "https://id.example.test/oidc/token", now, "abcdefghijklmnop", "nonce", "token")
	r := httptest.NewRequest(http.MethodPost, "http://untrusted.example/oidc/token?x=1", nil)
	got, err := Validate(raw, r, Options{Issuer: "https://id.example.test", Now: now, Nonce: "nonce", AccessToken: "token"})
	if err != nil || got.JKT == "" || got.JTI != "abcdefghijklmnop" || !got.Key.IsPublic() {
		t.Fatalf("proof=%+v err=%v", got, err)
	}
	public := key.Public()
	thumb, _ := public.Thumbprint(crypto.SHA256)
	if got.JKT != base64.RawURLEncoding.EncodeToString(thumb) {
		t.Fatalf("jkt=%q", got.JKT)
	}
}

func TestValidateUsesIssuerBasePathForHTU(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	raw, _ := signedProof(t, "POST", "https://id.example.test/tenant/oidc/token", now, "abcdefghijklmnop", "", "")
	if _, err := Validate(raw, httptest.NewRequest(http.MethodPost, "/oidc/token", nil), Options{Issuer: "https://id.example.test/tenant", Now: now}); err != nil {
		t.Fatalf("path issuer proof rejected: %v", err)
	}
}
func TestValidateRejectsBindings(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	raw, _ := signedProof(t, "POST", "https://id.example.test/oidc/token", now, "abcdefghijklmnop", "", "token")
	cases := []struct {
		name string
		r    *http.Request
		o    Options
		want error
	}{
		{"method", httptest.NewRequest("GET", "/oidc/token", nil), Options{Issuer: "https://id.example.test", Now: now}, ErrInvalidProof},
		{"wrong ath", httptest.NewRequest("POST", "/oidc/token", nil), Options{Issuer: "https://id.example.test", Now: now, AccessToken: "other"}, ErrInvalidProof},
		{"nonce", httptest.NewRequest("POST", "/oidc/token", nil), Options{Issuer: "https://id.example.test", Now: now, Nonce: "need"}, ErrUseNonce},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Validate(raw, tt.r, tt.o)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	withQuery, _ := signedProof(t, "POST", "https://id.example.test/oidc/token?x=1", now, "abcdefghijklmnop", "", "")
	if _, err := Validate(withQuery, httptest.NewRequest("POST", "/oidc/token", nil), Options{Issuer: "https://id.example.test", Now: now}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("query htu err=%v", err)
	}
	old, _ := signedProof(t, "POST", "https://id.example.test/oidc/token", now.Add(-2*time.Minute), "abcdefghijklmnop", "", "")
	if _, err := Validate(old, httptest.NewRequest("POST", "/oidc/token", nil), Options{Issuer: "https://id.example.test", Now: now}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("old iat err=%v", err)
	}
}
func TestValidateRejectsMalformedAndPrivateOrDuplicateHeader(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	r := httptest.NewRequest("POST", "/oidc/token", nil)
	for _, raw := range []string{"x.y.z", strings.Repeat("a", MaxProofSize+1), base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","typ":"JWT","alg":"EdDSA","jwk":{}}`)) + ".x.y"} {
		_, err := Validate(raw, r, Options{Issuer: "https://id.example.test", Now: now})
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("raw=%q err=%v", raw, err)
		}
	}
}
func signedProof(t *testing.T, method, htu string, now time.Time, jti, nonce, access string) (string, jose.JSONWebKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := jose.JSONWebKey{Key: private.Public()}
	claims := map[string]any{"jti": jti, "htm": method, "htu": htu, "iat": now.Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if access != "" {
		sum := sha256.Sum256([]byte(access))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader(jose.HeaderKey("jwk"), key))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw, key
}
