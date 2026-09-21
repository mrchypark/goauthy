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
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBackchannelLogoutHTTPVerifiesBeforeApplying(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Algorithm: "RS256"}}})
	}))
	defer jwks.Close()
	verifier := newTestJWKSVerifier(jwks.URL, jwks.Client())
	now := jwksTestNow()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "key"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": "issuer", "aud": "client", "sub": "subject", "sid": "sid", "jti": "jti", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "events": map[string]any{logoutEvent: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{"logout_token": {token}}.Encode()
	h := &Handler{configs: map[string]Config{"op": {Issuer: "issuer", ClientID: "client"}, "github": {Kind: ProviderKindGitHub}}, verifier: verifier, now: func() time.Time { return now }}
	for _, tc := range []struct {
		name, method, provider, contentType, body, query string
		fail                                             bool
		status, calls                                    int
	}{
		{"valid", "POST", "op", "application/x-www-form-urlencoded", body, "", false, 200, 1},
		{"durability failure", "POST", "op", "application/x-www-form-urlencoded", body, "", true, 400, 1},
		{"unconfigured", "POST", "other", "application/x-www-form-urlencoded", body, "", false, 400, 0},
		{"non OIDC", "POST", "github", "application/x-www-form-urlencoded", body, "", false, 400, 0},
		{"wrong method", "GET", "op", "application/x-www-form-urlencoded", body, "", false, 405, 0},
		{"wrong type", "POST", "op", "application/json", body, "", false, 400, 0},
		{"missing token", "POST", "op", "application/x-www-form-urlencoded", "x=y", "", false, 400, 0},
		{"query only", "POST", "op", "application/x-www-form-urlencoded", "", body, false, 400, 0},
		{"duplicate", "POST", "op", "application/x-www-form-urlencoded", body + "&" + body, "", false, 400, 0},
		{"malformed form", "POST", "op", "application/x-www-form-urlencoded", "logout_token=%xx", "", false, 400, 0},
		{"invalid signature", "POST", "op", "application/x-www-form-urlencoded", "logout_token=bad", "", false, 400, 0},
		{"oversized", "POST", "op", "application/x-www-form-urlencoded", "padding=" + strings.Repeat("x", 24<<10) + "&" + body, "", false, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			handler := h.BackchannelLogoutHandler(func(ctx context.Context, id string, claims *LogoutTokenClaims, digest string) error {
				calls++
				if id != "client" || claims.Issuer != "issuer" || claims.Subject != "subject" || claims.SessionID != "sid" || claims.JTI != "jti" || digest != DigestSHA256(token) {
					t.Fatal("incorrect verified logout arguments")
				}
				if tc.fail {
					return errors.New("object-store unavailable secret detail")
				}
				return nil
			})
			request := httptest.NewRequest(tc.method, "/upstream/"+tc.provider+"/backchannel-logout?"+tc.query, strings.NewReader(tc.body))
			request.SetPathValue("providerID", tc.provider)
			request.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || calls != tc.calls || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Set-Cookie") != "" {
				t.Fatalf("status=%d calls=%d headers=%v", response.Code, calls, response.Header())
			}
			if strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), "secret") {
				t.Fatal("logout response leaked sensitive details")
			}
		})
	}
}
