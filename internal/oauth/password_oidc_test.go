package oauth

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
)

func TestPasswordOIDCOriginWithoutBrowserSession(t *testing.T) {
	key := oidcTestKey(t)
	s := &Server{oidc: &OIDCConfig{Issuer: oidcTestIssuer}}
	for _, grant := range []string{"password", "refresh_token", "authorization_code"} {
		r := fosite.NewAccessRequest(&fosite.DefaultSession{Subject: "password-user", Extra: map[string]interface{}{passwordAuthTimeExtra: "1700000000"}})
		r.Client = &fosite.DefaultClient{ID: testClientID}
		r.GrantTypes = fosite.Arguments{grant}
		r.GrantScope("openid")
		token, err := s.signIDToken(t.Context(), r, key, "access", PrincipalClaims{}, oidc.CustomClaims{})
		if grant == "authorization_code" {
			if err == nil {
				t.Fatal("password origin accepted for authorization code")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		claims := verifyOIDCTestToken(t, token, key, time.Now().UTC())
		if claims.AuthTime.Unix() != 1700000000 || claims.SessionID != "" || claims.Nonce != "" || len(claims.AuthenticationMethods) != 1 || claims.AuthenticationMethods[0] != "pwd" {
			t.Fatal("incorrect password authentication claims")
		}
	}
	for _, raw := range []any{nil, int64(1700000000), "", "0", "-1", "invalid"} {
		r := fosite.NewAccessRequest(&fosite.DefaultSession{Subject: "password-user", Extra: map[string]interface{}{passwordAuthTimeExtra: raw}})
		r.Client = &fosite.DefaultClient{ID: testClientID}
		r.GrantTypes = fosite.Arguments{"password"}
		if _, err := s.signIDToken(t.Context(), r, key, "access", PrincipalClaims{}, oidc.CustomClaims{}); err == nil {
			t.Fatal("invalid authentication time accepted")
		}
	}
}
