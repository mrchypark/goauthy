package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestForgedSignedAccessTokenNeverQueriesTokenRows(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	valid := issueUserInfoToken(t, server)
	parts := strings.Split(valid, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("issued token is not compact JWT")
	}
	// Mutate a significant base64url character; the last character may have
	// unused trailing bits and decode to the same signature bytes.
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	forged := strings.Join(parts, ".")
	lookups := 0
	server.store.beforeAccessTokenLookup = func() { lookups++ }

	userInfo := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	userInfo.Header.Set("Authorization", "Bearer "+forged)
	assertUserInfoUnauthorized(t, server, userInfo)
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, forged, nil))
	if response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {forged}, "subject_token_type": {accessTokenType}}); response.Code != http.StatusBadRequest {
		t.Fatalf("forged exchange status=%d body=%s", response.Code, response.Body.String())
	}
	introspection := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {forged}}, testClientID, testClientSecret)
	if introspection.Code != http.StatusOK || !strings.Contains(introspection.Body.String(), `"active":false`) {
		t.Fatalf("forged introspection status=%d body=%s", introspection.Code, introspection.Body.String())
	}
	revoke := postOAuthForm(server.RevocationHandler(), url.Values{"token": {forged}}, testClientID, testClientSecret)
	if revoke.Code != http.StatusOK {
		t.Fatalf("forged revocation status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if lookups != 0 {
		t.Fatalf("forged JWT reached %d access-token row lookup(s)", lookups)
	}
	if signature := server.accessTokens.AccessTokenSignature(context.Background(), forged); signature != "" {
		t.Fatalf("forged JWT signature=%q", signature)
	}
}
