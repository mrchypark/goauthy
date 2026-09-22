package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTokenExchangeUserScopesAndCurrentClaims(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"access-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	source := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, "s", "openid employee goauthy.read")))
	actor := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, "a", "openid profile goauthy.read")))
	accessValue = json.RawMessage(`"access-v2"`)
	response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"employee goauthy.read"}})
	if response.Code != http.StatusOK {
		t.Fatalf("user exchange status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
	issued := decodeOIDCToken(t, response)
	claims := jwtPayload(t, issued.AccessToken)
	if claims["scope"] != "employee goauthy.read" || claims["custom"].(map[string]any)["access_value"] != "access-v2" {
		t.Fatalf("exchange claims scope=%q current_custom=%t", claims["scope"], claims["custom"].(map[string]any)["access_value"] == "access-v2")
	}
	assertCustomIntrospection(t, server, issued.AccessToken, "access-v2")
}

func TestTokenExchangeRetainsAndDownscopesCurrentGroups(t *testing.T) {
	t.Parallel()
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/old"}, Revision: 1}
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) { return state, nil })
	source := issueRBACAccessToken(t, server, strings.Repeat("g", 43), "openid groups goauthy.read")
	state = PrincipalClaims{Roles: []string{"admin"}, Groups: []string{"team/new"}, Revision: 1}
	retain := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"groups goauthy.read"}}))
	assertRBACJWTClaims(t, retain.AccessToken, []string{"admin"}, []string{"team/new"}, true)
	down := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}}))
	assertRBACJWTClaims(t, down.AccessToken, []string{"admin"}, nil, false)
	if response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"groups profile"}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_scope" {
		t.Fatalf("source scope widening status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
}
