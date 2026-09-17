package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTokenExchangeUsesSubjectScopesWithoutExchangerLoginPolicy(t *testing.T) {
	server, db := crossClientExchangeServer(t)
	seedCrossExchangeManagedClient(t, db, "scope-exchanger", "scope-exchanger-secret", true, []string{TokenExchangeGrantType}, nil, nil, 1)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read groups")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	server.oidc.ClientGroupPolicy = func(context.Context, string) (ClientGroupPolicy, error) {
		return ClientGroupPolicy{}, errors.New("exchange must not apply browser group admission")
	}
	response := postCrossExchange(server, "scope-exchanger", "scope-exchanger-secret", url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "scope": {"groups"}})
	if response.Code != http.StatusOK {
		t.Fatalf("subject scope outside exchanger allowlist rejected: status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
	if claims := jwtPayload(t, decodeToken(t, response).AccessToken); claims["scope"] != "groups" || claims["azp"] != "scope-exchanger" {
		t.Fatal("exchange did not retain the subject's requested scope")
	}
}
