package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestIntrospectionUsesCurrentPrincipalClaims(t *testing.T) {
	t.Parallel()
	claims := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) { return claims, nil })
	withGroups := issueRBACAccessToken(t, server, strings.Repeat("i", 43), "openid groups goauthy.read offline_access")
	withoutGroups := issueRBACAccessToken(t, server, strings.Repeat("j", 43), "openid goauthy.read offline_access")

	claims = PrincipalClaims{Roles: []string{"admin"}, Groups: []string{"team/b"}, Revision: 2}
	assertRBACIntrospection(t, server, withGroups, []string{"admin"}, []string{"team/b"}, true)
	assertRBACIntrospection(t, server, withoutGroups, []string{"admin"}, nil, false)
}

func TestIntrospectionMakesRevokedPrincipalInactive(t *testing.T) {
	t.Parallel()
	resolverErr := error(nil)
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		if resolverErr != nil {
			return PrincipalClaims{}, resolverErr
		}
		return PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}, nil
	})
	token := issueRBACAccessToken(t, server, strings.Repeat("k", 43), "openid groups goauthy.read offline_access")

	resolverErr = errors.New("revoked")
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret))

	resolverErr = nil
	server.oidc.ValidateSubject = func(context.Context, string) error { return errors.New("disabled") }
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
	if response.Code != http.StatusOK {
		t.Fatalf("disabled principal status=%d body=%s", response.Code, response.Body.String())
	}
	assertInactive(t, response)
}

func TestIntrospectionRefreshAccessUsesCurrentPrincipalClaims(t *testing.T) {
	t.Parallel()
	claims := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) { return claims, nil })
	verifier := strings.Repeat("l", 43)
	issued := decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid groups goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	claims = PrincipalClaims{Roles: []string{"editor"}, Groups: []string{"team/b"}, Revision: 2}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "introspection-refresh-revision", SQL: `UPDATE rbac_principal_versions SET revision=2 WHERE subject='user-1'`}); err != nil {
		t.Fatal(err)
	}
	refreshed := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))

	claims = PrincipalClaims{Roles: []string{"operator"}, Groups: []string{"team/c"}, Revision: 3}
	assertRBACIntrospection(t, server, refreshed.AccessToken, []string{"operator"}, []string{"team/c"}, true)
}

func TestIntrospectionClientCredentialsHasNoPrincipalClaims(t *testing.T) {
	t.Parallel()
	resolves := 0
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		resolves++
		return PrincipalClaims{Roles: []string{"admin"}, Groups: []string{"team/a"}, Revision: 1}, nil
	})
	issued := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || response.Code != http.StatusOK || payload["active"] != true || payload["roles"] != nil || payload["groups"] != nil || resolves != 0 {
		t.Fatalf("client credentials introspection status=%d payload=%#v resolves=%d err=%v", response.Code, payload, resolves, err)
	}
}
