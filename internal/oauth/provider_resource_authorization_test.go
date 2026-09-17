package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAuthorizeUserProviderResourceReadWrite(t *testing.T) {
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	for _, scope := range []string{"goauthy.providers.read", "goauthy.providers.write"} {
		t.Run(scope, func(t *testing.T) {
			token := issueResourceTokenForAudience(t, server, scope, resourceAuthorizationAudience)
			r := httptest.NewRequest(http.MethodGet, "/providers", nil)
			r.Header.Set("Authorization", "Bearer "+token.AccessToken)
			subject, authority, err := server.AuthorizeUserResource(r, scope, resourceAuthorizationAudience)
			if err != nil || subject != "resource-user" || authority == nil {
				t.Fatalf("authorize subject=%q authority=%v err=%v", subject, authority != nil, err)
			}
			guard, args := authority()
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 {
				t.Fatalf("provider guard rows=%#v err=%v", rows.Rows, err)
			}
		})
	}
}

func TestAuthorizeUserProviderResourceRejectsWrongScopeAudienceAndMachine(t *testing.T) {
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	wrongScope := issueResourceTokenForAudience(t, server, "goauthy.connections.read", resourceAuthorizationAudience)
	wrongAudience := issueResourceTokenForAudience(t, server, "goauthy.providers.read", wrongResourceAuthorizationAudience)
	server.store.client.(*fosite.DefaultClient).Scopes = append(server.store.client.(*fosite.DefaultClient).Scopes, "goauthy.providers.read")
	machine := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.providers.read"}, "resource": {resourceAuthorizationAudience}}))
	for name, token := range map[string]string{"wrong scope": wrongScope.AccessToken, "wrong audience": wrongAudience.AccessToken, "machine": machine.AccessToken} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/providers", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			if _, _, err := server.AuthorizeUserResource(r, "goauthy.providers.read", resourceAuthorizationAudience); err == nil {
				t.Fatal("accepted invalid provider resource token")
			}
		})
	}
}

func TestAuthorizeUserProviderResourceRevokedTokenInvalidatesLateGuard(t *testing.T) {
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	token := issueResourceTokenForAudience(t, server, "goauthy.providers.write", resourceAuthorizationAudience)
	r := httptest.NewRequest(http.MethodPost, "/providers", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	_, authority, err := server.AuthorizeUserResource(r, "goauthy.providers.write", resourceAuthorizationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), token.AccessToken)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.AuthorizeUserResource(r, "goauthy.providers.write", resourceAuthorizationAudience); err == nil {
		t.Fatal("accepted revoked provider token")
	}
	guard, args := authority()
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("revoked provider guard rows=%#v err=%v", rows.Rows, err)
	}
}
