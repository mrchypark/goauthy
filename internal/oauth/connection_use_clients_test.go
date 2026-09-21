package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAuthorizeConnectionUseReturnsDynamicConsumerAndOwnsGuard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	server.store.customScopeExists = claims.NewStore(db).ScopeExists
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "connection-use-scope", SQL: `INSERT INTO custom_scopes(name,attr_include_id_json,attr_include_access_json,revision) VALUES('goauthy.connections.use','[]','[]',1)`}); err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "connection-use-dcr", RedirectURIs: []string{"https://rp.example.test/callback"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.connections.use"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
		Audiences: []string{resourceAuthorizationAudience},
		Name:      "Connection use DCR",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.store.dynamicClients.GetClient(ctx, client.ClientID); err != nil {
		t.Fatalf("DCR client reload failed: %v", err)
	}
	seedOAuthUser(t, db, "dcr-connection-user")
	token := issueDynamicConnectionUseToken(t, server, client.ClientID, client.ClientSecret, "dcr-connection-user")

	r := httptest.NewRequest(http.MethodPost, "/connections/use", strings.NewReader(`{"client_id":"spoof","owner":"spoof"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	owner, consumer, authority, err := server.AuthorizeConnectionUse(r, resourceAuthorizationAudience)
	if err != nil || owner != "dcr-connection-user" || consumer != client.ClientID || authority == nil {
		t.Fatalf("owner=%q consumer=%q authority=%v err=%v", owner, consumer, authority != nil, err)
	}
	guard, args := authority()
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("DCR guard rows=%v err=%v", rows.Rows, err)
	}

	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "connection-use-change-client", SQL: `UPDATE oauth_access_tokens SET client_id=? WHERE signature=?`, Args: []any{"other-client", server.accessTokens.AccessTokenSignature(ctx, token)}}); err != nil {
		t.Fatal(err)
	}
	rows, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: authorityArgs(authority), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("guard accepted token after client ownership changed: rows=%v err=%v", rows.Rows, err)
	}
}

func issueDynamicConnectionUseToken(t *testing.T, server *Server, clientID, secret, subject string) string {
	t.Helper()
	const verifier = "dynamic-connection-use-verifier-abcdefghijklmnopqrstuvwxyz"
	values := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://rp.example.test/callback"},
		"scope": {"goauthy.connections.use"}, "state": {"dynamic-connection-use-state"},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {resourceAuthorizationAudience},
	}
	response := httptest.NewRecorder()
	authorizeRequest := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)
	if _, err := server.ValidateAuthorizationRequest(authorizeRequest); err != nil {
		t.Fatalf("dynamic authorization validation failed: %v", err)
	}
	server.WriteAuthorization(response, authorizeRequest, subject, []string{"goauthy.connections.use"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d", response.Code)
	}
	issued := decodeToken(t, postTokenWithCredentials(server, clientID, secret, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")},
		"redirect_uri": {"https://rp.example.test/callback"}, "code_verifier": {verifier},
	}))
	if issued.AccessToken == "" {
		t.Fatal("dynamic client exchange returned no access token")
	}
	return issued.AccessToken
}
