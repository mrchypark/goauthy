package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"golang.org/x/crypto/bcrypt"
)

const (
	crossExchangeDefaultA = "https://default-a.example.test/api"
	crossExchangeDefaultB = "https://default-b.example.test/api"
	crossExchangeTarget   = "https://target.example.test/api"
)

func TestManagedCrossClientExchangeAudiencesAndPolicyRevision(t *testing.T) {
	t.Parallel()
	server, db := crossClientExchangeServer(t)
	const exchangerID, exchangerSecret = "managed-exchanger", "managed-exchanger-secret"
	seedCrossExchangeManagedClient(t, db, exchangerID, exchangerSecret, true, []string{TokenExchangeGrantType}, []string{crossExchangeTarget}, []string{crossExchangeDefaultA, crossExchangeDefaultB}, 1)
	seedCrossExchangeManagedClient(t, db, "managed-source", "managed-source-secret", true, []string{"authorization_code"}, []string{exchangeResource}, nil, 1)
	seedCrossExchangeManagedClient(t, db, "managed-actor", "managed-actor-secret", true, []string{"authorization_code"}, []string{crossExchangeTarget}, nil, 1)
	source := crossExchangeManagedSource(t, server, "managed-source", "managed-source-secret", "source-user", exchangeResource)
	actor := crossExchangeManagedSource(t, server, "managed-actor", "managed-actor-secret", "actor-user", crossExchangeTarget)

	defaultOutput := decodeToken(t, postCrossExchange(server, exchangerID, exchangerSecret, url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "actor_token": {actor}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"},
	}))
	assertCrossExchangeClaims(t, defaultOutput.AccessToken, exchangerID, []string{exchangerID, crossExchangeDefaultA, crossExchangeDefaultB})
	introspection := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {defaultOutput.AccessToken}}, exchangerID, exchangerSecret)
	var metadata struct {
		Active   bool     `json:"active"`
		ClientID string   `json:"client_id"`
		Audience []string `json:"aud"`
	}
	if introspection.Code != http.StatusOK || json.Unmarshal(introspection.Body.Bytes(), &metadata) != nil || !metadata.Active || metadata.ClientID != exchangerID || !sameAccessStrings(metadata.Audience, []string{crossExchangeDefaultA, crossExchangeDefaultB}) {
		t.Fatalf("cross-client introspection status=%d active=%t client=%t audience=%v", introspection.Code, metadata.Active, metadata.ClientID == exchangerID, metadata.Audience)
	}
	explicitOutput := decodeToken(t, postCrossExchange(server, exchangerID, exchangerSecret, url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "resource": {crossExchangeTarget}, "scope": {"goauthy.read"},
	}))
	assertCrossExchangeClaims(t, explicitOutput.AccessToken, exchangerID, []string{exchangerID, crossExchangeDefaultA, crossExchangeDefaultB, crossExchangeTarget})
	aliasOutput := decodeToken(t, postCrossExchange(server, exchangerID, exchangerSecret, url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "audience": {crossExchangeTarget}, "scope": {"goauthy.read"},
	}))
	assertCrossExchangeClaims(t, aliasOutput.AccessToken, exchangerID, []string{exchangerID, crossExchangeDefaultA, crossExchangeDefaultB, crossExchangeTarget})

	updateCrossExchangeMetadata(t, db, exchangerID, 1, []string{crossExchangeDefaultB}, []string{crossExchangeTarget}, []string{TokenExchangeGrantType})
	revisedOutput := decodeToken(t, postCrossExchange(server, exchangerID, exchangerSecret, url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"},
	}))
	assertCrossExchangeClaims(t, revisedOutput.AccessToken, exchangerID, []string{exchangerID, crossExchangeDefaultB})
}

func TestManagedCrossClientExchangeRejectsUnauthorizedTargetsAndInputs(t *testing.T) {
	t.Parallel()
	server, db := crossClientExchangeServer(t)
	const enabledID, enabledSecret = "managed-enabled", "managed-enabled-secret"
	seedCrossExchangeManagedClient(t, db, enabledID, enabledSecret, true, []string{TokenExchangeGrantType}, []string{crossExchangeTarget}, nil, 1)
	source := crossExchangeSource(t, server, "source-user")
	base := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}}
	for name, tc := range map[string]struct {
		form url.Values
		err  string
	}{
		"unregistered target":   {url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "resource": {crossExchangeDefaultA}}, "invalid_target"},
		"multiple target":       {url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "resource": {crossExchangeTarget, crossExchangeTarget}}, "invalid_request"},
		"resource and audience": {url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "resource": {crossExchangeTarget}, "audience": {crossExchangeTarget}}, "invalid_request"},
	} {
		assertCrossExchangeError(t, postCrossExchange(server, enabledID, enabledSecret, tc.form), tc.err, name)
	}
	noTarget := decodeToken(t, postCrossExchange(server, enabledID, enabledSecret, base))
	assertCrossExchangeClaims(t, noTarget.AccessToken, enabledID, []string{enabledID})
	seedCrossExchangeManagedClient(t, db, "managed-no-flow", "managed-no-flow-secret", true, []string{"client_credentials"}, []string{crossExchangeTarget}, nil, 1)
	assertCrossExchangeError(t, postCrossExchange(server, "managed-no-flow", "managed-no-flow-secret", base), "unauthorized_client", "managed client without token-exchange flow")
	seedCrossExchangeManagedClient(t, db, "managed-public", "", false, []string{TokenExchangeGrantType}, []string{crossExchangeTarget}, nil, 1)
	assertCrossExchangeError(t, postCrossExchange(server, "managed-public", "", base), "unauthorized_client", "public managed exchanger")
	dynamic, err := server.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{ClientID: "dynamic-exchanger", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "dynamic"})
	if err != nil {
		t.Fatal(err)
	}
	assertCrossExchangeError(t, postCrossExchange(server, dynamic.ClientID, dynamic.ClientSecret, base), "unauthorized_client", "dynamic exchanger")
	if err := server.store.DeleteAccessTokenSession(t.Context(), server.accessTokens.AccessTokenSignature(t.Context(), source)); err != nil {
		t.Fatal(err)
	}
	assertCrossExchangeError(t, postCrossExchange(server, enabledID, enabledSecret, base), "invalid_grant", "revoked cross-client subject")

	bound := crossExchangeSource(t, server, "bound-source")
	bindForwardAuthTokenDPoP(t, db, server, bound)
	assertCrossExchangeError(t, postCrossExchange(server, enabledID, enabledSecret, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {bound}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}}), "invalid_grant", "DPoP-bound cross-client subject")
}

func TestManagedCrossClientExchangeInputPolicyChangesBeforeIssue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, changedID, change string
		actor                   bool
	}{
		{name: "disabled subject", changedID: "managed-source", change: "disabled"},
		{name: "generation changed actor", changedID: "managed-actor", change: "generation", actor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, db := crossClientExchangeServer(t)
			const exchangerID, exchangerSecret = "managed-exchanger", "managed-exchanger-secret"
			seedCrossExchangeManagedClient(t, db, exchangerID, exchangerSecret, true, []string{TokenExchangeGrantType}, []string{crossExchangeTarget}, nil, 1)
			seedCrossExchangeManagedClient(t, db, "managed-source", "managed-source-secret", true, []string{"authorization_code"}, []string{exchangeResource}, nil, 1)
			source := crossExchangeManagedSource(t, server, "managed-source", "managed-source-secret", "managed-source-user", exchangeResource)
			form := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}}
			if tc.actor {
				seedCrossExchangeManagedClient(t, db, "managed-actor", "managed-actor-secret", true, []string{"authorization_code"}, []string{exchangeResource}, nil, 1)
				actor := crossExchangeManagedSource(t, server, "managed-actor", "managed-actor-secret", "managed-actor-user", exchangeResource)
				form.Set("actor_token", actor)
				form.Set("actor_token_type", accessTokenType)
			}
			beforeAccess, beforeRequests := crossExchangeArtifacts(t, server)
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				var query string
				if tc.change == "disabled" {
					query = `UPDATE managed_oauth_clients SET enabled=0,revision=revision+1 WHERE id=?`
				} else {
					query = `UPDATE managed_oauth_clients SET generation='invalidated-generation',revision=revision+1 WHERE id=?`
				}
				if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "cross-exchange-input-policy-" + tc.changedID, SQL: query, Args: []any{tc.changedID}}); err != nil {
					t.Fatal(err)
				}
			}
			assertCrossExchangeError(t, postCrossExchange(server, exchangerID, exchangerSecret, form), "invalid_grant", "invalidated managed input")
			afterAccess, afterRequests := crossExchangeArtifacts(t, server)
			if afterAccess != beforeAccess || afterRequests != beforeRequests {
				t.Fatalf("invalidated managed input artifacts access=%d/%d request=%d/%d", afterAccess, beforeAccess, afterRequests, beforeRequests)
			}
			signature := server.accessTokens.AccessTokenSignature(t.Context(), source)
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 || rows.Rows[0][0] != int64(1) {
				t.Fatalf("invalidated input removed the durable source row rows=%v err=%v", rows.Rows, err)
			}
		})
	}
}

func TestManagedCrossClientExchangeExchangerPolicyChangesBeforeIssue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, query string }{
		{name: "default audience revision", query: `UPDATE managed_oauth_clients SET metadata_json=?,revision=revision+1 WHERE id=?`},
		{name: "generation", query: `UPDATE managed_oauth_clients SET generation='invalidated-exchanger-generation',revision=revision+1 WHERE id=?`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, db := crossClientExchangeServer(t)
			const exchangerID, exchangerSecret = "managed-exchanger", "managed-exchanger-secret"
			seedCrossExchangeManagedClient(t, db, exchangerID, exchangerSecret, true, []string{TokenExchangeGrantType}, []string{crossExchangeTarget}, []string{crossExchangeDefaultA}, 1)
			source := crossExchangeSource(t, server, "source-user")
			beforeAccess, beforeRequests := crossExchangeArtifacts(t, server)
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				args := []any{exchangerID}
				if tc.name == "default audience revision" {
					metadata, err := json.Marshal(map[string]any{"id": exchangerID, "confidential": true, "redirect_uris": []string{}, "scopes": []string{"goauthy.read"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": []string{TokenExchangeGrantType}, "audience": []string{crossExchangeTarget}, "default_aud": []string{crossExchangeDefaultB}})
					if err != nil {
						t.Fatal(err)
					}
					args = []any{string(metadata), exchangerID}
				}
				if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "cross-exchange-exchanger-policy-" + strings.ReplaceAll(tc.name, " ", "-"), SQL: tc.query, Args: args}); err != nil {
					t.Fatal(err)
				}
			}
			form := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}}
			assertCrossExchangeError(t, postCrossExchange(server, exchangerID, exchangerSecret, form), "invalid_grant", "invalidated exchanger policy")
			afterAccess, afterRequests := crossExchangeArtifacts(t, server)
			if afterAccess != beforeAccess || afterRequests != beforeRequests {
				t.Fatalf("invalidated exchanger artifacts access=%d/%d request=%d/%d", afterAccess, beforeAccess, afterRequests, beforeRequests)
			}
		})
	}
}

func crossClientExchangeServer(t *testing.T) (*Server, *rhiza.DB) {
	t.Helper()
	db := oauthTestDB(t)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{exchangeResource, crossExchangeDefaultA, crossExchangeDefaultB, crossExchangeTarget}, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }})
	if err != nil {
		t.Fatal(err)
	}
	server.store.managedClients = clients.NewStore(db, nil)
	return server, db
}

func seedCrossExchangeManagedClient(t *testing.T, db *rhiza.DB, id, secret string, confidential bool, grants, audiences, defaults []string, revision int64) {
	t.Helper()
	redirectURIs := []string{}
	if containsCrossExchangeGrant(grants, "authorization_code") {
		redirectURIs = []string{testRedirectURI}
	}
	metadata, err := json.Marshal(map[string]any{"id": id, "confidential": confidential, "redirect_uris": redirectURIs, "scopes": []string{"goauthy.read"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": grants, "audience": audiences, "default_aud": defaults})
	if err != nil {
		t.Fatal(err)
	}
	var hash []byte
	if confidential {
		hash, err = bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "seed-cross-exchange-" + id, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,secret_hash) VALUES(?,?,?,1,0,?,?)`, Args: []any{id, "generation-" + id, revision, string(metadata), hash}}); err != nil {
		t.Fatal(err)
	}
}

func updateCrossExchangeMetadata(t *testing.T, db *rhiza.DB, id string, revision int64, defaults, audiences, grants []string) {
	t.Helper()
	metadata, err := json.Marshal(map[string]any{"id": id, "confidential": true, "redirect_uris": []string{}, "scopes": []string{"goauthy.read"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": grants, "audience": audiences, "default_aud": defaults})
	if err != nil {
		t.Fatal(err)
	}
	result, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "update-cross-exchange-" + id, SQL: `UPDATE managed_oauth_clients SET metadata_json=?,revision=revision+1 WHERE id=? AND revision=?`, Args: []any{string(metadata), id, revision}})
	if err != nil || result.MutationReceipt.RowsAffected != 1 {
		t.Fatalf("cross-client policy revision update committed=%t", err == nil && result.MutationReceipt.RowsAffected == 1)
	}
}

func crossExchangeSource(t *testing.T, server *Server, subject string) string {
	t.Helper()
	response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, subject, "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}})
	return decodeToken(t, response).AccessToken
}

func crossExchangeManagedSource(t *testing.T, server *Server, clientID, secret, subject, resource string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, subject)
	verifier := strings.Repeat("m", 43)
	values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read"}, "resource": {resource}, "state": {strings.Repeat("s", 32)}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), subject, []string{"goauthy.read"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("managed source authorize status=%d", response.Code)
	}
	return decodeToken(t, postCrossExchange(server, clientID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})).AccessToken
}

func containsCrossExchangeGrant(grants []string, wanted string) bool {
	for _, grant := range grants {
		if grant == wanted {
			return true
		}
	}
	return false
}

func postCrossExchange(server *Server, clientID, secret string, values url.Values) *httptest.ResponseRecorder {
	values = values.Clone()
	if secret == "" {
		values.Set("client_id", clientID)
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		request.SetBasicAuth(clientID, secret)
	}
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func assertCrossExchangeClaims(t *testing.T, token, clientID string, audience []string) {
	t.Helper()
	claims, err := oidc.VerifyAccessToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{oidcTestKey(t).PublicJWK}}, oidcTestIssuer, time.Now().UTC())
	if err != nil || claims.AuthorizedParty != clientID || !sameAccessStrings(claims.Audience, audience) || !sameAccessStrings(claims.Scope, []string{"goauthy.read"}) {
		t.Fatalf("cross-client claims valid=%t client_matches=%t audience_matches=%t scope_matches=%t", err == nil, claims.AuthorizedParty == clientID, sameAccessStrings(claims.Audience, audience), sameAccessStrings(claims.Scope, []string{"goauthy.read"}))
	}
}

func assertCrossExchangeError(t *testing.T, response *httptest.ResponseRecorder, want, label string) {
	t.Helper()
	if response.Code != http.StatusBadRequest || tokenError(t, response) != want {
		t.Fatalf("%s status=%d error=%q want=%q", label, response.Code, tokenError(t, response), want)
	}
}

func crossExchangeArtifacts(t *testing.T, server *Server) (access, requests int64) {
	t.Helper()
	rows, err := server.store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_token_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 {
		t.Fatalf("cross-client exchange artifacts rows=%v err=%v", rows.Rows, err)
	}
	access, accessOK := rows.Rows[0][0].(int64)
	requests, requestsOK := rows.Rows[0][1].(int64)
	if !accessOK || !requestsOK {
		t.Fatalf("cross-client exchange artifacts values=%v", rows.Rows[0])
	}
	return access, requests
}
