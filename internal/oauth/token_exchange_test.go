package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

const exchangeResource = "https://resource.example.test/api"

func TestTokenExchangeAccessOnlyNarrowing(t *testing.T) {
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	sourceSignature := server.accessTokens.AccessTokenSignature(context.Background(), source.AccessToken)
	sourceExpiry, err := server.store.accessTokenExpiry(context.Background(), sourceSignature)
	if err != nil {
		t.Fatal(err)
	}
	response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource}})
	if response.Code != http.StatusOK {
		t.Fatalf("exchange status=%d source_signature=%q source_expiry=%d body=%s", response.Code, sourceSignature, sourceExpiry.UnixMilli(), response.Body.String())
	}
	exchanged := decodeToken(t, response)
	if exchanged.AccessToken == "" || exchanged.RefreshToken != "" || exchanged.TokenType != "bearer" || exchanged.Scope != "goauthy.read" {
		t.Fatalf("exchange=%+v", exchanged)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), exchanged.AccessToken), nil); err != nil {
		t.Fatal(err)
	}
}

func TestTokenExchangeRejectsPrivilegeWideningAndUnsupportedFields(t *testing.T) {
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	base := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}}
	for index, form := range []url.Values{
		{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}},
		{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}},
		{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "scope": {"admin"}},
		{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {"x"}},
		{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "audience": {"https://unregistered.example.test/api"}},
	} {
		if response := postToken(server, form); response.Code == http.StatusOK {
			t.Fatalf("accepted invalid exchange case %d", index)
		}
	}
	if response := postToken(server, base); response.Code != http.StatusOK {
		t.Fatalf("default scope exchange=%d %s", response.Code, response.Body.String())
	}
}

func TestTokenExchangeGroupsFollowSubjectScope(t *testing.T) {
	for _, tc := range []struct {
		name, sourceScopes, actorScopes, requestedScopes string
	}{
		{name: "inherited source", sourceScopes: "goauthy.read groups"},
		{name: "inherited actor", sourceScopes: "goauthy.read", actorScopes: "goauthy.read groups"},
		{name: "explicit target", sourceScopes: "goauthy.read", requestedScopes: groupsScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := exchangeTestServer(t)
			source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "source", tc.sourceScopes)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
			values := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}}
			if tc.requestedScopes != "" {
				values.Set("scope", tc.requestedScopes)
			}
			if tc.actorScopes != "" {
				actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor", tc.actorScopes)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
				values.Set("actor_token", actor.AccessToken)
				values.Set("actor_token_type", accessTokenType)
			}
			before := tokenExchangeAccessCount(t, server)
			response := postToken(server, values)
			if tc.requestedScopes == groupsScope {
				if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_scope" {
					t.Fatalf("source scope widening status=%d", response.Code)
				}
				if after := tokenExchangeAccessCount(t, server); after != before {
					t.Fatalf("scope widening minted access token: before=%d after=%d", before, after)
				}
			} else if response.Code != http.StatusOK || tokenExchangeAccessCount(t, server) != before+1 {
				t.Fatalf("valid source group scope rejected: status=%d", response.Code)
			}
		})
	}
}

func tokenExchangeAccessCount(t *testing.T, server *Server) int64 {
	t.Helper()
	result, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("access token count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("access token count=%#v", result.Rows)
	}
	return count
}

func TestTokenExchangeNeverOutlivesSourceAccessToken(t *testing.T) {
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	signature := server.accessTokens.AccessTokenSignature(context.Background(), source.AccessToken)
	request, err := server.store.GetAccessTokenSession(context.Background(), signature, nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceExpiry := time.Now().UTC().Add(90 * time.Second).Truncate(time.Millisecond)
	request.GetSession().SetExpiresAt(fosite.AccessToken, sourceExpiry)
	encoded, err := encodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "test-exchange-source-expiry", Statements: []rhiza.SQLStatement{{SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms = ? WHERE signature = ?`, Args: []any{sourceExpiry.UnixMilli(), signature}}, {SQL: `UPDATE oauth_token_requests SET request_json = ? WHERE signature = ?`, Args: []any{encoded, signature}}}}); err != nil {
		t.Fatal(err)
	}
	exchanged := decodeToken(t, postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}}))
	target, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), exchanged.AccessToken), nil)
	if err != nil {
		t.Fatal(err)
	}
	if target.GetSession().GetExpiresAt(fosite.AccessToken).After(sourceExpiry) {
		t.Fatalf("target expiry=%s source expiry=%s", target.GetSession().GetExpiresAt(fosite.AccessToken), sourceExpiry)
	}
}

func TestTokenExchangeActorDelegationPersistsOnlyActSubject(t *testing.T) {
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	clientSecret := testClientSecret
	response := postTokenWithClientSecret(server, url.Values{
		"grant_type":         {TokenExchangeGrantType},
		"client_id":          {testClientID},
		"client_secret":      {clientSecret},
		"subject_token":      {source.AccessToken},
		"subject_token_type": {accessTokenType},
		"actor_token":        {actor.AccessToken},
		"actor_token_type":   {accessTokenType},
		"scope":              {"goauthy.read"},
		"resource":           {exchangeResource},
	})
	exchanged := decodeToken(t, response)
	targetSignature := server.accessTokens.AccessTokenSignature(context.Background(), exchanged.AccessToken)
	target, err := server.store.GetAccessTokenSession(context.Background(), targetSignature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	session := target.GetSession().(*fosite.DefaultSession)
	act, ok := session.Extra["act"].(map[string]interface{})
	if !ok || act["sub"] != "actor-2" || session.Subject != "user-1" {
		t.Fatalf("session subject=%q act=%#v", session.Subject, session.Extra)
	}
	result, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT request_json FROM oauth_token_requests WHERE signature = ?`, Args: []any{targetSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("target request row=%#v err=%v", result.Rows, err)
	}
	encoded, ok := result.Rows[0][0].(string)
	if !ok || strings.Contains(encoded, source.AccessToken) || strings.Contains(encoded, actor.AccessToken) || strings.Contains(encoded, clientSecret) {
		t.Fatalf("target request persisted raw exchange credential")
	}
}

func TestTokenExchangeActorCannotExpandAuthority(t *testing.T) {
	server := exchangeTestServer(t)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	for name, values := range map[string]url.Values{
		"scope": {"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"profile"}},
		"type":  {"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {"urn:ietf:params:oauth:token-type:id_token"}},
	} {
		if response := postToken(server, values); response.Code == http.StatusOK {
			t.Fatalf("actor authority expansion accepted for %s", name)
		}
	}
}

func TestTokenExchangeRejectsRevokedOrExpiredActor(t *testing.T) {
	for name, revoke := range map[string]bool{"revoked": true, "expired": false} {
		t.Run(name, func(t *testing.T) {
			server := exchangeTestServer(t)
			source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCode(t, server)}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
			actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
			actorSignature := server.accessTokens.AccessTokenSignature(context.Background(), actor.AccessToken)
			if revoke {
				if err := server.store.DeleteAccessTokenSession(context.Background(), actorSignature); err != nil {
					t.Fatal(err)
				}
			} else if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "test-expire-actor", SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms = ? WHERE signature = ?`, Args: []any{time.Unix(1, 0).UTC().UnixMilli(), actorSignature}}); err != nil {
				t.Fatal(err)
			}
			values := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}}
			if response := postToken(server, values); response.Code == http.StatusOK {
				t.Fatalf("accepted %s actor", name)
			}
		})
	}
}

func exchangeTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServerWithOIDC(context.Background(), oauthTestDB(t), randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{exchangeResource}, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func postTokenAs(server *Server, clientID, clientSecret string, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func postTokenWithClientSecret(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}
func issueExchangeCode(t *testing.T, server *Server) string {
	return issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")
}

func issueExchangeCodeFor(t *testing.T, server *Server, subject, scopes string) string {
	return issueExchangeCodeForClient(t, server, testClientID, subject, scopes)
}

func issueExchangeCodeForClient(t *testing.T, server *Server, clientID, subject, scopes string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, subject)
	verifier := strings.Repeat("x", 43)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirectURI}, "scope": {scopes}, "resource": {exchangeResource}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	values.Set("state", strings.Repeat("s", 32))
	w := httptest.NewRecorder()
	server.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), subject, strings.Fields(scopes))
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("authorize status=%d location=%q err=%v", w.Code, w.Header().Get("Location"), err)
	}
	return u.Query().Get("code")
}
