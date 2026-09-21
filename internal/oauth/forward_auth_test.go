package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestForwardAuthAcceptsOpenIDUserToken(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, issueUserInfoToken(t, server), nil))
	if response.Code != http.StatusOK || response.Body.Len() != 0 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" || response.Header().Get("X-Forwarded-User") != "" {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestForwardAuthEmitsCurrentIdentityOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	token := issueUserInfoToken(t, server)
	server.oidc.ForwardAuthEnabled = true
	server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
		return PrincipalClaims{Roles: []string{"writer", "admin"}, Groups: []string{"team-a"}, Revision: 1}, nil
	}
	server.oidc.ResolveForwardAuthProfile = func(context.Context, string) (ForwardAuthProfile, error) {
		return ForwardAuthProfile{Email: "alice@example.test", EmailVerified: true, GivenName: "Alice"}, nil
	}
	server.oidc.ResolveForwardAuthPasskeyEnrollment = func(context.Context, string) (bool, error) { return true, nil }
	request := forwardAuthRequest(http.MethodGet, token, nil)
	request.Header.Set(ForwardAuthUserHeader, "attacker")
	response := forwardAuthResponse(server, request)
	if response.Code != http.StatusOK || request.Header.Get(ForwardAuthUserHeader) != "" || response.Header().Get(ForwardAuthUserHeader) != "user-1" || response.Header().Get(ForwardAuthRolesHeader) != "admin,writer" || response.Header().Get(ForwardAuthGroupsHeader) != "team-a" || response.Header().Get(ForwardAuthEmailHeader) != "alice@example.test" || response.Header().Get(ForwardAuthEmailVerifiedHeader) != "true" || response.Header().Get(ForwardAuthMFAHeader) != "true" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
}

func TestForwardAuthEnabledRequiresCurrentResolvers(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	server.oidc.ForwardAuthEnabled = true
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, issueUserInfoToken(t, server), nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
}

func TestForwardAuthRejectsInvalidTokenAndTransport(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	revoked := issueUserInfoToken(t, server)
	expired := issueUserInfoToken(t, server)
	expireUserInfoToken(t, db, server, expired)
	if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), revoked)); err != nil {
		t.Fatal(err)
	}
	nonOpenID := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueNonOIDCCode(t, server, strings.Repeat("n", 43))}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("n", 43)}})).AccessToken
	clientCredentials := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}})).AccessToken
	valid := issueUserInfoToken(t, server)
	for name, request := range map[string]*http.Request{
		"missing":            httptest.NewRequest(http.MethodGet, "/oidc/forward_auth", nil),
		"malformed":          forwardAuthRequest(http.MethodGet, "not-a-token", nil),
		"wrong_scheme":       forwardAuthRequest(http.MethodGet, valid, nil),
		"duplicate_auth":     forwardAuthRequest(http.MethodGet, valid, nil),
		"revoked":            forwardAuthRequest(http.MethodGet, revoked, nil),
		"expired":            forwardAuthRequest(http.MethodGet, expired, nil),
		"non_openid":         forwardAuthRequest(http.MethodGet, nonOpenID, nil),
		"client_credentials": forwardAuthRequest(http.MethodGet, clientCredentials, nil),
		"query":              forwardAuthRequest(http.MethodGet, valid, nil),
		"body":               forwardAuthRequest(http.MethodGet, valid, strings.NewReader("ignored")),
	} {
		switch name {
		case "wrong_scheme":
			request.Header.Set("Authorization", "DPoP "+valid)
		case "duplicate_auth":
			request.Header.Add("Authorization", "Bearer another-token")
		case "query":
			request.URL.RawQuery = "next=ignored"
		}
		t.Run(name, func(t *testing.T) { assertForwardAuthUnauthorized(t, server, request) })
	}
}

func TestForwardAuthRejectsDPoPBoundAndInvalidSubject(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	bound := issueUserInfoToken(t, server)
	bindForwardAuthTokenDPoP(t, db, server, bound)
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, bound, nil))

	server = userInfoTestServer(t, db, assertError("disabled"))
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, issueUserInfoToken(t, server), nil))
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodPost, issueUserInfoToken(t, server), nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method status=%d headers=%v", response.Code, response.Header())
	}
}

func forwardAuthRequest(method, token string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, "/oidc/forward_auth", body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func forwardAuthResponse(server *Server, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.ForwardAuthHandler().ServeHTTP(response, request)
	return response
}

func assertForwardAuthUnauthorized(t *testing.T, server *Server, request *http.Request) {
	t.Helper()
	response := forwardAuthResponse(server, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" || response.Body.Len() != 0 {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func bindForwardAuthTokenDPoP(t *testing.T, db *rhiza.DB, server *Server, token string) {
	t.Helper()
	signature := server.accessTokens.AccessTokenSignature(context.Background(), token)
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT request_json FROM oauth_token_requests WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("access request=%v err=%v", result.Rows, err)
	}
	var record requestRecord
	if err := json.Unmarshal([]byte(result.Rows[0][0].(string)), &record); err != nil {
		t.Fatal(err)
	}
	if record.Extra == nil {
		record.Extra = make(map[string]any)
	}
	record.Extra[dpopCNFExtra] = map[string]string{dpopJKTClaim: "bound-key"}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "bind-forward-auth-dpop", Statements: []rhiza.SQLStatement{{SQL: `UPDATE oauth_token_requests SET request_json = ? WHERE signature = ?`, Args: []any{string(encoded), signature}}}}); err != nil {
		t.Fatal(err)
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }
