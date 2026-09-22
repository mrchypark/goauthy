package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func TestUserInfoValidGETAndPOST(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	token := issueUserInfoToken(t, server)
	for name, request := range map[string]*http.Request{
		"get":  httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil),
		"post": httptest.NewRequest(http.MethodPost, "/oidc/userinfo", nil),
	} {
		t.Run(name, func(t *testing.T) {
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			server.UserInfoHandler().ServeHTTP(response, request)
			var claims map[string]any
			err := json.Unmarshal(response.Body.Bytes(), &claims)
			roles, rolesOK := claims["roles"].([]any)
			if err != nil || response.Code != http.StatusOK || claims["sub"] != "user-1" || !rolesOK || len(roles) != 0 {
				t.Fatalf("status=%d claims=%v body=%q err=%v", response.Code, claims, response.Body.String(), err)
			}
			if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("headers=%v", response.Header())
			}
		})
	}
}

func TestUserInfoRejectsInvalidTokenAndTransport(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	valid := issueUserInfoToken(t, server)
	transport := issueUserInfoToken(t, server)
	nonOpenID := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueNonOIDCCode(t, server, strings.Repeat("n", 43))}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("n", 43)}})).AccessToken
	clientCredentials := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}})).AccessToken
	expired := issueUserInfoToken(t, server)
	expireUserInfoToken(t, db, server, expired)
	if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), valid)); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]*http.Request{
		"missing":              httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil),
		"malformed":            userInfoRequest(http.MethodGet, "not-a-token", nil),
		"revoked":              userInfoRequest(http.MethodGet, valid, nil),
		"expired":              userInfoRequest(http.MethodGet, expired, nil),
		"non_openid":           userInfoRequest(http.MethodGet, nonOpenID, nil),
		"client_credentials":   userInfoRequest(http.MethodGet, clientCredentials, nil),
		"query_transport":      userInfoRequest(http.MethodGet, transport, nil),
		"form_token_transport": userInfoRequest(http.MethodPost, transport, strings.NewReader("access_token="+transport)),
	} {
		if name == "query_transport" {
			request.URL.RawQuery = "access_token=" + url.QueryEscape(transport)
		}
		if name == "form_token_transport" {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		t.Run(name, func(t *testing.T) { assertUserInfoUnauthorized(t, server, request) })
	}
}

func TestUserInfoSubjectValidationAndMethod(t *testing.T) {
	t.Parallel()
	server := userInfoTestServer(t, oauthTestDB(t), errors.New("disabled"))
	token := issueUserInfoToken(t, server)
	assertUserInfoUnauthorized(t, server, userInfoRequest(http.MethodGet, token, nil))
	server.oidc.ValidateSubject = nil
	assertUserInfoUnauthorized(t, server, userInfoRequest(http.MethodGet, token, nil))
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, userInfoRequest(http.MethodPut, token, nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("method status=%d headers=%v", response.Code, response.Header())
	}
}

func userInfoTestServer(t *testing.T, db *rhiza.DB, subjectErr error) *Server {
	t.Helper()
	seedOAuthUser(t, db, "user-1")
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ValidateSubject: func(context.Context, string) error { return subjectErr },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func issueUserInfoToken(t *testing.T, server *Server) string {
	t.Helper()
	verifier := strings.Repeat("u", 43)
	return decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, oidcTestSessionID(0))}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})).AccessToken
}

func userInfoRequest(method, token string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, "/oidc/userinfo", body)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func assertUserInfoUnauthorized(t *testing.T, server *Server, request *http.Request) {
	t.Helper()
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" || strings.Contains(response.Body.String(), "token") || strings.Contains(response.Body.String(), "user") {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func expireUserInfoToken(t *testing.T, db *rhiza.DB, server *Server, token string) {
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
	record.ExpiresAt[fosite.AccessToken] = time.Now().UTC().Add(-time.Second).UnixMilli()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "expire-userinfo-token", Statements: []rhiza.SQLStatement{{SQL: `UPDATE oauth_token_requests SET request_json = ? WHERE signature = ?`, Args: []any{string(encoded), signature}}}}); err != nil {
		t.Fatal(err)
	}
}
