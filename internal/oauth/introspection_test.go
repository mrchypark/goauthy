package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestIntrospectionAndRevocation(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, strings.Repeat("i", 43))},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("i", 43)},
	}))

	active := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	if active.Code != http.StatusOK {
		t.Fatalf("active introspection status=%d body=%s", active.Code, active.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(active.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["active"] != true || payload["client_id"] != testClientID || payload["scope"] != "goauthy.read offline_access" || payload["sub"] != "user-1" {
		t.Fatalf("unexpected active introspection: %#v", payload)
	}

	inactive := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {"not-a-token"}}, testClientID, testClientSecret)
	assertInactive(t, inactive)

	wrongClient := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, "wrong-client", testClientSecret)
	if wrongClient.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-client introspection status=%d body=%s", wrongClient.Code, wrongClient.Body.String())
	}

	revoked := postOAuthForm(server.RevocationHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	if revoked.Code != http.StatusOK || revoked.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("revocation status=%d headers=%#v body=%s", revoked.Code, revoked.Header(), revoked.Body.String())
	}
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret))
}

func TestRefreshTokenRevocationRevokesGrant(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	verifier := strings.Repeat("j", 43)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, verifier)},
		"redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))

	revoked := postOAuthForm(server.RevocationHandler(), url.Values{"token": {issued.RefreshToken}}, testClientID, testClientSecret)
	if revoked.Code != http.StatusOK {
		t.Fatalf("refresh revocation status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	for _, token := range []string{issued.AccessToken, issued.RefreshToken} {
		assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret))
	}
}

func TestIntrospectionAndRevocationRejectInvalidForms(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	for name, handler := range map[string]http.Handler{
		"introspection": server.IntrospectionHandler(),
		"revocation":    server.RevocationHandler(),
	} {
		t.Run(name+" content type", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/oidc/"+name, strings.NewReader("token=x"))
			request.Header.Set("Content-Type", "multipart/form-data; boundary=x")
			request.SetBasicAuth(testClientID, testClientSecret)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusOK {
				t.Fatal("multipart request accepted")
			}
		})
		t.Run(name+" basic auth", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/oidc/"+name, strings.NewReader("token=x"))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusOK {
				t.Fatal("unauthenticated request accepted")
			}
		})
		t.Run(name+" body limit", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/oidc/"+name, strings.NewReader("token="+strings.Repeat("x", oauthFormLimit+1)))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(testClientID, testClientSecret)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusOK {
				t.Fatal("oversized request accepted")
			}
		})
	}
}

func TestOAuthFormEndpointsRejectRepeatedHeaders(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	for name, handler := range map[string]http.Handler{
		"token":         server.TokenHandler(),
		"introspection": server.IntrospectionHandler(),
		"revocation":    server.RevocationHandler(),
	} {
		t.Run(name+" valid single headers", func(t *testing.T) {
			response := oauthFormEndpointRequest(handler, name, "")
			if response.Code != http.StatusOK {
				t.Fatalf("single headers status=%d body=%s", response.Code, response.Body.String())
			}
		})
		for _, header := range []string{"authorization", "content type"} {
			t.Run(name+" repeated "+header, func(t *testing.T) {
				response := oauthFormEndpointRequest(handler, name, header)
				assertInvalidFormRequest(t, response)
			})
		}
	}
}

func oauthFormEndpointRequest(handler http.Handler, endpoint, repeated string) *httptest.ResponseRecorder {
	values := url.Values{"token": {"not-a-token"}}
	if endpoint == "token" {
		values = url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/"+endpoint, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	switch repeated {
	case "authorization":
		request.Header.Add("Authorization", "Basic attacker")
	case "content type":
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertInvalidFormRequest(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, response.Body.String())
	}
	if payload.Error != "invalid_request" {
		t.Fatalf("error=%q body=%s", payload.Error, response.Body.String())
	}
}

func postOAuthForm(handler http.Handler, values url.Values, clientID, clientSecret string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertInactive(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("inactive introspection status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 || payload["active"] != false {
		t.Fatalf("unexpected inactive introspection: %#v", payload)
	}
}
