package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestClientCredentialsResourceIndicator(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	resource := "https://api.example.test/v1"
	server, err := NewServerWithResourceIndicators(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource})
	if err != nil {
		t.Fatal(err)
	}
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}, "resource": {resource},
	}))
	active := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	if active.Code != http.StatusOK {
		t.Fatalf("introspection status=%d body=%s", active.Code, active.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(active.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if audience, ok := payload["aud"].([]any); !ok || len(audience) != 1 || audience[0] != resource {
		t.Fatalf("resource audience was not preserved: %#v", payload)
	}
	stored, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT requested_audience, granted_audience FROM oauth_access_tokens`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(stored.Rows) != 1 || stored.Rows[0][0] != `["https://api.example.test/v1"]` || stored.Rows[0][1] != `["https://api.example.test/v1"]` {
		t.Fatalf("resource audience was not stored: rows=%#v err=%v", stored.Rows, err)
	}
}

func TestClientCredentialsResourceIndicatorRejected(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	resource := "https://api.example.test/v1"
	for name, resources := range map[string][]string{
		"http loopback": {"http://localhost/v1"},
		"query":         {resource + "?x=1"},
		"duplicate":     {resource, resource},
	} {
		t.Run("invalid allow-list "+name, func(t *testing.T) {
			if _, err := NewServerWithResourceIndicators(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, resources); err == nil {
				t.Fatal("invalid resource allow-list accepted")
			}
		})
	}
	server, err := NewServerWithResourceIndicators(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		values url.Values
		error  string
	}{
		"audience":           {url.Values{"grant_type": {"client_credentials"}, "audience": {resource}}, "invalid_request"},
		"mixed audience":     {url.Values{"grant_type": {"client_credentials"}, "resource": {resource}, "audience": {resource}}, "invalid_request"},
		"duplicate resource": {url.Values{"grant_type": {"client_credentials"}, "resource": {resource, resource}}, "invalid_request"},
		"unknown resource":   {url.Values{"grant_type": {"client_credentials"}, "resource": {"https://other.example.test/v1"}}, "invalid_target"},
		"relative resource":  {url.Values{"grant_type": {"client_credentials"}, "resource": {"/v1"}}, "invalid_target"},
		"query resource":     {url.Values{"grant_type": {"client_credentials"}, "resource": {resource + "?x=1"}}, "invalid_target"},
		"fragment resource":  {url.Values{"grant_type": {"client_credentials"}, "resource": {resource + "#part"}}, "invalid_target"},
		"userinfo resource":  {url.Values{"grant_type": {"client_credentials"}, "resource": {"https://user@api.example.test/v1"}}, "invalid_target"},
		"http resource":      {url.Values{"grant_type": {"client_credentials"}, "resource": {"http://localhost/v1"}}, "invalid_target"},
	} {
		t.Run(name, func(t *testing.T) {
			response := postToken(server, test.values)
			if response.Code == http.StatusOK || !strings.Contains(response.Body.String(), `"error":"`+test.error+`"`) {
				t.Fatalf("resource request accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	verifier := strings.Repeat("r", 43)
	code := issueCode(t, server, verifier)
	response := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}, "resource": {resource},
	})
	if response.Code == http.StatusOK || !strings.Contains(response.Body.String(), `"error":"invalid_target"`) {
		t.Fatalf("authorization-code resource accepted: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}); response.Code != http.StatusOK {
		t.Fatalf("rejected resource request consumed code: status=%d body=%s", response.Code, response.Body.String())
	}

	withoutAllowList := oauthTestServer(t, db, randomSecret(t))
	noAllowListResponse := postToken(withoutAllowList, url.Values{"grant_type": {"client_credentials"}, "resource": {resource}})
	if noAllowListResponse.Code == http.StatusOK || !strings.Contains(noAllowListResponse.Body.String(), `"error":"invalid_target"`) {
		t.Fatalf("empty allow-list accepted resource: status=%d body=%s", noAllowListResponse.Code, noAllowListResponse.Body.String())
	}
}

func TestAuthorizationCodeResourceIndicatorPreservesAudience(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	resource := "https://api.example.test/v1"
	server, err := NewServerWithResourceIndicators(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("a", 43)
	code := issueResourceCode(t, server, verifier, resource)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	assertResourceAudience(t, server, issued.AccessToken, resource)

	narrowed := postToken(server, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "resource": {resource},
	})
	if narrowed.Code == http.StatusOK || !strings.Contains(narrowed.Body.String(), `"error":"invalid_target"`) {
		t.Fatalf("unsupported refresh narrowing accepted: status=%d body=%s", narrowed.Code, narrowed.Body.String())
	}
	refreshed := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken},
	}))
	assertResourceAudience(t, server, refreshed.AccessToken, resource)
}

func TestDefaultAudienceAppliesAndPersistsThroughRefresh(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	resource := "https://api.example.test/default"
	explicit := "https://api.example.test/explicit"
	server, err := NewServerWithResourceIndicatorsAndDefaultAudiences(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource, explicit}, map[string]string{testClientID: resource})
	if err != nil {
		t.Fatal(err)
	}

	clientCredentials := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
	}))
	assertResourceAudience(t, server, clientCredentials.AccessToken, resource)

	verifier := strings.Repeat("d", 43)
	values := authorizationValues(verifier, resource)
	values.Del("resource")
	codeResponse := httptest.NewRecorder()
	server.WriteAuthorization(codeResponse, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(codeResponse.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", codeResponse.Code, codeResponse.Header().Get("Location"), err)
	}
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	assertResourceAudience(t, server, issued.AccessToken, resource)
	refreshed := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken},
	}))
	assertResourceAudience(t, server, refreshed.AccessToken, resource)

	explicitVerifier := strings.Repeat("e", 43)
	explicitCode := issueResourceCode(t, server, explicitVerifier, explicit)
	issuedExplicit := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {explicitCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {explicitVerifier},
	}))
	assertResourceAudience(t, server, issuedExplicit.AccessToken, explicit)
}

func TestDefaultAudienceValidation(t *testing.T) {
	t.Parallel()
	resource := "https://api.example.test/default"
	for name, defaults := range map[string]map[string]string{
		"not allowed":  {testClientID: "https://other.example.test/default"},
		"invalid URL":  {testClientID: "http://api.example.test/default"},
		"blank client": {" ": resource},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServerWithResourceIndicatorsAndDefaultAudiences(context.Background(), oauthTestDB(t), randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource}, defaults); err == nil {
				t.Fatal("invalid default audience accepted")
			}
		})
	}
}

func TestAuthorizationResourceIndicatorRejectsUnknownTarget(t *testing.T) {
	t.Parallel()
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	verifier := strings.Repeat("b", 43)
	for name, values := range map[string]url.Values{
		"unknown resource": authorizationValues(verifier, "https://unknown.example.test"),
		"audience": func() url.Values {
			values := authorizationValues(verifier, "https://api.example.test/v1")
			values.Del("resource")
			values.Set("audience", "https://api.example.test/v1")
			return values
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"})
			location, err := url.Parse(response.Header().Get("Location"))
			wantError := "invalid_target"
			if name == "audience" {
				wantError = "invalid_request"
			}
			if err != nil || location.Query().Get("error") != wantError || location.Query().Get("code") != "" {
				t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
			}
		})
	}
}

func issueResourceCode(t *testing.T, server *Server, verifier, resource string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, "user-1")
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorizationValues(verifier, resource).Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

func authorizationValues(verifier, resource string) url.Values {
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read offline_access"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "resource": {resource},
	}
}

func assertResourceAudience(t *testing.T, server *Server, token, resource string) {
	t.Helper()
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
	var payload map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil {
		t.Fatalf("introspection status=%d body=%s", response.Code, response.Body.String())
	}
	if audience, ok := payload["aud"].([]any); !ok || len(audience) != 1 || audience[0] != resource {
		t.Fatalf("resource audience was not preserved: %#v", payload)
	}
}
