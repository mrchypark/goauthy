package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

func init() { bcryptHashCost = bcrypt.MinCost }

func TestSecretFilesAreValidated(t *testing.T) {
	directory := t.TempDir()
	hmacPath := directory + "/hmac"
	clientPath := directory + "/client"
	hmacSecret := randomSecret(t)
	if err := os.WriteFile(hmacPath, []byte(base64.RawURLEncoding.EncodeToString(hmacSecret)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte("a-client-secret-at-least-16"), 0o600); err != nil {
		t.Fatal(err)
	}
	if secret, err := LoadSecret(hmacPath); err != nil || len(secret) != 32 {
		t.Fatalf("HMAC secret len=%d err=%v", len(secret), err)
	}
	if secret, err := LoadClientSecret(clientPath); err != nil || secret != "a-client-secret-at-least-16" {
		t.Fatalf("client secret=%q err=%v", secret, err)
	}
	if err := os.WriteFile(hmacPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecret(hmacPath); err == nil {
		t.Fatal("short HMAC secret accepted")
	}
	if _, err := NewServer(context.Background(), nil, make([]byte, 32), "client", "a-client-secret-at-least-16", "http://localhost/callback"); err == nil {
		t.Fatal("all-zero HMAC secret accepted")
	}
}

func TestClientCredentialsToken(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), db, randomSecret(t), "machine-client", "correct-horse-battery-staple", "http://localhost/callback")
	if err != nil {
		t.Fatal(err)
	}
	handler := server.TokenHandler()

	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("machine-client", "correct-horse-battery-staple")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.TokenType != "bearer" || token.ExpiresIn <= 0 || token.Scope != "goauthy.read" {
		t.Fatalf("unexpected token response: %#v", token)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("unsafe token cache headers: %#v", response.Header())
	}
	stored, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT client_id, granted_scopes FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(stored.Rows) != 1 || stored.Rows[0][0] != "machine-client" || stored.Rows[0][1] != `["goauthy.read"]` {
		t.Fatalf("persisted token=%#v err=%v", stored.Rows, err)
	}

	for _, test := range []struct{ secret, scope string }{{"wrong-secret-value", "goauthy.read"}, {"correct-horse-battery-staple", "admin"}} {
		request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
			"grant_type": {"client_credentials"}, "scope": {test.scope},
		}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("machine-client", test.secret)
		denied := httptest.NewRecorder()
		handler.ServeHTTP(denied, request)
		if denied.Code == http.StatusOK {
			t.Fatalf("credentials secret=%q scope=%q were accepted", test.secret, test.scope)
		}
	}
	multipart := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("--boundary--"))
	multipart.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	multipart.SetBasicAuth("machine-client", "correct-horse-battery-staple")
	deniedMultipart := httptest.NewRecorder()
	handler.ServeHTTP(deniedMultipart, multipart)
	if deniedMultipart.Code == http.StatusOK {
		t.Fatal("multipart token request accepted")
	}

	oversized := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials&padding="+strings.Repeat("x", 17<<10)))
	oversized.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oversized.SetBasicAuth("machine-client", "correct-horse-battery-staple")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, oversized)
	if denied.Code == http.StatusOK {
		t.Fatal("oversized token request accepted")
	}

	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-expire-access-token",
		SQL:       `UPDATE oauth_access_tokens SET expires_at_unix_ms = 0`,
	}); err != nil {
		t.Fatal(err)
	}
	replacement := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials&scope=goauthy.read"))
	replacement.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	replacement.SetBasicAuth("machine-client", "correct-horse-battery-staple")
	replaced := httptest.NewRecorder()
	handler.ServeHTTP(replaced, replacement)
	if replaced.Code != http.StatusOK {
		t.Fatalf("replacement status=%d body=%s", replaced.Code, replaced.Body.String())
	}
	remaining, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(remaining.Rows) != 1 || remaining.Rows[0][0] != int64(1) {
		t.Fatalf("remaining tokens=%#v err=%v", remaining.Rows, err)
	}
}

func TestDynamicClientsResolveForTokenAndAuthorize(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dynamic-client-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-machine", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "Dynamic machine",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(machine.ClientID, machine.ClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("dynamic token status=%d body=%s", response.Code, response.Body.String())
	}

	const redirectURI = "https://rp.example.test/callback"
	browserClient, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-browser", RedirectURIs: []string{redirectURI}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Dynamic browser",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{"response_type": {"code"}, "client_id": {browserClient.ClientID}, "redirect_uri": {redirectURI}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	view, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	if err != nil || view.ClientID != browserClient.ClientID || view.RedirectURI != redirectURI {
		t.Fatalf("dynamic authorize view=%#v err=%v", view, err)
	}
	const updatedRedirectURI = "https://rp.example.test/updated"
	if _, err := server.store.dynamicClients.Update(ctx, browserClient.ClientID, browserClient.RegistrationAccessToken, dcr.CreateRequest{
		ClientID: browserClient.ClientID, RedirectURIs: []string{updatedRedirectURI}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Updated dynamic browser",
	}); err != nil {
		t.Fatal(err)
	}
	values.Set("redirect_uri", updatedRedirectURI)
	view, err = server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	if err != nil || view.RedirectURI != updatedRedirectURI {
		t.Fatalf("updated dynamic authorize view=%#v err=%v", view, err)
	}
	values.Set("redirect_uri", redirectURI)
	if _, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)); !errors.Is(err, ErrInvalidAuthorizationRequest) {
		t.Fatalf("dynamic client accepted an unregistered redirect: %v", err)
	}

	if _, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: testClientID, RedirectURIs: []string{"https://shadow.example.test/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Bootstrap shadow",
	}); !errors.Is(err, dcr.ErrReservedClientID) {
		t.Fatalf("bootstrap ID dynamic registration err=%v", err)
	}
	if dynamic, err := server.store.dynamicClients.GetClient(ctx, testClientID); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("bootstrap shadow row client=%#v err=%v", dynamic, err)
	}
	bootstrap, err := server.store.GetClient(ctx, testClientID)
	if err != nil || len(bootstrap.GetRedirectURIs()) != 1 || bootstrap.GetRedirectURIs()[0] != testRedirectURI {
		t.Fatalf("bootstrap client did not take precedence: client=%#v err=%v", bootstrap, err)
	}
}

func TestDynamicCustomScopesUseDefaultsAndFailClosedWhenDeleted(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	catalog := map[string]bool{"employee": true}
	server, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		CustomScopeExists: func(_ context.Context, scope string) (bool, error) { return catalog[scope], nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "dynamic-employee"
	const redirectURI = "https://rp.example.test/employee"
	created, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: clientID, RedirectURIs: []string{redirectURI}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"openid", "employee"}, DefaultScopes: []string{"openid", "employee"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Employee app",
	})
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"response_type": {"code"}, "client_id": {created.ClientID}, "redirect_uri": {redirectURI}, "state": {strings.Repeat("s", 32)}, "nonce": {"nonce"}, "code_challenge": {strings.Repeat("v", 43)}, "code_challenge_method": {"S256"}}
	view, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	if err != nil || !sameStrings(view.RequestedScopes, []string{"openid", "employee"}) {
		t.Fatalf("default dynamic scopes=%#v err=%v", view.RequestedScopes, err)
	}
	catalog["employee"] = false
	if _, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)); !errors.Is(err, ErrInvalidAuthorizationRequest) {
		t.Fatalf("deleted dynamic custom scope was accepted: %v", err)
	}
}

func TestDynamicCustomScopesAreRejectedForClientCredentials(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		CustomScopeExists: func(_ context.Context, scope string) (bool, error) { return scope == "employee", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{ClientID: "dynamic-employee-machine", GrantTypes: []string{"client_credentials"}, Scopes: []string{"employee"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "Employee machine"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"employee"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(client.ClientID, client.ClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_scope"`) {
		t.Fatalf("dynamic client credentials status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOIDCAuthorizationForceMFAPolicy(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }, BootstrapForceMFA: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+oidcAuthorizationValues(strings.Repeat("b", 43), "nonce").Encode(), nil))
	if err != nil || !bootstrap.ForceMFA {
		t.Fatalf("bootstrap policy force_mfa=%t err=%v", bootstrap.ForceMFA, err)
	}
	const clientID, redirectURI = "force-mfa-dynamic", "https://rp.example.test/callback"
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: clientID, RedirectURIs: []string{redirectURI}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"openid", "goauthy.read", "offline_access"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Force MFA", ForceMFA: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	values := authorizationValues(strings.Repeat("d", 43), "")
	values.Del("resource")
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirectURI)
	view, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	if err != nil || view.ForceMFA {
		t.Fatalf("dynamic policy force_mfa=%t err=%v", view.ForceMFA, err)
	}
	if _, err = server.store.dynamicClients.Update(ctx, clientID, registered.RegistrationAccessToken, dcr.CreateRequest{
		ClientID: clientID, RedirectURIs: []string{redirectURI}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"openid", "goauthy.read", "offline_access"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Force MFA", ForceMFA: false,
	}); err != nil {
		t.Fatal(err)
	}
	view, err = server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	if err != nil || view.ForceMFA {
		t.Fatalf("updated dynamic policy force_mfa=%t err=%v", view.ForceMFA, err)
	}
}

func TestRFC8252AuthorizationRedirectPolicy(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "loopback-policy-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	newServer := func(enabled bool) *Server {
		t.Helper()
		server, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, "http://127.0.0.1/callback", nil, OIDCConfig{
			Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }, RFC8252LoopbackRedirects: enabled,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	request := func(clientID, redirect string) *http.Request {
		values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {strings.Repeat("v", 43)}, "code_challenge_method": {"S256"}}
		return httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)
	}
	requestWithoutRedirect := func(clientID string) *http.Request {
		values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {strings.Repeat("v", 43)}, "code_challenge_method": {"S256"}}
		return httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)
	}

	for _, enabled := range []bool{false, true} {
		server := newServer(enabled)
		if _, err := server.ValidateAuthorizationRequest(request(testClientID, "http://127.0.0.1:43123/callback")); !errors.Is(err, ErrInvalidAuthorizationRequest) {
			t.Fatalf("static bootstrap accepted port change when enabled=%t: %v", enabled, err)
		}
	}

	server := newServer(true)
	created, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-public", RedirectURIs: []string{"http://127.0.0.1/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Native app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ValidateAuthorizationRequest(request(created.ClientID, "http://127.0.0.1:43123/callback")); err != nil {
		t.Fatalf("enabled public dynamic client rejected a loopback port change: %v", err)
	}
	if _, err := server.ValidateAuthorizationRequest(requestWithoutRedirect(created.ClientID)); !errors.Is(err, ErrInvalidAuthorizationRequest) {
		t.Fatalf("public dynamic loopback client accepted an omitted redirect_uri: %v", err)
	}
	explicitPort, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID: "dynamic-public-explicit-port", RedirectURIs: []string{"http://127.0.0.1:43123/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, Name: "Native app fixed port",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ValidateAuthorizationRequest(requestWithoutRedirect(explicitPort.ClientID)); err != nil {
		t.Fatalf("public dynamic explicit-port loopback rejected an omitted redirect_uri: %v", err)
	}
	dynamic := &fosite.DefaultClient{ID: "dynamic-public", Public: true, RedirectURIs: []string{"http://127.0.0.1/callback"}}
	server.redirectPolicy.AllowLoopback = false
	if server.redirectPolicy.Matches(dynamic.GetRedirectURIs(), "http://127.0.0.1:43123/callback", server.publicDynamicClient(dynamic)) {
		t.Fatal("disabled public dynamic client accepted a loopback port change")
	}
	dynamic.Public = false
	server.redirectPolicy.AllowLoopback = true
	if server.redirectPolicy.Matches(dynamic.GetRedirectURIs(), "http://127.0.0.1:43123/callback", server.publicDynamicClient(dynamic)) {
		t.Fatal("confidential dynamic client accepted a loopback port change")
	}
}

func TestClientCredentialsTokenUsesClientLifespan(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "lifespan-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	lifetime := 2 * time.Second
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer:                         oidcTestIssuer,
		LoadSigningKey:                 func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ClientCredentialsTokenLifespan: lifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fosite.GetEffectiveLifespan(server.store.client, fosite.GrantTypeClientCredentials, fosite.AccessToken, time.Hour); got != lifetime {
		t.Fatalf("client-credentials lifespan=%s want=%s", got, lifetime)
	}
	if got := fosite.GetEffectiveLifespan(server.store.client, fosite.GrantTypeAuthorizationCode, fosite.AccessToken, time.Hour); got != time.Hour {
		t.Fatalf("authorization-code lifespan changed to %s", got)
	}
	for _, grant := range []fosite.GrantType{fosite.GrantTypeAuthorizationCode, fosite.GrantTypeRefreshToken} {
		if got := fosite.GetEffectiveLifespan(server.store.client, grant, fosite.RefreshToken, 30*24*time.Hour); got != 30*24*time.Hour {
			t.Fatalf("%s refresh-token lifespan changed to %s", grant, got)
		}
	}
	if got := fosite.GetEffectiveLifespan(server.store.client, fosite.GrantTypeRefreshToken, fosite.AccessToken, time.Hour); got != time.Hour {
		t.Fatalf("refresh-grant access-token lifespan changed to %s", got)
	}
}

func TestClientCredentialsTokenLifetimeCannotOutliveSigningKeyRetention(t *testing.T) {
	_, err := NewServerWithOIDC(context.Background(), oauthTestDB(t), randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ClientCredentialsTokenLifespan: oidc.MaxAccessTokenLifetime + time.Second,
	})
	if err == nil {
		t.Fatal("access-token lifetime above signing-key retention maximum was accepted")
	}
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}
