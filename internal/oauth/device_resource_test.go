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

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestManagedDeviceResourceAudienceHTTP(t *testing.T) {
	const audience = resourceAuthorizationAudience
	const defaultAudience = "https://default-device.example.test/api"
	db := oauthTestDB(t)
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resourceAuthorizationAudience, wrongResourceAuthorizationAudience}, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }})
	if err != nil {
		t.Fatal(err)
	}
	managed := clients.NewStore(db, &oidc.Keyring{})
	server.store.managedClients = managed
	guard := func() (string, []any) { return "1", nil }
	client, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{
		ID: "device-resource-http", RedirectURIs: []string{}, Scopes: []string{"goauthy.connections.read", "offline_access"},
		DefaultScopes: []string{"goauthy.connections.read"}, GrantTypes: []string{DeviceGrantType, "refresh_token"}, Audiences: []string{audience},
		DefaultAudiences: []string{defaultAudience},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	seedDeviceUser(t, db, "device-resource-user", nil)
	h, err := device.NewHandler(device.NewStore(db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := func(resource string, duplicate bool) (string, string, *httptest.ResponseRecorder) {
		form := url.Values{"client_id": {client.ID}, "scope": {"goauthy.connections.read offline_access"}, "resource": {resource}}
		if resource == "" {
			form.Del("resource")
		}
		if duplicate {
			form.Add("resource", resource)
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			return "", "", w
		}
		var out struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.DeviceCode, out.UserCode, w
	}
	post := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("client_id", client.ID)
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(w, r)
		return w
	}
	server.defaultAudiences = map[string]string{client.ID: audience}
	defaultCode, defaultUser, response := start("", false)
	if response.Code != http.StatusOK {
		t.Fatalf("default-audience device grant status=%d body=%s", response.Code, response.Body.String())
	}
	if err := device.NewStore(db).Approve(context.Background(), defaultUser, "device-resource-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	defaultToken := decodeToken(t, post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {defaultCode}}))
	defaultRequest := httptest.NewRequest(http.MethodGet, "/resource", nil)
	defaultRequest.Header.Set("Authorization", "Bearer "+defaultToken.AccessToken)
	if _, _, err := server.AuthorizeUserResource(defaultRequest, "goauthy.connections.read", audience); err != nil {
		t.Fatalf("default audience token rejected: %v", err)
	}
	policyCode, policyUser, response := start(audience, false)
	if response.Code != http.StatusOK {
		t.Fatal("policy-check grant creation failed")
	}
	if err := device.NewStore(db).Approve(t.Context(), policyUser, "device-resource-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	delete(server.allowedResources, audience)
	denied := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {policyCode}})
	if denied.Code != http.StatusBadRequest || oauthErrorCode(t, denied) != "invalid_target" {
		t.Fatalf("removed server policy status=%d", denied.Code)
	}
	server.allowedResources[audience] = struct{}{}
	decodeToken(t, post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {policyCode}}))
	deviceCode, userCode, response := start(audience, false)
	if response.Code != http.StatusOK || deviceCode == "" || userCode == "" {
		t.Fatalf("device grant status=%d body=%s", response.Code, response.Body.String())
	}
	if _, _, response = start(wrongResourceAuthorizationAudience, false); response.Code == http.StatusOK {
		t.Fatal("unregistered device resource accepted")
	}
	if _, _, response = start(audience, true); response.Code == http.StatusOK {
		t.Fatal("duplicate device resource accepted")
	}
	if err := device.NewStore(db).Approve(context.Background(), userCode, "device-resource-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {deviceCode}, "resource": {wrongResourceAuthorizationAudience}}).Code == http.StatusOK {
		t.Fatal("token endpoint accepted a resource override")
	}
	tokenResponse := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {deviceCode}})
	issued := decodeToken(t, tokenResponse)
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatalf("device token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	resourceRequest := httptest.NewRequest(http.MethodGet, "/resource", nil)
	resourceRequest.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	if _, _, err := server.AuthorizeUserResource(resourceRequest, "goauthy.connections.read", audience); err != nil {
		t.Fatalf("issued resource token rejected: %v", err)
	}
	if post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "resource": {wrongResourceAuthorizationAudience}}).Code == http.StatusOK {
		t.Fatal("refresh added an unregistered resource")
	}
	refreshed := decodeToken(t, post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	if refreshed.AccessToken == "" {
		t.Fatal("refresh did not preserve resource audience")
	}
	refreshedRequest := httptest.NewRequest(http.MethodGet, "/resource", nil)
	refreshedRequest.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	if _, _, err := server.AuthorizeUserResource(refreshedRequest, "goauthy.connections.read", audience); err != nil {
		t.Fatalf("refreshed resource token rejected: %v", err)
	}
	if _, _, err := server.AuthorizeUserResource(refreshedRequest, "goauthy.connections.read", wrongResourceAuthorizationAudience); err == nil {
		t.Fatal("refreshed token accepted wrong required audience")
	}
	for _, token := range []string{issued.AccessToken, refreshed.AccessToken} {
		claims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(t.Context(), token)
		if err != nil || !sameAccessStrings(claims.Audience, []string{client.ID, defaultAudience, audience}) {
			t.Fatal("Device access/refresh omitted independent default audience")
		}
	}
	_, authority, err := server.AuthorizeUserResource(refreshedRequest, "goauthy.connections.read", defaultAudience)
	if err != nil || authority == nil {
		t.Fatal("default audience resource authorization failed")
	}
	sql, args := authority()
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatal("default audience missing from access-token mutation guard")
	}

	pendingCode, pendingUser, response := start(audience, false)
	if response.Code != http.StatusOK {
		t.Fatalf("pending grant status=%d", response.Code)
	}
	if err := device.NewStore(db).Approve(context.Background(), pendingUser, "device-resource-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{Confidential: false, RedirectURIs: []string{}, Enabled: true, Scopes: client.Scopes, DefaultScopes: client.DefaultScopes, GrantTypes: client.GrantTypes, Audiences: []string{}}, guard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.AuthorizeUserResource(resourceRequest, "goauthy.connections.read", audience); err == nil {
		t.Fatal("old device token survived audience removal")
	}
	if post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}).Code == http.StatusOK {
		t.Fatal("refresh survived audience removal")
	}
	before, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(before.Rows) != 1 {
		t.Fatalf("access-token count before stale redemption: rows=%v err=%v", before.Rows, err)
	}
	stale := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {pendingCode}})
	if stale.Code == http.StatusOK {
		t.Fatal("pending device grant survived audience removal")
	}
	after, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(after.Rows) != 1 || after.Rows[0][0] != before.Rows[0][0] {
		t.Fatalf("stale redemption minted a token: before=%v after=%v err=%v", before.Rows, after.Rows, err)
	}
}

func TestDeviceResourceURLBoundary(t *testing.T) {
	for _, value := range []string{"https://resource.example.test?", "https://resource.example.test#", "https://:443", "https://resource.example.test/a b", "https://resource.example.test/a\u00a0b"} {
		if validResourceURL(value) {
			t.Fatalf("invalid resource accepted: %q", value)
		}
	}
	if !validResourceURL("https://resource.example.test/api/one,two") {
		t.Fatal("valid exact resource rejected")
	}
}

func TestAuthorizeDeviceClientAllowsPlatformPermissionAndRejectsUnknownCustomScope(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	server.oidc = &OIDCConfig{CustomScopeExists: claims.NewStore(db).ScopeExists}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "device-permission-catalog", SQL: `INSERT INTO custom_scopes(name,attr_include_id_json,attr_include_access_json,revision) VALUES('goauthy.providers.read','[]','[]',1),('employee','[]','[]',1)`}); err != nil {
		t.Fatal(err)
	}
	client := &fosite.DefaultClient{ID: "device-permission", GrantTypes: []string{DeviceGrantType}, Scopes: []string{"goauthy.providers.read", "employee"}}
	if err := server.authorizeDeviceScopes(t.Context(), client, []string{"goauthy.providers.read"}); err != nil {
		t.Fatalf("platform permission rejected: %v", err)
	}
	if err := server.authorizeDeviceScopes(t.Context(), client, []string{"employee"}); err == nil {
		t.Fatal("unknown custom scope accepted")
	}
}

func TestDeviceResourceCatalogRaceLeavesNoArtifacts(t *testing.T) {
	value := json.RawMessage(`"unused"`)
	server := customClaimsServer(t, false, &value)
	server.oidc.ResolveCustomClaims = claims.NewStore(server.store.db).Resolve
	grant, err := device.NewStore(server.store.db).Create(t.Context(), testClientID, []string{"goauthy.read", "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(server.store.db).Approve(t.Context(), grant.UserCode, "user-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(t.Context(), server.store.db, rhiza.ExecuteRequest{RequestID: "device-catalog-race", SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1`}); err != nil {
			t.Fatal(err)
		}
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}); response.Code == http.StatusOK {
		t.Fatal("stale catalog issued device tokens")
	}
	assertRBACTokenRows(t, server, 0, 0, 0)
}
