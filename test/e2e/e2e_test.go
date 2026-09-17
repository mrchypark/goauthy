// Package e2e tests the deployed process through its public HTTP surface.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCurrentProfile(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if baseURL == "" || secret == "" {
		t.Skip("set GOAUTHY_E2E_URL and GOAUTHY_E2E_CLIENT_SECRET to run deployed E2E tests")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	assertStatus(t, client, http.MethodGet, baseURL+"/livez", nil, http.StatusNoContent)
	if os.Getenv("GOAUTHY_E2E_EXPECT_NOT_READY") == "true" {
		assertStatus(t, client, http.MethodGet, baseURL+"/readyz", nil, http.StatusServiceUnavailable)
		return
	}
	assertStatus(t, client, http.MethodGet, baseURL+"/readyz", nil, http.StatusNoContent)
	assertDiscovery(t, client, baseURL)
	assertOpenIDDiscovery(t, client, baseURL)

	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS status = %d", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/jwk-set+json") || response.Header.Get("ETag") == "" {
		t.Fatalf("JWKS headers = %#v", response.Header)
	}
	var jwks struct {
		Keys []struct {
			Algorithm string `json:"alg"`
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
			Use       string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatalf("unexpected JWKS = %#v", jwks)
	}
	kids := make(map[string]struct{}, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Algorithm != "EdDSA" || key.KeyType != "OKP" || key.KeyID == "" || key.Use != "sig" {
			t.Fatalf("unexpected JWKS = %#v", jwks)
		}
		if _, duplicate := kids[key.KeyID]; duplicate {
			t.Fatalf("duplicate JWKS kid = %q", key.KeyID)
		}
		kids[key.KeyID] = struct{}{}
	}
	if expected := os.Getenv("GOAUTHY_E2E_EXPECT_JWKS_KID"); expected != "" {
		if _, persisted := kids[expected]; !persisted {
			t.Fatalf("JWKS does not contain persisted kid %q: %#v", expected, jwks)
		}
	}

	request, err = http.NewRequest(http.MethodGet, baseURL+"/oidc/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-None-Match", response.Header.Get("ETag"))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("JWKS conditional status = %d", response.StatusCode)
	}

	assertTokenStatus(t, client, baseURL, "", "", http.StatusBadRequest)
	assertTokenStatus(t, client, baseURL, "goauthy-dev", "wrong-client-secret", http.StatusUnauthorized)
	assertTokenStatus(t, client, baseURL, "goauthy-dev", secret, http.StatusBadRequest, "admin")
	assertOAuthClientAuthRequired(t, client, baseURL+"/oidc/introspect")
	assertOAuthClientAuthRequired(t, client, baseURL+"/oidc/revoke")
	const resource = "https://api.example.test/v1"
	assertResourceToken(t, client, baseURL, secret, "https://unknown.example.test", http.StatusBadRequest, "invalid_target")
	accessToken := assertResourceToken(t, client, baseURL, secret, resource, http.StatusOK, "")
	assertIntrospection(t, client, baseURL, secret, accessToken, true, resource)
	assertRevocation(t, client, baseURL, secret, accessToken)
	assertIntrospection(t, client, baseURL, secret, accessToken, false)
}

func assertOAuthClientAuthRequired(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	for _, credentials := range [][2]string{{}, {"goauthy-dev", "wrong-client-secret"}} {
		request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader("token=unknown"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if credentials[0] != "" {
			request.SetBasicAuth(credentials[0], credentials[1])
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s authentication status = %d", endpoint, response.StatusCode)
		}
	}
}

func TestCrossPodRevocation(t *testing.T) {
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || secret == "" {
		t.Skip("set both E2E URLs and the client secret to run cross-pod tests")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	const resource = "https://api.example.test/v1"
	token := assertResourceToken(t, client, primary, secret, resource, http.StatusOK, "")
	assertIntrospection(t, client, secondary, secret, token, true, resource)
	assertRevocation(t, client, secondary, secret, token)
	assertIntrospection(t, client, primary, secret, token, false)
}

func TestClientCredentialsPublic(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if baseURL == "" || secret == "" {
		t.Skip("set GOAUTHY_E2E_URL and GOAUTHY_E2E_CLIENT_SECRET to run client-credentials E2E")
	}
	client := &http.Client{Timeout: 10 * time.Second}

	token := assertTokenStatus(t, client, baseURL, "goauthy-dev", secret, http.StatusOK)
	assertIntrospection(t, client, baseURL, secret, token, true)
	assertTokenStatus(t, client, baseURL, "goauthy-dev", "wrong-client-secret", http.StatusUnauthorized)
	assertTokenStatus(t, client, baseURL, "goauthy-dev", secret, http.StatusBadRequest, "admin")
	if raw := os.Getenv("GOAUTHY_E2E_CLIENT_CREDENTIALS_TOKEN_LIFETIME"); raw != "" {
		lifetime, err := time.ParseDuration(raw)
		if err != nil || lifetime <= 0 || lifetime > 10*time.Second {
			t.Fatalf("invalid E2E client-credentials lifetime %q", raw)
		}
		waitForInactiveIntrospection(t, client, baseURL, secret, token, lifetime+5*time.Second)
	}
}

func waitForInactiveIntrospection(t *testing.T, client *http.Client, baseURL, secret, token string, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		response := postBasicForm(t, client, baseURL+"/oidc/introspect", secret, url.Values{"token": {token}})
		var payload map[string]json.RawMessage
		err := json.NewDecoder(response.Body).Decode(&payload)
		response.Body.Close()
		var active bool
		if err == nil {
			err = json.Unmarshal(payload["active"], &active)
		}
		last = fmt.Sprintf("status=%d active=%t err=%v", response.StatusCode, active, err)
		if response.StatusCode == http.StatusOK && err == nil && !active {
			assertIntrospection(t, client, baseURL, secret, token, false)
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatalf("timed out waiting for inactive introspection: %s", last)
		case <-ticker.C:
		}
	}
}

func TestDynamicClientRegistrationAcrossPods(t *testing.T) {
	expectedScope := "openid goauthy.read"
	if os.Getenv("GOAUTHY_E2E_DEVICE_LOGIN_FLOW") == "1" {
		expectedScope = "openid profile email groups goauthy.read offline_access"
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	globalToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if primary == "" || secondary == "" || globalToken == "" {
		t.Skip("set both E2E URLs and GOAUTHY_E2E_DCR_REGISTRATION_TOKEN to run DCR E2E")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	assertDCRDiscovery(t, client, primary)
	requestBody, err := json.Marshal(struct {
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}{
		RedirectURIs:            []string{"https://rp.example.test/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientName:              "GoAuthy E2E RP",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := primary + "/oidc/register"
	for _, bearer := range []string{"", "wrong-registration-token"} {
		response := dcrRequest(t, client, http.MethodPost, endpoint, requestBody, bearer)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" {
			t.Fatalf("DCR create authorization status=%d headers=%#v", response.StatusCode, response.Header)
		}
	}
	var scopeRequest map[string]any
	if err := json.Unmarshal(requestBody, &scopeRequest); err != nil {
		t.Fatal(err)
	}
	scopeRequest["scope"] = "openid goauthy.read"
	clientScopeBody, err := json.Marshal(scopeRequest)
	if err != nil {
		t.Fatal(err)
	}
	rejectedScope := dcrRequest(t, client, http.MethodPost, endpoint, clientScopeBody, globalToken)
	rejectedScope.Body.Close()
	if rejectedScope.StatusCode != http.StatusBadRequest {
		t.Fatalf("DCR accepted client-controlled scope: status=%d", rejectedScope.StatusCode)
	}

	createKey := dcrIdempotencyKey(t.Name()+"/create", "/oidc/register", requestBody)
	response := dcrRequestWithKey(t, client, http.MethodPost, endpoint, requestBody, globalToken, createKey)
	firstBody, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("DCR create status=%d headers=%#v", response.StatusCode, response.Header)
	}
	var created dcrRegistration
	if err := json.Unmarshal(firstBody, &created); err != nil {
		t.Fatal(err)
	}
	if created.ClientID == "" || created.ClientSecret == "" || created.RegistrationAccessToken == "" || created.RegistrationClientURI != endpoint+"/"+created.ClientID || !slices.Equal(created.RedirectURIs, []string{"https://rp.example.test/callback"}) || !slices.Equal(created.GrantTypes, []string{"authorization_code"}) || !slices.Equal(created.ResponseTypes, []string{"code"}) || created.TokenEndpointAuthMethod != "client_secret_basic" || created.Scope != expectedScope || created.ClientName != "GoAuthy E2E RP" {
		t.Fatal("unexpected DCR create metadata")
	}
	replay := dcrRequestWithKey(t, client, http.MethodPost, secondary+"/oidc/register", requestBody, globalToken, createKey)
	replayBody, err := io.ReadAll(io.LimitReader(replay.Body, 16<<10))
	replay.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if replay.StatusCode != http.StatusCreated || !bytes.Equal(replayBody, firstBody) {
		t.Fatalf("DCR idempotent replay status=%d byte_identical=%t", replay.StatusCode, bytes.Equal(replayBody, firstBody))
	}
	var mismatchRequest map[string]any
	if err := json.Unmarshal(requestBody, &mismatchRequest); err != nil {
		t.Fatal(err)
	}
	mismatchRequest["client_name"] = "GoAuthy E2E Mismatch"
	mismatchBody, err := json.Marshal(mismatchRequest)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := dcrRequestWithKey(t, client, http.MethodPost, secondary+"/oidc/register", mismatchBody, globalToken, createKey)
	mismatchBodyRaw, err := io.ReadAll(io.LimitReader(mismatch.Body, 16<<10))
	mismatch.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.StatusCode != http.StatusUnprocessableEntity || string(mismatchBodyRaw) != `{"error":"invalid_request"}`+"\n" {
		t.Fatalf("DCR idempotent mismatch status=%d body=%q", mismatch.StatusCode, mismatchBodyRaw)
	}

	metadataURL := secondary + "/oidc/register/" + created.ClientID
	wrong := dcrRequest(t, client, http.MethodGet, metadataURL, nil, "wrong-registration-access-token")
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized || wrong.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("DCR metadata authorization status=%d headers=%#v", wrong.StatusCode, wrong.Header)
	}
	metadata := dcrRequest(t, client, http.MethodGet, metadataURL, nil, created.RegistrationAccessToken)
	defer metadata.Body.Close()
	body, err := io.ReadAll(io.LimitReader(metadata.Body, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.StatusCode != http.StatusOK || metadata.Header.Get("Cache-Control") != "no-store" || metadata.Header.Get("Pragma") != "no-cache" || bytes.Contains(body, []byte(created.ClientSecret)) || bytes.Contains(body, []byte(created.RegistrationAccessToken)) {
		t.Fatalf("DCR metadata status=%d headers=%#v credentials_exposed=%t", metadata.StatusCode, metadata.Header, bytes.Contains(body, []byte(created.ClientSecret)) || bytes.Contains(body, []byte(created.RegistrationAccessToken)))
	}
	var loaded dcrRegistration
	if err := json.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.ClientID != created.ClientID || loaded.ClientSecret != "" || loaded.RegistrationAccessToken != "" || loaded.RegistrationClientURI != "" || !slices.Equal(loaded.RedirectURIs, created.RedirectURIs) || !slices.Equal(loaded.GrantTypes, created.GrantTypes) || !slices.Equal(loaded.ResponseTypes, created.ResponseTypes) || loaded.TokenEndpointAuthMethod != created.TokenEndpointAuthMethod || loaded.Scope != created.Scope || loaded.ClientName != created.ClientName {
		t.Fatal("unexpected DCR metadata")
	}

	updatedRedirect := "https://rp.example.test/updated-callback"
	updateBody, err := json.Marshal(struct {
		ClientID                string   `json:"client_id"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}{
		ClientID:                created.ClientID,
		RedirectURIs:            []string{updatedRedirect},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: created.TokenEndpointAuthMethod,
		ClientName:              "GoAuthy Updated E2E RP",
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongUpdate := dcrRequest(t, client, http.MethodPut, metadataURL, updateBody, "wrong-registration-access-token")
	wrongUpdate.Body.Close()
	if wrongUpdate.StatusCode != http.StatusUnauthorized || wrongUpdate.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("DCR update authorization status=%d headers=%#v", wrongUpdate.StatusCode, wrongUpdate.Header)
	}
	authMethodChange, err := json.Marshal(struct {
		ClientID                string   `json:"client_id"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}{
		ClientID:                created.ClientID,
		RedirectURIs:            []string{updatedRedirect},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ClientName:              "GoAuthy Updated E2E RP",
	})
	if err != nil {
		t.Fatal(err)
	}
	rejectedMethod := dcrRequest(t, client, http.MethodPut, metadataURL, authMethodChange, created.RegistrationAccessToken)
	rejectedMethod.Body.Close()
	if rejectedMethod.StatusCode != http.StatusBadRequest {
		t.Fatalf("DCR auth-method update status=%d", rejectedMethod.StatusCode)
	}
	updated := dcrRequest(t, client, http.MethodPut, metadataURL, updateBody, created.RegistrationAccessToken)
	defer updated.Body.Close()
	updatedBody, err := io.ReadAll(io.LimitReader(updated.Body, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	if updated.StatusCode != http.StatusOK || bytes.Contains(updatedBody, []byte(created.ClientSecret)) || bytes.Contains(updatedBody, []byte(created.RegistrationAccessToken)) {
		t.Fatalf("DCR update status=%d old_credentials_exposed=%t", updated.StatusCode, bytes.Contains(updatedBody, []byte(created.ClientSecret)) || bytes.Contains(updatedBody, []byte(created.RegistrationAccessToken)))
	}
	var updateResponse dcrRegistration
	if err := json.Unmarshal(updatedBody, &updateResponse); err != nil {
		t.Fatal(err)
	}
	if updateResponse.ClientSecret == "" || updateResponse.ClientSecret == created.ClientSecret || updateResponse.RegistrationAccessToken == "" || updateResponse.RegistrationAccessToken == created.RegistrationAccessToken || updateResponse.RegistrationClientURI != endpoint+"/"+created.ClientID || bytes.Count(updatedBody, []byte(updateResponse.ClientSecret)) != 1 || bytes.Count(updatedBody, []byte(updateResponse.RegistrationAccessToken)) != 1 || !slices.Equal(updateResponse.RedirectURIs, []string{updatedRedirect}) || updateResponse.Scope != created.Scope || updateResponse.ClientName != "GoAuthy Updated E2E RP" || updateResponse.TokenEndpointAuthMethod != created.TokenEndpointAuthMethod {
		t.Fatal("unexpected DCR update metadata")
	}
	oldMetadata := dcrRequest(t, client, http.MethodGet, primary+"/oidc/register/"+created.ClientID, nil, created.RegistrationAccessToken)
	oldMetadata.Body.Close()
	if oldMetadata.StatusCode != http.StatusUnauthorized || oldMetadata.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("old DCR registration token status=%d headers=%#v", oldMetadata.StatusCode, oldMetadata.Header)
	}
	assertDCRClientSecretStatus(t, client, primary, created.ClientID, created.ClientSecret, http.StatusUnauthorized, "invalid_client")
	assertDCRClientSecretStatus(t, client, primary, created.ClientID, updateResponse.ClientSecret, http.StatusBadRequest, "invalid_grant")

	updatedMetadata := dcrRequest(t, client, http.MethodGet, primary+"/oidc/register/"+created.ClientID, nil, updateResponse.RegistrationAccessToken)
	defer updatedMetadata.Body.Close()
	updatedMetadataBody, err := io.ReadAll(io.LimitReader(updatedMetadata.Body, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	if updatedMetadata.StatusCode != http.StatusOK || bytes.Contains(updatedMetadataBody, []byte(created.ClientSecret)) || bytes.Contains(updatedMetadataBody, []byte(created.RegistrationAccessToken)) || bytes.Contains(updatedMetadataBody, []byte(updateResponse.ClientSecret)) || bytes.Contains(updatedMetadataBody, []byte(updateResponse.RegistrationAccessToken)) {
		t.Fatalf("cross-pod DCR update status=%d credentials_exposed=%t", updatedMetadata.StatusCode, bytes.Contains(updatedMetadataBody, []byte(created.ClientSecret)) || bytes.Contains(updatedMetadataBody, []byte(created.RegistrationAccessToken)) || bytes.Contains(updatedMetadataBody, []byte(updateResponse.ClientSecret)) || bytes.Contains(updatedMetadataBody, []byte(updateResponse.RegistrationAccessToken)))
	}
	var reloaded dcrRegistration
	if err := json.Unmarshal(updatedMetadataBody, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.ClientID != created.ClientID || reloaded.ClientSecret != "" || reloaded.RegistrationAccessToken != "" || reloaded.RegistrationClientURI != "" || !slices.Equal(reloaded.RedirectURIs, []string{updatedRedirect}) || !slices.Equal(reloaded.GrantTypes, []string{"authorization_code"}) || !slices.Equal(reloaded.ResponseTypes, []string{"code"}) || reloaded.TokenEndpointAuthMethod != created.TokenEndpointAuthMethod || reloaded.Scope != expectedScope || reloaded.ClientName != "GoAuthy Updated E2E RP" {
		t.Fatal("cross-pod DCR update did not persist exact metadata")
	}

	// RFC 7592 deletion is authorized by the current per-registration token,
	// never by the global create token. The delete happens through pod B after
	// pod A created the client, so subsequent reads prove the shared mutation.
	wrongDelete := dcrRequest(t, client, http.MethodDelete, metadataURL, nil, globalToken)
	assertDCRManagementUnauthorized(t, wrongDelete, created.ClientID, updateResponse.ClientSecret, updateResponse.RegistrationAccessToken)
	deleted := dcrRequest(t, client, http.MethodDelete, metadataURL, nil, updateResponse.RegistrationAccessToken)
	deletedBody, err := io.ReadAll(io.LimitReader(deleted.Body, 16<<10))
	deleted.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if deleted.StatusCode != http.StatusNoContent || len(deletedBody) != 0 || deleted.Header.Get("Cache-Control") != "no-store" || deleted.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("cross-pod DCR delete status=%d body=%q headers=%#v", deleted.StatusCode, deletedBody, deleted.Header)
	}

	// Every management method now has the same generic unauthorized boundary,
	// without revealing whether the former registration still exists.
	deletedMetadataURL := primary + "/oidc/register/" + created.ClientID
	assertDCRManagementUnauthorized(t, dcrRequest(t, client, http.MethodGet, deletedMetadataURL, nil, updateResponse.RegistrationAccessToken), created.ClientID, updateResponse.ClientSecret, updateResponse.RegistrationAccessToken)
	assertDCRManagementUnauthorized(t, dcrRequest(t, client, http.MethodPut, metadataURL, updateBody, updateResponse.RegistrationAccessToken), created.ClientID, updateResponse.ClientSecret, updateResponse.RegistrationAccessToken)
	assertDCRManagementUnauthorized(t, dcrRequest(t, client, http.MethodDelete, deletedMetadataURL, nil, updateResponse.RegistrationAccessToken), created.ClientID, updateResponse.ClientSecret, updateResponse.RegistrationAccessToken)

	// A deleted client must be rejected by both nodes before grant handling.
	assertDCRClientSecretStatus(t, client, primary, created.ClientID, updateResponse.ClientSecret, http.StatusUnauthorized, "invalid_client")
	assertDCRClientSecretStatus(t, client, secondary, created.ClientID, updateResponse.ClientSecret, http.StatusUnauthorized, "invalid_client")
}

func assertDCRManagementUnauthorized(t *testing.T, response *http.Response, clientID, secret, registrationToken string) {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" || bytes.Contains(body, []byte(clientID)) || bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte(registrationToken)) {
		t.Fatalf("DCR management unauthorized status=%d body=%q headers=%#v", response.StatusCode, body, response.Header)
	}
}

// assertDCRClientSecretStatus uses a deliberately invalid authorization code
// to distinguish client authentication: a valid secret reaches invalid_grant,
// while a retired secret is rejected as invalid_client before grant handling.
func assertDCRClientSecretStatus(t *testing.T, client *http.Client, baseURL, clientID, secret string, wantStatus int, wantError string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"invalid"}}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body); err != nil || response.StatusCode != wantStatus || body.Error != wantError {
		t.Fatalf("DCR client secret status=%d error=%q decode=%v, want status=%d error=%q", response.StatusCode, body.Error, err, wantStatus, wantError)
	}
}

type dcrRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	ClientName              string   `json:"client_name"`
}

func assertDCRDiscovery(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response, err := client.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&metadata) != nil || metadata.RegistrationEndpoint != baseURL+"/oidc/register" {
		t.Fatalf("DCR discovery status=%d endpoint=%q", response.StatusCode, metadata.RegistrationEndpoint)
	}
}

func dcrRequest(t *testing.T, client *http.Client, method, endpoint string, body []byte, bearer string) *http.Response {
	return dcrRequestWithKey(t, client, method, endpoint, body, bearer, "")
}

func dcrRequestWithKey(t *testing.T, client *http.Client, method, endpoint string, body []byte, bearer, key string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost || method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost {
		if key == "" {
			key = dcrIdempotencyKey(t.Name(), endpoint, body)
		}
		request.Header.Set("Idempotency-Key", key)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func dcrIdempotencyKey(testName, endpoint string, body []byte) string {
	h := sha256.New()
	for _, part := range []string{"goauthy-e2e-dcr-v1", testName, endpointPath(endpoint), string(body)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func endpointPath(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Path == "" {
		return endpoint
	}
	if parsed.RawQuery != "" {
		return parsed.Path + "?" + parsed.RawQuery
	}
	return parsed.Path
}

func assertResourceToken(t *testing.T, client *http.Client, baseURL, secret, resource string, want int, wantError string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}, "resource": {resource}}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want || payload.Error != wantError || want == http.StatusOK && payload.AccessToken == "" {
		t.Fatalf("resource token status=%d payload=%#v", response.StatusCode, payload)
	}
	return payload.AccessToken
}

func assertDiscovery(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response, err := client.Get(baseURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", response.StatusCode)
	}
	etag := response.Header.Get("ETag")
	if etag == "" || response.Header.Get("Cache-Control") != "public, max-age=300, must-revalidate" {
		t.Fatalf("discovery cache headers = %#v", response.Header)
	}
	var metadata map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	var issuer string
	if err := json.Unmarshal(metadata["issuer"], &issuer); err != nil || issuer != baseURL {
		t.Fatalf("discovery issuer = %q, err=%v", issuer, err)
	}
	for field, want := range map[string]string{
		"authorization_endpoint": baseURL + "/oidc/authorize",
		"token_endpoint":         baseURL + "/oidc/token",
		"jwks_uri":               baseURL + "/oidc/jwks.json",
		"introspection_endpoint": baseURL + "/oidc/introspect",
		"revocation_endpoint":    baseURL + "/oidc/revoke",
	} {
		var got string
		if err := json.Unmarshal(metadata[field], &got); err != nil || got != want {
			t.Fatalf("discovery %s = %q, want %q (err=%v)", field, got, want, err)
		}
	}
	for field, want := range map[string][]string{
		"grant_types_supported":                 {"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange", "password"},
		"response_types_supported":              {"code"},
		"code_challenge_methods_supported":      {"S256"},
		"token_endpoint_auth_methods_supported": {"none", "client_secret_basic", "client_secret_post"},
	} {
		var got []string
		if err := json.Unmarshal(metadata[field], &got); err != nil || !slices.Equal(got, want) {
			t.Fatalf("discovery %s = %#v, want %#v (err=%v)", field, got, want, err)
		}
	}
	if _, exists := metadata["id_token_signing_alg_values_supported"]; exists {
		t.Fatal("OAuth-only metadata unexpectedly contains OpenID Provider fields")
	}
	request, err := http.NewRequest(http.MethodGet, baseURL+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-None-Match", etag)
	conditional, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	conditional.Body.Close()
	if conditional.StatusCode != http.StatusNotModified {
		t.Fatalf("discovery conditional status = %d", conditional.StatusCode)
	}
}

func assertOpenIDDiscovery(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response, err := client.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata struct {
		Issuer               string   `json:"issuer"`
		Scopes               []string `json:"scopes_supported"`
		SubjectTypes         []string `json:"subject_types_supported"`
		IDTokenSigningAlgs   []string `json:"id_token_signing_alg_values_supported"`
		UserInfoEndpoint     string   `json:"userinfo_endpoint"`
		EndSessionEndpoint   string   `json:"end_session_endpoint"`
		RegistrationEndpoint string   `json:"registration_endpoint"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&metadata) != nil {
		t.Fatalf("OpenID discovery status=%d", response.StatusCode)
	}
	registrationEndpoint := ""
	if os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN") != "" {
		registrationEndpoint = baseURL + "/oidc/register"
	}
	if metadata.Issuer != baseURL || !slices.Contains(metadata.Scopes, "openid") || !slices.Contains(metadata.SubjectTypes, "public") || !slices.Contains(metadata.IDTokenSigningAlgs, "EdDSA") || metadata.UserInfoEndpoint != baseURL+"/oidc/userinfo" || metadata.EndSessionEndpoint != baseURL+"/oidc/logout" || metadata.RegistrationEndpoint != registrationEndpoint {
		t.Fatalf("unexpected OpenID metadata: %#v", metadata)
	}
}

func assertStatus(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, want int) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("%s %s status = %d, want %d", method, endpoint, response.StatusCode, want)
	}
}

func assertTokenStatus(t *testing.T, client *http.Client, baseURL, clientID, secret string, want int, scope ...string) string {
	t.Helper()
	requestedScope := "goauthy.read"
	if len(scope) != 0 {
		requestedScope = scope[0]
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {requestedScope}}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		request.SetBasicAuth(clientID, secret)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("token status = %d, want %d: %s", response.StatusCode, want, body)
	}
	if want != http.StatusOK {
		return ""
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 {
		t.Fatalf("unexpected token response = %#v", token)
	}
	return token.AccessToken
}

func assertIntrospection(t *testing.T, client *http.Client, baseURL, secret, token string, active bool, audience ...string) {
	t.Helper()
	response := postBasicForm(t, client, baseURL+"/oidc/introspect", secret, url.Values{"token": {token}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("introspection status = %d", response.StatusCode)
	}
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	var gotActive bool
	if err := json.Unmarshal(payload["active"], &gotActive); err != nil || gotActive != active {
		t.Fatalf("introspection active = %t, want %t (err=%v)", gotActive, active, err)
	}
	if !active {
		if len(payload) != 1 {
			t.Fatalf("inactive introspection disclosed fields: %#v", payload)
		}
		return
	}
	for field, want := range map[string]string{"client_id": "goauthy-dev", "scope": "goauthy.read"} {
		var got string
		if err := json.Unmarshal(payload[field], &got); err != nil || got != want {
			t.Fatalf("introspection %s = %q, want %q (err=%v)", field, got, want, err)
		}
	}
	var expiresAt int64
	serverTime, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		t.Fatalf("introspection Date header = %q: %v", response.Header.Get("Date"), err)
	}
	if err := json.Unmarshal(payload["exp"], &expiresAt); err != nil || expiresAt <= serverTime.Unix() {
		t.Fatalf("introspection exp = %d, want expiry after server time %d (err=%v)", expiresAt, serverTime.Unix(), err)
	}
	if len(audience) != 0 {
		var got []string
		if err := json.Unmarshal(payload["aud"], &got); err != nil || len(got) != 1 || got[0] != audience[0] {
			t.Fatalf("introspection aud = %#v, want %#v (err=%v)", got, audience, err)
		}
	}
}

func assertRevocation(t *testing.T, client *http.Client, baseURL, secret, token string) {
	t.Helper()
	response := postBasicForm(t, client, baseURL+"/oidc/revoke", secret, url.Values{"token": {token}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revocation status = %d", response.StatusCode)
	}
}

func postBasicForm(t *testing.T, client *http.Client, endpoint, secret string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
