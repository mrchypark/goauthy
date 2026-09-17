package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPasswordGrantAcrossPods exercises the OAuth2 Resource Owner Password
// Credentials grant through the deployed token endpoint.  The grant type is
// advertised in discovery, so the test asserts the full contract: valid
// issuance, introspection, revocation, and negative boundaries (wrong
// credentials, missing fields, public-client rejection).
func TestPasswordGrantAcrossPods(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	if baseURL == "" || secondary == "" || secret == "" || username == "" || password == "" {
		t.Skip("set GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, GOAUTHY_E2E_CLIENT_SECRET, GOAUTHY_E2E_BROWSER_USERNAME, and GOAUTHY_E2E_BROWSER_PASSWORD to run password-grant E2E")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// --- Discovery advertises the password grant type ---
	assertPasswordGrantDiscovery(t, client, baseURL)

	// --- Positive: valid password grant returns access token ---
	accessToken := assertPasswordGrantToken(t, client, baseURL, "goauthy-dev", secret, username, password, http.StatusOK)
	if accessToken == "" {
		t.Fatal("password grant returned empty access token")
	}

	// --- Introspection: the token is active ---
	assertPasswordGrantIntrospection(t, client, baseURL, secret, accessToken, true)

	// --- Cross-pod: the same token is active on the secondary ---
	assertPasswordGrantIntrospection(t, client, secondary, secret, accessToken, true)

	// --- Revocation: the token is revoked from any pod ---
	assertPasswordGrantRevocation(t, client, secondary, secret, accessToken)

	// --- Post-revocation: the token is inactive ---
	assertPasswordGrantIntrospection(t, client, baseURL, secret, accessToken, false)

	// --- Negative: wrong password ---
	assertPasswordGrantToken(t, client, baseURL, "goauthy-dev", secret, username, "wrong-password", http.StatusUnauthorized)

	// --- Negative: wrong client secret ---
	assertPasswordGrantToken(t, client, baseURL, "goauthy-dev", "wrong-secret", username, password, http.StatusUnauthorized)

	// --- Negative: missing username ---
	assertPasswordGrantMissingField(t, client, baseURL, secret, map[string]string{"grant_type": "password", "password": password})

	// --- Negative: missing password ---
	assertPasswordGrantMissingField(t, client, baseURL, secret, map[string]string{"grant_type": "password", "username": username})

	// --- Negative: missing grant_type ---
	assertPasswordGrantMissingField(t, client, baseURL, secret, map[string]string{"username": username, "password": password})
}

func assertPasswordGrantDiscovery(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response, err := client.Get(baseURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata struct {
		GrantTypes []string `json:"grant_types_supported"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&metadata) != nil {
		t.Fatalf("discovery status=%d", response.StatusCode)
	}
	found := false
	for _, gt := range metadata.GrantTypes {
		if gt == "password" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("discovery grant_types_supported does not include 'password': %#v", metadata.GrantTypes)
	}
}

func assertPasswordGrantToken(t *testing.T, client *http.Client, baseURL, clientID, secret, username, password string, wantStatus int) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid goauthy.read"},
	}
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
	if response.StatusCode != wantStatus {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("password grant status=%d, want %d: %s", response.StatusCode, wantStatus, body)
	}
	if wantStatus != http.StatusOK {
		return ""
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 {
		t.Fatalf("unexpected password grant token response: %#v", token)
	}
	if token.RefreshToken == "" {
		t.Fatal("password grant did not return a refresh token")
	}
	if token.IDToken == "" {
		t.Fatal("password grant with openid scope did not return an ID token")
	}
	return token.AccessToken
}

func assertPasswordGrantIntrospection(t *testing.T, client *http.Client, baseURL, secret, token string, active bool) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
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
	if response.StatusCode != http.StatusOK {
		t.Fatalf("introspection status=%d", response.StatusCode)
	}
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	var gotActive bool
	if err := json.Unmarshal(payload["active"], &gotActive); err != nil || gotActive != active {
		t.Fatalf("introspection active=%t, want %t (err=%v)", gotActive, active, err)
	}
	if !active {
		if len(payload) != 1 {
			t.Fatalf("inactive introspection disclosed fields: %#v", payload)
		}
		return
	}
	for field, want := range map[string]string{"client_id": "goauthy-dev"} {
		var got string
		if err := json.Unmarshal(payload[field], &got); err != nil || got != want {
			t.Fatalf("introspection %s=%q, want %q (err=%v)", field, got, want, err)
		}
	}
}

func assertPasswordGrantRevocation(t *testing.T, client *http.Client, baseURL, secret, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/revoke", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revocation status=%d", response.StatusCode)
	}
}

func assertPasswordGrantMissingField(t *testing.T, client *http.Client, baseURL, secret string, form map[string]string) {
	t.Helper()
	values := url.Values{}
	for k, v := range form {
		values.Set(k, v)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("password grant with missing field status=%d, want 400 (form=%v)", response.StatusCode, form)
	}
}
