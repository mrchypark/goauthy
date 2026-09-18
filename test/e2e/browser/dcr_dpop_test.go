package browser

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type dcrDPoPRegistration struct {
	dynamicClientRegistration
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
}

// TestDynamicClientDPoPPolicyLive covers a confidential dynamic client's
// required-DPoP setting through its authenticated registration endpoint.
func TestDynamicClientDPoPPolicyLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DCR_DPOP") != "1" {
		t.Skip("set GOAUTHY_E2E_DCR_DPOP=1 to run dynamic-client DPoP E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required for dynamic-client DPoP E2E")
	}
	client := newBrowserClient(t)
	registration := registerDCRDPoPClient(t, primary, registrationToken)
	t.Cleanup(func() {
		response := do(t, newBrowserClient(t), http.MethodDelete, tertiary+"/oidc/register/"+url.PathEscape(registration.ClientID), nil, map[string]string{"Authorization": "Bearer " + registration.RegistrationAccessToken})
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("dynamic DPoP client cleanup status=%d", response.StatusCode)
		}
	})
	registration = updateDCRDPoPClient(t, secondary, registration, true)
	assertDCRDPoPRegistration(t, tertiary, registration, true)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := dcrDPoPJKT(t, public)

	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, primary, registration.ClientID, registration.RedirectURIs[0], pkceChallenge(verifier), "dcr-dpop-code", "dcr-dpop-code-nonce", "openid goauthy.read"), primary, secondary, username, password, "dcr-dpop-code")
	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {registration.RedirectURIs[0]}, "code_verifier": {verifier}}
	assertDCRDPoPTokenError(t, postDCRDPoPToken(t, client, primary, registration, codeForm, ""), "invalid_request")
	codeChallenge := postDCRDPoPToken(t, client, primary, registration, codeForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	codeNonce := assertDPoPTokenNonce(t, codeChallenge)
	codeChallenge.Body.Close()
	codeIssuedResponse := postDCRDPoPToken(t, client, secondary, registration, codeForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", codeNonce, ""))
	codeIssued := decodeDPoPToken(t, codeIssuedResponse, wantJKT)
	codeIssuedResponse.Body.Close()
	verifyPublicAccessToken(t, codeIssued.AccessToken, publicJWKS(t, client, tertiary), primary, registration.ClientID, "openid goauthy.read", wantJKT)
	assertDCRDPoPIntrospection(t, client, tertiary, registration, codeIssued.AccessToken, registration.ClientID, wantJKT)

	credentialsForm := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	assertDCRDPoPTokenError(t, postDCRDPoPToken(t, client, primary, registration, credentialsForm, ""), "invalid_request")
	credentialsChallenge := postDCRDPoPToken(t, client, primary, registration, credentialsForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	credentialsNonce := assertDPoPTokenNonce(t, credentialsChallenge)
	credentialsChallenge.Body.Close()
	credentialsIssuedResponse := postDCRDPoPToken(t, client, secondary, registration, credentialsForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", credentialsNonce, ""))
	credentialsIssued := decodeDPoPToken(t, credentialsIssuedResponse, wantJKT)
	credentialsIssuedResponse.Body.Close()
	verifyPublicAccessToken(t, credentialsIssued.AccessToken, publicJWKS(t, client, tertiary), primary, registration.ClientID, "goauthy.read", wantJKT)
	assertDCRDPoPIntrospection(t, client, tertiary, registration, credentialsIssued.AccessToken, registration.ClientID, wantJKT)

	registration = updateDCRDPoPClient(t, primary, registration, false)
	assertDCRDPoPRegistration(t, secondary, registration, false)
	bearerResponse := postDCRDPoPToken(t, client, secondary, registration, credentialsForm, "")
	defer bearerResponse.Body.Close()
	if bearerResponse.StatusCode != http.StatusOK {
		t.Fatalf("dynamic client bearer issuance after DPoP disable status=%d", bearerResponse.StatusCode)
	}
	var bearer tokenResponse
	if err := json.NewDecoder(io.LimitReader(bearerResponse.Body, 32<<10)).Decode(&bearer); err != nil || bearer.AccessToken == "" {
		t.Fatalf("dynamic client bearer issuance decode_ok=%t token_set=%t", err == nil, bearer.AccessToken != "")
	}
	verifyPublicAccessToken(t, bearer.AccessToken, publicJWKS(t, client, tertiary), primary, registration.ClientID, "goauthy.read", "")

	registration = updateDCRDPoPClient(t, secondary, registration, true)
	assertDCRDPoPRegistration(t, tertiary, registration, true)
	assertDCRDPoPTokenError(t, postDCRDPoPToken(t, client, tertiary, registration, credentialsForm, ""), "invalid_request")
}

func registerDCRDPoPClient(t *testing.T, baseURL, registrationToken string) dcrDPoPRegistration {
	t.Helper()
	body := dcrDPoPClientBody(t, "", false)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/register", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+registrationToken)
	request.Header.Set("Idempotency-Key", dcrIdempotencyKey(t.Name(), "/oidc/register", body))
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var registration dcrDPoPRegistration
	if response.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&registration) != nil || registration.ClientID == "" || registration.ClientSecret == "" || registration.RegistrationAccessToken == "" || registration.DPoPBoundAccessTokens || len(registration.RedirectURIs) != 1 || registration.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("dynamic DPoP client registration status=%d client_set=%t secret_set=%t policy=%t", response.StatusCode, registration.ClientID != "", registration.ClientSecret != "", registration.DPoPBoundAccessTokens)
	}
	return registration
}

func updateDCRDPoPClient(t *testing.T, baseURL string, current dcrDPoPRegistration, required bool) dcrDPoPRegistration {
	t.Helper()
	body := dcrDPoPClientBody(t, current.ClientID, required)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, baseURL+"/oidc/register/"+url.PathEscape(current.ClientID), strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+current.RegistrationAccessToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var updated dcrDPoPRegistration
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&updated) != nil || updated.ClientID != current.ClientID || updated.ClientSecret == "" || updated.RegistrationAccessToken == "" || updated.RegistrationAccessToken == current.RegistrationAccessToken || updated.DPoPBoundAccessTokens != required {
		t.Fatalf("dynamic DPoP metadata update status=%d policy=%t credentials_rotated=%t", response.StatusCode, updated.DPoPBoundAccessTokens, updated.ClientSecret != "" && updated.RegistrationAccessToken != "" && updated.RegistrationAccessToken != current.RegistrationAccessToken)
	}
	return updated
}

func dcrDPoPClientBody(t *testing.T, clientID string, required bool) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		ClientID                string   `json:"client_id,omitempty"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
		DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens"`
	}{
		ClientID:                clientID,
		RedirectURIs:            []string{"https://rp.example.test/dcr-dpop-callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientName:              "GoAuthy Dynamic DPoP E2E",
		DPoPBoundAccessTokens:   required,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertDCRDPoPRegistration(t *testing.T, baseURL string, registration dcrDPoPRegistration, required bool) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/oidc/register/"+url.PathEscape(registration.ClientID), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+registration.RegistrationAccessToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata struct {
		ClientID                string `json:"client_id"`
		DPoPBoundAccessTokens   bool   `json:"dpop_bound_access_tokens"`
		ClientSecret            string `json:"client_secret"`
		RegistrationAccessToken string `json:"registration_access_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&metadata) != nil || metadata.ClientID != registration.ClientID || metadata.DPoPBoundAccessTokens != required || metadata.ClientSecret != "" || metadata.RegistrationAccessToken != "" {
		t.Fatalf("dynamic DPoP metadata read status=%d policy=%t credentials_exposed=%t", response.StatusCode, metadata.DPoPBoundAccessTokens, metadata.ClientSecret != "" || metadata.RegistrationAccessToken != "")
	}
}

func postDCRDPoPToken(t *testing.T, client *http.Client, baseURL string, registration dcrDPoPRegistration, form url.Values, proof string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(registration.ClientID, registration.ClientSecret)
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertDCRDPoPTokenError(t *testing.T, response *http.Response, want string) {
	t.Helper()
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Error != want {
		t.Fatalf("dynamic DPoP token rejection status=%d expected_error=%q actual_matches=%t", response.StatusCode, want, body.Error == want)
	}
}

func assertDCRDPoPIntrospection(t *testing.T, client *http.Client, baseURL string, registration dcrDPoPRegistration, token, wantClientID, wantJKT string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(registration.ClientID, registration.ClientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Active bool   `json:"active"`
		Client string `json:"client_id"`
		CNF    struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || !body.Active || body.Client != wantClientID || body.CNF.JKT != wantJKT {
		t.Fatalf("dynamic DPoP introspection status=%d active=%t client_matches=%t jkt_matches=%t", response.StatusCode, body.Active, body.Client == wantClientID, body.CNF.JKT == wantJKT)
	}
}

func dcrDPoPJKT(t *testing.T, public ed25519.PublicKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: public}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}
