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
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestDeviceDPoPLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_DPOP") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_DPOP=1 to run device DPoP E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{Key: public}
	thumbprint, err := publicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := base64.RawURLEncoding.EncodeToString(thumbprint)

	grant := startDeviceOIDC(t, client, primary, clientSecret)
	loginAndApproveDevice(t, newBrowserClient(t), grant, primary, tertiary, username, password)
	deviceForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {grant.DeviceCode},
	}
	assertError := func(response *http.Response, want string) {
		t.Helper()
		defer response.Body.Close()
		var body struct {
			Error string `json:"error"`
		}
		if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body) != nil || body.Error != want {
			t.Fatalf("token rejection status=%d error=%q want=%q", response.StatusCode, body.Error, want)
		}
	}
	assertError(postDPoPToken(t, client, primary, clientSecret, deviceForm, "invalid-proof"), "invalid_dpop_proof")
	challenge := postDPoPToken(t, client, primary, clientSecret, deviceForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()

	issuedResponse := postDPoPToken(t, client, secondary, clientSecret, deviceForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	issued := decodeDPoPToken(t, issuedResponse, wantJKT)
	issuedResponse.Body.Close()
	if issued.RefreshToken == "" {
		t.Fatal("device DPoP response has no refresh token")
	}
	keys := publicJWKS(t, client, tertiary)
	verifyPublicAccessToken(t, issued.AccessToken, keys, primary, "goauthy-dev", grant.Scope, wantJKT)
	identity := verifyDeviceIDToken(t, issued.IDToken, keys, primary, issued.AccessToken)
	if identity.Subject != "bootstrap-admin" {
		t.Fatal("device ID token has unexpected subject")
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
	missing := tokenResponseFor(t, client, primary, clientSecret, refreshForm)
	assertError(missing, "invalid_request")

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := postDPoPToken(t, client, secondary, clientSecret, refreshForm, dpopProof(t, wrongPrivate, http.MethodPost, primary+"/oidc/token", "", ""))
	assertError(wrong, "invalid_dpop_proof")

	refreshChallenge := postDPoPToken(t, client, tertiary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	refreshNonce := assertDPoPTokenNonce(t, refreshChallenge)
	refreshChallenge.Body.Close()
	refreshedResponse := postDPoPToken(t, client, primary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", refreshNonce, ""))
	refreshed := decodeDPoPToken(t, refreshedResponse, wantJKT)
	refreshedResponse.Body.Close()
	verifyPublicAccessToken(t, refreshed.AccessToken, keys, primary, "goauthy-dev", grant.Scope, wantJKT)
	if refreshedIdentity := verifyDeviceIDToken(t, refreshed.IDToken, keys, primary, refreshed.AccessToken); refreshedIdentity.Subject != identity.Subject {
		t.Fatal("refreshed device ID token changed subject")
	}

	resourceChallenge := dpopUserInfo(t, client, tertiary, refreshed.AccessToken, dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", "", refreshed.AccessToken), "DPoP")
	resourceNonce := assertDPoPResourceNonce(t, resourceChallenge)
	resourceChallenge.Body.Close()
	resource := dpopUserInfo(t, client, primary, refreshed.AccessToken, dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", resourceNonce, refreshed.AccessToken), "DPoP")
	var info struct {
		Subject string `json:"sub"`
	}
	if resource.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resource.Body, 4096)).Decode(&info) != nil || info.Subject != identity.Subject {
		resource.Body.Close()
		t.Fatal("DPoP UserInfo does not match authenticated device subject")
	}
	resource.Body.Close()
}

func TestDeviceDPoPPublicLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_DPOP") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_DPOP=1 to run public device DPoP E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required for the selected public device DPoP gate")
	}
	registration := registerPublicDeviceClient(t, primary, registrationToken)
	t.Cleanup(func() {
		response := do(t, newBrowserClient(t), http.MethodDelete, primary+"/oidc/register/"+url.PathEscape(registration.ClientID), nil, map[string]string{"Authorization": "Bearer " + registration.RegistrationAccessToken})
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("public device client cleanup status=%d", response.StatusCode)
		}
	})
	enablePublicDeviceDPoP(t, primary, &registration)
	client := newBrowserClient(t)
	grant := startPublicDeviceDPoP(t, client, primary, registration.ClientID)
	loginAndApproveDevice(t, newBrowserClient(t), grant, primary, tertiary, username, password)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{Key: public}
	thumbprint, err := publicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := base64.RawURLEncoding.EncodeToString(thumbprint)
	deviceForm := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {registration.ClientID}}
	assertError := func(response *http.Response, want string) {
		t.Helper()
		defer response.Body.Close()
		var body struct {
			Error string `json:"error"`
		}
		if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body) != nil || body.Error != want {
			t.Fatalf("public token rejection status=%d error=%q want=%q", response.StatusCode, body.Error, want)
		}
	}
	assertError(postPublicDPoPToken(t, client, primary, deviceForm, ""), "invalid_request")
	assertError(postPublicDPoPToken(t, client, primary, deviceForm, "invalid-proof"), "invalid_dpop_proof")
	challenge := postPublicDPoPToken(t, client, primary, deviceForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	issuedResponse := postPublicDPoPToken(t, client, secondary, deviceForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	issued := decodeDPoPToken(t, issuedResponse, wantJKT)
	issuedResponse.Body.Close()
	if issued.RefreshToken == "" || issued.IDToken == "" {
		t.Fatal("public device DPoP response is incomplete")
	}
	keys := publicJWKS(t, client, tertiary)
	verifyPublicAccessToken(t, issued.AccessToken, keys, primary, registration.ClientID, grant.Scope, wantJKT)
	identity := verifyPublicDeviceDPoPIDToken(t, issued.IDToken, keys, primary, registration.ClientID, issued.AccessToken)
	if identity.Subject != "bootstrap-admin" {
		t.Fatal("public device ID token has unexpected subject")
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {registration.ClientID}}
	assertError(postPublicDPoPToken(t, client, primary, refreshForm, ""), "invalid_request")
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertError(postPublicDPoPToken(t, client, secondary, refreshForm, dpopProof(t, wrongPrivate, http.MethodPost, primary+"/oidc/token", "", "")), "invalid_dpop_proof")
	refreshChallenge := postPublicDPoPToken(t, client, tertiary, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	refreshNonce := assertDPoPTokenNonce(t, refreshChallenge)
	refreshChallenge.Body.Close()
	refreshedResponse := postPublicDPoPToken(t, client, primary, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", refreshNonce, ""))
	refreshed := decodeDPoPToken(t, refreshedResponse, wantJKT)
	refreshedResponse.Body.Close()
	verifyPublicAccessToken(t, refreshed.AccessToken, keys, primary, registration.ClientID, grant.Scope, wantJKT)
	if refreshedIdentity := verifyPublicDeviceDPoPIDToken(t, refreshed.IDToken, keys, primary, registration.ClientID, refreshed.AccessToken); refreshedIdentity.Subject != identity.Subject {
		t.Fatal("public refreshed device ID token changed subject")
	}

	resourceChallenge := dpopUserInfo(t, client, tertiary, refreshed.AccessToken, dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", "", refreshed.AccessToken), "DPoP")
	resourceNonce := assertDPoPResourceNonce(t, resourceChallenge)
	resourceChallenge.Body.Close()
	resource := dpopUserInfo(t, client, primary, refreshed.AccessToken, dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", resourceNonce, refreshed.AccessToken), "DPoP")
	var info struct {
		Subject string `json:"sub"`
	}
	if resource.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resource.Body, 4096)).Decode(&info) != nil || info.Subject != identity.Subject {
		resource.Body.Close()
		t.Fatal("public DPoP UserInfo does not match authenticated device subject")
	}
	resource.Body.Close()
}

func startPublicDeviceDPoP(t *testing.T, client *http.Client, baseURL, clientID string) deviceLoginGrant {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {"openid groups offline_access"}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/device", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var grant deviceLoginGrant
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&grant) != nil || grant.DeviceCode == "" || grant.UserCode == "" || grant.VerificationURIComplete == "" {
		t.Fatalf("public device authorization status=%d", response.StatusCode)
	}
	grant.Scope = "openid groups offline_access"
	return grant
}

func enablePublicDeviceDPoP(t *testing.T, baseURL string, current *dynamicClientRegistration) {
	t.Helper()
	clientID, err := json.Marshal(current.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"client_id":` + string(clientID) + `,"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Public Device E2E","dpop_bound_access_tokens":true}`
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, baseURL+"/oidc/register/"+url.PathEscape(current.ClientID), strings.NewReader(body))
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
	var updated struct {
		dynamicClientRegistration
		DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&updated) != nil || !updated.DPoPBoundAccessTokens || updated.ClientID != current.ClientID || updated.RegistrationAccessToken == "" || updated.RegistrationAccessToken == current.RegistrationAccessToken {
		t.Fatalf("public DPoP registration update status=%d enabled=%t", response.StatusCode, updated.DPoPBoundAccessTokens)
	}
	*current = updated.dynamicClientRegistration // Cleanup must use the rotated token even if GET fails.
	readRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/oidc/register/"+url.PathEscape(updated.ClientID), nil)
	if err != nil {
		t.Fatal(err)
	}
	readRequest.Header.Set("Authorization", "Bearer "+updated.RegistrationAccessToken)
	readResponse, err := (&http.Client{Timeout: 10 * time.Second}).Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer readResponse.Body.Close()
	var loaded struct {
		DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
	}
	if readResponse.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(readResponse.Body, 16<<10)).Decode(&loaded) != nil || !loaded.DPoPBoundAccessTokens {
		t.Fatalf("public DPoP registration read status=%d enabled=%t", readResponse.StatusCode, loaded.DPoPBoundAccessTokens)
	}
}

func postPublicDPoPToken(t *testing.T, client *http.Client, baseURL string, form url.Values, proof string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func verifyPublicDeviceDPoPIDToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, clientID, accessToken string) oidc.IDTokenClaims {
	t.Helper()
	claims, err := oidc.VerifyIDToken(token, keys, issuer, clientID, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify public device ID token: %v", err)
	}
	if claims.AccessTokenHash != oidc.AccessTokenHash(accessToken) {
		t.Fatal("public device ID token at_hash mismatch")
	}
	return claims
}
