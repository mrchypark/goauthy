// Package browser exercises the deployed browser authorization surface only.
package browser

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const defaultRedirectURI = "http://localhost:5555/callback"
const defaultPostLogoutRedirectURI = "http://localhost:5555/logout?from=goauthy"
const defaultResourceIndicator = "https://api.example.test/v1"
const explicitResourceIndicator = "https://resource.example.test/v1"

func TestAuthorizationCodeLoginAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	verifier := pkceVerifier(t)
	challenge := pkceChallenge(verifier)
	authorizeURL := oidcAuthorizationURL(t, primary, redirectURI, challenge, "browser-e2e-state", "browser-e2e-nonce")

	// An anonymous prompt=none request must never render a login page or issue a code.
	anonymous := noRedirectClient(t, nil)
	promptNone := authorizeURL + "&prompt=none"
	response := do(t, anonymous, http.MethodGet, promptNone, nil, nil)
	assertLoginRequired(t, response, "browser-e2e-state")

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := noRedirectClient(t, jar)
	response = do(t, client, http.MethodGet, authorizeURL, nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("authorize status = %d, want login form", response.StatusCode)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		response.Body.Close()
		t.Fatalf("login security headers = %#v", response.Header)
	}
	initCookie := assertSessionCookie(t, response.Cookies(), primary)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	interaction, ok := hiddenInputValue(string(body), "interaction")
	if !ok {
		t.Fatal("login form has no interaction token")
	}

	// Cookie hosts ignore ports, so this crosses two independently port-forwarded pods.
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	response = do(t, client, http.MethodPost, secondary+"/auth/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "same-origin",
	})
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		response.Body.Close()
		t.Fatalf("login status = %d, want redirect", response.StatusCode)
	}
	location := response.Header.Get("Location")
	rotatedCookie := assertSessionCookie(t, response.Cookies(), primary)
	if rotatedCookie.Value == initCookie.Value {
		response.Body.Close()
		t.Fatal("login did not rotate the browser session")
	}
	response.Body.Close()
	callback, err := url.Parse(location)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != redirectURI || callback.Query().Get("state") != "browser-e2e-state" || callback.Query().Get("error") != "" {
		t.Fatalf("login redirect is not a valid callback")
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("login redirect has no authorization code")
	}
	replayJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuerURL, err := url.Parse(primary)
	if err != nil {
		t.Fatal(err)
	}
	replayJar.SetCookies(issuerURL, []*http.Cookie{initCookie})
	replay := do(t, noRedirectClient(t, replayJar), http.MethodPost, primary+"/auth/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
	})
	replay.Body.Close()
	if replay.StatusCode != http.StatusForbidden {
		t.Fatalf("old init session replay status = %d", replay.StatusCode)
	}

	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatal("authorization-code exchange did not return access, refresh, and ID tokens")
	}
	keys := publicJWKS(t, client, primary)
	claims := verifyPublicIDToken(t, tokens.IDToken, keys, primary)
	assertInitialIDTokenClaims(t, claims, tokens.AccessToken)
	rotated := refresh(t, client, secondary, clientSecret, tokens.RefreshToken)
	if rotated.AccessToken == "" || rotated.RefreshToken == "" || rotated.IDToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh did not rotate the refresh and ID tokens")
	}
	refreshedClaims := verifyPublicIDToken(t, rotated.IDToken, publicJWKS(t, client, secondary), primary)
	assertRefreshedIDTokenClaims(t, refreshedClaims, claims, rotated.AccessToken)
	assertRefreshRejected(t, client, primary, clientSecret, tokens.RefreshToken)
}

func TestDynamicClientAuthorizationCodePKCEAcrossPods(t *testing.T) {
	primary, secondary, username, password, _ := browserE2EConfig(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Skip("set GOAUTHY_E2E_DCR_REGISTRATION_TOKEN to run dynamic-client browser E2E")
	}
	const redirectURI = "https://rp.example.test/callback"
	registration := registerDynamicClient(t, primary, registrationToken, redirectURI)
	firstRotation := rotateDynamicClient(t, primary, registration, "GoAuthy Dynamic Browser E2E Rotated")
	assertDynamicRegistrationUnauthorized(t, secondary, registration.ClientID, registration.RegistrationAccessToken)
	assertDynamicRegistrationMetadata(t, secondary, firstRotation, "GoAuthy Dynamic Browser E2E Rotated")
	secondRotation := rotateDynamicClient(t, secondary, firstRotation, "GoAuthy Dynamic Browser E2E Rotated Again")
	assertDynamicRegistrationUnauthorized(t, primary, registration.ClientID, firstRotation.RegistrationAccessToken)
	assertDynamicRegistrationMetadata(t, primary, secondRotation, "GoAuthy Dynamic Browser E2E Rotated Again")

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	state, nonce := "dynamic-client-state", "dynamic-client-nonce"
	authorizeURL := oidcAuthorizationURLForClient(t, primary, registration.ClientID, redirectURI, pkceChallenge(verifier), state, nonce, "openid goauthy.read")
	code, _ := loginForAuthorizationURL(t, client, authorizeURL, primary, secondary, username, password, state)
	assertDynamicClientSecretRejected(t, client, secondary, registration.ClientID, registration.ClientSecret, redirectURI, code, verifier)
	tokens := exchangeCodeForClient(t, client, secondary, registration.ClientID, secondRotation.ClientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" || tokens.IDToken == "" || tokens.RefreshToken != "" {
		t.Fatal("dynamic authorization-code exchange returned unexpected tokens")
	}
	claims, err := oidc.VerifyIDToken(tokens.IDToken, publicJWKS(t, client, secondary), primary, registration.ClientID, time.Now().UTC())
	if err != nil || claims.Subject == "" || claims.Nonce != nonce || claims.SessionID == "" {
		t.Fatalf("verify dynamic public ID token: %v", err)
	}
	assertDynamicClientIntrospection(t, client, secondary, registration.ClientID, secondRotation.ClientSecret, tokens.AccessToken)
}

func TestRFC8252LoopbackDynamicClientAcrossPods(t *testing.T) {
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if os.Getenv("GOAUTHY_E2E_RFC8252_LOOPBACK_REDIRECTS") != "1" || registrationToken == "" {
		t.Skip("set GOAUTHY_E2E_RFC8252_LOOPBACK_REDIRECTS=1 and GOAUTHY_E2E_DCR_REGISTRATION_TOKEN to run RFC 8252 E2E")
	}

	const templateRedirect = "http://127.0.0.1/native-callback"
	const requestedRedirect = "http://127.0.0.1:43123/native-callback"
	registration := registerLoopbackPublicClient(t, primary, registrationToken, templateRedirect)
	assertDynamicRegistrationMetadata(t, secondary, registration, "GoAuthy RFC8252 Browser E2E")
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	authorizationURL := authorizationURLForClient(secondary, registration.ClientID, requestedRedirect, pkceChallenge(verifier), "rfc8252-loopback", "goauthy.read")
	code, _, location := loginForAuthorizationURLWithLocation(t, client, authorizationURL, primary, secondary, username, password, "rfc8252-loopback")
	callback, err := url.Parse(location)
	if err != nil || callback.String() == "" || callback.Scheme+"://"+callback.Host+callback.Path != requestedRedirect || callback.Query().Get("code") != code || callback.Query().Get("state") != "rfc8252-loopback" {
		t.Fatalf("loopback authorization redirect=%q", location)
	}

	assertPublicCodeExchangeRejected(t, client, tertiary, registration.ClientID, "http://127.0.0.1:43124/native-callback", code, verifier, "wrong loopback port")
	assertPublicCodeExchangeRejected(t, client, tertiary, registration.ClientID, templateRedirect, code, verifier, "raw loopback template")
	tokens := exchangePublicCode(t, client, tertiary, registration.ClientID, requestedRedirect, code, verifier)
	if tokens.AccessToken == "" || tokens.RefreshToken != "" || tokens.IDToken != "" {
		t.Fatal("loopback public-client exchange returned unexpected tokens")
	}

	const ipv6Template = "http://[::1]/native-callback"
	const ipv6Requested = "http://[::1]:43124/native-callback"
	ipv6Registration := registerLoopbackPublicClient(t, primary, registrationToken, ipv6Template)
	ipv6Client := newBrowserClient(t)
	ipv6Verifier := pkceVerifier(t)
	ipv6AuthorizationURL := authorizationURLForClient(secondary, ipv6Registration.ClientID, ipv6Requested, pkceChallenge(ipv6Verifier), "rfc8252-ipv6", "goauthy.read")
	ipv6Code, _, ipv6Location := loginForAuthorizationURLWithLocation(t, ipv6Client, ipv6AuthorizationURL, primary, secondary, username, password, "rfc8252-ipv6")
	ipv6Callback, err := url.Parse(ipv6Location)
	if err != nil || ipv6Callback.String() == "" || ipv6Callback.Scheme+"://"+ipv6Callback.Host+ipv6Callback.Path != ipv6Requested || ipv6Callback.Query().Get("code") != ipv6Code || ipv6Callback.Query().Get("state") != "rfc8252-ipv6" {
		t.Fatalf("IPv6 loopback authorization redirect=%q", ipv6Location)
	}
	ipv6Tokens := exchangePublicCode(t, ipv6Client, tertiary, ipv6Registration.ClientID, ipv6Requested, ipv6Code, ipv6Verifier)
	if ipv6Tokens.AccessToken == "" || ipv6Tokens.RefreshToken != "" || ipv6Tokens.IDToken != "" {
		t.Fatal("IPv6 loopback public-client exchange returned unexpected tokens")
	}

	const localhostRedirect = "http://localhost:43123/native-callback"
	localhostRegistration := registerLoopbackPublicClient(t, primary, registrationToken, localhostRedirect)
	localhostClient := newBrowserClient(t)
	localhostVerifier := pkceVerifier(t)
	localhostAuthorizationURL := authorizationURLForClient(secondary, localhostRegistration.ClientID, localhostRedirect, pkceChallenge(localhostVerifier), "rfc8252-localhost", "goauthy.read")
	localhostCode, _, localhostLocation := loginForAuthorizationURLWithLocation(t, localhostClient, localhostAuthorizationURL, primary, secondary, username, password, "rfc8252-localhost")
	localhostCallback, err := url.Parse(localhostLocation)
	if err != nil || localhostCallback.String() == "" || localhostCallback.Scheme+"://"+localhostCallback.Host+localhostCallback.Path != localhostRedirect || localhostCallback.Query().Get("code") != localhostCode || localhostCallback.Query().Get("state") != "rfc8252-localhost" {
		t.Fatalf("localhost loopback authorization redirect=%q", localhostLocation)
	}
	localhostTokens := exchangePublicCode(t, localhostClient, tertiary, localhostRegistration.ClientID, localhostRedirect, localhostCode, localhostVerifier)
	if localhostTokens.AccessToken == "" || localhostTokens.RefreshToken != "" || localhostTokens.IDToken != "" {
		t.Fatal("localhost public-client exchange returned unexpected tokens")
	}

	for _, tc := range []struct {
		name     string
		clientID string
		redirect string
	}{
		{"localhost", registration.ClientID, "http://localhost:43123/native-callback"},
		{"localhost changed port", localhostRegistration.ClientID, "http://localhost:43124/native-callback"},
		{"cross family", registration.ClientID, "http://[::1]:43123/native-callback"},
		{"other loopback host", registration.ClientID, "http://127.0.0.2:43123/native-callback"},
		{"userinfo", registration.ClientID, "http://user@127.0.0.1:43123/native-callback"},
		{"path", registration.ClientID, "http://127.0.0.1:43123/other-callback"},
		{"query", registration.ClientID, "http://127.0.0.1:43123/native-callback?unexpected=1"},
		{"bootstrap changed port", "goauthy-dev", "http://localhost:6553/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthorizationWithoutUsableCode(t, secondary, tc.clientID, tc.redirect)
		})
	}
}

func TestDeviceAuthorizationAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)

	grant := startDeviceAuthorization(t, client, primary)
	assertDeviceTokenError(t, client, secondary, clientSecret, grant.DeviceCode, "authorization_pending")
	assertDeviceTokenError(t, client, secondary, clientSecret, grant.DeviceCode, "slow_down")

	_, _ = loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "device-verification-login")
	approveDevice(t, client, tertiary, primary, grant.UserCode, "approve")
	deviceWait(t, grant.Interval+5)
	tokens := deviceToken(t, client, tertiary, clientSecret, grant.DeviceCode)
	if tokens.AccessToken == "" || tokens.RefreshToken != "" || tokens.IDToken != "" {
		t.Fatal("device token response is invalid")
	}
	assertDeviceIntrospection(t, client, primary, clientSecret, tokens.AccessToken)
	assertDeviceTokenError(t, client, primary, clientSecret, grant.DeviceCode, "expired_token")

	// Use a fresh browser for denial: the ordinary E2E profile keeps sessions
	// alive for 90 minutes, so the polling interval must not imply logout.
	client = newBrowserClient(t)
	_, _ = loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "device-denial-login")
	denied := startDeviceAuthorization(t, client, primary)
	approveDevice(t, client, secondary, tertiary, denied.UserCode, "deny")
	assertDeviceTokenError(t, client, tertiary, clientSecret, denied.DeviceCode, "access_denied")
}

func TestDPoPAuthorizationCodeRefreshAndUserInfoAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{Key: public}
	jkt, err := publicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := base64.RawURLEncoding.EncodeToString(jkt)
	clientCredentialsForm := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	clientChallenge := postDPoPToken(t, client, primary, clientSecret, clientCredentialsForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	clientNonce := assertDPoPTokenNonce(t, clientChallenge)
	clientChallenge.Body.Close()
	clientSuccessProof := dpopProof(t, private, http.MethodPost, primary+"/oidc/token", clientNonce, "")
	clientIssuedResponse := postDPoPToken(t, client, secondary, clientSecret, clientCredentialsForm, clientSuccessProof)
	clientIssued := decodeDPoPToken(t, clientIssuedResponse, wantJKT)
	clientIssuedResponse.Body.Close()
	verifyPublicAccessToken(t, clientIssued.AccessToken, publicJWKS(t, client, tertiary), primary, "goauthy-dev", "goauthy.read", wantJKT)
	assertDPoPClientIntrospection(t, client, tertiary, clientSecret, clientIssued.AccessToken, wantJKT)
	clientReplay := postDPoPToken(t, client, primary, clientSecret, clientCredentialsForm, clientSuccessProof)
	assertDPoPTokenNonce(t, clientReplay)
	clientReplay.Body.Close()

	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "dpop-state", "dpop-nonce"), primary, secondary, username, password, "dpop-state")
	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {defaultRedirectURI}, "code_verifier": {verifier}}
	challenge := postDPoPToken(t, client, primary, clientSecret, codeForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	issuedResponse := postDPoPToken(t, client, secondary, clientSecret, codeForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	issued := decodeDPoPToken(t, issuedResponse, wantJKT)
	issuedResponse.Body.Close()
	if issued.RefreshToken == "" || issued.AccessToken == "" || issued.IDToken == "" {
		t.Fatal("DPoP authorization-code response is incomplete")
	}
	verifyPublicAccessToken(t, issued.AccessToken, publicJWKS(t, client, tertiary), primary, "goauthy-dev", "openid goauthy.read offline_access", wantJKT)

	resourceChallenge := dpopUserInfo(t, client, tertiary, issued.AccessToken, dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", "", issued.AccessToken), "DPoP")
	resourceNonce := assertDPoPResourceNonce(t, resourceChallenge)
	resourceChallenge.Body.Close()
	resourceProof := dpopProof(t, private, http.MethodGet, primary+"/oidc/userinfo", resourceNonce, issued.AccessToken)
	assertDPoPProofATH(t, resourceProof, private.Public().(ed25519.PublicKey), issued.AccessToken)
	resource := dpopUserInfo(t, client, primary, issued.AccessToken, resourceProof, "DPoP")
	assertDPoPUserInfo(t, resource)
	resource.Body.Close()

	replay := dpopUserInfo(t, client, secondary, issued.AccessToken, resourceProof, "DPoP")
	assertDPoPRejected(t, replay)
	replay.Body.Close()
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyResponse := dpopUserInfo(t, client, tertiary, issued.AccessToken, dpopProof(t, wrongKey, http.MethodGet, primary+"/oidc/userinfo", "", issued.AccessToken), "DPoP")
	assertDPoPRejected(t, wrongKeyResponse)
	wrongKeyResponse.Body.Close()
	bearer := dpopUserInfo(t, client, primary, issued.AccessToken, "", "Bearer")
	assertDPoPRejected(t, bearer)
	bearer.Body.Close()

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
	refreshChallenge := postDPoPToken(t, client, secondary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	refreshNonce := assertDPoPTokenNonce(t, refreshChallenge)
	refreshChallenge.Body.Close()
	refreshedResponse := postDPoPToken(t, client, tertiary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", refreshNonce, ""))
	refreshed := decodeDPoPToken(t, refreshedResponse, wantJKT)
	refreshedResponse.Body.Close()
	if refreshed.RefreshToken == "" || refreshed.AccessToken == "" {
		t.Fatal("DPoP refresh response is incomplete")
	}
	verifyPublicAccessToken(t, refreshed.AccessToken, publicJWKS(t, client, primary), primary, "goauthy-dev", "openid goauthy.read offline_access", wantJKT)
	otherKeyResponse := postDPoPToken(t, client, primary, clientSecret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}, dpopProof(t, wrongKey, http.MethodPost, primary+"/oidc/token", "", ""))
	if otherKeyResponse.StatusCode == http.StatusOK {
		otherKeyResponse.Body.Close()
		t.Fatal("DPoP refresh accepted a different key")
	}
	otherKeyResponse.Body.Close()
}

type dpopTokenResponse struct {
	tokenResponse
	TokenType string `json:"token_type"`
	CNF       struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

func dpopProof(t *testing.T, private ed25519.PrivateKey, method, htu, nonce, accessToken string) string {
	t.Helper()
	claims := map[string]any{"jti": pkceVerifier(t), "htm": method, "htu": htu, "iat": time.Now().UTC().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader(jose.HeaderKey("jwk"), jose.JSONWebKey{Key: private.Public()}))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func assertDPoPProofATH(t *testing.T, proof string, public ed25519.PublicKey, accessToken string) {
	t.Helper()
	signed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(signed.Signatures) != 1 {
		t.Fatalf("parse DPoP proof: %v", err)
	}
	payload, err := signed.Verify(public)
	if err != nil {
		t.Fatalf("verify DPoP proof: %v", err)
	}
	var claims struct {
		ATH string `json:"ath"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode DPoP proof: %v", err)
	}
	sum := sha256.Sum256([]byte(accessToken))
	if claims.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("DPoP ath=%q does not bind the access token", claims.ATH)
	}
}

func postDPoPToken(t *testing.T, client *http.Client, baseURL, clientSecret string, form url.Values, proof string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	request.Header.Set("DPoP", proof)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertDPoPTokenNonce(t *testing.T, response *http.Response) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Error != "use_dpop_nonce" || response.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("DPoP token nonce challenge status=%d error=%q nonce_set=%t", response.StatusCode, body.Error, response.Header.Get("DPoP-Nonce") != "")
	}
	return response.Header.Get("DPoP-Nonce")
}

func decodeDPoPToken(t *testing.T, response *http.Response, wantJKT string) dpopTokenResponse {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("DPoP token status=%d", response.StatusCode)
	}
	var token dpopTokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.TokenType != "DPoP" || token.CNF.JKT != wantJKT {
		t.Fatalf("invalid DPoP token response type=%q cnf_set=%t", token.TokenType, token.CNF.JKT != "")
	}
	return token
}

func assertDPoPClientIntrospection(t *testing.T, client *http.Client, baseURL, clientSecret, token, wantJKT string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active bool `json:"active"`
		CNF    struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload) != nil || !payload.Active || payload.CNF.JKT != wantJKT {
		t.Fatalf("DPoP client introspection status=%d active=%t cnf_set=%t", response.StatusCode, payload.Active, payload.CNF.JKT != "")
	}
}

func dpopUserInfo(t *testing.T, client *http.Client, baseURL, token, proof, scheme string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", scheme+" "+token)
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertDPoPResourceNonce(t *testing.T, response *http.Response) string {
	t.Helper()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` || response.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("DPoP resource nonce challenge status=%d auth=%q nonce_set=%t", response.StatusCode, response.Header.Get("WWW-Authenticate"), response.Header.Get("DPoP-Nonce") != "")
	}
	return response.Header.Get("DPoP-Nonce")
}

func assertDPoPUserInfo(t *testing.T, response *http.Response) {
	t.Helper()
	var body struct {
		Subject string `json:"sub"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Subject == "" {
		t.Fatalf("DPoP userinfo status=%d subject_set=%t", response.StatusCode, body.Subject != "")
	}
}

func assertDPoPRejected(t *testing.T, response *http.Response) {
	t.Helper()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "DPoP" && response.Header.Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` {
		t.Fatalf("DPoP rejection status=%d auth=%q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
	}
}

type deviceAuthorizationResponse struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	Interval   int    `json:"interval"`
}

func startDeviceAuthorization(t *testing.T, client *http.Client, baseURL string) deviceAuthorizationResponse {
	t.Helper()
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if secret == "" {
		t.Fatal("device authorization requires GOAUTHY_E2E_CLIENT_SECRET")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/device", strings.NewReader(url.Values{"client_id": {"goauthy-dev"}, "scope": {"goauthy.read"}}.Encode()))
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
		t.Fatalf("device authorization status=%d", response.StatusCode)
	}
	var grant deviceAuthorizationResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	if grant.DeviceCode == "" || grant.UserCode == "" || grant.Interval < 1 {
		t.Fatal("invalid device authorization response")
	}
	return grant
}

func approveDevice(t *testing.T, client *http.Client, getBaseURL, postBaseURL, userCode, action string) {
	t.Helper()
	response := do(t, client, http.MethodGet, getBaseURL+"/oidc/device/verify?"+url.Values{"user_code": {userCode}}.Encode(), nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("device verification page status=%d", response.StatusCode)
	}
	csrf, ok := hiddenInputValue(readLimitedBody(t, response), "csrf_token")
	response.Body.Close()
	if !ok {
		t.Fatal("device verification page has no CSRF token")
	}
	form := url.Values{"user_code": {userCode}, "csrf_token": {csrf}, "action": {action}}
	response = do(t, client, http.MethodPost, postBaseURL+"/oidc/device/verify", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Origin": primaryOrigin(t, postBaseURL), "Sec-Fetch-Site": "same-origin",
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device %s status=%d body=%q", action, response.StatusCode, readLimitedBody(t, response))
	}
}

func primaryOrigin(t *testing.T, baseURL string) string {
	t.Helper()
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	if issuer == "" {
		issuer = baseURL
	}
	return issuer
}

func deviceWait(t *testing.T, seconds int) {
	t.Helper()
	if seconds < 1 || seconds > 30 {
		t.Fatalf("invalid device polling interval %d", seconds)
	}
	// This is the deployed RFC 8628 poll window. The browser E2E has no clock
	// injection or database access, so the production throttle is exercised here.
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}

func deviceToken(t *testing.T, client *http.Client, baseURL, clientSecret, deviceCode string) tokenResponse {
	t.Helper()
	return tokenRequest(t, client, baseURL, clientSecret, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
}

func assertDeviceTokenError(t *testing.T, client *http.Client, baseURL, clientSecret, deviceCode, want string) {
	t.Helper()
	response := tokenResponseFor(t, client, baseURL, clientSecret, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Error != want {
		t.Fatalf("device token error status=%d error=%q want=%q", response.StatusCode, body.Error, want)
	}
}

func assertDeviceIntrospection(t *testing.T, client *http.Client, baseURL, clientSecret, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Active  bool   `json:"active"`
		Client  string `json:"client_id"`
		Scope   string `json:"scope"`
		Subject string `json:"sub"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || !body.Active || body.Client != "goauthy-dev" || body.Scope != "goauthy.read" || body.Subject == "" {
		t.Fatalf("device introspection status=%d active=%t client=%q scope=%q subject_set=%t", response.StatusCode, body.Active, body.Client, body.Scope, body.Subject != "")
	}
}

type dynamicClientRegistration struct {
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

func registerDynamicClient(t *testing.T, baseURL, globalToken, redirectURI string) dynamicClientRegistration {
	t.Helper()
	body, err := dynamicClientRegistrationBody(redirectURI, "GoAuthy Dynamic Browser E2E")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/register", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+globalToken)
	request.Header.Set("Idempotency-Key", dcrIdempotencyKey(t.Name(), "/oidc/register", body))
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("dynamic client registration status=%d", response.StatusCode)
	}
	var registration dynamicClientRegistration
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	if registration.ClientID == "" || registration.ClientSecret == "" || registration.RegistrationAccessToken == "" || registration.RegistrationClientURI != baseURL+"/oidc/register/"+registration.ClientID || len(registration.RedirectURIs) != 1 || registration.RedirectURIs[0] != redirectURI {
		t.Fatal("unexpected dynamic client registration")
	}
	return registration
}

func rotateDynamicClient(t *testing.T, baseURL string, current dynamicClientRegistration, name string) dynamicClientRegistration {
	t.Helper()
	body, err := dynamicClientRegistrationBody(current.RedirectURIs[0], name, current.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, baseURL+"/oidc/register/"+current.ClientID, strings.NewReader(string(body)))
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
	var rotated dynamicClientRegistration
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&rotated) != nil || rotated.ClientID != current.ClientID || rotated.ClientSecret == "" || rotated.ClientSecret == current.ClientSecret || rotated.RegistrationAccessToken == "" || rotated.RegistrationAccessToken == current.RegistrationAccessToken {
		t.Fatalf("dynamic client rotation status=%d client_id=%q credentials_rotated=%t", response.StatusCode, rotated.ClientID, rotated.ClientSecret != "" && rotated.ClientSecret != current.ClientSecret && rotated.RegistrationAccessToken != "" && rotated.RegistrationAccessToken != current.RegistrationAccessToken)
	}
	return rotated
}

func dynamicClientRegistrationBody(redirectURI, name string, clientID ...string) ([]byte, error) {
	id := ""
	if len(clientID) == 1 {
		id = clientID[0]
	}
	return json.Marshal(struct {
		ClientID                string   `json:"client_id,omitempty"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}{
		ClientID:                id,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientName:              name,
	})
}

func dcrIdempotencyKey(testName, endpoint string, body []byte) string {
	h := sha256.New()
	for _, part := range []string{"goauthy-e2e-dcr-v1", testName, endpoint, string(body)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func registerLoopbackPublicClient(t *testing.T, baseURL, globalToken, redirectURI string) dynamicClientRegistration {
	t.Helper()
	body, err := json.Marshal(struct {
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}{
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ClientName:              "GoAuthy RFC8252 Browser E2E",
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/register", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+globalToken)
	request.Header.Set("Idempotency-Key", dcrIdempotencyKey(t.Name(), "/oidc/register", body))
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var registration dynamicClientRegistration
	if response.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&registration) != nil || registration.ClientID == "" || registration.ClientSecret != "" || registration.RegistrationAccessToken == "" || len(registration.RedirectURIs) != 1 || registration.RedirectURIs[0] != redirectURI || registration.TokenEndpointAuthMethod != "none" {
		t.Fatalf("RFC8252 loopback registration status=%d client_id=%q public=%t", response.StatusCode, registration.ClientID, registration.ClientSecret == "")
	}
	return registration
}

func exchangePublicCode(t *testing.T, client *http.Client, baseURL, clientID, redirectURI, code, verifier string) tokenResponse {
	t.Helper()
	response := publicTokenResponse(t, client, baseURL, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public authorization-code token status=%d", response.StatusCode)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	return tokens
}

func assertPublicCodeExchangeRejected(t *testing.T, client *http.Client, baseURL, clientID, redirectURI, code, verifier, label string) {
	t.Helper()
	response := publicTokenResponse(t, client, baseURL, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s status=%d, want %d", label, response.StatusCode, http.StatusBadRequest)
	}
}

func publicTokenResponse(t *testing.T, client *http.Client, baseURL string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertAuthorizationWithoutUsableCode(t *testing.T, baseURL, clientID, redirectURI string) {
	t.Helper()
	response := do(t, noRedirectClient(t, nil), http.MethodGet, authorizationURLForClient(baseURL, clientID, redirectURI, pkceChallenge(pkceVerifier(t)), "rfc8252-rejected", "goauthy.read"), nil, nil)
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if response.StatusCode != http.StatusBadRequest || err != nil || location.Query().Get("code") != "" {
		t.Fatalf("unaccepted redirect %q status=%d location=%q", redirectURI, response.StatusCode, response.Header.Get("Location"))
	}
}

func assertDynamicRegistrationUnauthorized(t *testing.T, baseURL, clientID, registrationAccessToken string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/register/"+clientID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("old registration access token status=%d headers=%#v", response.StatusCode, response.Header)
	}
}

func assertDynamicRegistrationMetadata(t *testing.T, baseURL string, registration dynamicClientRegistration, wantName string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/register/"+registration.ClientID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+registration.RegistrationAccessToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata dynamicClientRegistration
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&metadata) != nil || metadata.ClientID != registration.ClientID || metadata.ClientSecret != "" || metadata.RegistrationAccessToken != "" || metadata.RegistrationClientURI != "" || metadata.ClientName != wantName || !slices.Equal(metadata.RedirectURIs, registration.RedirectURIs) || metadata.Scope != registration.Scope || metadata.TokenEndpointAuthMethod != registration.TokenEndpointAuthMethod {
		t.Fatalf("dynamic registration metadata status=%d client_id=%q credentials_exposed=%t name=%q", response.StatusCode, metadata.ClientID, metadata.ClientSecret != "" || metadata.RegistrationAccessToken != "" || metadata.RegistrationClientURI != "", metadata.ClientName)
	}
}

func assertDynamicClientSecretRejected(t *testing.T, client *http.Client, baseURL, clientID, clientSecret, redirectURI, code, verifier string) {
	t.Helper()
	response := tokenResponseForClient(t, client, baseURL, clientID, clientSecret, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old dynamic client secret status=%d", response.StatusCode)
	}
}

func assertDynamicClientIntrospection(t *testing.T, client *http.Client, baseURL, clientID, clientSecret, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active   bool   `json:"active"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload) != nil || !payload.Active || payload.ClientID != clientID || payload.Scope != "openid goauthy.read" {
		t.Fatalf("dynamic introspection status=%d active=%t client_id=%q scope=%q", response.StatusCode, payload.Active, payload.ClientID, payload.Scope)
	}
}

func TestAuthorizationBoundaryMatrix(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	assertPKCERejectedWithoutRedirectLeakage(t, primary, redirectURI)

	verifier := pkceVerifier(t)
	challenge := pkceChallenge(verifier)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := noRedirectClient(t, jar)
	code, authCookie := loginForCode(t, client, primary, secondary, redirectURI, challenge, username, password, "matrix-login")

	wrongVerifier := pkceVerifier(t)
	if wrongVerifier == verifier {
		t.Fatal("random PKCE verifier collision")
	}
	assertCodeExchangeRejected(t, client, primary, clientSecret, redirectURI, code, wrongVerifier, "wrong verifier")
	if tokens := exchangeCode(t, client, secondary, clientSecret, redirectURI, code, verifier); tokens.AccessToken == "" {
		t.Fatal("correct verifier did not exchange the authorization code")
	}
	assertCodeExchangeRejected(t, client, primary, clientSecret, redirectURI, code, verifier, "cross-pod code replay")

	for _, tc := range []struct {
		name   string
		prompt string
		maxAge string
	}{
		{name: "prompt login", prompt: "login"},
		{name: "prompt consent", prompt: "consent"},
		{name: "max age zero", maxAge: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertFreshLogin(t, primary, redirectURI, challenge, authCookie, tc.prompt, tc.maxAge)
		})
	}

	promptNoneClient := clientWithCookie(t, primary, authCookie)
	promptNone := authorizationURL(t, primary, redirectURI, challenge, "authenticated-prompt-none") + "&prompt=none"
	response := do(t, promptNoneClient, http.MethodGet, promptNone, nil, nil)
	assertAuthorizationCodeRedirect(t, response, "authenticated-prompt-none")

	anonymous := noRedirectClient(t, nil)
	response = do(t, anonymous, http.MethodGet, authorizationURL(t, primary, redirectURI, challenge, "anonymous-prompt-none")+"&prompt=none", nil, nil)
	assertLoginRequired(t, response, "anonymous-prompt-none")

	assertDeployedIdleExpiry(t, primary, redirectURI, challenge, authCookie)
}

func TestLoginBruteForceBlockAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGIN_BLOCK") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGIN_BLOCK=1 to run the distributed login brute-force block E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	targets := []string{primary, secondary, tertiary}
	for i := range 7 { // The seventh committed failure starts the one-minute block.
		target := targets[i%len(targets)]
		client := newBrowserClient(t)
		client.Timeout = 60 * time.Second
		state := "login-block-" + strconv.Itoa(i)
		response := do(t, client, http.MethodGet, authorizationURL(t, target, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), state), nil, nil)
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("login-block init %d status=%d", i, response.StatusCode)
		}
		interaction := loginInteraction(t, response)
		response.Body.Close()
		response = do(t, client, http.MethodPost, target+"/auth/login", strings.NewReader(url.Values{"interaction": {interaction}, "username": {username}, "password": {password + "-wrong"}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
		response.Body.Close()
		if i < 6 && response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login-block failure %d status=%d", i+1, response.StatusCode)
		}
		if i == 6 {
			retry, _ := strconv.Atoi(response.Header.Get("Retry-After"))
			if response.StatusCode != http.StatusTooManyRequests || retry < 1 || retry > 70 {
				t.Fatalf("login-block trigger status=%d retry-after=%d", response.StatusCode, retry)
			}
		}
	}
}

func TestAuthorizationCodeResourceIndicatorAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_RESOURCE_INDICATORS") != "1" && os.Getenv("GOAUTHY_E2E_DEFAULT_AUD_PHASE") == "" {
		t.Skip("set GOAUTHY_E2E_RESOURCE_INDICATORS=1 to run resource-indicator E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, _ := loginForResourceCode(t, client, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "resource-allowed", explicitResourceIndicator)
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
	assertResourceAudience(t, client, secondary, clientSecret, tokens.AccessToken, explicitResourceIndicator)

	for _, tc := range []struct {
		name      string
		resources []string
	}{
		{"same", []string{explicitResourceIndicator}},
		{"changed", []string{"https://other.example.test/v1"}},
		{"expanded", []string{explicitResourceIndicator, "https://other.example.test/v1"}},
	} {
		t.Run("refresh "+tc.name+" target is rejected", func(t *testing.T) {
			assertRefreshResourceRejected(t, client, secondary, clientSecret, tokens.RefreshToken, tc.resources)
		})
	}
	refreshed := refresh(t, client, primary, clientSecret, tokens.RefreshToken)
	assertResourceAudience(t, client, secondary, clientSecret, refreshed.AccessToken, explicitResourceIndicator)

	badVerifier := pkceVerifier(t)
	assertResourceAuthorizationRejected(t, client, secondary, redirectURI, pkceChallenge(badVerifier), "resource-unallowed", "https://other.example.test/v1")
}

func TestDefaultResourceAudienceAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_RESOURCE_INDICATORS") != "1" && os.Getenv("GOAUTHY_E2E_DEFAULT_AUD_PHASE") == "" {
		t.Skip("set GOAUTHY_E2E_RESOURCE_INDICATORS=1 to run default-audience E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	if statePath := os.Getenv("GOAUTHY_E2E_DEFAULT_AUD_STATE"); os.Getenv("GOAUTHY_E2E_DEFAULT_AUD_PHASE") == "after-replacement" {
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state tokenResponse
		if err := json.Unmarshal(data, &state); err != nil || state.AccessToken == "" || state.RefreshToken == "" {
			t.Fatalf("invalid saved default-audience state: %v", err)
		}
		assertResourceAudience(t, newBrowserClient(t), secondary, clientSecret, state.AccessToken, defaultResourceIndicator)
		refreshed := refresh(t, newBrowserClient(t), secondary, clientSecret, state.RefreshToken)
		assertResourceAudience(t, newBrowserClient(t), primary, clientSecret, refreshed.AccessToken, defaultResourceIndicator)
		return
	}
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}
	client := newBrowserClient(t)

	// Omitted resource uses the production bootstrap default for authorization_code.
	verifier := pkceVerifier(t)
	code, _ := loginForCode(t, client, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "default-aud-code")
	tokens := exchangeCode(t, client, secondary, clientSecret, redirectURI, code, verifier)
	assertResourceAudience(t, client, primary, clientSecret, tokens.AccessToken, defaultResourceIndicator)

	// The stored audience survives refresh and a different pod handles the refresh.
	refreshed := refresh(t, client, primary, clientSecret, tokens.RefreshToken)
	assertResourceAudience(t, client, secondary, clientSecret, refreshed.AccessToken, defaultResourceIndicator)
	if statePath := os.Getenv("GOAUTHY_E2E_DEFAULT_AUD_STATE"); statePath != "" {
		data, err := json.Marshal(tokens)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Omitted resource also uses the default for client_credentials.
	cc := tokenRequest(t, client, secondary, clientSecret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	assertResourceAudience(t, client, primary, clientSecret, cc.AccessToken, defaultResourceIndicator)
}

func TestTokenExchangeAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, _ := loginForResourceCode(t, client, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "token-exchange-source", defaultResourceIndicator)
	source := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
	if source.AccessToken == "" {
		t.Fatal("authorization-code exchange did not issue a source access token")
	}

	exchangeForm := func() url.Values {
		return url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":        {source.AccessToken},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"scope":                {"goauthy.read"},
			"resource":             {defaultResourceIndicator},
		}
	}
	response := tokenResponseFor(t, client, secondary, clientSecret, exchangeForm())
	var exchanged struct {
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		IDToken         string `json:"id_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&exchanged)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || exchanged.AccessToken == "" || exchanged.RefreshToken != "" || exchanged.IDToken != "" || exchanged.TokenType != "bearer" || exchanged.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("token exchange status=%d access=%t refresh=%t id=%t type=%q issued_type=%q err=%v", response.StatusCode, exchanged.AccessToken != "", exchanged.RefreshToken != "", exchanged.IDToken != "", exchanged.TokenType, exchanged.IssuedTokenType, err)
	}
	assertTokenExchangeIntrospection(t, client, tertiary, clientSecret, exchanged.AccessToken, defaultResourceIndicator)
	assertDPoPTokenExchangeAcrossPods(t, client, primary, secondary, tertiary, clientSecret, exchangeForm)

	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{"unknown resource", func(form url.Values) { form.Set("resource", "https://other.example.test/v1") }, "invalid_target"},
		{"widened scope", func(form url.Values) { form.Set("scope", "openid") }, "invalid_scope"},
		{"missing actor type", func(form url.Values) { form.Set("actor_token", source.AccessToken) }, "invalid_request"},
		{"wrong actor type", func(form url.Values) {
			form.Set("actor_token", source.AccessToken)
			form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:id_token")
		}, "invalid_request"},
		{"resource and audience", func(form url.Values) { form.Set("audience", defaultResourceIndicator) }, "invalid_request"},
		{"wrong subject type", func(form url.Values) { form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token") }, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := exchangeForm()
			tc.mutate(form)
			assertTokenExchangeRejected(t, client, secondary, clientSecret, form, tc.want)
		})
	}
	actorUsername, actorPassword, actorEnabled := tokenExchangeActorCredentials(t, primary, secondary, username, password)
	if actorEnabled {
		assertActorTokenExchangeAcrossPods(t, client, primary, secondary, tertiary, redirectURI, clientSecret, username, actorUsername, actorPassword, source, exchangeForm)
	}

	revokeAccessToken(t, client, primary, clientSecret, source.AccessToken)
	assertTokenExchangeRejected(t, client, secondary, clientSecret, exchangeForm(), "invalid_grant")
}

func tokenExchangeActorCredentials(t *testing.T, primary, secondary, adminUsername, adminPassword string) (username, password string, enabled bool) {
	t.Helper()
	username, password = os.Getenv("GOAUTHY_E2E_ACTOR_USERNAME"), os.Getenv("GOAUTHY_E2E_ACTOR_PASSWORD")
	if username != "" && password != "" {
		return username, password, true
	}
	if os.Getenv("GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR") != "1" {
		t.Log("set GOAUTHY_E2E_ACTOR_USERNAME/password or GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR=1 to run delegated actor exchange coverage")
		return "", "", false
	}
	if username != "" || password != "" {
		t.Fatal("GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR requires both external actor credentials or neither")
	}
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, adminUsername, adminPassword)
	username, password = "token-exchange-actor-"+randomManagedUIID(t)+"@goauthy.e2e", "Token-Exchange-Actor-Password-1A"
	subject := createCatalogSessionUser(t, admin, primary, rbacMutationHeaders(csrf), username, password)
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(subject), nil, rbacMutationHeaders(csrf))
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("token-exchange actor cleanup status=%d", response.StatusCode)
		}
	})
	return username, password, true
}

func assertDPoPTokenExchangeAcrossPods(t *testing.T, client *http.Client, primary, secondary, tertiary, secret string, form func() url.Values) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{Key: public}
	thumb, err := publicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	challenge := postDPoPToken(t, client, primary, secret, form(), dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	proof := dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, "")
	response := postDPoPToken(t, client, secondary, secret, form(), proof)
	issued := decodeDPoPToken(t, response, jkt)
	response.Body.Close()
	if issued.RefreshToken != "" || issued.IDToken != "" {
		t.Fatal("DPoP exchange issued refresh or ID token")
	}
	claims, err := oidc.VerifyAccessToken(issued.AccessToken, publicJWKS(t, client, tertiary), primary, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify exchanged DPoP signature: %v", err)
	}
	if claims.Type != "DPoP" || claims.ConfirmationJKT != jkt || !slices.Equal(claims.Audience, []string{"goauthy-dev", defaultResourceIndicator}) || claims.AuthorizedParty != "goauthy-dev" || strings.Join(claims.Scope, " ") != "goauthy.read" {
		t.Fatalf("exchanged DPoP claims mismatch: type=%t binding=%t audience=%t client=%t scope=%t", claims.Type == "DPoP", claims.ConfirmationJKT == jkt, slices.Equal(claims.Audience, []string{"goauthy-dev", defaultResourceIndicator}), claims.AuthorizedParty == "goauthy-dev", strings.Join(claims.Scope, " ") == "goauthy.read")
	}
	assertDPoPClientIntrospection(t, client, tertiary, secret, issued.AccessToken, jkt)
	replay := postDPoPToken(t, client, tertiary, secret, form(), proof)
	assertDPoPTokenNonce(t, replay)
	replay.Body.Close()
	for _, field := range []string{"subject_token", "actor_token"} {
		challenge := postDPoPToken(t, client, primary, secret, form(), dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
		nonce := assertDPoPTokenNonce(t, challenge)
		challenge.Body.Close()
		boundInput := form()
		boundInput.Set(field, issued.AccessToken)
		if field == "actor_token" {
			boundInput.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
		}
		// A fresh request proof must not make a constrained input exchangeable.
		denied := postDPoPToken(t, client, secondary, secret, boundInput, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
		var payload struct {
			Error string `json:"error"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(denied.Body, 8<<10)).Decode(&payload)
		denied.Body.Close()
		if denied.StatusCode != http.StatusBadRequest || decodeErr != nil || payload.Error != "invalid_grant" {
			t.Fatalf("bound %s rejection status=%d error=%q", field, denied.StatusCode, payload.Error)
		}
	}
}

func assertActorTokenExchangeAcrossPods(t *testing.T, sourceClient *http.Client, primary, secondary, tertiary, redirectURI, clientSecret, sourceUsername, actorUsername, actorPassword string, source tokenResponse, exchangeForm func() url.Values) {
	t.Helper()
	actorClient := newBrowserClient(t)
	actorVerifier := pkceVerifier(t)
	actorCode, _ := loginForResourceCode(t, actorClient, primary, secondary, redirectURI, pkceChallenge(actorVerifier), actorUsername, actorPassword, "token-exchange-actor", defaultResourceIndicator)
	actorResponse := tokenResponseFor(t, actorClient, primary, clientSecret, url.Values{"grant_type": {"authorization_code"}, "code": {actorCode}, "redirect_uri": {redirectURI}, "code_verifier": {actorVerifier}})
	var actor struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err := json.NewDecoder(io.LimitReader(actorResponse.Body, 8<<10)).Decode(&actor)
	actorResponse.Body.Close()
	if actorResponse.StatusCode != http.StatusOK || err != nil || actor.AccessToken == "" || actor.ExpiresIn <= 0 {
		t.Fatalf("actor authorization-code token status=%d expires_in=%d err=%v", actorResponse.StatusCode, actor.ExpiresIn, err)
	}
	sourceSubject := tokenSubject(t, sourceClient, tertiary, clientSecret, source.AccessToken)
	actorSubject := tokenSubject(t, actorClient, tertiary, clientSecret, actor.AccessToken)
	if sourceSubject == "" || actorSubject == "" || sourceSubject == actorSubject || sourceUsername == actorUsername {
		t.Fatalf("delegation requires distinct authenticated users: source=%q actor=%q", sourceSubject, actorSubject)
	}

	delegation := exchangeForm()
	delegation.Set("actor_token", actor.AccessToken)
	delegation.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	response := tokenResponseFor(t, sourceClient, secondary, clientSecret, delegation)
	var exchanged struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&exchanged)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || exchanged.AccessToken == "" || exchanged.ExpiresIn <= 0 || exchanged.ExpiresIn > actor.ExpiresIn {
		t.Fatalf("actor token exchange status=%d expires_in=%d actor_expires_in=%d err=%v", response.StatusCode, exchanged.ExpiresIn, actor.ExpiresIn, err)
	}
	assertActorTokenExchangeIntrospection(t, sourceClient, tertiary, clientSecret, exchanged.AccessToken, sourceSubject, actorSubject)
	nestedDelegation := exchangeForm()
	nestedDelegation.Set("actor_token", exchanged.AccessToken)
	nestedDelegation.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	nestedResponse := tokenResponseFor(t, sourceClient, tertiary, clientSecret, nestedDelegation)
	var nested struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.NewDecoder(io.LimitReader(nestedResponse.Body, 8<<10)).Decode(&nested)
	nestedResponse.Body.Close()
	if nestedResponse.StatusCode != http.StatusOK || err != nil || nested.AccessToken == "" || nested.ExpiresIn <= 0 || nested.ExpiresIn > exchanged.ExpiresIn {
		t.Fatalf("nested actor token exchange status=%d expires_in=%d first_expires_in=%d decode_ok=%t", nestedResponse.StatusCode, nested.ExpiresIn, exchanged.ExpiresIn, err == nil)
	}
	nestedClaims, err := oidc.VerifyAccessToken(nested.AccessToken, publicJWKS(t, sourceClient, primary), primary, time.Now().UTC())
	if err != nil || nestedClaims.Subject != sourceSubject || nestedClaims.Actor == nil || nestedClaims.Actor.Subject != sourceSubject || nestedClaims.Actor.Actor == nil || nestedClaims.Actor.Actor.Subject != actorSubject || nestedClaims.Actor.Actor.Actor != nil {
		t.Fatalf("nested actor signed claims valid=%t subject_matches=%t chain_matches=%t", err == nil, nestedClaims.Subject == sourceSubject, nestedClaims.Actor != nil && nestedClaims.Actor.Subject == sourceSubject && nestedClaims.Actor.Actor != nil && nestedClaims.Actor.Actor.Subject == actorSubject && nestedClaims.Actor.Actor.Actor == nil)
	}
	assertNestedActorTokenExchangeIntrospection(t, sourceClient, secondary, clientSecret, nested.AccessToken, sourceSubject, actorSubject)

	dpopActor := issueDPoPActorAccessToken(t, primary, secondary, redirectURI, clientSecret, actorUsername, actorPassword)
	dpopRejected := exchangeForm()
	dpopRejected.Set("actor_token", dpopActor)
	dpopRejected.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	assertTokenExchangeRejected(t, sourceClient, secondary, clientSecret, dpopRejected, "invalid_grant")

	revokeAccessToken(t, actorClient, primary, clientSecret, actor.AccessToken)
	assertTokenExchangeRejected(t, sourceClient, secondary, clientSecret, delegation, "invalid_grant")
}

func issueDPoPActorAccessToken(t *testing.T, primary, secondary, redirectURI, clientSecret, username, password string) string {
	t.Helper()
	client := newBrowserClient(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := pkceVerifier(t)
	code, _ := loginForResourceCode(t, client, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "token-exchange-dpop-actor", defaultResourceIndicator)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	challenge := postDPoPToken(t, client, primary, clientSecret, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	issued := postDPoPToken(t, client, secondary, clientSecret, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	defer issued.Body.Close()
	if issued.StatusCode != http.StatusOK {
		t.Fatalf("DPoP actor token status=%d", issued.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(issued.Body, 8<<10)).Decode(&token); err != nil || token.AccessToken == "" {
		t.Fatalf("decode DPoP actor token: %v", err)
	}
	return token.AccessToken
}

func TestUserInfoAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	verifier := pkceVerifier(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := noRedirectClient(t, jar)
	code, _ := loginForCode(t, client, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "userinfo-oauth")
	// loginForCode intentionally requests OAuth-only scopes; request the OpenID code explicitly.
	// Reuse the authenticated browser session for the OpenID request.
	oidcVerifier := pkceVerifier(t)
	oidcCode := authorizeWithCookie(t, client, primary, redirectURI, pkceChallenge(oidcVerifier), "userinfo-openid", "userinfo-nonce")
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, oidcCode, oidcVerifier)
	claims := verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, client, primary), primary)
	if claims.Subject == "" {
		t.Fatal("OpenID token has no subject")
	}
	assertUserInfoSubject(t, client, secondary, http.MethodGet, tokens.AccessToken, claims.Subject)
	assertUserInfoSubject(t, client, primary, http.MethodPost, tokens.AccessToken, claims.Subject)

	assertUserInfoRejected(t, client, secondary, http.MethodGet, "", "")
	assertUserInfoRejected(t, client, secondary, http.MethodGet, "Basic not-a-bearer-token", "")
	assertUserInfoRejected(t, client, secondary, http.MethodGet, "Bearer "+tokens.AccessToken, "?access_token=not-allowed")
	formToken := do(t, client, http.MethodPost, secondary+"/oidc/userinfo", strings.NewReader(url.Values{"access_token": {tokens.AccessToken}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if formToken.StatusCode != http.StatusUnauthorized || formToken.Header.Get("WWW-Authenticate") != "Bearer" {
		formToken.Body.Close()
		t.Fatalf("UserInfo form-token rejection status=%d headers=%#v", formToken.StatusCode, formToken.Header)
	}
	formToken.Body.Close()

	// This OAuth-only code was issued before the OpenID request and must not authorize UserInfo.
	oauthOnly := exchangeCode(t, client, secondary, clientSecret, redirectURI, code, verifier)
	assertUserInfoRejected(t, client, primary, http.MethodGet, "Bearer "+oauthOnly.AccessToken, "")

	revokeAccessToken(t, client, primary, clientSecret, tokens.AccessToken)
	assertUserInfoRejected(t, client, secondary, http.MethodGet, "Bearer "+tokens.AccessToken, "")
}

func TestRPInitiatedLogoutAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	backchannelSinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}
	postLogoutRedirectURI := os.Getenv("GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = defaultPostLogoutRedirectURI
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := noRedirectClient(t, jar)
	loginVerifier := pkceVerifier(t)
	_, _ = loginForCode(t, client, primary, secondary, redirectURI, pkceChallenge(loginVerifier), username, password, "logout-login")
	// Login first, then obtain the ID-token hint and retain a second code tied
	// to that same browser sid for logout revocation.
	oidcVerifier := pkceVerifier(t)
	oidcCode := authorizeWithCookie(t, client, primary, redirectURI, pkceChallenge(oidcVerifier), "logout-oidc", "logout-nonce")
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, oidcCode, oidcVerifier)
	if tokens.IDToken == "" {
		t.Fatal("OpenID authorization did not return an ID-token hint")
	}
	keys := publicJWKS(t, client, primary)
	idTokenClaims := verifyPublicIDToken(t, tokens.IDToken, keys, primary)
	assertPublicBackchannelDiscovery(t, client, primary)
	pendingVerifier := pkceVerifier(t)
	pendingCode := authorizeWithCookie(t, client, secondary, redirectURI, pkceChallenge(pendingVerifier), "logout-pending", "logout-pending-nonce")

	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "near match", url: logoutURL(t, secondary, tokens.IDToken, postLogoutRedirectURI+"&next=attacker", "bad")},
		{name: "open redirect", url: logoutURL(t, secondary, tokens.IDToken, "https://attacker.invalid/logout", "bad")},
		{name: "malformed hint", url: logoutURL(t, secondary, "not-a-jwt", postLogoutRedirectURI, "bad")},
		{name: "oversize hint", url: logoutURL(t, secondary, strings.Repeat("x", 4097), postLogoutRedirectURI, "bad")},
		{name: "duplicate parameter", url: secondary + "/oidc/logout?" + url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {postLogoutRedirectURI, postLogoutRedirectURI}}.Encode()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := do(t, client, http.MethodGet, tc.url, nil, map[string]string{"Sec-Fetch-Site": "none"})
			assertRejectedLogout(t, response, http.StatusBadRequest)
			response.Body.Close()
			assertSessionStillActive(t, client, primary, redirectURI, "logout-invalid-"+strings.ReplaceAll(tc.name, " ", "-"))
		})
	}

	state := "logout-state%20&+"
	response := do(t, client, http.MethodGet, logoutURL(t, secondary, tokens.IDToken, postLogoutRedirectURI, state), nil, map[string]string{"Sec-Fetch-Site": "none"})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != postLogoutRedirectURI+"&state="+url.QueryEscape(state) {
		response.Body.Close()
		t.Fatalf("hint logout status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	assertDeletedSessionCookie(t, response.Cookies(), secondary)
	response.Body.Close()
	if backchannelSinkURL != "" {
		assertBackchannelLogoutDelivery(t, backchannelSinkURL, keys, primary, idTokenClaims.SessionID)
	}

	assertLoginRequired(t, do(t, client, http.MethodGet, authorizationURL(t, primary, redirectURI, pkceChallenge(pkceVerifier(t)), "logout-after-hint")+"&prompt=none", nil, nil), "logout-after-hint")
	assertUserInfoRejected(t, client, tertiary, http.MethodGet, "Bearer "+tokens.AccessToken, "")
	assertRefreshRejected(t, client, primary, clientSecret, tokens.RefreshToken)
	assertCodeExchangeRejected(t, client, secondary, clientSecret, redirectURI, pendingCode, pendingVerifier, "logout-invalidated pending code")

	confirmationJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	confirmationClient := noRedirectClient(t, confirmationJar)
	confirmationVerifier := pkceVerifier(t)
	_, _ = loginForCode(t, confirmationClient, primary, secondary, redirectURI, pkceChallenge(confirmationVerifier), username, password, "logout-confirm-login")
	confirmURL := secondary + "/oidc/logout?" + url.Values{
		"client_id":                {"goauthy-dev"},
		"post_logout_redirect_uri": {postLogoutRedirectURI},
		"state":                    {"confirm-state"},
	}.Encode()
	response = do(t, confirmationClient, http.MethodGet, confirmURL, nil, map[string]string{"Sec-Fetch-Site": "none"})
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("no-hint logout status=%d, want confirmation page", response.StatusCode)
	}
	confirmation, ok := hiddenInputValue(readLimitedBody(t, response), "confirmation")
	if !ok {
		response.Body.Close()
		t.Fatal("logout confirmation page has no confirmation token")
	}
	response.Body.Close()

	form := url.Values{"confirmation": {confirmation}}
	response = do(t, confirmationClient, http.MethodPost, primary+"/oidc/logout", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
	})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != postLogoutRedirectURI+"&state=confirm-state" {
		response.Body.Close()
		t.Fatalf("confirmation logout status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	assertDeletedSessionCookie(t, response.Cookies(), primary)
	response.Body.Close()

	assertLoginRequired(t, do(t, confirmationClient, http.MethodGet, authorizationURL(t, secondary, redirectURI, pkceChallenge(pkceVerifier(t)), "logout-after-confirm")+"&prompt=none", nil, nil), "logout-after-confirm")
	replay := do(t, confirmationClient, http.MethodPost, secondary+"/oidc/logout", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
	})
	assertRejectedLogout(t, replay, http.StatusForbidden)
	replay.Body.Close()
}

func TestBackchannelLogoutDeliveryFailureModesAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	if sinkURL == "" {
		t.Skip("set GOAUTHY_E2E_BACKCHANNEL_SINK_URL to run back-channel delivery E2E")
	}
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}
	postLogoutRedirectURI := os.Getenv("GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = defaultPostLogoutRedirectURI
	}

	t.Run("single success", func(t *testing.T) {
		setBackchannelSinkControl(t, sinkURL, 0, 0, http.StatusNoContent)
		client := newBrowserClient(t)
		_, _ = loginForCode(t, client, primary, secondary, redirectURI, pkceChallenge(pkceVerifier(t)), username, password, "backchannel-success-login")
		verifier := pkceVerifier(t)
		code := authorizeWithCookie(t, client, tertiary, redirectURI, pkceChallenge(verifier), "backchannel-success-oidc", "backchannel-success-nonce")
		tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
		claims := verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, client, secondary), primary)
		response := do(t, client, http.MethodGet, logoutURL(t, secondary, tokens.IDToken, postLogoutRedirectURI, "backchannel-success-logout"), nil, map[string]string{"Sec-Fetch-Site": "none"})
		if response.StatusCode != http.StatusSeeOther {
			response.Body.Close()
			t.Fatalf("success logout status=%d", response.StatusCode)
		}
		response.Body.Close()

		events := waitForBackchannelEvents(t, sinkURL, func(events []backchannelEvent) bool {
			return len(events) == 1 && events[0].Status == http.StatusNoContent
		})
		assertPublicLogoutToken(t, events[0].Token, publicJWKS(t, client, tertiary), primary, claims.SessionID)
		if events, err := backchannelEvents(&http.Client{Timeout: 5 * time.Second}, sinkURL); err != nil || len(events) != 1 || events[0].Status != http.StatusNoContent {
			t.Fatalf("successful back-channel logout must be delivered once: count=%d err=%v", len(events), err)
		}
	})

	t.Run("timed out first attempt retries", func(t *testing.T) {
		setBackchannelSinkControl(t, sinkURL, 1, 12000, http.StatusNoContent)
		client := newBrowserClient(t)
		_, _ = loginForCode(t, client, tertiary, primary, redirectURI, pkceChallenge(pkceVerifier(t)), username, password, "backchannel-timeout-login")
		verifier := pkceVerifier(t)
		code := authorizeWithCookie(t, client, secondary, redirectURI, pkceChallenge(verifier), "backchannel-timeout-oidc", "backchannel-timeout-nonce")
		tokens := exchangeCode(t, client, tertiary, clientSecret, redirectURI, code, verifier)
		claims := verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, client, primary), primary)
		response := do(t, client, http.MethodGet, logoutURL(t, primary, tokens.IDToken, postLogoutRedirectURI, "backchannel-timeout-logout"), nil, map[string]string{"Sec-Fetch-Site": "none"})
		if response.StatusCode != http.StatusSeeOther {
			response.Body.Close()
			t.Fatalf("timeout logout status=%d", response.StatusCode)
		}
		response.Body.Close()

		first := waitForBackchannelEvents(t, sinkURL, func(events []backchannelEvent) bool { return len(events) >= 1 })[0]
		if first.Status != 0 && first.Status != http.StatusServiceUnavailable {
			t.Fatalf("first delayed delivery status=%d, want cancellation or 503", first.Status)
		}
		events := waitForBackchannelEvents(t, sinkURL, func(events []backchannelEvent) bool {
			return len(events) >= 2 && events[1].Status == http.StatusNoContent
		})
		firstClaims := assertPublicLogoutToken(t, events[0].Token, publicJWKS(t, client, secondary), primary, claims.SessionID)
		secondClaims := assertPublicLogoutToken(t, events[1].Token, publicJWKS(t, client, secondary), primary, claims.SessionID)
		if firstClaims.JTI == secondClaims.JTI {
			t.Fatal("retried public logout token reused jti")
		}
	})
}

func newBrowserClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return noRedirectClient(t, jar)
}

type backchannelEvent struct {
	Token  string `json:"token"`
	Status int    `json:"status"`
}

func assertPublicBackchannelDiscovery(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	response := do(t, client, http.MethodGet, baseURL+"/.well-known/openid-configuration", nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("OpenID discovery status=%d", response.StatusCode)
	}
	var metadata struct {
		BackChannelLogoutSupported        bool `json:"backchannel_logout_supported"`
		BackChannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if !metadata.BackChannelLogoutSupported || !metadata.BackChannelLogoutSessionSupported {
		t.Fatalf("OpenID discovery back-channel support=%#v", metadata)
	}
}

func assertBackchannelLogoutDelivery(t *testing.T, sinkURL string, keys jose.JSONWebKeySet, issuer, sessionID string) {
	t.Helper()
	events := waitForBackchannelEvents(t, sinkURL, func(events []backchannelEvent) bool { return len(events) >= 2 })
	first, second := events[0], events[1]
	if first.Status != http.StatusServiceUnavailable || second.Status != http.StatusNoContent || first.Token == "" || second.Token == "" {
		t.Fatalf("back-channel retry statuses=%d,%d", first.Status, second.Status)
	}
	firstClaims := assertPublicLogoutToken(t, first.Token, keys, issuer, sessionID)
	secondClaims := assertPublicLogoutToken(t, second.Token, keys, issuer, sessionID)
	if firstClaims.SessionID != sessionID || secondClaims.SessionID != sessionID || firstClaims.JTI == secondClaims.JTI || !isThirtySecondLifetime(firstClaims) || !isThirtySecondLifetime(secondClaims) {
		t.Fatalf("unexpected public logout-token retries: first=%#v second=%#v", firstClaims, secondClaims)
	}
}

func waitForBackchannelEvents(t *testing.T, sinkURL string, ready func([]backchannelEvent) bool) []backchannelEvent {
	t.Helper()
	// Event state, rather than elapsed time, determines success; these values
	// only pace polling and bound a failed deployment.
	deadline := time.Now().Add(20 * time.Second)
	client := backchannelHTTPClient(t, sinkURL)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var events []backchannelEvent
	var lastErr error
	for {
		events, lastErr = backchannelEvents(client, sinkURL)
		if lastErr == nil && ready(events) {
			return events
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out waiting for back-channel delivery: count=%d err=%v", len(events), lastErr)
		}
		select {
		case <-ticker.C:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

func backchannelHTTPClient(t *testing.T, sinkURL string) *http.Client {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if !strings.HasPrefix(sinkURL, "https://") {
		return client
	}
	caFile := os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_CA_FILE")
	if caFile == "" {
		t.Fatal("HTTPS back-channel sink requires GOAUTHY_E2E_BACKCHANNEL_SINK_CA_FILE")
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read back-channel sink CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("invalid back-channel sink CA")
	}
	u, err := url.Parse(sinkURL)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("invalid back-channel sink URL: %v", err)
	}
	client.Transport = &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}}
	return client
}

func setBackchannelSinkControl(t *testing.T, sinkURL string, failFirst, delayFirstMS, successStatus int) {
	t.Helper()
	body, err := json.Marshal(struct {
		FailFirst     int `json:"fail_first"`
		DelayFirstMS  int `json:"delay_first_ms"`
		SuccessStatus int `json:"success_status"`
	}{failFirst, delayFirstMS, successStatus})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, backchannelHTTPClient(t, sinkURL), http.MethodPost, sinkURL+"/control", strings.NewReader(string(body)), map[string]string{"Content-Type": "application/json"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("sink control status=%d", response.StatusCode)
	}
}

func assertPublicLogoutToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, sessionID string) oidc.LogoutTokenClaims {
	t.Helper()
	claims, err := oidc.VerifyLogoutToken(token, keys, issuer, "goauthy-dev", time.Now().UTC())
	if err != nil {
		t.Fatalf("verify public logout token: %v", err)
	}
	if claims.SessionID != sessionID || !isThirtySecondLifetime(claims) {
		t.Fatalf("unexpected public logout token: %#v", claims)
	}
	return claims
}

func backchannelEvents(client *http.Client, sinkURL string) ([]backchannelEvent, error) {
	response, err := client.Get(sinkURL + "/events")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sink events status=%d", response.StatusCode)
	}
	var body struct {
		Events []backchannelEvent `json:"events"`
	}
	// The sink retains up to 128 bounded logout-token records. A full
	// retry-limit history exceeds the former 64 KiB small-smoke limit.
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.Events, nil
}

func isThirtySecondLifetime(claims oidc.LogoutTokenClaims) bool {
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt)
	return lifetime == 30*time.Second
}

func assertDeployedIdleExpiry(t *testing.T, baseURL, redirectURI, challenge string, authCookie *http.Cookie) {
	t.Helper()
	if os.Getenv("GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY") != "1" {
		t.Log("skipping wall-clock idle-expiry assertion; set GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=1 and GOAUTHY_E2E_SESSION_IDLE_TIMEOUT (for example, 10s)")
		return
	}
	raw := os.Getenv("GOAUTHY_E2E_SESSION_IDLE_TIMEOUT")
	if raw == "" {
		t.Skip("set GOAUTHY_E2E_SESSION_IDLE_TIMEOUT (for example, 10s) with GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=1")
	}
	idle, err := time.ParseDuration(raw)
	if err != nil || idle < time.Second || idle > time.Minute {
		t.Fatalf("invalid GOAUTHY_E2E_SESSION_IDLE_TIMEOUT %q", raw)
	}
	deadline := time.NewTimer(idle + 5*time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	client := clientWithCookie(t, baseURL, authCookie)
	var lastStatus int
	var lastLocation string
	for {
		response := do(t, client, http.MethodGet,
			authorizationURL(t, baseURL, redirectURI, challenge, "idle-session")+"&prompt=none", nil, nil)
		lastStatus, lastLocation = response.StatusCode, response.Header.Get("Location")
		location, parseErr := url.Parse(lastLocation)
		loginRequired := parseErr == nil && (response.StatusCode == http.StatusFound || response.StatusCode == http.StatusSeeOther) && location.Query().Get("error") == "login_required" && location.Query().Get("state") == "idle-session" && location.Query().Get("code") == ""
		response.Body.Close()
		if loginRequired {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatalf("timed out waiting for idle session expiry: status=%d location=%q", lastStatus, lastLocation)
		case <-ticker.C:
		}
	}
}

func logoutURL(t *testing.T, baseURL, idTokenHint, postLogoutRedirectURI, state string) string {
	t.Helper()
	return baseURL + "/oidc/logout?" + url.Values{
		"id_token_hint":            {idTokenHint},
		"post_logout_redirect_uri": {postLogoutRedirectURI},
		"state":                    {state},
	}.Encode()
}

func assertSessionStillActive(t *testing.T, client *http.Client, baseURL, redirectURI, state string) {
	t.Helper()
	response := do(t, client, http.MethodGet, authorizationURL(t, baseURL, redirectURI, pkceChallenge(pkceVerifier(t)), state)+"&prompt=none", nil, nil)
	assertAuthorizationCodeRedirect(t, response, state)
}

func assertRejectedLogout(t *testing.T, response *http.Response, status int) {
	t.Helper()
	if response.StatusCode != status || response.Header.Get("Location") != "" {
		t.Fatalf("rejected logout status=%d location=%q, want status=%d and no redirect", response.StatusCode, response.Header.Get("Location"), status)
	}
	for _, cookie := range response.Cookies() {
		if cookie.MaxAge < 0 {
			t.Fatalf("rejected logout must not delete a cookie: %#v", cookie)
		}
	}
}

func assertDeletedSessionCookie(t *testing.T, cookies []*http.Cookie, issuer string) {
	t.Helper()
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	name, secure := "goauthy_session", false
	if u.Scheme == "https" {
		name, secure = "__Host-goauthy_session", true
	}
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value == "" && cookie.MaxAge < 0 && cookie.Expires.Equal(time.Unix(1, 0).UTC()) && cookie.HttpOnly && cookie.SameSite == http.SameSiteLaxMode && cookie.Secure == secure && cookie.Path == "/" {
			return
		}
	}
	t.Fatalf("logout response did not securely delete %q cookie: %#v", name, cookies)
}

func readLimitedBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func browserE2EConfig(t *testing.T) (primary, secondary, username, password, clientSecret string) {
	t.Helper()
	primary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username = os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password = os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	clientSecret = os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || username == "" || password == "" || clientSecret == "" {
		t.Skip("set both E2E URLs, browser username/password, and OAuth client secret to run browser E2E")
	}
	return primary, secondary, username, password, clientSecret
}

func logoutTertiaryURL(t *testing.T) string {
	t.Helper()
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		t.Skip("set GOAUTHY_E2E_TERTIARY_URL to run three-pod logout E2E")
	}
	return tertiary
}

func noRedirectClient(t *testing.T, jar http.CookieJar) *http.Client {
	t.Helper()
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func authorizationURL(t *testing.T, baseURL, redirectURI, challenge, state string) string {
	t.Helper()
	return authorizationURLForClient(baseURL, "goauthy-dev", redirectURI, challenge, state, "goauthy.read offline_access")
}

func authorizationURLForClient(baseURL, clientID, redirectURI, challenge, state, scope string) string {
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return baseURL + "/oidc/authorize?" + values.Encode()
}

func authorizationURLWithResource(t *testing.T, baseURL, redirectURI, challenge, state, resource string) string {
	t.Helper()
	endpoint, err := url.Parse(authorizationURL(t, baseURL, redirectURI, challenge, state))
	if err != nil {
		t.Fatal(err)
	}
	values := endpoint.Query()
	values.Set("resource", resource)
	endpoint.RawQuery = values.Encode()
	return endpoint.String()
}

func oidcAuthorizationURL(t *testing.T, baseURL, redirectURI, challenge, state, nonce string) string {
	t.Helper()
	return oidcAuthorizationURLForClient(t, baseURL, "goauthy-dev", redirectURI, challenge, state, nonce, "openid goauthy.read offline_access")
}

func oidcAuthorizationURLForClient(t *testing.T, baseURL, clientID, redirectURI, challenge, state, nonce, scope string) string {
	t.Helper()
	endpoint, err := url.Parse(authorizationURLForClient(baseURL, clientID, redirectURI, challenge, state, scope))
	if err != nil {
		t.Fatal(err)
	}
	values := endpoint.Query()
	values.Set("nonce", nonce)
	endpoint.RawQuery = values.Encode()
	return endpoint.String()
}

func assertPKCERejectedWithoutRedirectLeakage(t *testing.T, baseURL, redirectURI string) {
	t.Helper()
	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
	}{
		{name: "missing challenge", mutate: func(values url.Values) { values.Del("code_challenge"); values.Del("code_challenge_method") }},
		{name: "plain challenge", mutate: func(values url.Values) {
			values.Set("code_challenge", "plain-challenge-value")
			values.Set("code_challenge_method", "plain")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := url.Values{
				"response_type": {"code"}, "client_id": {"goauthy-dev"}, "redirect_uri": {redirectURI},
				"scope": {"goauthy.read"}, "state": {"must-not-leak"},
			}
			tc.mutate(values)
			response := do(t, noRedirectClient(t, nil), http.MethodGet, baseURL+"/oidc/authorize?"+values.Encode(), nil, nil)
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest || response.Header.Get("Location") != "" {
				t.Fatalf("invalid PKCE status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
			}
		})
	}
}

func loginForCode(t *testing.T, client *http.Client, primary, secondary, redirectURI, challenge, username, password, state string) (string, *http.Cookie) {
	t.Helper()
	return loginForAuthorizationURL(t, client, authorizationURL(t, primary, redirectURI, challenge, state), primary, secondary, username, password, state)
}

func loginForResourceCode(t *testing.T, client *http.Client, primary, secondary, redirectURI, challenge, username, password, state, resource string) (string, *http.Cookie) {
	t.Helper()
	return loginForAuthorizationURL(t, client, authorizationURLWithResource(t, primary, redirectURI, challenge, state, resource), primary, secondary, username, password, state)
}

func loginForAuthorizationURL(t *testing.T, client *http.Client, authorizeURL, primary, secondary, username, password, state string) (string, *http.Cookie) {
	t.Helper()
	code, cookie, _ := loginForAuthorizationURLWithLocation(t, client, authorizeURL, primary, secondary, username, password, state)
	return code, cookie
}

// passwordLoginResponse respects the deployed limiter without retrying credential
// failures. A retry creates a fresh authorization interaction.
func passwordLoginResponse(t *testing.T, client *http.Client, authorizeURL, primary, secondary, username, password string) (*http.Response, *http.Cookie) {
	t.Helper()
	for attempt := 0; ; attempt++ {
		response := do(t, client, http.MethodGet, authorizeURL, nil, nil)
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
			response.Body.Close()
			t.Fatalf("authorize status = %d, want login form: %q", response.StatusCode, body)
		}
		interaction := loginInteraction(t, response)
		initCookie := assertSessionCookie(t, response.Cookies(), primary)
		response.Body.Close()
		form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
		response = do(t, client, http.MethodPost, secondary+"/auth/login", strings.NewReader(form.Encode()), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin",
		})

		if response.StatusCode != http.StatusTooManyRequests || attempt != 0 {
			return response, initCookie
		}
		response.Body.Close()
		seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
		if err != nil || seconds < 1 || seconds > 60 {
			t.Fatal("invalid login Retry-After")
		}
		t.Logf("waiting %d seconds for the login attempt window", seconds)
		time.Sleep(time.Duration(seconds)*time.Second + 100*time.Millisecond)
	}
}

func loginForAuthorizationURLWithLocation(t *testing.T, client *http.Client, authorizeURL, primary, secondary, username, password, state string) (string, *http.Cookie, string) {
	t.Helper()
	response, initCookie := passwordLoginResponse(t, client, authorizeURL, primary, secondary, username, password)
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		response.Body.Close()
		t.Fatalf("login status = %d, want redirect", response.StatusCode)
	}
	authCookie := assertSessionCookie(t, response.Cookies(), primary)
	if authCookie.Value == initCookie.Value {
		response.Body.Close()
		t.Fatal("login did not rotate the browser session")
	}
	location := response.Header.Get("Location")
	response.Body.Close()
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("error") != "" || callback.Query().Get("code") == "" {
		t.Fatalf("login redirect is not a valid callback: %q", location)
	}
	return callback.Query().Get("code"), authCookie, location
}

func authorizeWithCookie(t *testing.T, client *http.Client, baseURL, redirectURI, challenge, state, nonce string) string {
	t.Helper()
	response := do(t, client, http.MethodGet, oidcAuthorizationURL(t, baseURL, redirectURI, challenge, state, nonce), nil, nil)
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || err != nil || location.Query().Get("state") != state || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("OpenID authorization status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	return location.Query().Get("code")
}

func loginInteraction(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	interaction, ok := hiddenInputValue(string(body), "interaction")
	if !ok {
		t.Fatal("login form has no interaction token")
	}
	return interaction
}

func assertCodeExchangeRejected(t *testing.T, client *http.Client, baseURL, clientSecret, redirectURI, code, verifier, label string) {
	t.Helper()
	response := tokenResponseFor(t, client, baseURL, clientSecret, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s status=%d, want %d", label, response.StatusCode, http.StatusBadRequest)
	}
}

func assertFreshLogin(t *testing.T, baseURL, redirectURI, challenge string, authCookie *http.Cookie, prompt, maxAge string) {
	t.Helper()
	client := clientWithCookie(t, baseURL, authCookie)
	values := url.Values{
		"response_type": {"code"}, "client_id": {"goauthy-dev"}, "redirect_uri": {redirectURI}, "scope": {"goauthy.read"},
		"state": {"forced-login-" + strings.ReplaceAll(prompt+maxAge, " ", "-")}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if prompt != "" {
		values.Set("prompt", prompt)
	}
	if maxAge != "" {
		values.Set("max_age", maxAge)
	}
	response := do(t, client, http.MethodGet, baseURL+"/oidc/authorize?"+values.Encode(), nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("forced login status=%d, want login form", response.StatusCode)
	}
	if interaction := loginInteraction(t, response); interaction == "" {
		t.Fatal("forced login has no interaction")
	}
	fresh := assertSessionCookie(t, response.Cookies(), baseURL)
	if fresh.Value == authCookie.Value {
		t.Fatal("forced login reused authenticated session cookie")
	}
}

func clientWithCookie(t *testing.T, baseURL string, cookie *http.Cookie) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(issuer, []*http.Cookie{cookie})
	return noRedirectClient(t, jar)
}

func assertAuthorizationCodeRedirect(t *testing.T, response *http.Response, state string) {
	t.Helper()
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || err != nil || location.Query().Get("state") != state || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization response status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func pkceVerifier(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 48)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func exchangeCode(t *testing.T, client *http.Client, baseURL, clientSecret, redirectURI, code, verifier string) tokenResponse {
	t.Helper()
	return exchangeCodeForClient(t, client, baseURL, "goauthy-dev", clientSecret, redirectURI, code, verifier)
}

func exchangeCodeForClient(t *testing.T, client *http.Client, baseURL, clientID, clientSecret, redirectURI, code, verifier string) tokenResponse {
	t.Helper()
	return tokenRequestForClient(t, client, baseURL, clientID, clientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

func refresh(t *testing.T, client *http.Client, baseURL, clientSecret, refreshToken string) tokenResponse {
	t.Helper()
	return tokenRequest(t, client, baseURL, clientSecret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

func tokenRequest(t *testing.T, client *http.Client, baseURL, clientSecret string, form url.Values) tokenResponse {
	t.Helper()
	return tokenRequestForClient(t, client, baseURL, "goauthy-dev", clientSecret, form)
}

func tokenRequestForClient(t *testing.T, client *http.Client, baseURL, clientID, clientSecret string, form url.Values) tokenResponse {
	t.Helper()
	response := tokenResponseForClient(t, client, baseURL, clientID, clientSecret, form)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("token status = %d body=%s", response.StatusCode, body)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	return tokens
}

func publicJWKS(t *testing.T, client *http.Client, baseURL string) jose.JSONWebKeySet {
	t.Helper()
	response := do(t, client, http.MethodGet, baseURL+"/oidc/jwks.json", nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS status = %d", response.StatusCode)
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) == 0 {
		t.Fatal("public JWKS has no signing keys")
	}
	return keys
}

func verifyPublicIDToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer string) oidc.IDTokenClaims {
	t.Helper()
	claims, err := oidc.VerifyIDToken(token, keys, issuer, "goauthy-dev", time.Now().UTC())
	if err != nil {
		t.Fatalf("verify public ID token: %v", err)
	}
	return claims
}

// verifyPublicAccessToken verifies the deployed EdDSA JWT using only the
// public JWKS, then checks immutable authorization fields exactly.
func verifyPublicAccessToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, clientID, scope, wantJKT string) oidc.AccessTokenClaims {
	t.Helper()
	if strings.Count(token, ".") != 2 {
		t.Fatal("access token is not a compact JWT")
	}
	claims, err := oidc.VerifyAccessToken(token, keys, issuer, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify public access token: %v", err)
	}
	if claims.Issuer != issuer || len(claims.Audience) != 1 || claims.Audience[0] != clientID || claims.AuthorizedParty != clientID || strings.Join(claims.Scope, " ") != scope || claims.ID == "" {
		t.Fatalf("unexpected signed access-token claims: %#v", claims)
	}
	wantType := "Bearer"
	if wantJKT != "" {
		wantType = "DPoP"
	}
	if claims.Type != wantType || claims.ConfirmationJKT != wantJKT {
		t.Fatalf("access-token binding type=%q jkt=%q want_type=%q want_jkt=%q", claims.Type, claims.ConfirmationJKT, wantType, wantJKT)
	}
	return claims
}

func assertInitialIDTokenClaims(t *testing.T, claims oidc.IDTokenClaims, accessToken string) {
	t.Helper()
	if claims.Subject == "" || len(claims.Audience) != 1 || claims.Audience[0] != "goauthy-dev" || claims.AuthorizedParty != "goauthy-dev" || claims.Nonce != "browser-e2e-nonce" || claims.SessionID == "" || claims.AuthTime.IsZero() || strings.Join(claims.AuthenticationMethods, ",") != "pwd" || claims.AccessTokenHash != expectedAccessTokenHash(accessToken) {
		t.Fatalf("unexpected initial ID-token claims: %#v", claims)
	}
}

func assertRefreshedIDTokenClaims(t *testing.T, refreshed, initial oidc.IDTokenClaims, accessToken string) {
	t.Helper()
	if refreshed.Subject != initial.Subject || refreshed.SessionID != initial.SessionID || !refreshed.AuthTime.Equal(initial.AuthTime) || refreshed.Nonce != "" || len(refreshed.Audience) != 1 || refreshed.Audience[0] != "goauthy-dev" || refreshed.AuthorizedParty != "goauthy-dev" || strings.Join(refreshed.AuthenticationMethods, ",") != "pwd" || refreshed.AccessTokenHash != expectedAccessTokenHash(accessToken) {
		t.Fatalf("unexpected refreshed ID-token claims: %#v", refreshed)
	}
}

func expectedAccessTokenHash(accessToken string) string {
	sum := sha512.Sum512([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:sha512.Size/2])
}

func tokenResponseFor(t *testing.T, client *http.Client, baseURL, clientSecret string, form url.Values) *http.Response {
	t.Helper()
	return tokenResponseForClient(t, client, baseURL, "goauthy-dev", clientSecret, form)
}

func tokenResponseForClient(t *testing.T, client *http.Client, baseURL, clientID, clientSecret string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertResourceAudience(t *testing.T, client *http.Client, baseURL, clientSecret, token, resource string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active   bool     `json:"active"`
		Audience []string `json:"aud"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || !payload.Active || len(payload.Audience) != 1 || payload.Audience[0] != resource {
		t.Fatalf("resource introspection status=%d payload=%#v", response.StatusCode, payload)
	}
}

func assertTokenExchangeIntrospection(t *testing.T, client *http.Client, baseURL, clientSecret, token, resource string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active   bool     `json:"active"`
		Subject  string   `json:"sub"`
		Scope    string   `json:"scope"`
		Audience []string `json:"aud"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || !payload.Active || payload.Subject == "" || payload.Scope != "goauthy.read" || len(payload.Audience) != 1 || payload.Audience[0] != resource {
		t.Fatalf("token-exchange introspection status=%d payload=%#v", response.StatusCode, payload)
	}
}

func tokenSubject(t *testing.T, client *http.Client, baseURL, clientSecret, token string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || !payload.Active || payload.Subject == "" {
		t.Fatalf("token subject introspection status=%d active=%t subject=%q", response.StatusCode, payload.Active, payload.Subject)
	}
	return payload.Subject
}

func assertActorTokenExchangeIntrospection(t *testing.T, client *http.Client, baseURL, clientSecret, token, wantSubject, wantActor string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
		Actor   struct {
			Subject string `json:"sub"`
		} `json:"act"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || !payload.Active || payload.Subject != wantSubject || payload.Actor.Subject != wantActor {
		t.Fatalf("actor token-exchange introspection status=%d active=%t subject=%q actor=%q", response.StatusCode, payload.Active, payload.Subject, payload.Actor.Subject)
	}
}

func assertNestedActorTokenExchangeIntrospection(t *testing.T, client *http.Client, baseURL, clientSecret, token, wantSubject, wantNestedActor string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
		Actor   struct {
			Subject string `json:"sub"`
			Actor   struct {
				Subject string `json:"sub"`
			} `json:"act"`
		} `json:"act"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || !payload.Active || payload.Subject != wantSubject || payload.Actor.Subject != wantSubject || payload.Actor.Actor.Subject != wantNestedActor {
		t.Fatalf("nested actor introspection status=%d active=%t subject_matches=%t chain_matches=%t", response.StatusCode, payload.Active, payload.Subject == wantSubject, payload.Actor.Subject == wantSubject && payload.Actor.Actor.Subject == wantNestedActor)
	}
}

func assertTokenExchangeRejected(t *testing.T, client *http.Client, baseURL, clientSecret string, form url.Values, wantError string) {
	t.Helper()
	response := tokenResponseFor(t, client, baseURL, clientSecret, form)
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body) != nil || body.Error != wantError {
		t.Fatalf("token exchange rejection status=%d error=%q want=%q", response.StatusCode, body.Error, wantError)
	}
}

func assertRefreshResourceRejected(t *testing.T, client *http.Client, baseURL, clientSecret, refreshToken string, resources []string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "resource": resources}
	response := tokenResponseFor(t, client, baseURL, clientSecret, form)
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body) != nil || body.Error != "invalid_target" {
		t.Fatalf("refresh resource=%#v status=%d error=%q", resources, response.StatusCode, body.Error)
	}
}

func assertResourceAuthorizationRejected(t *testing.T, client *http.Client, baseURL, redirectURI, challenge, state, resource string) {
	t.Helper()
	response := do(t, client, http.MethodGet, authorizationURLWithResource(t, baseURL, redirectURI, challenge, state, resource), nil, nil)
	defer response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || err != nil || callback.Scheme+"://"+callback.Host+callback.Path != redirectURI || callback.Query().Get("state") != state || callback.Query().Get("error") != "invalid_target" || callback.Query().Get("code") != "" {
		t.Fatalf("unallowed resource status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func assertRefreshRejected(t *testing.T, client *http.Client, baseURL, clientSecret, refreshToken string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused refresh-token status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

func assertUserInfoSubject(t *testing.T, client *http.Client, baseURL, method, accessToken, wantSubject string) {
	t.Helper()
	response := userInfoResponse(t, client, method, baseURL, "Bearer "+accessToken, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("UserInfo status=%d headers=%#v", response.StatusCode, response.Header)
	}
	var body struct {
		Subject string `json:"sub"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&body); err != nil || body.Subject != wantSubject {
		t.Fatalf("UserInfo subject=%q want=%q err=%v", body.Subject, wantSubject, err)
	}
}

func assertUserInfoRejected(t *testing.T, client *http.Client, baseURL, method, authorization, query string) {
	t.Helper()
	response := userInfoResponse(t, client, method, baseURL, authorization, query)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("UserInfo rejection status=%d headers=%#v", response.StatusCode, response.Header)
	}
}

func userInfoResponse(t *testing.T, client *http.Client, method, baseURL, authorization, query string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+"/oidc/userinfo"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func revokeAccessToken(t *testing.T, client *http.Client, baseURL, clientSecret, token string, clientIDs ...string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/revoke", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	clientID := "goauthy-dev"
	if len(clientIDs) != 0 {
		clientID = clientIDs[0]
	}
	request.SetBasicAuth(clientID, clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("access-token revocation status=%d", response.StatusCode)
	}
}

func do(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertLoginRequired(t *testing.T, response *http.Response, state string) {
	t.Helper()
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther || err != nil || location.Query().Get("error") != "login_required" || location.Query().Get("state") != state || location.Query().Get("code") != "" {
		t.Fatalf("anonymous prompt=none status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func assertSessionCookie(t *testing.T, cookies []*http.Cookie, baseURL string) *http.Cookie {
	t.Helper()
	issuer, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range cookies {
		if cookie.Name == "goauthy_session" || cookie.Name == "__Host-goauthy_session" {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge <= 0 || cookie.Expires.IsZero() || issuer.Scheme == "https" && (!cookie.Secure || cookie.Name != "__Host-goauthy_session") {
				t.Fatalf("unsafe browser session cookie")
			}
			return cookie
		}
	}
	t.Fatal("authorize response did not set a browser session cookie")
	return nil
}

var inputTag = regexp.MustCompile(`(?is)<input\b[^>]*>`)
var inputName = regexp.MustCompile(`(?is)\bname\s*=\s*(?:"([^"]+)"|'([^']+)')`)
var inputValue = regexp.MustCompile(`(?is)\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func hiddenInputValue(document, wantName string) (string, bool) {
	for _, tag := range inputTag.FindAllString(document, -1) {
		name := inputName.FindStringSubmatch(tag)
		value := inputValue.FindStringSubmatch(tag)
		if len(name) == 3 && len(value) == 3 && firstNonEmpty(name[1:]) == wantName && firstNonEmpty(value[1:]) != "" {
			return firstNonEmpty(value[1:]), true
		}
	}
	return "", false
}

func firstNonEmpty(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func TestHiddenInputValue(t *testing.T) {
	value, ok := hiddenInputValue(`<input value="token-value" type="hidden" name="interaction">`, "interaction")
	if !ok || value != "token-value" {
		t.Fatalf("value=%q ok=%t", value, ok)
	}
}
