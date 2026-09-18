// Package e2e_upstream tests a deployed upstream-provider flow through HTTP.
package e2e_upstream

import (
	"crypto/ed25519"
	"crypto/sha256"
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
	"strings"
	"testing"
	"time"
)

const (
	providerID          = "fixture"
	bootstrapClientID   = "goauthy-dev"
	defaultRedirectURI  = "http://localhost:5555/callback"
	defaultUsername     = "admin"
	maxResponseBodySize = 64 << 10
)

func TestUpstreamLinkLoginAndUnlink(t *testing.T) {
	primary, fixture, secondary, username, password, clientSecret := upstreamConfig(t)
	client := upstreamClient(t)

	// Establish the local account session that authorizes an explicit link.
	passwordAuthorize(t, client, primary, primary, username, password, "upstream-password-login")
	csrf := accountCSRF(t, client, primary)
	linkAuthorization := startLink(t, client, primary, csrf)
	linkCallback := fixtureCallback(t, client, linkAuthorization, fixture)
	linkReplay := clientWithCallbackCookies(t, client, linkCallback)
	assertCallbackStatus(t, client, linkCallback, http.StatusNoContent)
	// Ask the fixture for a new code with the original state. The preserved
	// GoAuthy cookies then prove transaction consumption, not fixture replay.
	assertCallbackStatus(t, linkReplay, fixtureCallback(t, linkReplay, linkAuthorization, fixture), http.StatusBadRequest)

	// A fresh init interaction has no local subject. It can authenticate only
	// through the link just created, and exercises a separate deployed base URL.
	external := upstreamClient(t)
	verifier := "upstream-e2e-verifier-0123456789abcdef0123456789abcdef"
	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	state, nonce := "upstream-external-state", "upstream-external-nonce"
	interaction := authorizeInteraction(t, external, secondary, redirectURI, verifier, state, nonce)
	callbackURI := primary + "/upstream/" + providerID + "/callback"
	start := secondary + "/upstream/" + providerID + "/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {interaction},
	}.Encode()
	response := request(t, external, http.MethodGet, start, nil, nil)
	fixtureAuthorization := redirectLocation(t, response, http.StatusFound)
	if parsed := mustURL(t, fixtureAuthorization); parsed.Host != mustURL(t, fixture).Host || parsed.Query().Get("redirect_uri") != callbackURI || parsed.Query().Get("state") == "" {
		t.Fatalf("upstream start location=%q", fixtureAuthorization)
	}
	callback := fixtureCallback(t, external, fixtureAuthorization, fixture)
	externalReplay := clientWithCallbackCookies(t, external, callback)
	rpLocation := callbackLocation(t, external, callback, state, redirectURI)
	code := rpCode(t, rpLocation)
	tokens := exchangeCode(t, external, secondary, clientSecret, redirectURI, code, verifier)
	claims := verifyIDToken(t, external, secondary, primary, tokens.IDToken)
	if claims.Subject != envOr("GOAUTHY_UPSTREAM_E2E_SUBJECT", "bootstrap-admin") || !contains(claims.AMR, "external") {
		t.Fatalf("external ID token claims=%+v", claims)
	}
	assertCallbackStatus(t, externalReplay, fixtureCallback(t, externalReplay, fixtureAuthorization, fixture), http.StatusBadRequest)

	csrf = accountCSRF(t, external, secondary)
	response = request(t, external, http.MethodDelete, secondary+"/auth/v1/providers/"+providerID+"/link", nil, map[string]string{"X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()

	// Removing the link must reject the same upstream identity without exposing
	// whether it was ever linked, while password admission remains intact.
	assertExternalLoginRejected(t, primary, fixture, callbackURI, redirectURI, verifier, state, nonce)
	passwordAuthorize(t, upstreamClient(t), primary, primary, username, password, "upstream-password-after-unlink")
}

func TestGitHubOAuthAppLinkLoginAndUnlink(t *testing.T) {
	primary, _, secondary, username, password, clientSecret := upstreamConfig(t)
	fixture := strings.TrimRight(os.Getenv("GOAUTHY_UPSTREAM_GITHUB_FIXTURE_URL"), "/")
	if fixture == "" {
		t.Skip("set GOAUTHY_UPSTREAM_GITHUB_FIXTURE_URL to run GitHub upstream E2E; the app still calls fixed github.com and api.github.com hosts")
	}
	if _, err := url.Parse(fixture); err != nil {
		t.Fatal(err)
	}
	client := upstreamClient(t)
	passwordAuthorize(t, client, primary, primary, username, password, "github-password-login")

	csrf := accountCSRF(t, client, primary)
	authorizationURL := startProviderLink(t, client, primary, csrf, "github")
	callback := githubFixtureCallback(t, client, authorizationURL, fixture)
	assertCallbackStatus(t, client, callback, http.StatusNoContent)
	assertCallbackStatus(t, client, callback, http.StatusBadRequest)

	// A fresh local interaction must resolve the immutable numeric GitHub
	// subject returned by the fixed-host token/user exchange.
	external := upstreamClient(t)
	verifier := "github-upstream-e2e-verifier-0123456789abcdef0123456789abcdef"
	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	state := "github-external-state"
	interaction := authorizeInteraction(t, external, secondary, redirectURI, verifier, state, "")
	callbackURI := primary + "/upstream/github/callback"
	start := secondary + "/upstream/github/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {interaction},
	}.Encode()
	authorizationURL = redirectLocation(t, request(t, external, http.MethodGet, start, nil, nil), http.StatusFound)
	callback = githubFixtureCallback(t, external, authorizationURL, fixture)
	externalReplay := clientWithCallbackCookies(t, external, callback)
	rpLocation := callbackLocation(t, external, callback, state, redirectURI)
	tokens := exchangeCode(t, external, secondary, clientSecret, redirectURI, rpCode(t, rpLocation), verifier)
	claims := verifyIDToken(t, external, secondary, primary, tokens.IDToken)
	if claims.Subject != envOr("GOAUTHY_UPSTREAM_E2E_SUBJECT", "bootstrap-admin") || !contains(claims.AMR, "external") {
		t.Fatalf("GitHub external ID token claims=%+v", claims)
	}
	assertCallbackStatus(t, externalReplay, callback, http.StatusBadRequest)

	csrf = accountCSRF(t, external, secondary)
	response := request(t, external, http.MethodDelete, secondary+"/auth/v1/providers/github/link", nil, map[string]string{"X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()
	assertGitHubLoginRejected(t, primary, fixture, callbackURI, redirectURI)
}

func startProviderLink(t *testing.T, client *http.Client, base, csrf, provider string) string {
	t.Helper()
	response := request(t, client, http.MethodPost, base+"/auth/v1/providers/"+provider+"/link", nil, map[string]string{"X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusOK)
	var document struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(readBody(t, response), &document); err != nil || document.AuthorizationURL == "" {
		t.Fatalf("link authorization err=%v URL=%q", err, document.AuthorizationURL)
	}
	return document.AuthorizationURL
}

func githubFixtureCallback(t *testing.T, client *http.Client, authorizationURL, fixture string) string {
	t.Helper()
	parsed := mustURL(t, authorizationURL)
	if parsed.Host != "github.com" || parsed.Path != "/login/oauth/authorize" {
		t.Fatalf("GitHub authorization URL=%q", authorizationURL)
	}
	fixtureURL := mustURL(t, fixture)
	parsed.Scheme, parsed.Host, parsed.Path, parsed.RawPath = fixtureURL.Scheme, fixtureURL.Host, "/login/oauth/authorize", ""
	response := request(t, client, http.MethodGet, parsed.String(), nil, nil)
	return redirectLocation(t, response, http.StatusFound)
}

func assertGitHubLoginRejected(t *testing.T, base, fixture, callbackURI, redirectURI string) {
	t.Helper()
	client := upstreamClient(t)
	state := "github-unlinked-state"
	interaction := authorizeInteraction(t, client, base, redirectURI, "github-unlinked-verifier-0123456789abcdef0123456789abcdef", state, "")
	start := base + "/upstream/github/start?" + url.Values{"redirect_uri": {callbackURI}, "interaction": {interaction}}.Encode()
	authorizationURL := redirectLocation(t, request(t, client, http.MethodGet, start, nil, nil), http.StatusFound)
	callback := githubFixtureCallback(t, client, authorizationURL, fixture)
	response := request(t, client, http.MethodGet, callback, nil, nil)
	if response.StatusCode != http.StatusBadRequest || strings.TrimSpace(string(readBody(t, response))) != "State mismatch" {
		t.Fatalf("unlinked GitHub callback status=%d", response.StatusCode)
	}
}

func upstreamConfig(t *testing.T) (primary, fixture, secondary, username, password, clientSecret string) {
	t.Helper()
	primary = strings.TrimRight(os.Getenv("GOAUTHY_UPSTREAM_E2E_URL"), "/")
	fixture = strings.TrimRight(os.Getenv("GOAUTHY_UPSTREAM_FIXTURE_URL"), "/")
	secondary = strings.TrimRight(os.Getenv("GOAUTHY_UPSTREAM_E2E_SECONDARY_URL"), "/")
	if secondary == "" {
		secondary = primary
	}
	username = envOr("GOAUTHY_E2E_BROWSER_USERNAME", defaultUsername)
	password = os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	clientSecret = os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || fixture == "" || os.Getenv("GOAUTHY_UPSTREAM_E2E_CA_FILE") == "" || password == "" || clientSecret == "" {
		t.Skip("set upstream URLs, CA file, browser password, and OAuth client secret to run upstream E2E")
	}
	return primary, fixture, secondary, username, password, clientSecret
}

func upstreamClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(os.Getenv("GOAUTHY_UPSTREAM_E2E_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("upstream E2E CA file contains no certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func clientWithCallbackCookies(t *testing.T, source *http.Client, callback string) *http.Client {
	t.Helper()
	callbackURL := mustURL(t, callback)
	if source.Jar == nil {
		t.Fatal("source client has no cookie jar")
	}
	clone := upstreamClient(t)
	clone.Jar.SetCookies(callbackURL, source.Jar.Cookies(callbackURL))
	return clone
}

func passwordAuthorize(t *testing.T, client *http.Client, base, loginBase, username, password, state string) {
	t.Helper()
	interaction := authorizeInteraction(t, client, base, defaultRedirectURI, "upstream-password-verifier-0123456789abcdef0123456789", state, "")
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	response := request(t, client, http.MethodPost, loginBase+"/auth/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	assertRPRedirect(t, redirectLocation(t, response, http.StatusSeeOther), state, defaultRedirectURI)
}

func authorizeInteractionForClient(t *testing.T, client *http.Client, base, redirectURI, verifier, state, nonce, clientID string) string {
	t.Helper()
	values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"openid"}, "state": {state}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	if nonce != "" {
		values.Set("nonce", nonce)
	}
	response := request(t, client, http.MethodGet, base+"/oidc/authorize?"+values.Encode(), nil, nil)
	if response.StatusCode != http.StatusOK {
		body := readBody(t, response)
		t.Fatalf("authorize status=%d body=%q", response.StatusCode, body)
	}
	return hiddenInput(t, string(readBody(t, response)), "interaction")
}

func authorizeInteraction(t *testing.T, client *http.Client, base, redirectURI, verifier, state, nonce string) string {
	t.Helper()
	return authorizeInteractionForClient(t, client, base, redirectURI, verifier, state, nonce, bootstrapClientID)
}

func accountCSRF(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	response := request(t, client, http.MethodGet, base+"/account/password", nil, nil)
	assertStatus(t, response, http.StatusOK)
	var document struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(readBody(t, response), &document); err != nil || document.CSRFToken == "" {
		t.Fatalf("account CSRF err=%v token=%q", err, document.CSRFToken)
	}
	return document.CSRFToken
}

func startLink(t *testing.T, client *http.Client, base, csrf string) string {
	return startProviderLink(t, client, base, csrf, providerID)
}

func fixtureCallback(t *testing.T, client *http.Client, authorizationURL, fixture string) string {
	t.Helper()
	if parsed := mustURL(t, authorizationURL); parsed.Host != mustURL(t, fixture).Host {
		t.Fatalf("fixture authorization host=%q want=%q", parsed.Host, mustURL(t, fixture).Host)
	}
	response := request(t, client, http.MethodGet, authorizationURL, nil, nil)
	return redirectLocation(t, response, http.StatusFound)
}

func assertExternalLoginRejected(t *testing.T, base, fixture, callbackURI, redirectURI, verifier, state, nonce string) {
	t.Helper()
	client := upstreamClient(t)
	interaction := authorizeInteraction(t, client, base, redirectURI, verifier, state+"-unlinked", nonce+"-unlinked")
	start := base + "/upstream/" + providerID + "/start?" + url.Values{"redirect_uri": {callbackURI}, "interaction": {interaction}}.Encode()
	fixtureAuthorization := redirectLocation(t, request(t, client, http.MethodGet, start, nil, nil), http.StatusFound)
	callback := fixtureCallback(t, client, fixtureAuthorization, fixture)
	response := request(t, client, http.MethodGet, callback, nil, nil)
	if response.StatusCode != http.StatusBadRequest || strings.TrimSpace(string(readBody(t, response))) != "State mismatch" {
		t.Fatalf("unlinked external callback status=%d", response.StatusCode)
	}
}

type tokenResponse struct {
	IDToken string `json:"id_token"`
}

func exchangeCodeForClient(t *testing.T, client *http.Client, base, secret, redirectURI, code, verifier, clientID string) tokenResponse {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	if secret == "" {
		form.Set("client_id", clientID)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(clientID, secret)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, http.StatusOK)
	var tokens tokenResponse
	if err := json.Unmarshal(readBody(t, response), &tokens); err != nil || tokens.IDToken == "" {
		t.Fatalf("token response err=%v id_token=%q", err, tokens.IDToken)
	}
	return tokens
}

func exchangeCode(t *testing.T, client *http.Client, base, secret, redirectURI, code, verifier string) tokenResponse {
	t.Helper()
	return exchangeCodeForClient(t, client, base, secret, redirectURI, code, verifier, bootstrapClientID)
}

type idTokenClaims struct {
	Issuer   string   `json:"iss"`
	Audience audience `json:"aud"`
	Subject  string   `json:"sub"`
	AMR      []string `json:"amr"`
}

// audience handles JWT aud claims that may be a single string or an array.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		*a = audience{val}
		return nil
	case []any:
		out := make(audience, 0, len(val))
		for _, elem := range val {
			s, ok := elem.(string)
			if !ok {
				return fmt.Errorf("aud: expected string element, got %T", elem)
			}
			out = append(out, s)
		}
		*a = out
		return nil
	}
	return fmt.Errorf("aud: expected string or array, got %T", v)
}

func verifyIDTokenForClient(t *testing.T, client *http.Client, base, issuer, token, clientID string) idTokenClaims {
	t.Helper()
	response := request(t, client, http.MethodGet, base+"/oidc/jwks.json", nil, nil)
	assertStatus(t, response, http.StatusOK)
	var jwks struct {
		Keys []struct {
			KeyID   string `json:"kid"`
			KeyType string `json:"kty"`
			Curve   string `json:"crv"`
			X       string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(readBody(t, response), &jwks); err != nil || len(jwks.Keys) == 0 {
		t.Fatalf("JWKS err=%v keys=%d", err, len(jwks.Keys))
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("ID token is not compact JWS")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil || header.Algorithm != "EdDSA" || header.KeyID == "" {
		t.Fatalf("ID token header=%+v err=%v", header, err)
	}
	var claims idTokenClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil || claims.Issuer != issuer || claims.Subject == "" || !contains([]string(claims.Audience), clientID) {
		t.Fatalf("ID token claims=%+v err=%v", claims, err)
	}
	for _, key := range jwks.Keys {
		if key.KeyID != header.KeyID || key.KeyType != "OKP" || key.Curve != "Ed25519" {
			continue
		}
		public, err := base64.RawURLEncoding.DecodeString(key.X)
		signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
		if err == nil && signatureErr == nil && ed25519.Verify(ed25519.PublicKey(public), []byte(parts[0]+"."+parts[1]), signature) {
			return claims
		}
	}
	t.Fatal("ID token signature did not verify against GoAuthy JWKS")
	return idTokenClaims{}
}

func verifyIDToken(t *testing.T, client *http.Client, base, issuer, token string) idTokenClaims {
	return verifyIDTokenForClient(t, client, base, issuer, token, bootstrapClientID)
}

func decodeJWTPart(raw string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, target)
}

func callbackLocation(t *testing.T, client *http.Client, callback, state, redirectURI string) string {
	t.Helper()
	response := request(t, client, http.MethodGet, callback, nil, nil)
	location := redirectLocation(t, response, http.StatusSeeOther)
	assertRPRedirect(t, location, state, redirectURI)
	return location
}

func assertRPRedirect(t *testing.T, location, state, redirectURI string) {
	t.Helper()
	parsed, err := url.Parse(location)
	configured, configuredErr := url.Parse(redirectURI)
	if err != nil || configuredErr != nil || parsed.Scheme != configured.Scheme || parsed.Host != configured.Host || parsed.Path != configured.Path || parsed.Query().Get("state") != state || parsed.Query().Get("error") != "" || parsed.Query().Get("code") == "" {
		t.Fatalf("callback location=%q", location)
	}
}

func assertCallbackStatus(t *testing.T, client *http.Client, callback string, want int) {
	t.Helper()
	response := request(t, client, http.MethodGet, callback, nil, nil)
	assertStatus(t, response, want)
	response.Body.Close()
}

func request(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func redirectLocation(t *testing.T, response *http.Response, want int) string {
	t.Helper()
	if response.StatusCode != want || response.Header.Get("Location") == "" {
		body := readBody(t, response)
		t.Fatalf("redirect status=%d location=%q body=%q", response.StatusCode, response.Header.Get("Location"), body)
	}
	location := response.Header.Get("Location")
	response.Body.Close()
	return location
}

func assertStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		body := readBody(t, response)
		t.Fatalf("status=%d want=%d body=%q", response.StatusCode, want, body)
	}
}

func rpCode(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil || parsed.Query().Get("code") == "" {
		t.Fatalf("RP location=%q", location)
	}
	return parsed.Query().Get("code")
}

func readBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodySize))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		t.Fatalf("invalid HTTPS URL %q: %v", raw, err)
	}
	return parsed
}

var inputTags = regexp.MustCompile(`(?is)<input\b[^>]*>`)
var inputName = regexp.MustCompile(`(?is)\bname\s*=\s*(?:"([^"]+)"|'([^']+)')`)
var inputValue = regexp.MustCompile(`(?is)\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func hiddenInput(t *testing.T, document, want string) string {
	t.Helper()
	for _, tag := range inputTags.FindAllString(document, -1) {
		name, value := inputName.FindStringSubmatch(tag), inputValue.FindStringSubmatch(tag)
		if len(name) == 3 && len(value) == 3 && first(name[1:]) == want && first(value[1:]) != "" {
			return first(value[1:])
		}
	}
	t.Fatalf("missing hidden input %q", want)
	return ""
}

func first(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
