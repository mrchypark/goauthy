// Package e2e_issuer_path exercises a public issuer mounted below the root.
package e2e_issuer_path

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	clientID    = "goauthy-dev"
	redirectURI = "http://localhost:5555/callback"
)

type e2eConfig struct {
	issuer, secondary, tertiary string
	username, password, secret  string
	sessionFile                 string
	client                      *http.Client
}

func TestIssuerPathDiscoveryAndRootIsolation(t *testing.T) {
	c := config(t)
	origin := publicOrigin(t, c.issuer)

	rootDiscovery := get(t, c.client, origin+"/.well-known/oauth-authorization-server/tenant")
	assertStatus(t, rootDiscovery, http.StatusOK)
	var oauthMetadata map[string]any
	decode(t, rootDiscovery, &oauthMetadata)
	assertIssuerEndpoints(t, oauthMetadata, c.issuer, false)

	pathDiscovery := get(t, c.client, c.issuer+"/.well-known/openid-configuration")
	assertStatus(t, pathDiscovery, http.StatusOK)
	var oidcMetadata map[string]any
	decode(t, pathDiscovery, &oidcMetadata)
	assertIssuerEndpoints(t, oidcMetadata, c.issuer, true)
	if oidcMetadata["issuer"] != c.issuer {
		t.Fatalf("OIDC discovery issuer=%v want=%s", oidcMetadata["issuer"], c.issuer)
	}
	for _, endpoint := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"} {
		if value, _ := oidcMetadata[endpoint].(string); value == "" || !strings.Contains(value, "/tenant/") {
			t.Fatalf("OIDC discovery endpoint %s=%q does not include /tenant", endpoint, value)
		}
	}

	for _, endpoint := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/oidc/token", "/oidc/authorize", "/oidc/userinfo", "/oidc/jwks.json", "/auth/login", "/wrong/oidc/token"} {
		response := get(t, c.client, origin+endpoint)
		if response.StatusCode != http.StatusNotFound {
			response.Body.Close()
			t.Fatalf("root application endpoint %s status=%d", endpoint, response.StatusCode)
		}
		response.Body.Close()
	}
	for _, endpoint := range []string{c.issuer + "/oidc/%74oken", origin + "/tenant%2Foidc/token", origin + "/tenant/%2e/oidc/token"} {
		response := get(t, c.client, endpoint)
		if response.StatusCode != http.StatusNotFound {
			response.Body.Close()
			t.Fatalf("escaped issuer-path endpoint %s status=%d", endpoint, response.StatusCode)
		}
		response.Body.Close()
	}
	response := get(t, c.client, c.issuer+"/.well-known/oauth-authorization-server")
	if response.StatusCode != http.StatusNotFound {
		response.Body.Close()
		t.Fatalf("appended RFC8414 endpoint status=%d", response.StatusCode)
	}
	response.Body.Close()
	healthResponse := get(t, c.client, origin+"/readyz")
	assertStatus(t, healthResponse, http.StatusNoContent)
	healthResponse.Body.Close()
	if response := get(t, c.client, c.issuer+"/readyz"); response.StatusCode != http.StatusNotFound {
		response.Body.Close()
		t.Fatalf("prefixed health status=%d", response.StatusCode)
	}
}

func TestIssuerPathPreReplacement(t *testing.T) {
	c := config(t)
	client := newClient(t)
	verifier := randomString(t)
	state := "issuer-path-login"
	authorize := c.issuer + "/oidc/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid goauthy.read offline_access"}, "state": {state},
		"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}, "nonce": {"issuer-path-nonce"},
	}.Encode()
	response := get(t, client, authorize)
	assertStatus(t, response, http.StatusOK)
	interaction := hiddenInput(t, readBody(t, response), "interaction")
	form := url.Values{"interaction": {interaction}, "username": {c.username}, "password": {c.password}}
	response = post(t, client, c.secondary+"/auth/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("password login status=%d body=%q", response.StatusCode, readBody(t, response))
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	response.Body.Close()
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		t.Fatalf("password login callback=%q", callback)
	}
	persistSessionCookie(t, c, response)

	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := dpopToken(t, client, c.issuer, c.issuer, c.secret, codeForm, private, "")
	nonce := challenge.Header.Get("DPoP-Nonce")
	if challenge.StatusCode != http.StatusBadRequest || nonce == "" {
		t.Fatalf("DPoP token challenge status=%d nonce=%q", challenge.StatusCode, nonce)
	}
	challenge.Body.Close()
	issued := dpopToken(t, client, c.secondary, c.issuer, c.secret, codeForm, private, nonce)
	if issued.StatusCode != http.StatusOK {
		t.Fatalf("DPoP token status=%d body=%q", issued.StatusCode, readBody(t, issued))
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	decode(t, issued, &token)
	if token.AccessToken == "" || token.TokenType != "DPoP" {
		t.Fatalf("DPoP token response=%#v", token)
	}

	proof := dpopProof(t, private, http.MethodGet, c.issuer+"/oidc/userinfo", "", token.AccessToken)
	resourceChallenge := userinfo(t, client, c.tertiary, token.AccessToken, proof)
	if resourceChallenge.StatusCode != http.StatusUnauthorized || resourceChallenge.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("DPoP UserInfo challenge status=%d nonce=%q", resourceChallenge.StatusCode, resourceChallenge.Header.Get("DPoP-Nonce"))
	}
	resourceNonce := resourceChallenge.Header.Get("DPoP-Nonce")
	resourceChallenge.Body.Close()
	resource := userinfo(t, client, c.issuer, token.AccessToken, dpopProof(t, private, http.MethodGet, c.issuer+"/oidc/userinfo", resourceNonce, token.AccessToken))
	if resource.StatusCode != http.StatusOK {
		t.Fatalf("DPoP UserInfo status=%d body=%q", resource.StatusCode, readBody(t, resource))
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	decode(t, resource, &claims)
	if claims.Subject == "" {
		t.Fatal("DPoP UserInfo did not return sub")
	}
}

// TestIssuerPathPostReplacement is run by the harness after replacing goauthy-0.
func TestIssuerPathPostReplacement(t *testing.T) {
	c := config(t)
	if c.sessionFile == "" {
		t.Skip("set GOAUTHY_E2E_SESSION_FILE to run post-replacement issuer-path E2E")
	}
	value, err := os.ReadFile(c.sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(value)) == "" {
		t.Fatal("persisted issuer-path session cookie is empty")
	}
	client := newClient(t)
	u, err := url.Parse(c.issuer)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-goauthy_session", Value: strings.TrimSpace(string(value)), Path: "/", Secure: true, HttpOnly: true}})
	response := get(t, client, c.issuer+"/account/password")
	assertStatus(t, response, http.StatusOK)
	var account struct {
		CSRFToken string `json:"csrf_token"`
	}
	decode(t, response, &account)
	if account.CSRFToken == "" {
		t.Fatal("replacement pod did not retain authenticated browser session")
	}
	response = get(t, c.client, publicOrigin(t, c.issuer)+"/readyz")
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()
	response = get(t, c.client, c.issuer+"/.well-known/openid-configuration")
	assertStatus(t, response, http.StatusOK)
	var metadata map[string]any
	decode(t, response, &metadata)
	if metadata["issuer"] != c.issuer || !strings.HasPrefix(metadata["token_endpoint"].(string), c.issuer+"/") {
		t.Fatalf("recovered issuer metadata=%#v", metadata)
	}
}

func config(t *testing.T) e2eConfig {
	t.Helper()
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	if issuer == "" {
		issuer = strings.TrimRight(os.Getenv("GOAUTHY_ISSUER"), "/")
	}
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	username, password, secret := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD"), os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if issuer == "" || secondary == "" || tertiary == "" || os.Getenv("GOAUTHY_E2E_CA_FILE") == "" || username == "" || password == "" || secret == "" {
		t.Skip("set issuer-path URLs, CA file, browser credentials, and OAuth client secret to run issuer-path E2E")
	}
	return e2eConfig{issuer: issuer, secondary: secondary, tertiary: tertiary, username: username, password: password, secret: secret, sessionFile: os.Getenv("GOAUTHY_E2E_SESSION_FILE"), client: newClient(t)}
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(os.Getenv("GOAUTHY_E2E_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("issuer-path CA file contains no certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func publicOrigin(t *testing.T, value string) string {
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return u.Scheme + "://" + u.Host
}

func assertIssuerEndpoints(t *testing.T, metadata map[string]any, issuer string, oidc bool) {
	t.Helper()
	expected := map[string]string{
		"issuer":                        issuer,
		"authorization_endpoint":        issuer + "/oidc/authorize",
		"token_endpoint":                issuer + "/oidc/token",
		"jwks_uri":                      issuer + "/oidc/jwks.json",
		"introspection_endpoint":        issuer + "/oidc/introspect",
		"revocation_endpoint":           issuer + "/oidc/revoke",
		"device_authorization_endpoint": issuer + "/oidc/device",
	}
	if oidc {
		expected["userinfo_endpoint"] = issuer + "/oidc/userinfo"
		expected["end_session_endpoint"] = issuer + "/oidc/logout"
	}
	// DCR is enabled by the Kind issuer-path fixture, so RFC 8414 metadata
	// must advertise its registration endpoint as well.
	expected["registration_endpoint"] = issuer + "/oidc/register"
	for name := range metadata {
		if !strings.HasSuffix(name, "_endpoint") && name != "jwks_uri" {
			continue
		}
		if _, ok := expected[name]; !ok {
			t.Fatalf("unexpected discovery endpoint field %s", name)
		}
	}
	for name, want := range expected {
		value, ok := metadata[name].(string)
		if !ok || value != want {
			t.Fatalf("discovery endpoint %s=%v want=%s", name, metadata[name], want)
		}
	}
}

func persistSessionCookie(t *testing.T, c e2eConfig, response *http.Response) {
	t.Helper()
	if c.sessionFile == "" {
		t.Skip("set GOAUTHY_E2E_SESSION_FILE to run pre-replacement issuer-path E2E")
	}
	var value string
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-goauthy_session" && cookie.Value != "" {
			value = cookie.Value
			break
		}
	}
	if value == "" {
		t.Fatal("password login did not issue an opaque __Host-goauthy_session cookie")
	}
	if err := os.MkdirAll(filepath.Dir(c.sessionFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.sessionFile, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(c.sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("session cookie permissions=%v", info.Mode().Perm())
	}
}

func dpopToken(t *testing.T, client *http.Client, endpoint, issuer, secret string, form url.Values, private ed25519.PrivateKey, nonce string) *http.Response {
	request, err := http.NewRequest(http.MethodPost, endpoint+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", dpopProof(t, private, http.MethodPost, issuer+"/oidc/token", nonce, ""))
	request.SetBasicAuth(clientID, secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func userinfo(t *testing.T, client *http.Client, endpoint, token, proof string) *http.Response {
	request, err := http.NewRequest(http.MethodGet, endpoint+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set("DPoP", proof)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func dpopProof(t *testing.T, private ed25519.PrivateKey, method, htu, nonce, accessToken string) string {
	claims := map[string]any{"jti": randomString(t), "htm": method, "htu": htu, "iat": time.Now().UTC().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader(jose.HeaderKey("jwk"), jose.JSONWebKey{Key: private.Public()}))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := compact.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func pkce(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func randomString(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hiddenInput(t *testing.T, body, name string) string {
	t.Helper()
	match := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("missing hidden input %q", name)
	}
	return match[1]
}

func get(t *testing.T, client *http.Client, endpoint string) *http.Response {
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func post(t *testing.T, client *http.Client, endpoint string, body io.Reader, headers map[string]string) *http.Response {
	request, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%q", response.StatusCode, want, readBody(t, response))
	}
}

func decode(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
