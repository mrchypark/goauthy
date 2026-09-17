package browser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const oauth2ConsumerFixtureCallback = "https://compos.local.test/oauth2/callback"
const beesuhConsumerFixtureCallback = "https://beesuh.local.test/oauth2/callback"

type oauth2ConsumerFixtureConfig struct {
	name          string
	callback      string
	resource      string
	positiveScope string
	wrongScope    string
	requiredScope string
	emailPrefix   string
	customScope   bool
	beesuh        bool
}

// TestOAuth2ConsumerFixture provisions the two confidential clients expected by
// the Compos OAuth2 harness: one RP for authorization_code and one device-flow
// client whose Basic credentials are used for introspection.
func TestOAuth2ConsumerFixture(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_OAUTH2_CONSUMER_FIXTURE") != "1" {
		t.Skip("set GOAUTHY_E2E_OAUTH2_CONSUMER_FIXTURE=1 to run OAuth2 consumer fixture E2E")
	}
	runOAuth2ConsumerFixture(t, oauth2ConsumerFixtureConfig{
		name: "compos", callback: oauth2ConsumerFixtureCallback, resource: consumerFixtureResource,
		positiveScope: "openid email profile compos.api", wrongScope: "openid email profile", requiredScope: "compos.api", emailPrefix: "compos-oauth2-fixture-", customScope: true,
	})
}

func TestBeesuhConsumerFixture(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_BEESUH_CONSUMER_FIXTURE") != "1" {
		t.Skip("set GOAUTHY_E2E_BEESUH_CONSUMER_FIXTURE=1 to run Beesuh consumer fixture E2E")
	}
	runOAuth2ConsumerFixture(t, oauth2ConsumerFixtureConfig{
		name: "beesuh", callback: beesuhConsumerFixtureCallback, resource: "https://beesuh.local.test",
		positiveScope: "openid email profile", wrongScope: "email profile", requiredScope: "openid", emailPrefix: "beesuh-oauth2-fixture-", beesuh: true,
	})
}

func runOAuth2ConsumerFixture(t *testing.T, config oauth2ConsumerFixtureConfig) {
	dir := consumerFixtureOutputDir(t)
	if config.beesuh {
		preflightConsumerFixtureFile(t, dir, "memberships.json")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required")
	}

	// DCR scopes come from the server policy. The request deliberately has no
	// scope field; authorization requests still select the issued scopes.
	rp := registerOAuth2ConsumerRPFor(t, primary, registrationToken, config.callback, config.name)
	device := registerOAuth2ConsumerDeviceClientFor(t, primary, registrationToken, config.name)
	// The outer disposable runner owns cleanup after the consumer uses these credentials.

	admin := newBrowserClient(t)
	verifier := pkceVerifier(t)
	authorize := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "oauth2-consumer-admin", "oauth2-consumer-admin-nonce", "openid")
	_, sessionCookie := loginForAuthorizationURL(t, admin, authorize, primary, secondary, username, password, "oauth2-consumer-admin")
	csrf, err := browsersession.DeriveCSRFToken(sessionCookie.Value)
	if err != nil {
		t.Fatal("derive admin CSRF token")
	}
	// Operator DCR admission and the active custom-scope catalog are separate gates.
	if config.customScope {
		scopeResponse := do(t, admin, http.MethodPost, primary+"/auth/v1/scopes", strings.NewReader(`{"scope":"compos.api","attr_include_id":[],"attr_include_access":[]}`), rbacMutationHeaders(csrf))
		scopeResponse.Body.Close()
		if scopeResponse.StatusCode != http.StatusOK {
			t.Fatalf("create resource scope status=%d", scopeResponse.StatusCode)
		}
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("generate fixture user identifier")
	}
	email, userPassword := config.emailPrefix+hex.EncodeToString(suffix)+"@goauthy.e2e", "OAuth2-Fixture-Password-1A"
	userID := createCatalogSessionUser(t, admin, primary, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}, email, userPassword)
	if userID == "" {
		t.Fatal("fixture user creation returned no subject")
	}
	issue := func(label, scope, resource string) string {
		client := newBrowserClient(t)
		verifier := pkceVerifier(t)
		raw := oidcAuthorizationURLForClient(t, primary, rp.ClientID, rp.RedirectURIs[0], pkceChallenge(verifier), label, label+"-nonce", scope)
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal("build authorization URL")
		}
		values := parsed.Query()
		values.Set("resource", resource)
		parsed.RawQuery = values.Encode()
		code, _ := loginForAuthorizationURL(t, client, parsed.String(), primary, secondary, email, userPassword, label)
		tokens := exchangeCodeForClient(t, client, primary, rp.ClientID, rp.ClientSecret, rp.RedirectURIs[0], code, verifier)
		if tokens.AccessToken == "" {
			t.Fatal("authorization-code exchange returned no access token")
		}
		return tokens.AccessToken
	}

	accessToken := issue(config.name+"-positive", config.positiveScope, config.resource)
	client := newBrowserClient(t)
	positive := introspectOAuth2ConsumerFixtureToken(t, client, primary, device.ClientID, device.ClientSecret, accessToken)
	wantScopes := strings.Fields(config.positiveScope)
	if !positive.Active || positive.Subject != userID || positive.ClientID != rp.ClientID || !containsAudience(positive.Audience, config.resource) || !containsScopes(positive.Scope, wantScopes...) {
		t.Fatal("OAuth2 fixture positive introspection claims did not validate")
	}
	assertOAuth2ConsumerUserInfo(t, client, primary, accessToken, positive.Subject, email)

	wrongAudience := issue(config.name+"-wrong-aud", config.positiveScope, "https://other-consumer.local.test")
	wrongScope := issue(config.name+"-wrong-scope", config.wrongScope, config.resource)
	wrongAudienceClaims := introspectOAuth2ConsumerFixtureToken(t, client, primary, device.ClientID, device.ClientSecret, wrongAudience)
	wrongScopeClaims := introspectOAuth2ConsumerFixtureToken(t, client, primary, device.ClientID, device.ClientSecret, wrongScope)
	if !wrongAudienceClaims.Active || containsAudience(wrongAudienceClaims.Audience, config.resource) || !wrongScopeClaims.Active || containsScopes(wrongScopeClaims.Scope, config.requiredScope) {
		t.Fatal("OAuth2 fixture negatives do not isolate audience or missing required scope")
	}

	revoked := issue(config.name+"-revoked", config.positiveScope, config.resource)
	revokeRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, primary+"/oidc/revoke", strings.NewReader(url.Values{"token": {revoked}, "token_type_hint": {"access_token"}}.Encode()))
	if err != nil {
		t.Fatal("build revoke request")
	}
	revokeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRequest.SetBasicAuth(rp.ClientID, rp.ClientSecret)
	revoke, err := client.Do(revokeRequest)
	if err != nil {
		t.Fatal("revoke request failed")
	}
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK || introspectOAuth2ConsumerFixtureToken(t, client, primary, device.ClientID, device.ClientSecret, revoked).Active {
		t.Fatal("revoked OAuth2 fixture token remains active")
	}

	if err := writeConsumerFixture(dir, map[string]string{
		"access-token": accessToken, "client-secret": device.ClientSecret, "issuer": primary,
		"client-id": device.ClientID, "resource": config.resource, "subject": positive.Subject,
		"email": email, "wrong-aud-token": wrongAudience, "wrong-scope-token": wrongScope, "revoked-token": revoked,
	}); err != nil {
		t.Fatal(err)
	}
	if config.beesuh {
		memberships, err := json.Marshal([]struct {
			Issuer      string `json:"issuer"`
			Subject     string `json:"subject"`
			WorkspaceID string `json:"workspace_id"`
		}{{Issuer: primary, Subject: positive.Subject, WorkspaceID: "workspace-a"}})
		if err != nil {
			t.Fatalf("marshal Beesuh memberships fixture: %v", err)
		}
		file, err := os.OpenFile(filepath.Join(dir, "memberships.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, writeErr := file.Write(append(memberships, '\n'))
			closeErr := file.Close()
			err = writeErr
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			t.Fatalf("write Beesuh memberships fixture: %v", err)
		}
	}
}

func preflightConsumerFixtureFile(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
		t.Fatalf("consumer fixture output already exists: %s", name)
	} else if !os.IsNotExist(err) {
		t.Fatalf("consumer fixture output cannot be checked: %s", name)
	}
}

func registerOAuth2ConsumerRPFor(t *testing.T, base, bearer, callback, name string) dynamicClientRegistration {
	t.Helper()
	audience := strings.TrimSuffix(callback, "/oauth2/callback")
	body := `{"redirect_uris":["` + callback + `"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"` + name + ` OAuth2 RP","audience":["` + audience + `","https://other-consumer.local.test"]}`
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/oidc/register", strings.NewReader(body), map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json", "Idempotency-Key": "oauth2-consumer-rp-" + pkceVerifier(t)})
	defer r.Body.Close()
	var out dynamicClientRegistration
	if r.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&out) != nil || out.ClientID == "" || out.ClientSecret == "" || len(out.RedirectURIs) != 1 || out.RedirectURIs[0] != callback {
		t.Fatalf("OAuth2 RP registration status=%d", r.StatusCode)
	}
	return out
}

func registerOAuth2ConsumerDeviceClientFor(t *testing.T, base, bearer, name string) dynamicClientRegistration {
	t.Helper()
	body := `{"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"response_types":[],"token_endpoint_auth_method":"client_secret_basic","client_name":"` + name + ` OAuth2 Introspection Device"}`
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/oidc/register", strings.NewReader(body), map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json", "Idempotency-Key": "oauth2-consumer-device-" + pkceVerifier(t)})
	defer r.Body.Close()
	var out dynamicClientRegistration
	if r.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&out) != nil || out.ClientID == "" || out.ClientSecret == "" || out.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("OAuth2 device registration status=%d client_id=%q secret=%t", r.StatusCode, out.ClientID, out.ClientSecret != "")
	}
	return out
}

func introspectOAuth2ConsumerFixtureToken(t *testing.T, client *http.Client, issuer, clientID, secret, token string) consumerFixtureIntrospection {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, issuer+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal("build introspection request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("introspection request")
	}
	defer response.Body.Close()
	var payload consumerFixtureIntrospection
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&payload) != nil {
		t.Fatalf("introspection status=%d", response.StatusCode)
	}
	return payload
}

func containsScopes(raw string, want ...string) bool {
	got := strings.Fields(raw)
	for _, scope := range want {
		found := false
		for _, value := range got {
			if value == scope {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func assertOAuth2ConsumerUserInfo(t *testing.T, client *http.Client, issuer, token, subject, email string) {
	r := do(t, client, http.MethodGet, issuer+"/oidc/userinfo", nil, map[string]string{"Authorization": "Bearer " + token})
	defer r.Body.Close()
	var info struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&info)
	if r.StatusCode != http.StatusOK || err != nil || info.Subject != subject || info.Email != email || !info.EmailVerified {
		t.Fatalf("UserInfo claims did not validate: status=%d subject=%q", r.StatusCode, info.Subject)
	}
}
