// Package e2e_upstream tests a deployed upstream-provider flow through HTTP.
package e2e_upstream

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestManagedProviderLifecycle(t *testing.T) {
	if os.Getenv("GOAUTHY_UPSTREAM_MANAGED_E2E") != "1" {
		t.Skip("set GOAUTHY_UPSTREAM_MANAGED_E2E=1 to run managed provider lifecycle E2E")
	}
	primary, fixture, secondary, username, password, clientSecret := upstreamConfig(t)
	client := upstreamClient(t)
	// Authenticate as admin.
	passwordAuthorize(t, client, primary, primary, username, password, "managed-admin-login")
	csrf := accountCSRF(t, client, primary)
	// Create a managed provider via the runtime providers API.
	managedID := createManagedProvider(t, client, primary, csrf, fixture)
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "managed-cleanup-login")
		deleteManagedProvider(t, c, primary, accountCSRF(t, c, primary), managedID)
	})
	// Link the managed provider to the bootstrap admin account.
	csrf = accountCSRF(t, client, primary)
	linkAuthorization := startProviderLink(t, client, primary, csrf, managedID)
	linkCallback := fixtureCallback(t, client, linkAuthorization, fixture)
	linkReplay := clientWithCallbackCookies(t, client, linkCallback)
	assertCallbackStatus(t, client, linkCallback, http.StatusNoContent)
	assertCallbackStatus(t, linkReplay, fixtureCallback(t, linkReplay, linkAuthorization, fixture), http.StatusBadRequest)
	// Fresh external interaction exercises a separate deployed base URL.
	external := upstreamClient(t)
	verifier := "managed-e2e-verifier-0123456789abcdef0123456789abcdef"
	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	state, nonce := "managed-external-state", "managed-external-nonce"
	interaction := authorizeInteraction(t, external, secondary, redirectURI, verifier, state, nonce)
	callbackURI := primary + "/upstream/" + managedID + "/callback"
	start := secondary + "/upstream/" + managedID + "/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {interaction},
	}.Encode()
	response := request(t, external, http.MethodGet, start, nil, nil)
	fixtureAuthorization := redirectLocation(t, response, http.StatusFound)
	if parsed := mustURL(t, fixtureAuthorization); parsed.Host != mustURL(t, fixture).Host || parsed.Query().Get("redirect_uri") != callbackURI || parsed.Query().Get("state") == "" {
		t.Fatalf("managed upstream start location=%q", fixtureAuthorization)
	}
	callback := fixtureCallback(t, external, fixtureAuthorization, fixture)
	externalReplay := clientWithCallbackCookies(t, external, callback)
	rpLocation := callbackLocation(t, external, callback, state, redirectURI)
	code := rpCode(t, rpLocation)
	tokens := exchangeCode(t, external, secondary, clientSecret, redirectURI, code, verifier)
	claims := verifyIDToken(t, external, secondary, primary, tokens.IDToken)
	if claims.Subject != envOr("GOAUTHY_UPSTREAM_E2E_SUBJECT", "bootstrap-admin") || !contains(claims.AMR, "external") {
		t.Fatalf("managed external ID token claims=%+v", claims)
	}
	assertCallbackStatus(t, externalReplay, fixtureCallback(t, externalReplay, fixtureAuthorization, fixture), http.StatusBadRequest)
	// Unlink the managed provider.
	csrf = accountCSRF(t, external, secondary)
	response = request(t, external, http.MethodDelete, secondary+"/auth/v1/providers/"+managedID+"/link", nil, map[string]string{"X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()
	// The same upstream identity must be rejected after unlink.
	assertManagedExternalLoginRejected(t, primary, fixture, managedID, callbackURI, redirectURI, verifier, state, nonce)
	// Local password admission must remain intact.
	passwordAuthorize(t, upstreamClient(t), primary, primary, username, password, "managed-password-after-unlink")
	// Delete the managed provider.
	csrf = accountCSRF(t, client, primary)
	deleteManagedProvider(t, client, primary, csrf, managedID)
	deleted = true
}

func TestPendingCallbackAfterManagedUnlink(t *testing.T) {
	if os.Getenv("GOAUTHY_UPSTREAM_MANAGED_E2E") != "1" {
		t.Skip("set GOAUTHY_UPSTREAM_MANAGED_E2E=1 to run managed provider pending-callback E2E")
	}
	primary, fixture, _, username, password, _ := upstreamConfig(t)
	client := upstreamClient(t)
	passwordAuthorize(t, client, primary, primary, username, password, "managed-pending-admin-login")
	csrf := accountCSRF(t, client, primary)
	managedID := createManagedProvider(t, client, primary, csrf, fixture)
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "managed-pending-cleanup-login")
		deleteManagedProvider(t, c, primary, accountCSRF(t, c, primary), managedID)
	})
	// Link the managed provider before testing pending callbacks.
	csrf = accountCSRF(t, client, primary)
	linkAuthorization := startProviderLink(t, client, primary, csrf, managedID)
	linkCallback := fixtureCallback(t, client, linkAuthorization, fixture)
	assertCallbackStatus(t, client, linkCallback, http.StatusNoContent)
	// Start the external interaction BEFORE unlink to create a pending callback.
	verifier := "managed-pending-verifier-0123456789abcdef0123456789abcdef"
	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	callbackURI := primary + "/upstream/" + managedID + "/callback"
	external := upstreamClient(t)
	interaction := authorizeInteraction(t, external, primary, redirectURI, verifier, "managed-pending-state", "managed-pending-nonce")
	start := primary + "/upstream/" + managedID + "/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {interaction},
	}.Encode()
	response := request(t, external, http.MethodGet, start, nil, nil)
	fixtureAuthorization := redirectLocation(t, response, http.StatusFound)
	pendingCallback := fixtureCallback(t, external, fixtureAuthorization, fixture)
	// Unlink while the callback is still pending.
	csrf = accountCSRF(t, client, primary)
	response = request(t, client, http.MethodDelete, primary+"/auth/v1/providers/"+managedID+"/link", nil, map[string]string{"X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()
	// The pending callback must now be rejected.
	pendingReplay := clientWithCallbackCookies(t, external, pendingCallback)
	response = request(t, pendingReplay, http.MethodGet, pendingCallback, nil, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending callback after unlink status=%d want=%d", response.StatusCode, http.StatusBadRequest)
	}
	response.Body.Close()
	// Delete the managed provider.
	csrf = accountCSRF(t, client, primary)
	deleteManagedProvider(t, client, primary, csrf, managedID)
	deleted = true
}

func createManagedProvider(t *testing.T, client *http.Client, base, csrf, fixture string) string {
	t.Helper()
	fixtureURL := mustURL(t, fixture)
	createBody := map[string]any{
		"name":                   "managed-e2e-provider",
		"typ":                    "oidc",
		"enabled":                true,
		"issuer":                 "https://upstream-fixture.goauthy.svc.cluster.local",
		"authorization_endpoint": fixtureURL.Scheme + "://" + fixtureURL.Host + "/authorize",
		"token_endpoint":         "https://upstream-fixture.goauthy.svc.cluster.local/token",
		"jwks_endpoint":          "https://upstream-fixture.goauthy.svc.cluster.local/jwks",
		"userinfo_endpoint":      "https://upstream-fixture.goauthy.svc.cluster.local/userinfo",
		"client_id":              "goauthy-upstream-e2e",
		"client_secret":          "goauthy-upstream-e2e-secret",
		"scope":                  "openid profile",
		"use_pkce":               true,
		"client_secret_basic":    true,
		"client_secret_post":     false,
		"auto_onboarding":        false,
		"auto_link":              false,
	}
	b, err := json.Marshal(createBody)
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, client, http.MethodPost, base+"/auth/v1/providers/create", strings.NewReader(string(b)), map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	})
	assertStatus(t, response, http.StatusOK)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(readBody(t, response), &created); err != nil || created.ID == "" {
		t.Fatalf("create managed provider err=%v id=%q", err, created.ID)
	}
	if len(created.ID) != 24 {
		t.Fatalf("managed provider ID length=%d want=24", len(created.ID))
	}
	for _, c := range created.ID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Fatalf("managed provider ID contains non-alphanumeric character %q", c)
		}
	}
	return created.ID
}

func deleteManagedProvider(t *testing.T, client *http.Client, base, csrf, providerID string) {
	t.Helper()
	response := request(t, client, http.MethodDelete, base+"/auth/v1/providers/"+providerID, nil, map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	})
	assertStatus(t, response, http.StatusOK)
	response.Body.Close()
}

func assertManagedExternalLoginRejected(t *testing.T, base, fixture, managedID, callbackURI, redirectURI, verifier, state, nonce string) {
	t.Helper()
	client := upstreamClient(t)
	interaction := authorizeInteraction(t, client, base, redirectURI, verifier, state+"-unlinked", nonce+"-unlinked")
	start := base + "/upstream/" + managedID + "/start?" + url.Values{"redirect_uri": {callbackURI}, "interaction": {interaction}}.Encode()
	fixtureAuthorization := redirectLocation(t, request(t, client, http.MethodGet, start, nil, nil), http.StatusFound)
	callback := fixtureCallback(t, client, fixtureAuthorization, fixture)
	response := request(t, client, http.MethodGet, callback, nil, nil)
	if response.StatusCode != http.StatusBadRequest || strings.TrimSpace(string(readBody(t, response))) != "State mismatch" {
		t.Fatalf("unlinked managed callback status=%d", response.StatusCode)
	}
}
