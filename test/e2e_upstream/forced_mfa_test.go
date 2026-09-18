package e2e_upstream

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestForcedMFAUpstream(t *testing.T) {
	if os.Getenv("GOAUTHY_UPSTREAM_MANAGED_E2E") != "1" {
		t.Skip("set GOAUTHY_UPSTREAM_MANAGED_E2E=1 to run forced MFA upstream E2E")
	}
	primary, fixture, secondary, username, password, _ := upstreamConfig(t)
	admin := upstreamClient(t)

	// Authenticate as admin for CRUD operations.
	passwordAuthorize(t, admin, primary, primary, username, password, "forced-mfa-admin-login")
	csrf := accountCSRF(t, admin, primary)

	// Create a managed provider with MFA claim configuration.
	mfaPath := "$.amr.*" // Equivalent array wildcard accepted by the provider DTO's URI pattern.
	mfaVal := "mfa"
	managedID := forcedMFACreateManagedProvider(t, admin, primary, csrf, fixture, &mfaPath, &mfaVal)
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "forced-mfa-cleanup-provider-login")
		forcedMFADeleteManagedProvider(t, c, primary, accountCSRF(t, c, primary), managedID)
	})

	// Create a managed client with ForceMFA=true.
	clientID := forcedMFACreateManagedClient(t, admin, primary, csrf, managedID)
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "forced-mfa-cleanup-client-login")
		forcedMFADeleteManagedClient(t, c, primary, accountCSRF(t, c, primary), clientID)
	})

	// Verify the client was created with force_mfa=true.
	forcedMFAMustForceMFA(t, admin, primary, clientID)

	// --- Positive case: fixture emits amr:[mfa] ---
	// Fresh unauthenticated client for the upstream flow.
	positiveClient := upstreamClient(t)
	verifier := "forced-mfa-e2e-verifier-0123456789abcdef0123456789abcdef"
	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	state, nonce := "forced-mfa-positive-state", "forced-mfa-positive-nonce"
	interaction := authorizeInteractionForClient(t, positiveClient, secondary, redirectURI, verifier, state, nonce, clientID)
	callbackURI := primary + "/upstream/" + managedID + "/callback"
	startURL := secondary + "/upstream/" + managedID + "/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {interaction},
	}.Encode()
	response := request(t, positiveClient, http.MethodGet, startURL, nil, nil)
	fixtureAuth := redirectLocation(t, response, http.StatusFound)
	// Append fixture test-claims to the upstream authorization URL.
	fixtureAuthWithClaims := forcedMFAAppendFixtureParams(t, fixtureAuth,
		"fixture_email=test-forced-mfa@example.com",
		"fixture_email_verified=1",
		"fixture_mfa=1",
	)
	callback := fixtureCallback(t, positiveClient, fixtureAuthWithClaims, fixture)
	rpLocation := callbackLocation(t, positiveClient, callback, state, redirectURI)
	code := rpCode(t, rpLocation)
	// Public client: no basic auth; token exchange sends client_id in form body.
	tokens := exchangeCodeForClient(t, positiveClient, secondary, "", redirectURI, code, verifier, clientID)
	claims := verifyIDTokenForClient(t, positiveClient, secondary, primary, tokens.IDToken, clientID)
	subject := claims.Subject
	if subject == "" {
		t.Fatal("forced MFA positive: missing subject in claims")
	}
	// Register user cleanup immediately; runs first in LIFO before client/provider.
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "forced-mfa-cleanup-user-login")
		deleteUserViaAdmin(t, c, primary, accountCSRF(t, c, primary), subject)
	})
	if !contains(claims.AMR, "mfa") {
		t.Fatalf("forced MFA positive: AMR=%v, want mfa", claims.AMR)
	}

	// --- Negative case: fixture omits MFA claim ---
	// Same email as positive so the linked identity already exists;
	// no new user is created on the failed MFA path.
	negClient := upstreamClient(t)
	negVerifier := "forced-mfa-neg-e2e-verifier-0123456789abcdef0123456789abcdef"
	negState := "forced-mfa-negative-state"
	negInteraction := authorizeInteractionForClient(t, negClient, secondary, redirectURI, negVerifier, negState, "", clientID)
	negStartURL := secondary + "/upstream/" + managedID + "/start?" + url.Values{
		"redirect_uri": {callbackURI}, "interaction": {negInteraction},
	}.Encode()
	response = request(t, negClient, http.MethodGet, negStartURL, nil, nil)
	negFixtureAuth := redirectLocation(t, response, http.StatusFound)
	// Same email/email_verified as positive; only omit fixture_mfa.
	negFixtureAuthWithClaims := forcedMFAAppendFixtureParams(t, negFixtureAuth,
		"fixture_email=test-forced-mfa@example.com",
		"fixture_email_verified=1",
	)
	negCallback := fixtureCallback(t, negClient, negFixtureAuthWithClaims, fixture)
	negResponse := request(t, negClient, http.MethodGet, negCallback, nil, nil)
	// ForceMFA guard in login.completeExternalAuthentication returns 403.
	if negResponse.StatusCode != http.StatusForbidden {
		body := readBody(t, negResponse)
		t.Fatalf("forced MFA negative: status=%d want=%d body=%q", negResponse.StatusCode, http.StatusForbidden, body)
	}
	if loc := negResponse.Header.Get("Location"); loc != "" {
		t.Fatalf("forced MFA negative: unexpected Location=%q", loc)
	}
	negResponse.Body.Close()
}

// forcedMFACreateManagedProvider creates an OIDC provider via the /auth/v1/providers/create
// endpoint with auto_onboarding=true and the specified MFA claim path/value.
func forcedMFACreateManagedProvider(t *testing.T, client *http.Client, base, csrf, fixture string, mfaPath, mfaVal *string) string {
	t.Helper()
	fixtureURL := mustURL(t, fixture)
	body := map[string]any{
		"name":                   "forced-mfa-e2e-provider",
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
		"auto_onboarding":        true,
		"auto_link":              false,
	}
	if mfaPath != nil {
		body["mfa_claim_path"] = *mfaPath
	}
	if mfaVal != nil {
		body["mfa_claim_value"] = *mfaVal
	}
	b, _ := json.Marshal(body)
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
	return created.ID
}

// forcedMFADeleteManagedProvider deletes a managed provider by ID.
func forcedMFADeleteManagedProvider(t *testing.T, client *http.Client, base, csrf, providerID string) {
	t.Helper()
	response := request(t, client, http.MethodDelete, base+"/auth/v1/providers/"+providerID, nil, map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	})
	assertStatus(t, response, http.StatusOK)
	response.Body.Close()
}

// forcedMFACreateManagedClient creates a public managed client with force_mfa=true
// and authorization_code grant using PKCE.
func forcedMFACreateManagedClient(t *testing.T, client *http.Client, base, csrf, rpClientID string) string {
	t.Helper()
	body := map[string]any{
		"id":              rpClientID,
		"confidential":    false,
		"redirect_uris":   []string{defaultRedirectURI},
		"enabled_flows":   []string{"authorization_code"},
		"scopes":          []string{"openid", "email", "profile"},
		"default_scopes":  []string{"openid"},
		"force_mfa":       true,
	}
	b, _ := json.Marshal(body)
	response := request(t, client, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(string(b)), map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	})
	assertStatus(t, response, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(readBody(t, response), &created); err != nil || created.ID == "" {
		t.Fatalf("create managed client err=%v id=%q", err, created.ID)
	}
	return created.ID
}

// forcedMFADeleteManagedClient deletes a managed client by ID.
func forcedMFADeleteManagedClient(t *testing.T, client *http.Client, base, csrf, clientID string) {
	t.Helper()
	response := request(t, client, http.MethodGet, base+"/auth/v1/clients/"+clientID, nil, nil)
	assertStatus(t, response, http.StatusOK)
	var doc struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(readBody(t, response), &doc); err != nil || doc.Revision < 1 {
		t.Fatalf("read managed client for delete err=%v rev=%d", err, doc.Revision)
	}
	response = request(t, client, http.MethodDelete, base+"/auth/v1/clients/"+clientID, nil, map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
		"If-Match":       `"` + strconv.FormatInt(doc.Revision, 10) + `"`,
	})
	assertStatus(t, response, http.StatusNoContent)
	response.Body.Close()
}

// forcedMFAMustForceMFA reads back the managed client and asserts force_mfa=true.
func forcedMFAMustForceMFA(t *testing.T, client *http.Client, base, clientID string) {
	t.Helper()
	response := request(t, client, http.MethodGet, base+"/auth/v1/clients/"+clientID, nil, nil)
	assertStatus(t, response, http.StatusOK)
	var doc struct {
		ForceMFA bool `json:"force_mfa"`
	}
	if err := json.Unmarshal(readBody(t, response), &doc); err != nil {
		t.Fatalf("read managed client err=%v", err)
	}
	if !doc.ForceMFA {
		t.Fatal("managed client force_mfa=false, want true")
	}
}

// forcedMFAAppendFixtureParams appends fixture_* query parameters to an
// upstream authorization URL.
func forcedMFAAppendFixtureParams(t *testing.T, rawURL string, params ...string) string {
	t.Helper()
	parsed := mustURL(t, rawURL)
	q := parsed.Query()
	for _, p := range params {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			t.Fatalf("fixture param missing '=': %q", p)
		}
		q.Set(k, v)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
