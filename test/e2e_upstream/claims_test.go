package e2e_upstream

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type userDetailResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
	EmailVerified bool    `json:"email_verified"`
	Enabled       bool    `json:"enabled"`
	Language      string  `json:"language"`
	AccountType   string  `json:"account_type"`
}

func createManagedProviderWithFlags(t *testing.T, client *http.Client, base, csrf, fixture string, autoOnboard, autoLink bool, mfaPath, mfaVal *string) string {
	t.Helper()
	fixtureURL := mustURL(t, fixture)
	body := map[string]any{
		"name":                   "claims-e2e-provider",
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
		"auto_onboarding":        autoOnboard,
		"auto_link":              autoLink,
	}
	if mfaPath != nil {
		body["mfa_claim_path"] = *mfaPath
	}
	if mfaVal != nil {
		body["mfa_claim_value"] = *mfaVal
	}
	b, _ := json.Marshal(body)
	response := request(t, client, http.MethodPost, base+"/auth/v1/providers/create", strings.NewReader(string(b)), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusOK)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(readBody(t, response), &created); err != nil || created.ID == "" {
		t.Fatalf("create managed provider err=%v id=%q", err, created.ID)
	}
	return created.ID
}

// createUserViaAdmin creates a local user via POST /auth/v1/users +
// PUT /auth/v1/users/{id} with required fields.
func createUserViaAdmin(t *testing.T, client *http.Client, base, csrf, email, password string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"email": email, "language": "en", "roles": []string{}})
	response := request(t, client, http.MethodPost, base+"/auth/v1/users", strings.NewReader(string(b)), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusOK)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(readBody(t, response), &created); err != nil || created.ID == "" {
		t.Fatalf("create user err=%v id=%q", err, created.ID)
	}
	gn := "Local"
	fn := "User"
	b, _ = json.Marshal(map[string]any{"email": email, "password": password, "email_verified": true, "enabled": true, "language": "en", "given_name": gn, "family_name": fn, "roles": []string{}})
	response = request(t, client, http.MethodPut, base+"/auth/v1/users/"+created.ID, strings.NewReader(string(b)), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	assertStatus(t, response, http.StatusOK)
	response.Body.Close()
	return created.ID
}

func deleteUserViaAdmin(t *testing.T, client *http.Client, base, csrf, subject string) {
	t.Helper()
	response := request(t, client, http.MethodDelete, base+"/auth/v1/users/"+subject, nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		t.Fatalf("delete user status=%d", response.StatusCode)
	}
	response.Body.Close()
}

// appendFixtureParams appends fixture_ prefixed claim params to an authorization URL.
func appendFixtureParams(t *testing.T, rawURL, email, givenName, familyName string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("fixture_email", email)
	q.Set("fixture_email_verified", "1")
	q.Set("fixture_given_name", givenName)
	q.Set("fixture_family_name", familyName)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// upstreamLogin performs authorize -> start -> fixture -> callback -> exchange -> verify
// on a fresh client. fixtureParams if non-nil are appended to the fixture authorization URL.
func upstreamLogin(t *testing.T, primary, secondary, fixture, clientSecret, managedID, redirectURI, verifier, state string, fixtureParams map[string]string) idTokenClaims {
	t.Helper()
	external := upstreamClient(t)
	interaction := authorizeInteraction(t, external, secondary, redirectURI, verifier, state, "")
	callbackURI := primary + "/upstream/" + managedID + "/callback"
	start := secondary + "/upstream/" + managedID + "/start?" + url.Values{"redirect_uri": {callbackURI}, "interaction": {interaction}}.Encode()
	fixtureAuth := redirectLocation(t, request(t, external, http.MethodGet, start, nil, nil), http.StatusFound)
	if fixtureParams != nil {
		parsed, err := url.Parse(fixtureAuth)
		if err != nil {
			t.Fatal(err)
		}
		q := parsed.Query()
		for k, v := range fixtureParams {
			q.Set(k, v)
		}
		parsed.RawQuery = q.Encode()
		fixtureAuth = parsed.String()
	}
	callback := fixtureCallback(t, external, fixtureAuth, fixture)
	rpLoc := callbackLocation(t, external, callback, state, redirectURI)
	code := rpCode(t, rpLoc)
	tokens := exchangeCode(t, external, secondary, clientSecret, redirectURI, code, verifier)
	return verifyIDToken(t, external, secondary, primary, tokens.IDToken)
}

func TestOnboardingAndProfileRefresh(t *testing.T) {
	if os.Getenv("GOAUTHY_UPSTREAM_MANAGED_E2E") != "1" {
		t.Skip("set GOAUTHY_UPSTREAM_MANAGED_E2E=1 to run onboarding E2E")
	}
	primary, fixture, secondary, username, password, clientSecret := upstreamConfig(t)
	client := upstreamClient(t)
	passwordAuthorize(t, client, primary, primary, username, password, "onboarding-admin-login")
	csrf := accountCSRF(t, client, primary)

	managedID := createManagedProviderWithFlags(t, client, primary, csrf, fixture, true, false, nil, nil)
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "onboarding-cleanup")
		deleteManagedProvider(t, c, primary, accountCSRF(t, c, primary), managedID)
	})

	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	verifier := "onboarding-verifier-0123456789abcdef0123456789abcdef"

	// First login: auto_onboarding creates new user.
	params1 := map[string]string{"fixture_email": "onboard@example.com", "fixture_email_verified": "1", "fixture_given_name": "Onboard", "fixture_family_name": "User"}
	claims := upstreamLogin(t, primary, secondary, fixture, clientSecret, managedID, redirectURI, verifier, "onboarding-state", params1)
	if claims.Subject == "" {
		t.Fatal("onboarding ID token has empty subject")
	}

	// Register user cleanup immediately (LIFO: user deleted before provider).
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "onboarding-cleanup-user")
		deleteUserViaAdmin(t, c, primary, accountCSRF(t, c, primary), claims.Subject)
	})

	// Verify user profile.
	response := request(t, client, http.MethodGet, primary+"/auth/v1/users/"+claims.Subject, nil, nil)
	assertStatus(t, response, http.StatusOK)
	var detail userDetailResponse
	if err := json.Unmarshal(readBody(t, response), &detail); err != nil {
		t.Fatalf("user detail: %v", err)
	}
	if detail.ID != claims.Subject {
		t.Fatalf("detail.ID=%q want=%q", detail.ID, claims.Subject)
	}
	if detail.Email != "onboard@example.com" {
		t.Fatalf("email=%q want=onboard@example.com", detail.Email)
	}
	if !detail.EmailVerified {
		t.Fatal("email_verified=false want=true")
	}
	if detail.GivenName == nil || *detail.GivenName != "Onboard" {
		t.Fatalf("given_name=%v want=Onboard", detail.GivenName)
	}
	if detail.FamilyName == nil || *detail.FamilyName != "User" {
		t.Fatalf("family_name=%v want=User", detail.FamilyName)
	}

	// Profile refresh: fresh client, different names, same provider/same user.
	params2 := map[string]string{"fixture_email": "onboard@example.com", "fixture_email_verified": "1", "fixture_given_name": "Updated", "fixture_family_name": "Identity"}
	claims2 := upstreamLogin(t, primary, secondary, fixture, clientSecret, managedID, redirectURI, verifier, "onboarding-refresh-state", params2)
	if claims2.Subject != claims.Subject {
		t.Fatalf("refresh subject=%q want=%q", claims2.Subject, claims.Subject)
	}
	response2 := request(t, client, http.MethodGet, primary+"/auth/v1/users/"+claims2.Subject, nil, nil)
	assertStatus(t, response2, http.StatusOK)
	var detail2 userDetailResponse
	if err := json.Unmarshal(readBody(t, response2), &detail2); err != nil {
		t.Fatalf("refresh user detail: %v", err)
	}
	if detail2.GivenName == nil || *detail2.GivenName != "Updated" {
		t.Fatalf("refresh given_name=%v want=Updated", detail2.GivenName)
	}
	if detail2.FamilyName == nil || *detail2.FamilyName != "Identity" {
		t.Fatalf("refresh family_name=%v want=Identity", detail2.FamilyName)
	}
}

func TestAutolinkLocalPasswordSurvives(t *testing.T) {
	if os.Getenv("GOAUTHY_UPSTREAM_MANAGED_E2E") != "1" {
		t.Skip("set GOAUTHY_UPSTREAM_MANAGED_E2E=1 to run autolink E2E")
	}
	primary, fixture, secondary, username, password, clientSecret := upstreamConfig(t)
	client := upstreamClient(t)
	passwordAuthorize(t, client, primary, primary, username, password, "autolink-admin-login")
	csrf := accountCSRF(t, client, primary)

	// Provider first, then user — LIFO deletes user then provider.
	managedID := createManagedProviderWithFlags(t, client, primary, csrf, fixture, false, true, nil, nil)
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "autolink-cleanup-provider")
		deleteManagedProvider(t, c, primary, accountCSRF(t, c, primary), managedID)
	})

	localEmail := "autolink-local@example.com"
	localPassword := "Autolink-Password-1A"
	localID := createUserViaAdmin(t, client, primary, csrf, localEmail, localPassword)
	t.Cleanup(func() {
		c := upstreamClient(t)
		passwordAuthorize(t, c, primary, primary, username, password, "autolink-cleanup-user")
		deleteUserViaAdmin(t, c, primary, accountCSRF(t, c, primary), localID)
	})

	redirectURI := envOr("GOAUTHY_UPSTREAM_E2E_REDIRECT_URI", defaultRedirectURI)
	verifier := "autolink-verifier-0123456789abcdef0123456789abcdef"

	// External login with same email triggers auto_link to existing local user.
	params := map[string]string{"fixture_email": localEmail, "fixture_email_verified": "1", "fixture_given_name": "Autolink", "fixture_family_name": "External"}
	claims := upstreamLogin(t, primary, secondary, fixture, clientSecret, managedID, redirectURI, verifier, "autolink-state", params)
	if claims.Subject != localID {
		t.Fatalf("autolink subject=%q want=%q (local user ID)", claims.Subject, localID)
	}

	// Password login after link must still work.
	passwordAuthorize(t, upstreamClient(t), primary, primary, localEmail, localPassword, "autolink-password-after-link")
}
