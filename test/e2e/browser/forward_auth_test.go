package browser

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestForwardAuthAcrossPods(t *testing.T) {
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	// Keep code issuance on one pod to minimize unrelated follower writes before
	// the cross-pod forward_auth and revocation checks.
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, redirectURI, pkceChallenge(verifier), "forward-auth", "forward-auth-nonce"), primary, primary, username, password, "forward-auth")
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatal("OpenID authorization did not issue a user access token")
	}

	assertForwardAuthAllowed(t, client, secondary, tokens.AccessToken)
	revokeAccessToken(t, client, tertiary, clientSecret, tokens.AccessToken)
	assertForwardAuthRejected(t, client, primary, tokens.AccessToken, username)
}

// TestForwardAuthIdentityHeadersAcrossPods exercises the opt-in identity
// projection on every independently routed pod.  The passkey profile is
// enrolled before this test runs, so MFA is read from current identity state,
// not from the OAuth request snapshot.
func TestForwardAuthIdentityHeadersAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FORWARD_AUTH_HEADERS") != "1" {
		t.Skip("set GOAUTHY_E2E_FORWARD_AUTH_HEADERS=1 to run identity-header E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	subject := os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	if subject == "" {
		subject = "bootstrap-admin"
	}
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, redirectURI, pkceChallenge(verifier), "forward-auth-headers", "forward-auth-headers-nonce"), primary, secondary, username, password, "forward-auth-headers")
	tokens := exchangeCode(t, client, tertiary, clientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("identity-header authorization did not issue an access token")
	}

	want := map[string]string{
		"X-Forwarded-User":                subject,
		"X-Forwarded-User-Roles":          "forward-auth-admin,rauthy_admin",
		"X-Forwarded-User-Groups":         "forward-auth-group",
		"X-Forwarded-User-Email":          "admin@goauthy.e2e",
		"X-Forwarded-User-Email-Verified": "false",
		"X-Forwarded-User-Family-Name":    "",
		"X-Forwarded-User-Given-Name":     "",
		"X-Forwarded-User-MFA":            "true",
	}
	for _, base := range []string{secondary, tertiary, primary} {
		assertForwardAuthIdentity(t, client, base, tokens.AccessToken, want, true)
	}

	// Revocation is acknowledged on pod C and rejected on pod A.  The
	// response must remain generic and must not retain spoofed identity state.
	revokeAccessToken(t, client, tertiary, clientSecret, tokens.AccessToken)
	assertForwardAuthRejectedNoIdentity(t, client, primary, tokens.AccessToken, username, true)
}

func assertForwardAuthIdentity(t *testing.T, client *http.Client, baseURL, token string, want map[string]string, spoof bool) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/forward_auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if spoof {
		for name := range want {
			request.Header.Add(name, "spoofed")
		}
		request.Header.Add("X-Forwarded-User-Pref-Username", "spoofed")
		request.Header.Add("X-Forwarded-User-Injected", "spoofed")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(body) != 0 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("forward_auth identity status=%d headers=%#v body=%q", response.StatusCode, response.Header, body)
	}
	for name, expected := range want {
		values := response.Header.Values(name)
		if len(values) != 1 || values[0] != expected {
			t.Fatalf("forward_auth header %s=%#v want [%q]", name, values, expected)
		}
	}
	for name := range response.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-forwarded-user-") && name != "X-Forwarded-User-Pref-Username" {
			if _, ok := want[name]; !ok {
				t.Fatalf("unexpected forward_auth identity header %q", name)
			}
		}
	}
	if values := response.Header.Values("X-Forwarded-User-Pref-Username"); len(values) != 0 {
		t.Fatalf("optional spoofed preferred username survived: %#v", values)
	}
	if values := response.Header.Values("X-Forwarded-User-Injected"); len(values) != 0 {
		t.Fatalf("unknown spoofed identity header survived: %#v", values)
	}
}

func assertForwardAuthRejectedNoIdentity(t *testing.T, client *http.Client, baseURL, token, username string, spoof bool) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/forward_auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if spoof {
		request.Header.Set("X-Forwarded-User", "spoofed")
		request.Header.Set("X-Forwarded-User-Roles", "spoofed")
		request.Header.Set("X-Forwarded-User-Groups", "spoofed")
		request.Header.Set("X-Forwarded-User-Injected", "spoofed")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Bearer" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || len(body) != 0 || strings.Contains(string(body), token) || strings.Contains(string(body), username) {
		t.Fatalf("forward_auth generic reject status=%d headers=%#v body=%q", response.StatusCode, response.Header, body)
	}
	for _, name := range []string{
		"X-Forwarded-User", "X-Forwarded-User-Roles", "X-Forwarded-User-Groups",
		"X-Forwarded-User-Email", "X-Forwarded-User-Email-Verified",
		"X-Forwarded-User-Family-Name", "X-Forwarded-User-Given-Name",
		"X-Forwarded-User-MFA", "X-Forwarded-User-Pref-Username", "X-Forwarded-User-Injected",
	} {
		if values := response.Header.Values(name); len(values) != 0 {
			t.Fatalf("rejected forward_auth retained %s=%#v", name, values)
		}
	}
}

func assertForwardAuthAllowed(t *testing.T, client *http.Client, baseURL, token string) {
	t.Helper()
	response := forwardAuthResponse(t, client, baseURL, token)
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || err != nil || len(body) != 0 {
		t.Fatalf("forward_auth allow status=%d headers=%#v body=%q err=%v", response.StatusCode, response.Header, body, err)
	}
}

func assertForwardAuthRejected(t *testing.T, client *http.Client, baseURL, token, username string) {
	t.Helper()
	response := forwardAuthResponse(t, client, baseURL, token)
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Bearer" || err != nil || strings.Contains(string(body), token) || strings.Contains(string(body), username) {
		t.Fatalf("forward_auth reject status=%d headers=%#v body=%q err=%v", response.StatusCode, response.Header, body, err)
	}
}

func forwardAuthResponse(t *testing.T, client *http.Client, baseURL, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/forward_auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
