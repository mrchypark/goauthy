package browser

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

type forwardAuthHAState struct {
	AccessToken string `json:"access_token"`
}

// TestForwardAuthHA is a deterministic three-pod gate for the public
// identity-header projection. It uses only the OAuth and self-delete APIs;
// there is no test-only storage or debug endpoint.
func TestForwardAuthHA(t *testing.T) {
	urls := splitForwardAuthHAURLs(t)
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	clientSecret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if username == "" || password == "" || clientSecret == "" {
		t.Skip("set browser username/password and OAuth client secret to run Forward Auth HA E2E")
	}
	subject := os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	if subject == "" {
		subject = "bootstrap-admin"
	}
	statePath := os.Getenv("GOAUTHY_E2E_FORWARD_AUTH_STATE_FILE")
	if statePath == "" {
		t.Fatal("GOAUTHY_E2E_FORWARD_AUTH_STATE_FILE is required")
	}
	phase := os.Getenv("GOAUTHY_E2E_FORWARD_AUTH_PHASE")
	client := newBrowserClient(t)
	state := forwardAuthHAState{}
	if phase == "post-restart" {
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &state); err != nil || state.AccessToken == "" {
			t.Fatalf("invalid persisted Forward Auth state: %v", err)
		}
	} else {
		state.AccessToken = issueForwardAuthHAToken(t, client, urls, username, password, clientSecret)
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want := map[string]string{
		"X-Forwarded-User":                subject,
		"X-Forwarded-User-Roles":          "forward-auth-admin,rauthy_admin",
		"X-Forwarded-User-Groups":         "forward-auth-group",
		"X-Forwarded-User-Email":          username,
		"X-Forwarded-User-Email-Verified": "false",
		"X-Forwarded-User-Family-Name":    "",
		"X-Forwarded-User-Given-Name":     "",
		"X-Forwarded-User-Mfa":            "false",
	}
	for _, base := range urls {
		assertForwardAuthIdentity(t, client, base, state.AccessToken, want, true)
	}
	if phase != "post-restart" {
		t.Log("initial token projected consistently on all three pods with hostile managed headers cleared")
		return
	}

	// Revoke the persisted token on pod 2 and verify the denial is visible on
	// every pod, including pod 0 after it has been replaced.
	revokeAccessToken(t, client, urls[2], clientSecret, state.AccessToken)
	for _, base := range urls {
		assertForwardAuthRejectedNoIdentity(t, client, base, state.AccessToken, username, true)
	}

	// The public API has no mutable "disabled" flag. Exercise the authenticated,
	// opt-in self-delete boundary without bypassing production authorization:
	// the bootstrap principal is a protected final admin, so self-delete must
	// be denied and the still-valid replacement token must remain usable.
	deleteClient := newBrowserClient(t)
	deleteToken := issueForwardAuthHATokenWithCookie(t, deleteClient, urls, username, password, clientSecret)
	cookie := deleteToken.cookie
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodDelete, urls[1]+"/auth/v1/users/"+url.PathEscape(subject)+"/self/delete", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := deleteClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("protected-admin self-delete status=%d", response.StatusCode)
	}
	for _, base := range urls {
		assertForwardAuthIdentity(t, deleteClient, base, deleteToken.accessToken, want, true)
	}
	t.Log("cross-pod token revocation and protected-admin self-delete denial passed after pod replacement")
}

type forwardAuthHAToken struct {
	accessToken string
	cookie      *http.Cookie
}

func issueForwardAuthHAToken(t *testing.T, client *http.Client, urls []string, username, password, clientSecret string) string {
	t.Helper()
	result := issueForwardAuthHATokenWithCookie(t, client, urls, username, password, clientSecret)
	return result.accessToken
}

func issueForwardAuthHATokenWithCookie(t *testing.T, client *http.Client, urls []string, username, password, clientSecret string) forwardAuthHAToken {
	t.Helper()
	redirectURI := defaultRedirectURI
	if configured := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI"); configured != "" {
		redirectURI = configured
	}
	verifier := pkceVerifier(t)
	code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, urls[0], redirectURI, pkceChallenge(verifier), "forward-auth-ha", "forward-auth-ha-nonce"), urls[0], urls[1], username, password, "forward-auth-ha")
	tokens := exchangeCode(t, client, urls[0], clientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("Forward Auth HA authorization did not issue an access token")
	}
	return forwardAuthHAToken{accessToken: tokens.AccessToken, cookie: cookie}
}

func splitForwardAuthHAURLs(t *testing.T) []string {
	t.Helper()
	raw := strings.Split(strings.TrimSpace(os.Getenv("GOAUTHY_E2E_FORWARD_AUTH_URLS")), ",")
	if len(raw) != 3 {
		t.Skip("set GOAUTHY_E2E_FORWARD_AUTH_URLS to three comma-separated pod URLs")
	}
	for i := range raw {
		raw[i] = strings.TrimRight(strings.TrimSpace(raw[i]), "/")
		if raw[i] == "" {
			t.Fatal("Forward Auth HA URL is empty")
		}
	}
	return raw
}
