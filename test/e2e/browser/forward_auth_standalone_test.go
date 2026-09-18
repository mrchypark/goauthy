package browser

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestForwardAuthStandaloneMalformedTransport exercises the public standalone
// route with a real password-issued access token. It reuses the existing
// browser authorization/token helpers while adding the malformed
// Authorization/body/query cases that a reverse proxy can forward.
func TestForwardAuthStandaloneMalformedTransport(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FORWARD_AUTH_STANDALONE") != "1" {
		t.Skip("set GOAUTHY_E2E_FORWARD_AUTH_STANDALONE=1 to run standalone forward-auth E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
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
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, redirectURI, pkceChallenge(verifier), "forward-auth-standalone", "forward-auth-standalone-nonce"), primary, secondary, username, password, "forward-auth-standalone")
	tokens := exchangeCode(t, client, primary, clientSecret, redirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("standalone forward_auth authorization did not issue an access token")
	}

	want := map[string]string{
		"X-Forwarded-User":                subject,
		"X-Forwarded-User-Roles":          "forward-auth-admin,rauthy_admin",
		"X-Forwarded-User-Groups":         "forward-auth-group",
		"X-Forwarded-User-Email":          username,
		"X-Forwarded-User-Email-Verified": "false",
		"X-Forwarded-User-Family-Name":    "",
		"X-Forwarded-User-Given-Name":     "",
		"X-Forwarded-User-MFA":            "false",
	}
	assertForwardAuthHostileInboundCleared(t, client, primary, tokens.AccessToken, want)

	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "duplicate authorization", mutate: func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer "+tokens.AccessToken)
		}},
		{name: "wrong scheme", mutate: func(request *http.Request) {
			request.Header.Set("Authorization", "Basic "+tokens.AccessToken)
		}},
		{name: "token whitespace", mutate: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+tokens.AccessToken+" extra")
		}},
		{name: "query", mutate: func(request *http.Request) {
			request.URL.RawQuery = "probe=1"
		}},
		{name: "body", mutate: func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("unexpected"))
			request.ContentLength = int64(len("unexpected"))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertForwardAuthMalformedRejected(t, client, primary, tokens.AccessToken, test.mutate)
		})
	}
}

func assertForwardAuthHostileInboundCleared(t *testing.T, client *http.Client, baseURL, token string, want map[string]string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/forward_auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	for _, name := range []string{
		"X-Forwarded-User", "X-Forwarded-User-Roles", "X-Forwarded-User-Groups",
		"X-Forwarded-User-Email", "X-Forwarded-User-Email-Verified",
		"X-Forwarded-User-Family-Name", "X-Forwarded-User-Given-Name",
		"X-Forwarded-User-MFA", "X-Forwarded-User-Pref-Username",
	} {
		request.Header.Add(name, "spoofed")
	}
	request.Header.Add("X-Forwarded-User", strings.Repeat("x", 4097))
	request.Header.Add("x-forwarded-user", "spoofed-case")
	request.Header.Add("X-Forwarded-User-Injected", "spoofed")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	assertForwardAuthResponseHeaders(t, response, want)
}

func assertForwardAuthMalformedRejected(t *testing.T, client *http.Client, baseURL, token string, mutate func(*http.Request)) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/forward_auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Forwarded-User", "spoofed")
	request.Header.Set("X-Forwarded-User-Roles", "spoofed")
	request.Header.Set("X-Forwarded-User-Groups", "spoofed")
	request.Header.Set("X-Forwarded-User-Injected", "spoofed")
	mutate(request)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Bearer" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || len(body) != 0 {
		t.Fatalf("malformed forward_auth status=%d headers=%#v body=%q", response.StatusCode, response.Header, body)
	}
	for _, name := range []string{
		"X-Forwarded-User", "X-Forwarded-User-Roles", "X-Forwarded-User-Groups",
		"X-Forwarded-User-Email", "X-Forwarded-User-Email-Verified",
		"X-Forwarded-User-Family-Name", "X-Forwarded-User-Given-Name",
		"X-Forwarded-User-MFA", "X-Forwarded-User-Pref-Username", "X-Forwarded-User-Injected",
	} {
		if values := response.Header.Values(name); len(values) != 0 {
			t.Fatalf("malformed forward_auth retained %s=%#v", name, values)
		}
	}
}

func assertForwardAuthResponseHeaders(t *testing.T, response *http.Response, want map[string]string) {
	t.Helper()
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
		if strings.HasPrefix(strings.ToLower(name), "x-forwarded-user-") {
			known := false
			for expected := range want {
				if strings.EqualFold(name, expected) {
					known = true
					break
				}
			}
			if !known {
				t.Fatalf("unexpected forward_auth identity header %q", name)
			}
		}
	}
}
