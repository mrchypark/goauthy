package browser

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Uses an existing browser session and a real code+PKCE exchange. No token
// claims are patched; the public invoke tests stop before outbound dispatch.
func issueGrantInvokeToken(t *testing.T, owner *http.Client, base, consumer, resource string) string {
	t.Helper()
	return issueGrantResourceToken(t, owner, base, consumer, resource, "goauthy.connections.use")
}

func issueGrantResourceToken(t *testing.T, owner *http.Client, base, consumer, resource, scope string) string {
	return issueGrantResourceTokenWithSecret(t, owner, base, consumer, resource, scope, "")
}

func issueGrantResourceTokenWithSecret(t *testing.T, owner *http.Client, base, consumer, resource, scope, secret string) string {
	t.Helper()
	const redirect = "https://rp.example.test/use-grant"
	verifier := pkceVerifier(t)
	u, err := url.Parse(oidcAuthorizationURLForClient(t, base, consumer, redirect, pkceChallenge(verifier), "invoke-state", "invoke-nonce", scope))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if resource != "" {
		q.Set("resource", resource)
	}
	u.RawQuery = q.Encode()
	r := do(t, owner, http.MethodGet, u.String(), nil, nil)
	r.Body.Close()
	callback, err := url.Parse(r.Header.Get("Location"))
	if err != nil || (r.StatusCode != http.StatusFound && r.StatusCode != http.StatusSeeOther) || callback.Query().Get("code") == "" || callback.Query().Get("state") != "invoke-state" {
		t.Fatalf("invoke authorize status=%d", r.StatusCode)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {consumer}, "code": {callback.Query().Get("code")}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if secret != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(consumer)+":"+url.QueryEscape(secret)))
	}
	r = do(t, newBrowserClient(t), http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()), headers)
	defer r.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&token) != nil || token.AccessToken == "" {
		t.Fatalf("invoke token status=%d", r.StatusCode)
	}
	return token.AccessToken
}

func assertGrantInvokeStatus(t *testing.T, base, grant, token, body string, want int) {
	t.Helper()
	headers := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grant)+"/invoke", strings.NewReader(body), headers)
	defer r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("invoke status=%d want=%d", r.StatusCode, want)
	}
}
