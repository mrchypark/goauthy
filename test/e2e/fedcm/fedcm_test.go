// Package fedcm exercises the deployed FedCM HTTP contract. Browser API
// coverage is intentionally separate: this package remains useful when the
// installed Chrome lacks IdentityCredential support.
package fedcm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
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
	clientID = "rp-client"
	rpOrigin = "https://rp.example.test"
)

func TestProtocolAndSecurityContract(t *testing.T) {
	issuer, secondary, client := config(t)
	waitReady(t, client, issuer)
	if secondary != "" {
		waitReady(t, client, secondary)
	}

	get(t, client, issuer+"/.well-known/web-identity", "webidentity", "", http.StatusOK)
	var manifest struct {
		ProviderURLs []string `json:"provider_urls"`
	}
	decode(t, client, issuer+"/.well-known/web-identity", "webidentity", "", &manifest)
	if len(manifest.ProviderURLs) != 1 || manifest.ProviderURLs[0] != issuer+"/auth/v1/fed_cm/config" {
		t.Fatalf("manifest=%+v", manifest)
	}
	var cfg struct {
		Accounts       string `json:"accounts_endpoint"`
		ClientMetadata string `json:"client_metadata_endpoint"`
		Assertion      string `json:"id_assertion_endpoint"`
		Login          string `json:"login_url"`
	}
	decode(t, client, issuer+"/auth/v1/fed_cm/config", "webidentity", "", &cfg)
	if cfg.Accounts != "/auth/v1/fed_cm/accounts" || cfg.ClientMetadata != "/auth/v1/fed_cm/client_meta" || cfg.Assertion != "/auth/v1/fed_cm/token" || cfg.Login != "/auth/login" {
		t.Fatalf("config=%+v", cfg)
	}
	for _, path := range []string{"/auth/v1/fed_cm/accounts", "/auth/v1/fed_cm/status"} {
		get(t, client, issuer+path, "webidentity", "", http.StatusUnauthorized)
	}
	get(t, client, issuer+"/auth/v1/fed_cm/client_meta?client_id="+url.QueryEscape(clientID), "webidentity", rpOrigin, http.StatusOK)
	get(t, client, issuer+"/auth/v1/fed_cm/client_meta?client_id="+url.QueryEscape(clientID), "webidentity", "https://wrong.example.test", http.StatusForbidden)
	get(t, client, issuer+"/auth/v1/fed_cm/status?extra=1", "webidentity", "", http.StatusBadRequest)
	post(t, client, issuer+"/auth/v1/fed_cm/token", "webidentity", rpOrigin, url.Values{"account_id": {"bootstrap-admin"}, "client_id": {"" + clientID}, "nonce": {"e2e"}, "disclosure_text_shown": {"true"}}, http.StatusUnauthorized)
	post(t, client, issuer+"/auth/v1/fed_cm/token", "webidentity", "https://wrong.example.test", url.Values{"account_id": {"bootstrap-admin"}, "client_id": {clientID}, "nonce": {"e2e"}, "disclosure_text_shown": {"true"}}, http.StatusForbidden)
	if secondary != "" {
		get(t, client, secondary+"/.well-known/web-identity", "webidentity", "", http.StatusOK)
	}
}

func TestCookieBoundaryAndLogout(t *testing.T) {
	issuer, secondary, client := config(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	r := request(t, client, http.MethodGet, issuer+"/auth/login", "", "")
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		t.Skip("FedCM landing requires deployed browser login fixture")
	}
	// The initial GET legitimately issues the normal Lax cookie; it is the
	// authenticated FedCM GET below that must add the separate None cookie.
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	interaction, csrf := hidden(string(body), "interaction"), hidden(string(body), "csrf_token")
	username := os.Getenv("GOAUTHY_E2E_FEDCM_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_FEDCM_PASSWORD")
	if username == "" || password == "" {
		t.Skip("set GOAUTHY_E2E_FEDCM_USERNAME and GOAUTHY_E2E_FEDCM_PASSWORD for authenticated cookie/assertion checks")
	}
	post(t, client, issuer+"/auth/login", "", issuer, url.Values{"fedcm": {"1"}, "interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}, http.StatusOK)
	r = request(t, client, http.MethodGet, issuer+"/auth/login", "", "")
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		t.Fatalf("authenticated landing status=%d", r.StatusCode)
	}
	r.Body.Close()
	cookies := jar.Cookies(mustURL(t, issuer))
	var normal, fedcm *http.Cookie
	for _, c := range cookies {
		c := *c
		if c.Name == "goauthy_session" || c.Name == "__Host-goauthy_session" {
			normal = &c
		}
		if c.Name == "__Host-goauthy_fedcm_session" {
			fedcm = &c
		}
	}
	if normal == nil || fedcm == nil {
		t.Fatalf("cookie boundary missing normal=%v fedcm=%v", normal != nil, fedcm != nil)
	}
	get(t, client, issuer+"/auth/v1/fed_cm/accounts", "webidentity", "", http.StatusOK)
	if secondary != "" {
		get(t, client, secondary+"/auth/v1/fed_cm/accounts", "webidentity", "", http.StatusOK)
	}
	// A normal session alone never crosses the FedCM trust boundary.
	other, _ := cookiejar.New(nil)
	other.SetCookies(mustURL(t, issuer), []*http.Cookie{normal})
	get(t, &http.Client{Transport: client.Transport, Jar: other}, issuer+"/auth/v1/fed_cm/accounts", "webidentity", "", http.StatusUnauthorized)
	form := url.Values{"account_id": {"bootstrap-admin"}, "client_id": {clientID}, "nonce": {"e2e-nonce"}, "disclosure_text_shown": {"true"}}
	resp := requestBody(t, client, http.MethodPost, issuer+"/auth/v1/fed_cm/token", "webidentity", rpOrigin, strings.NewReader(form.Encode()))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assertion status=%d", resp.StatusCode)
	}
	var assertion struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(resp.Body).Decode(&assertion) != nil || assertion.Token == "" {
		t.Fatal("missing assertion token")
	}
	keysResp := request(t, client, http.MethodGet, issuer+"/oidc/jwks.json", "", "")
	defer keysResp.Body.Close()
	var keys jose.JSONWebKeySet
	if json.NewDecoder(keysResp.Body).Decode(&keys) != nil {
		t.Fatal("invalid JWKS")
	}
	claims, err := oidc.VerifyIDToken(assertion.Token, keys, issuer, clientID, time.Now().UTC())
	if err != nil || claims.Subject != "bootstrap-admin" || claims.Nonce != "e2e-nonce" {
		t.Fatalf("assertion claims=%+v err=%v", claims, err)
	}
	if repeat := requestBody(t, client, http.MethodPost, issuer+"/auth/v1/fed_cm/token", "webidentity", rpOrigin, strings.NewReader(form.Encode())); repeat.StatusCode != http.StatusOK {
		repeat.Body.Close()
		t.Fatalf("repeat assertion issuance status=%d", repeat.StatusCode)
	} else {
		repeat.Body.Close()
	}
	logout := request(t, client, http.MethodGet, issuer+"/oidc/logout", "", "")
	logoutBody, _ := io.ReadAll(logout.Body)
	logout.Body.Close()
	confirmation := hidden(string(logoutBody), "confirmation")
	if confirmation == "" {
		t.Fatalf("logout confirmation missing")
	}
	logout = requestBody(t, client, http.MethodPost, issuer+"/oidc/logout", "", issuer, strings.NewReader(url.Values{"confirmation": {confirmation}}.Encode()))
	logout.Body.Close()
	if logout.StatusCode != http.StatusSeeOther && logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d", logout.StatusCode)
	}
	get(t, client, issuer+"/auth/v1/fed_cm/accounts", "webidentity", "", http.StatusUnauthorized)
	if secondary != "" {
		get(t, client, secondary+"/auth/v1/fed_cm/accounts", "webidentity", "", http.StatusUnauthorized)
	}
	_ = fedcm
}

var hiddenField = regexp.MustCompile(`<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"`)

func hidden(body, name string) string {
	for _, m := range hiddenField.FindAllStringSubmatch(body, -1) {
		if m[1] == name {
			return m[2]
		}
	}
	return ""
}

func config(t *testing.T) (string, string, *http.Client) {
	t.Helper()
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_FEDCM_URL"), "/")
	if issuer == "" {
		t.Skip("set GOAUTHY_E2E_FEDCM_URL to run FedCM E2E")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("FedCM issuer must be HTTPS: %q", issuer)
	}
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_FEDCM_SECONDARY_URL"), "/")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if ca := os.Getenv("GOAUTHY_E2E_CA_FILE"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("invalid FedCM CA file")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return issuer, secondary, &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func waitReady(t *testing.T, c *http.Client, base string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := c.Get(base + "/readyz")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusNoContent {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s/readyz", base)
		case <-tick.C:
		}
	}
}
func get(t *testing.T, c *http.Client, endpoint, dest, origin string, want int) {
	t.Helper()
	r := request(t, c, http.MethodGet, endpoint, dest, origin)
	defer r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("GET %s status=%d want=%d", endpoint, r.StatusCode, want)
	}
}
func post(t *testing.T, c *http.Client, endpoint, dest, origin string, form url.Values, want int) {
	t.Helper()
	r := requestBody(t, c, http.MethodPost, endpoint, dest, origin, strings.NewReader(form.Encode()))
	defer r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("POST %s status=%d want=%d", endpoint, r.StatusCode, want)
	}
}
func decode(t *testing.T, c *http.Client, endpoint, dest, origin string, out any) {
	t.Helper()
	r := request(t, c, http.MethodGet, endpoint, dest, origin)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d", endpoint, r.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(out); err != nil {
		t.Fatal(err)
	}
}
func request(t *testing.T, c *http.Client, m, u, dest, origin string) *http.Response {
	return requestBody(t, c, m, u, dest, origin, nil)
}
func requestBody(t *testing.T, c *http.Client, m, u, dest, origin string, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(m, u, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Sec-Fetch-Dest", dest)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
