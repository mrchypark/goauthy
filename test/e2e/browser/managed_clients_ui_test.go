package browser

// This is deliberately opt-in: it needs the three-node browser fixture.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

// TestManagedClientsUIAcrossPods drives managed-client CRUD through the shipped
// admin UI, then uses the resulting public client in the real device flow.
func TestManagedClientsUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MANAGED_CLIENTS_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_MANAGED_CLIENTS_UI=1 to run managed-client UI E2E")
	}
	primary, secondary, adminUser, adminPassword, bootstrapSecret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	nodes := []string{primary, secondary, tertiary}
	admin := newBrowserClient(t)
	_, cookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "managed-clients-ui-admin")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	id := "managed-ui-" + randomManagedUIID(t)
	t.Cleanup(func() {
		r := do(t, admin, http.MethodGet, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
		var v managedUIClient
		if r.StatusCode == http.StatusOK && json.NewDecoder(r.Body).Decode(&v) == nil {
			r.Body.Close()
			h := cloneManagedUIHeaders(headers)
			h["If-Match"] = `"` + strconv.FormatInt(v.Revision, 10) + `"`
			d := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, h)
			d.Body.Close()
			return
		}
		r.Body.Close()
	})
	missingCSRF := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(`{"id":"missing-csrf","name":"missing-csrf","confidential":false}`), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	missingCSRF.Body.Close()
	if missingCSRF.StatusCode != http.StatusForbidden && missingCSRF.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing CSRF status=%d", missingCSRF.StatusCode)
	}
	ctx, cancel := managedUIContext(t, primary, cookie, id)
	defer cancel()
	ordinaryEmail, ordinaryPassword := "managed-ui-"+randomManagedUIID(t)+"@goauthy.e2e", "Managed-UI-Ordinary-2B"
	ordinaryID := createCatalogSessionUser(t, admin, primary, headers, ordinaryEmail, ordinaryPassword)
	t.Cleanup(func() {
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(ordinaryID), nil, headers)
		r.Body.Close()
	})

	// Ordinary users must not see the admin page.
	ordinary := newBrowserClient(t)
	_, ordinaryCookie := loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), ordinaryEmail, ordinaryPassword, "managed-clients-ui-ordinary")
	ordinary = clientWithCookie(t, primary, ordinaryCookie)
	unauth := do(t, ordinary, http.MethodGet, primary+"/auth/v1/admin/clients", nil, nil)
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ordinary admin page status=%d", unauth.StatusCode)
	}

	if err := chromedp.Run(ctx, chromedp.Navigate(primary+"/auth/v1/admin/clients"), managedClientsUIReady(),
		chromedp.Click(`a[href="/auth/v1/admin/clients/new"]`), chromedp.WaitVisible("#client-form"),
		chromedp.SetValue("#client-id", id), chromedp.SetValue("#client-name", "Managed UI Device"),
		chromedp.Click("#client-device"), chromedp.Click("#client-save"), chromedp.WaitVisible("#client-enabled")); err != nil {
		t.Fatalf("create public Device client through admin UI: %v", err)
	}

	assertManagedUIClient(t, admin, nodes, id, "Managed UI Device", false, true, headers)
	grant := startDeviceAuthorizationOffline(t, newBrowserClient(t), primary, id, "")
	// Login and approval happen in a cold, separate browser session.
	verify := newBrowserClient(t)
	loginAndApproveDevice(t, verify, grant, primary, tertiary, ordinaryEmail, ordinaryPassword)
	deviceClient := newBrowserClient(t)
	tokens := publicDeviceToken(t, deviceClient, secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {id}})
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("public Device token response is incomplete")
	}
	assertDeviceLoginIntrospection(t, primary, bootstrapSecret, tokens.AccessToken, grant.Scope)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {id}}
	refreshed := publicDeviceToken(t, deviceClient, tertiary, refreshForm)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("public Device refresh response is incomplete")
	}
	for _, base := range nodes {
		assertDeviceLoginIntrospection(t, base, bootstrapSecret, refreshed.AccessToken, grant.Scope)
	}
	assertDeviceRefreshReplayDenied(t, deviceClient, primary, refreshForm)

	// Disable and delete are checked through the API after the UI mutation so
	// the assertion is about persisted HA state, not merely the rendered list.
	if err := chromedp.Run(ctx, chromedp.SetValue("#client-name", "Managed UI Device Updated"), chromedp.Click("#client-enabled"), managedUISave()); err != nil {
		t.Fatalf("disable managed client through admin UI: %v", err)
	}
	assertManagedUIClient(t, admin, nodes, id, "Managed UI Device Updated", false, false, headers)
	for _, base := range nodes {
		assertManagedTokenRejected(t, deviceClient, base, bootstrapSecret, id, refreshed.AccessToken)
	}
	if err := chromedp.Run(ctx, chromedp.Click("#client-enabled"), managedUISave()); err != nil {
		t.Fatalf("reenable managed client: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.Click("#client-delete"), chromedp.WaitVisible("#client-list"), managedClientsUIReady()); err != nil {
		t.Fatalf("delete managed client through admin UI: %v", err)
	}
	for _, base := range nodes {
		r := do(t, admin, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatalf("deleted client node=%s status=%d", base, r.StatusCode)
		}
	}
	// Confidential web client: the secret is only exposed by explicit UI
	// actions and never by the ordinary client GET response.
	confID := "managed-ui-conf-" + randomManagedUIID(t)
	t.Cleanup(func() {
		r := do(t, admin, http.MethodGet, primary+"/auth/v1/clients/"+url.PathEscape(confID), nil, headers)
		var v managedUIClient
		if r.StatusCode == http.StatusOK && json.NewDecoder(r.Body).Decode(&v) == nil {
			r.Body.Close()
			h := cloneManagedUIHeaders(headers)
			h["If-Match"] = `"` + strconv.FormatInt(v.Revision, 10) + `"`
			d := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(confID), nil, h)
			d.Body.Close()
			return
		}
		r.Body.Close()
	})
	if err := chromedp.Run(ctx, chromedp.Navigate(primary+"/auth/v1/admin/clients/new"), chromedp.WaitVisible("#client-form"), chromedp.SetValue("#client-id", confID), chromedp.SetValue("#client-name", "Managed UI Confidential"), chromedp.Click("#client-web"), chromedp.SetValue("#client-redirects", "https://rp.example.test/callback"), chromedp.Click("#client-save"), chromedp.WaitVisible("#client-secret")); err != nil {
		t.Fatalf("create confidential web client through admin UI: %v", err)
	}
	var secretText string
	if err := chromedp.Run(ctx, chromedp.Click("#client-secret-read"), chromedp.Poll(`document.querySelector('#client-secret')?.textContent && !document.querySelector('#client-secret').textContent.includes('hidden')`, nil), chromedp.TextContent("#client-secret", &secretText)); err != nil {
		t.Fatalf("read confidential secret through UI: %v", err)
	}
	oldSecret := strings.TrimSpace(strings.TrimPrefix(secretText, "Secret (copy now): "))
	if oldSecret == "" {
		t.Fatal("confidential UI returned empty secret")
	}
	if err := chromedp.Run(ctx, chromedp.Click("#client-secret-hide"), chromedp.Poll(`document.querySelector('#client-secret')?.textContent === 'Secret is hidden.'`, nil), chromedp.Click("#client-secret-rotate"), chromedp.Poll(`document.querySelector('#client-secret')?.textContent && !document.querySelector('#client-secret').textContent.includes('hidden')`, nil), chromedp.TextContent("#client-secret", &secretText)); err != nil {
		t.Fatalf("rotate confidential secret through UI: %v", err)
	}
	newSecret := strings.TrimSpace(strings.TrimPrefix(secretText, "Secret (copy now): "))
	if newSecret == "" || newSecret == oldSecret {
		t.Fatal("confidential UI did not rotate secret")
	}
	// The shipped form has no client-credentials preset; finish that policy
	// through the same authenticated managed-client endpoint before exercising
	// the token endpoint.
	current := managedUIRevision(t, admin, primary, confID, headers)
	uh := cloneManagedUIHeaders(headers)
	uh["If-Match"] = `"` + strconv.FormatInt(current, 10) + `"`
	body := strings.NewReader(`{"name":"Managed UI Confidential","confidential":true,"redirect_uris":[],"enabled":true,"scopes":["goauthy.read"],"default_scopes":["goauthy.read"],"enabled_flows":["client_credentials"]}`)
	r := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(confID), body, uh)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("configure client_credentials status=%d", r.StatusCode)
	}
	managedClientTokenStatus(t, primary, confID, oldSecret, http.StatusUnauthorized)
	managedClientTokenStatus(t, primary, confID, newSecret, http.StatusOK)
	for _, base := range nodes {
		r := do(t, admin, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(confID), nil, headers)
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || bytes.Contains(bytes.ToLower(b), []byte(`"secret"`)) {
			t.Fatalf("confidential ordinary GET leaked secret node=%s status=%d", base, r.StatusCode)
		}
	}
}

func managedUIRevision(t *testing.T, c *http.Client, base, id string, h map[string]string) int64 {
	r := do(t, c, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, h)
	defer r.Body.Close()
	var v managedUIClient
	if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&v) != nil {
		t.Fatalf("client revision status=%d", r.StatusCode)
	}
	return v.Revision
}
func managedClientTokenStatus(t *testing.T, base, id, secret string, want int) {
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))})
	defer r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("client_credentials status=%d want=%d", r.StatusCode, want)
	}
}

func managedUIContext(t *testing.T, base string, cookie *http.Cookie, deleteID string) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	alloc, stopAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless, chromedp.NoFirstRun)...)
	browser, stopBrowser := chromedp.NewContext(alloc)
	chromedp.ListenTarget(browser, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok && dialog.Message == "Delete client "+deleteID+" permanently?" {
			go func() { _ = chromedp.Run(browser, page.HandleJavaScriptDialog(true)) }()
		}
	})
	u := mustE2EURL(t, base+"/")
	if err := chromedp.Run(browser, network.SetCookie(cookie.Name, cookie.Value).WithDomain(u.Hostname()).WithPath("/").WithSecure(u.Scheme == "https")); err != nil {
		stopBrowser()
		stopAlloc()
		cancel()
		t.Fatal(err)
	}
	return browser, func() { stopBrowser(); stopAlloc(); cancel() }
}

func managedClientsUIReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#client-list"), chromedp.Poll(`document.querySelector('#client-status')?.textContent !== 'Loading…'`, nil)}
}

type managedUIClient struct {
	ID, Name              string
	RedirectURIs          []string `json:"redirect_uris"`
	Scopes                []string `json:"scopes"`
	DefaultScopes         []string `json:"default_scopes"`
	EnabledFlows          []string `json:"enabled_flows"`
	Enabled, Confidential bool
	Revision              int64
}

func managedUISave() chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Evaluate(`window.managedClientOldForm = document.querySelector('#client-form'); true`, nil),
		chromedp.Click("#client-save"),
		chromedp.Poll(`document.querySelector('#client-form') !== window.managedClientOldForm && document.querySelector('#client-save') && !document.querySelector('#client-save').disabled`, nil),
	}
}

func cloneManagedUIHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func assertManagedUIClient(t *testing.T, c *http.Client, nodes []string, id, name string, confidential, enabled bool, h map[string]string) {
	t.Helper()
	for _, base := range nodes {
		r := do(t, c, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, h)
		var v managedUIClient
		if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&v) != nil {
			r.Body.Close()
			t.Fatalf("managed client read node=%s status=%d", base, r.StatusCode)
		}
		r.Body.Close()
		if v.ID != id || v.Name != name || v.Confidential != confidential || v.Enabled != enabled || v.Revision == 0 {
			t.Fatalf("managed client node=%s got=%+v", base, v)
		}
		if !confidential && (len(v.RedirectURIs) != 0 || !containsManaged(v.Scopes, "goauthy.read") || !containsManaged(v.Scopes, "offline_access") || !containsManaged(v.DefaultScopes, "goauthy.read") || !containsManaged(v.DefaultScopes, "offline_access") || !containsManaged(v.EnabledFlows, "urn:ietf:params:oauth:grant-type:device_code") || !containsManaged(v.EnabledFlows, "refresh_token")) {
			t.Fatalf("public device policy node=%s got=%+v", base, v)
		}
	}
}
func containsManaged(v []string, want string) bool {
	for _, x := range v {
		if x == want {
			return true
		}
	}
	return false
}
func randomManagedUIID(t *testing.T) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func loginAndApproveDevice(t *testing.T, c *http.Client, grant deviceLoginGrant, primary, postBase, username, password string) {
	t.Helper()
	r := do(t, c, http.MethodGet, grant.VerificationURIComplete, nil, nil)
	if r.StatusCode != http.StatusSeeOther {
		r.Body.Close()
		t.Fatalf("device verify redirect status=%d", r.StatusCode)
	}
	loginURL := r.Header.Get("Location")
	r.Body.Close()
	r = do(t, c, http.MethodGet, loginURL, nil, nil)
	body := readLimitedBody(t, r)
	r.Body.Close()
	interaction, iok := hiddenInputValue(body, "interaction")
	csrf, cok := hiddenInputValue(body, "csrf_token")
	if !iok || !cok {
		t.Fatal("device login form missing fields")
	}
	r = do(t, c, http.MethodPost, primary+"/oidc/device/login", strings.NewReader(url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary)})
	if r.StatusCode != http.StatusSeeOther {
		r.Body.Close()
		t.Fatalf("device login status=%d", r.StatusCode)
	}
	verifyURL := r.Header.Get("Location")
	r.Body.Close()
	r = do(t, c, http.MethodGet, verifyURL, nil, nil)
	body = readLimitedBody(t, r)
	r.Body.Close()
	csrf, ok := hiddenInputValue(body, "csrf_token")
	if !ok {
		t.Fatal("device approval CSRF missing")
	}
	r = do(t, c, http.MethodPost, postBase+"/oidc/device/verify", strings.NewReader(url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary)})
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device approval status=%d", r.StatusCode)
	}
}
func assertDeviceRefreshReplayDenied(t *testing.T, c *http.Client, base string, form url.Values) {
	r := do(t, c, http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh replay status=%d", r.StatusCode)
	}
	b, _ := io.ReadAll(r.Body)
	if !bytes.Contains(b, []byte(`"invalid_grant"`)) {
		t.Fatalf("refresh replay error missing")
	}
}

func assertManagedTokenRejected(t *testing.T, c *http.Client, base, secret, clientID, token string) {
	t.Helper()
	r := do(t, c, http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("goauthy-dev:"+secret))})
	defer r.Body.Close()
	var v struct {
		Active bool `json:"active"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&v) != nil || v.Active {
		t.Fatalf("disabled managed token remained active client=%s status=%d", clientID, r.StatusCode)
	}
}
