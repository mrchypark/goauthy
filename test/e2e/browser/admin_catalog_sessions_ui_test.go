package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

// TestAdminCatalogSessionsUIAcrossPods covers the catalog and session screens
// through Chromium. It is opt-in because it needs a deployed HA fixture.
func TestAdminCatalogSessionsUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_CATALOG_SESSIONS_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_CATALOG_SESSIONS_UI=1 to run Chromium catalog/session UI E2E")
	}
	primary, secondary, adminUser, adminPassword, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	adminClient := newBrowserClient(t)
	_, adminCookie := loginForCode(t, adminClient, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "admin-catalog-sessions-ui")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}

	// Create a disposable ordinary account with the administrator API. This
	// keeps the admin bootstrap account out of the revoke assertion.
	const ordinaryEmail, ordinaryPassword = "catalog-session-ui@goauthy.e2e", "Catalog-Session-UI-Initial-1A"
	ordinaryID := createCatalogSessionUser(t, adminClient, primary, headers, ordinaryEmail, ordinaryPassword)
	t.Cleanup(func() {
		response := do(t, adminClient, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(ordinaryID), nil, headers)
		response.Body.Close()
	})

	ordinaryClient := newBrowserClient(t)
	_, ordinaryCookie := loginForCode(t, ordinaryClient, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), ordinaryEmail, ordinaryPassword, "catalog-session-ui-user")

	const attributeName, scopeName = "catalog-session-ui-attribute", "catalog-session-ui-scope"
	deleteCatalogFixture(t, adminClient, primary, headers, attributeName, scopeName)
	t.Cleanup(func() { deleteCatalogFixture(t, adminClient, primary, headers, attributeName, scopeName) })

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless, chromedp.NoFirstRun)...)
	defer cancelAlloc()
	browser, cancelBrowser := chromedp.NewContext(alloc)
	defer cancelBrowser()
	var expectedDialog atomic.Value
	expectedDialog.Store("")
	chromedp.ListenTarget(browser, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			accept := dialog.Message == expectedDialog.Load().(string) && dialog.Message != ""
			go func() { _ = chromedp.Run(browser, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	parsed, err := url.Parse(primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(browser, network.SetCookie(adminCookie.Name, adminCookie.Value).WithDomain(parsed.Hostname()).WithPath("/").WithSecure(parsed.Scheme == "https"), chromedp.Navigate(primary+"/auth/v1/admin/attributes"), catalogListReady()); err != nil {
		t.Fatalf("catalog UI unavailable: %v", err)
	}
	if err := chromedp.Run(browser,
		chromedp.Click("#catalog-new"), chromedp.WaitVisible("#catalog-form"),
		chromedp.SetValue("#catalog-name", attributeName), chromedp.SetValue("#catalog-desc", "UI catalog attribute"),
		chromedp.SetValue("#catalog-default", `{"tier":"gold","enabled":true}`), chromedp.SetValue("#catalog-type", "email"),
		chromedp.Click("#catalog-editable"), chromedp.Click("#catalog-form button[type=submit]"), catalogListReady(),
	); err != nil {
		t.Fatalf("attribute CRUD UI: %v", err)
	}
	assertCatalogAttribute(t, adminClient, primary, attributeName, "UI catalog attribute")
	if err := chromedp.Run(browser,
		chromedp.Click(`a[href="/auth/v1/admin/attributes/`+attributeName+`"]`), chromedp.WaitVisible("#catalog-form"),
		chromedp.SetValue("#catalog-desc", "UI catalog attribute updated"), chromedp.Click("#catalog-form button[type=submit]"), catalogListReady(),
	); err != nil {
		t.Fatalf("attribute edit UI: %v", err)
	}
	for _, node := range nodes {
		assertCatalogAttribute(t, adminClient, node, attributeName, "UI catalog attribute updated")
	}

	if err := chromedp.Run(browser, chromedp.Navigate(primary+"/auth/v1/admin/scopes"), catalogListReady(), chromedp.Click("#catalog-new"), chromedp.WaitVisible("#catalog-form"), chromedp.SetValue("#catalog-name", scopeName), chromedp.SetValue("#catalog-access", attributeName), chromedp.SetValue("#catalog-id", attributeName), chromedp.Click("#catalog-form button[type=submit]"), catalogListReady()); err != nil {
		t.Fatalf("scope CRUD UI: %v", err)
	}
	assertCatalogScope(t, adminClient, primary, scopeName, attributeName, false)
	if err := chromedp.Run(browser, chromedp.Click(`a[href="/auth/v1/admin/scopes/`+scopeName+`"]`), chromedp.WaitVisible("#catalog-form"), chromedp.Click("#catalog-root"), chromedp.Click("#catalog-form button[type=submit]"), catalogListReady()); err != nil {
		t.Fatalf("scope edit UI: %v", err)
	}
	for _, node := range nodes {
		assertCatalogScope(t, adminClient, node, scopeName, attributeName, true)
	}
	expectedDialog.Store("Delete this scope permanently?")
	if err := chromedp.Run(browser, chromedp.Click(`a[href="/auth/v1/admin/scopes/`+scopeName+`"]`), chromedp.WaitVisible("#catalog-form"), chromedp.Click("#catalog-delete"), catalogListReady(), chromedp.WaitNotPresent(`a[href="/auth/v1/admin/scopes/`+scopeName+`"]`)); err != nil {
		t.Fatalf("scope delete UI: %v", err)
	}
	expectedDialog.Store("Delete this attribute permanently?")
	if err := chromedp.Run(browser, chromedp.Navigate(primary+"/auth/v1/admin/attributes"), catalogListReady(), chromedp.Click(`a[href="/auth/v1/admin/attributes/`+attributeName+`"]`), chromedp.WaitVisible("#catalog-form"), chromedp.Click("#catalog-delete"), catalogListReady(), chromedp.WaitNotPresent(`a[href="/auth/v1/admin/attributes/`+attributeName+`"]`)); err != nil {
		t.Fatalf("attribute delete UI: %v", err)
	}

	if err := chromedp.Run(browser, chromedp.Navigate(primary+"/auth/v1/admin/sessions"), sessionListReady(), chromedp.SetValue("#session-state", "Auth"), chromedp.Click("#session-filter button[type=submit]"), sessionListReady()); err != nil {
		t.Fatalf("session list/filter UI: %v", err)
	}
	for _, node := range nodes {
		response := do(t, clientWithCookie(t, node, ordinaryCookie), http.MethodGet, node+"/account/data", nil, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("ordinary cookie before revoke node=%s status=%d", node, response.StatusCode)
		}
	}
	var sessionID string
	if err := chromedp.Run(browser, chromedp.Evaluate(`(()=>{const want=`+jsonString(ordinaryID)+`; const row=[...document.querySelectorAll('#session-table tbody tr')].find(x=>x.textContent.includes(want)); return row?.querySelector('[data-revoke-session]')?.dataset.revokeSession || '';})()`, &sessionID)); err != nil || sessionID == "" {
		t.Fatalf("ordinary session not listed id=%q err=%v", sessionID, err)
	}
	expectedDialog.Store("Revoke this browser session?")
	if err := chromedp.Run(browser, chromedp.Click(`[data-revoke-session="`+sessionID+`"]`, chromedp.ByQuery), chromedp.WaitNotPresent(`[data-revoke-session="`+sessionID+`"]`), sessionListReady()); err != nil {
		t.Fatalf("session revoke UI: %v", err)
	}
	for _, node := range nodes {
		response := do(t, clientWithCookie(t, node, ordinaryCookie), http.MethodGet, node+"/account/data", nil, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked ordinary cookie accepted node=%s status=%d", node, response.StatusCode)
		}
	}
}

func createCatalogSessionUser(t *testing.T, client *http.Client, base string, headers map[string]string, email, password string) string {
	t.Helper()
	body := bytes.NewBufferString(`{"email":"` + email + `","language":"en","roles":[]}`)
	response := do(t, client, http.MethodPost, base+"/auth/v1/users", body, headers)
	var user struct {
		ID string `json:"id"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&user)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || user.ID == "" {
		t.Fatalf("ordinary fixture create status=%d id=%q err=%v", response.StatusCode, user.ID, err)
	}
	profile, _ := json.Marshal(map[string]any{"email": email, "given_name": "Catalog", "family_name": "Session", "roles": []string{}, "enabled": true, "email_verified": true, "password": password})
	response = do(t, client, http.MethodPut, base+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(profile), headers)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("ordinary fixture activation status=%d", response.StatusCode)
	}
	return user.ID
}

func deleteCatalogFixture(t *testing.T, client *http.Client, base string, headers map[string]string, attribute, scope string) {
	t.Helper()
	for _, target := range []struct{ collection, name string }{{"/auth/v1/scopes", scope}, {"/auth/v1/users/attr", attribute}} {
		response := do(t, client, http.MethodGet, base+target.collection, nil, nil)
		type row struct {
			Name  string `json:"name"`
			Scope string `json:"scope"`
		}
		var rows []row
		var data struct {
			Values []row `json:"values"`
		}
		var err error
		if target.collection == "/auth/v1/scopes" {
			err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&rows)
		} else {
			err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&data)
			rows = data.Values
		}
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("fixture lookup status=%d err=%v", response.StatusCode, err)
		}
		found := false
		for _, item := range rows {
			if item.Name == target.name || item.Scope == target.name {
				found = true
				break
			}
		}
		if !found {
			continue
		} // Missing catalog entries return 409 on DELETE; do not mutate them.
		path := target.collection + "/" + url.PathEscape(target.name)
		response = do(t, client, http.MethodDelete, base+path, nil, headers)
		response.Body.Close()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
			t.Fatalf("fixture cleanup %s status=%d", path, response.StatusCode)
		}
	}
}

func assertCatalogAttribute(t *testing.T, client *http.Client, base, name, description string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/attr", nil, nil)
	defer response.Body.Close()
	var out struct {
		Values []struct {
			Name         string          `json:"name"`
			Description  string          `json:"desc"`
			Type         string          `json:"typ"`
			Default      json.RawMessage `json:"default_value"`
			UserEditable bool            `json:"user_editable"`
		} `json:"values"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("attribute list status=%d err=%v", response.StatusCode, err)
	}
	for _, value := range out.Values {
		var defaultValue map[string]any
		if json.Unmarshal(value.Default, &defaultValue) == nil && value.Name == name && value.Description == description && value.Type == "email" && value.UserEditable && defaultValue["tier"] == "gold" && defaultValue["enabled"] == true {
			return
		}
	}
	t.Fatalf("typed editable attribute %q not persisted", name)
}

func assertCatalogScope(t *testing.T, client *http.Client, base, name, attribute string, root bool) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/scopes", nil, nil)
	defer response.Body.Close()
	var scopes []struct {
		Name   string   `json:"scope"`
		Access []string `json:"attr_include_access"`
		ID     []string `json:"attr_include_id"`
		Root   bool     `json:"claims_at_root"`
	}
	if err := json.NewDecoder(response.Body).Decode(&scopes); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("scope list status=%d err=%v", response.StatusCode, err)
	}
	for _, scope := range scopes {
		if scope.Name == name && scope.Root == root && strings.Contains(strings.Join(scope.Access, ","), attribute) && strings.Contains(strings.Join(scope.ID, ","), attribute) {
			return
		}
	}
	t.Fatalf("scope %q binding not persisted", name)
}

func catalogListReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#catalog-list"), chromedp.Poll(`document.querySelector('#catalog-status')?.textContent !== 'Loading…' && document.querySelector('#catalog-status')?.textContent?.length > 0`, nil)}
}
func sessionListReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#session-table"), chromedp.Poll(`document.querySelector('#session-status')?.textContent !== 'Loading…' && document.querySelector('#session-status')?.textContent?.length > 0`, nil)}
}
func jsonString(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }
