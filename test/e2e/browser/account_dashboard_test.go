package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/browser"
)

// TestAccountDashboardAcrossPods is an opt-in Chromium gate for the ordinary
// user's account surface. It deliberately uses a unique user and never
// changes the configured bootstrap administrator password.
func TestAccountDashboardAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ACCOUNT_DASHBOARD") != "1" {
		t.Skip("set GOAUTHY_E2E_ACCOUNT_DASHBOARD=1 to run account dashboard E2E")
	}
	primary, secondary, adminUser, adminPassword, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, adminCookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "account-dashboard-admin")
	csrf, err := browser.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	attribute := userAttributeCreate(t, client, primary, csrf, userAttributeConfig{Name: "dashboard_detail", UserEditable: true})
	t.Cleanup(func() { userAttributeDelete(t, client, primary, csrf, attribute.Name) })
	email := "account-dashboard-" + strings.ToLower(strings.ReplaceAll(adminUser, "@", "-")) + "@goauthy.e2e"
	password := "Account-Dashboard-Initial-1A"
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewBufferString(`{"email":"`+email+`","language":"en","roles":[]}`), adminHeaders)
	var user struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || err != nil || user.ID == "" {
		t.Fatalf("ordinary user create status=%d id=%q err=%v", created.StatusCode, user.ID, err)
	}
	t.Cleanup(func() {
		response := do(t, client, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(user.ID), nil, adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("ordinary user cleanup status=%d", response.StatusCode)
		}
	})
	profile := map[string]any{"email": email, "given_name": "Dashboard", "family_name": "Member", "roles": []string{}, "enabled": true, "email_verified": true, "password": password}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	updated := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(body), adminHeaders)
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("ordinary user activation status=%d", updated.StatusCode)
	}

	anonymous := newBrowserClient(t)
	for _, path := range []string{"/account", "/account/data"} {
		response := do(t, anonymous, http.MethodGet, primary+path, nil, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous %s status=%d, want 401", path, response.StatusCode)
		}
	}
	bearer := do(t, anonymous, http.MethodGet, primary+"/account/data", nil, map[string]string{"Authorization": "Bearer not-a-browser-session"})
	bearer.Body.Close()
	if bearer.StatusCode != http.StatusUnauthorized {
		t.Fatalf("authorization-header fallback status=%d, want 401", bearer.StatusCode)
	}

	ordinary := newBrowserClient(t)
	_, cookie := loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), email, password, "account-dashboard-user")
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		if err := assertDashboardData(t, ordinary, node, email, "Dashboard", "Member"); err != nil {
			t.Fatal(err)
		}
	}
	// A valid browser session must not be replaced by an Authorization header.
	// This proves the route does not silently fall back to bearer credentials.
	fallback := do(t, ordinary, http.MethodGet, primary+"/account/data", nil, map[string]string{"Authorization": "Bearer not-a-browser-session"})
	fallback.Body.Close()
	if fallback.StatusCode != http.StatusUnauthorized {
		t.Fatalf("valid cookie with bearer header status=%d, want 401", fallback.StatusCode)
	}

	parsed, err := url.Parse(primary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true), chromedp.Flag("no-first-run", true))...)
	defer cancelAlloc()
	pageCtx, cancelPage := chromedp.NewContext(alloc)
	defer cancelPage()
	if err := chromedp.Run(pageCtx,
		chromedp.Navigate(primary),
		network.SetCookie(cookie.Name, cookie.Value).WithDomain(parsed.Hostname()).WithPath("/").WithSecure(parsed.Scheme == "https"),
		chromedp.Navigate(primary+"/account"), chromedp.WaitVisible("#profile"),
		chromedp.Poll(`document.querySelector('#profile')?.textContent?.includes('Dashboard Member') && document.querySelector('#profile')?.textContent?.includes('`+email+`')`, nil),
	); err != nil {
		t.Fatalf("dashboard Chromium profile: %v", err)
	}
	if err := chromedp.Run(pageCtx, chromedp.Navigate(secondary+"/account"), chromedp.WaitVisible("#profile"), chromedp.Poll(`document.querySelector('#profile')?.textContent?.includes('Dashboard Member')`, nil)); err != nil {
		t.Fatalf("secondary dashboard profile: %v", err)
	}
	if err := chromedp.Run(pageCtx,
		chromedp.Navigate(primary+"/account"), chromedp.WaitVisible(`#username-form`),
		chromedp.Poll(`document.querySelector('#profile')?.textContent?.includes('Dashboard Member')`, nil),
		chromedp.SetValue(`#preferred-username`, "dashboard-member"), chromedp.Click(`#username-form button[type="submit"]`),
		chromedp.Poll(`document.querySelector('#username-status')?.textContent === 'Username saved.'`, nil),
	); err != nil {
		t.Fatalf("preferred username form: %v", err)
	}
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		assertPreferredUsername(t, ordinary, node, "dashboard-member")
	}
	if err := chromedp.Run(pageCtx,
		chromedp.WaitVisible(`#attribute-dashboard_detail`),
		chromedp.SetValue(`#attribute-dashboard_detail`, "Seoul"),
		chromedp.Click(`#attributes-form button[type="submit"]`),
		chromedp.Poll(`document.querySelector('#attributes-status')?.textContent === 'Details saved.'`, nil),
	); err != nil {
		t.Fatalf("editable attribute form: %v", err)
	}
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		userAttributeAssertEditable(t, ordinary, node, user.ID, []userAttributeConfig{editableAttribute(attribute, json.RawMessage(`"Seoul"`))}, "dashboard edit")
	}

	// The shipped password form is exercised through its real controls. A
	// successful self-change intentionally preserves the current session.
	if err := chromedp.Run(pageCtx, chromedp.Navigate(primary+"/account"), chromedp.WaitVisible(`#password-form`), chromedp.Poll(`document.querySelector('#profile')?.textContent?.includes('Dashboard Member')`, nil), chromedp.SetValue(`#password-current`, password), chromedp.SetValue(`#password-new`, "Account-Dashboard-Updated-2B"), chromedp.SetValue(`#password-confirm`, "Account-Dashboard-Updated-2B"), chromedp.Click(`#password-form button[type="submit"]`), chromedp.Poll(`document.querySelector('#password-status')?.textContent === 'Password changed. Use the new password the next time you sign in.'`, nil)); err != nil {
		t.Fatalf("password form: %v", err)
	}
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		if err := assertDashboardData(t, ordinary, node, email, "Dashboard", "Member"); err != nil {
			t.Fatalf("session after password mutation on %s: %v", node, err)
		}
	}
	assertPasswordLogin(t, primary, secondary, email, "dashboard-old-password", password, http.StatusUnauthorized)
	assertPasswordLogin(t, primary, secondary, email, "dashboard-new-password", "Account-Dashboard-Updated-2B", http.StatusFound)
}

func assertPreferredUsername(t *testing.T, client *http.Client, base, want string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/account/data", nil, nil)
	defer response.Body.Close()
	var data struct {
		Preferred string `json:"preferred_username"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&data); err != nil || response.StatusCode != http.StatusOK || data.Preferred != want {
		t.Fatalf("preferred username status=%d value=%q err=%v", response.StatusCode, data.Preferred, err)
	}
}

func assertDashboardData(t *testing.T, client *http.Client, base, email, given, family string) error {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/account/data", nil, nil)
	defer response.Body.Close()
	var data struct {
		Email      string `json:"email"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&data); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || data.Email != email || data.GivenName != given || data.FamilyName != family {
		return fmt.Errorf("dashboard data status=%d data=%+v", response.StatusCode, data)
	}
	return nil
}
