package browser

import (
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
)

// TestAdminUIBrowserAcrossPods exercises the shipped UI in Chromium. It is
// opt-in because it needs a deployed admin fixture and a local Chromium.
func TestAdminUIBrowserAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_UI_BROWSER") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_UI_BROWSER=1 to run Chromium admin UI E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "admin-ui-browser")
	parsed, err := url.Parse(primary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true), chromedp.Flag("no-first-run", true))...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(alloc)
	defer cancelBrowser()
	var expectedDialog atomic.Value
	expectedDialog.Store("")
	chromedp.ListenTarget(browserCtx, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			accept := dialog.Message == expectedDialog.Load().(string) && dialog.Message != ""
			go func() { _ = chromedp.Run(browserCtx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	if err := chromedp.Run(browserCtx, chromedp.Navigate(primary)); err != nil {
		t.Fatalf("Chromium unavailable: %v", err)
	}
	if err := chromedp.Run(browserCtx, network.SetCookie(cookie.Name, cookie.Value).WithDomain(parsed.Hostname()).WithPath("/").WithSecure(parsed.Scheme == "https")); err != nil {
		t.Fatal(err)
	}
	roleName := "ui-browser-role-" + strings.ToLower(strings.ReplaceAll(username, "@", "-"))
	groupName := roleName + "-group"
	for _, tc := range []struct{ kind, name string }{{"roles", roleName}, {"groups", groupName}} {
		base := primary + "/auth/v1/admin/" + tc.kind
		if err := chromedp.Run(browserCtx, chromedp.Navigate(base), chromedp.WaitVisible("a.button"), chromedp.Click("a.button", chromedp.ByQuery), chromedp.WaitVisible("#entity"), chromedp.SendKeys("#name", tc.name), chromedp.Click("#entity button", chromedp.ByQuery), adminUIListReady()); err != nil {
			t.Fatalf("%s create UI: %v", tc.kind, err)
		}
		entity := rbacAssertListed(t, client, primary, tc.kind, rbacEntity{Name: tc.name})
		if err := chromedp.Run(browserCtx, chromedp.Navigate(base), adminUIListReady()); err != nil {
			t.Fatal(err)
		}
		var html string
		selector := `a[href="/auth/v1/admin/` + tc.kind + `/` + entity.ID + `"]`
		if err := chromedp.Run(browserCtx, chromedp.WaitVisible(selector), chromedp.OuterHTML("#table", &html)); err != nil || !strings.Contains(html, tc.name) {
			t.Fatalf("%s not persisted html=%q err=%v", tc.kind, html, err)
		}
		updated := tc.name + "-updated"
		if err := chromedp.Run(browserCtx, chromedp.Click(selector), chromedp.WaitVisible("#entity"), chromedp.SetValue("#name", updated), chromedp.Click("#entity button", chromedp.ByQuery), adminUIListReady()); err != nil {
			t.Fatalf("%s edit UI: %v", tc.kind, err)
		}
		rbacAssertListed(t, client, primary, tc.kind, rbacEntity{Name: updated})
		expectedDialog.Store("Delete this " + strings.TrimSuffix(tc.kind, "s") + " permanently?")
		if err := chromedp.Run(browserCtx, chromedp.Navigate(base), adminUIListReady(), chromedp.Click(`a[href="/auth/v1/admin/`+tc.kind+`/`+entity.ID+`"]`), chromedp.WaitVisible("#entity"), chromedp.Click("#delete", chromedp.ByQuery), adminUIListReady(), chromedp.WaitNotPresent(`a[href="/auth/v1/admin/`+tc.kind+`/`+entity.ID+`"]`)); err != nil {
			t.Fatalf("%s delete UI: %v", tc.kind, err)
		}
		rbacAssertAbsent(t, client, primary, tc.kind, updated)
	}
	userEmail := "ui-browser-user-" + strings.ToLower(strings.ReplaceAll(username, "@", "-")) + "@goauthy.e2e"
	if err := chromedp.Run(browserCtx, chromedp.Navigate(primary+"/auth/v1/admin/users"), chromedp.WaitVisible("a.button"), chromedp.Click("a.button", chromedp.ByQuery), chromedp.WaitVisible("#user"), chromedp.SendKeys("#email", userEmail), chromedp.SendKeys("#given", "Initial"), chromedp.SetValue("#language", "fr"), chromedp.SendKeys("#preferred", "ui-created-member"), chromedp.SendKeys("#timezone", "Asia/Seoul"), chromedp.SendKeys("#expiry", "4102444800"), chromedp.Click("#user button", chromedp.ByQuery), adminUIListReady()); err != nil {
		t.Fatalf("user create UI: %v", err)
	}
	userID := findAdminUser(t, client, primary, userEmail)
	selector := `a[href="/auth/v1/admin/users/` + userID + `"]`
	if err := chromedp.Run(browserCtx, chromedp.WaitVisible(selector), chromedp.Click(selector), chromedp.WaitVisible("#user"), chromedp.SetValue("#given", "Browser"), chromedp.Click("#user button", chromedp.ByQuery), adminUIListReady()); err != nil {
		t.Fatalf("user edit UI: %v", err)
	}
	response := do(t, client, http.MethodGet, primary+"/auth/v1/users/"+userID, nil, nil)
	var detail struct {
		GivenName   string `json:"given_name"`
		Language    string `json:"language"`
		UserExpires int64  `json:"user_expires"`
		UserValues  struct {
			PreferredUsername string `json:"preferred_username"`
			Timezone          string `json:"tz"`
		} `json:"user_values"`
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&detail)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || decodeErr != nil || detail.GivenName != "Browser" || detail.Language != "fr" || detail.UserExpires != 4102444800 || detail.UserValues.PreferredUsername != "ui-created-member" || detail.UserValues.Timezone != "Asia/Seoul" {
		t.Fatal("UI creation fields were lost during creation or editing")
	}
	expectedDialog.Store("Delete subject " + userID + " permanently?")
	if err := chromedp.Run(browserCtx, chromedp.Click(selector), chromedp.WaitVisible("#user"), chromedp.Click("#user-delete", chromedp.ByQuery), adminUIListReady(), chromedp.WaitNotPresent(selector)); err != nil {
		t.Fatalf("user delete UI: %v", err)
	}
	response = do(t, client, http.MethodGet, primary+"/auth/v1/users/"+userID, nil, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted user status=%d", response.StatusCode)
	}
	// A second node must accept the same issuer-bound cookie after the UI work.
	if err := chromedp.Run(browserCtx, chromedp.Navigate(secondary+"/auth/v1/admin/users"), adminUIListReady()); err != nil {
		t.Fatalf("secondary admin UI: %v", err)
	}
}

func findAdminUser(t *testing.T, client *http.Client, base, email string) string {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/auth/v1/users?page_size=65535", nil, nil)
	defer r.Body.Close()
	var users []struct{ ID, Email string }
	if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusPartialContent {
		t.Fatalf("user list status=%d", r.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&users); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		if user.Email == email {
			return user.ID
		}
	}
	t.Fatalf("created user %q not found", email)
	return ""
}

// A list container appears before its fetch finishes. Wait for populated status,
// so empty-list assertions cannot pass against a still-loading page.
func adminUIListReady() chromedp.Tasks {
	return chromedp.Tasks{chromedp.WaitVisible("#table"), chromedp.Poll(`document.querySelector("#status")?.textContent !== "Loading…" && document.querySelector("#status")?.textContent?.length > 0`, nil)}
}
