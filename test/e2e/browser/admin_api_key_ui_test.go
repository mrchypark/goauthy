package browser

import (
	"context"
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

// TestAdminAPIKeyUIAcrossPods covers the one-time secret lifecycle through the
// shipped admin UI, then verifies the resulting credential on every configured node.
func TestAdminAPIKeyUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_API_KEY_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_API_KEY_UI=1 to run Chromium API-key UI E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "admin-api-key-ui")

	parsed, err := url.Parse(primary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless, chromedp.NoFirstRun)...)
	defer cancelAlloc()
	browser, cancelBrowser := chromedp.NewContext(alloc)
	defer cancelBrowser()

	var dialogExpected, dialogPrompt atomic.Value
	dialogExpected.Store("")
	dialogPrompt.Store("")
	chromedp.ListenTarget(browser, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			want := dialogExpected.Load().(string)
			accept := want != "" && dialog.Message == want
			action := page.HandleJavaScriptDialog(accept)
			if dialog.Type == page.DialogTypePrompt && accept {
				action = action.WithPromptText(dialogPrompt.Load().(string))
			}
			go func() { _ = chromedp.Run(browser, action) }()
		}
	})

	if err := chromedp.Run(browser,
		network.SetCookie(cookie.Name, cookie.Value).WithDomain(parsed.Hostname()).WithPath("/").WithSecure(parsed.Scheme == "https"),
		chromedp.Navigate(primary+"/auth/v1/admin/api-keys"),
		apiKeyUIListReady(),
	); err != nil {
		t.Fatalf("API-key admin UI unavailable: %v", err)
	}

	name := "fixedtestkey"
	dialogExpected.Store("API key name")
	dialogPrompt.Store(name)
	if err := chromedp.Run(browser,
		chromedp.Click("#new-key"),
		chromedp.WaitVisible("#key-form"),
		chromedp.SetValue("#key-name", name),
		chromedp.Click(`[data-group="Events"][data-right="read"]`),
		// The credential self-test endpoint also requires ApiKeys:read.
		chromedp.Click(`[data-group="ApiKeys"][data-right="read"]`),
		chromedp.Click("#key-form button", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector('#result')?.textContent?.startsWith('Secret (copy now): ')`, nil),
	); err != nil {
		t.Fatalf("create API key UI: %v", err)
	}
	var secretText string
	if err := chromedp.Run(browser, chromedp.TextContent("#result", &secretText)); err != nil {
		t.Fatalf("read one-time API-key secret: %v", err)
	}
	secret := strings.TrimPrefix(secretText, "Secret (copy now): ")
	if secret == "" || !strings.HasPrefix(secret, name+"$") {
		t.Fatalf("API-key UI returned an invalid secret")
	}
	apiKeyTestAcrossNodes(t, nodes, name, secret, http.StatusOK, "created key")
	apiKeyStatusAcrossNodes(t, nodes, http.MethodGet, "/auth/v1/events", secret, http.StatusOK, "Events read before edit")

	if err := chromedp.Run(browser,
		chromedp.Navigate(primary+"/auth/v1/admin/api-keys"),
		apiKeyUIListReady(),
		chromedp.Click(`[data-edit-key="`+name+`"]`, chromedp.ByQuery),
		chromedp.WaitVisible("#key-form"),
		chromedp.Click(`[data-group="Events"][data-right="read"]`),
		chromedp.Click(`[data-group="Clients"][data-right="read"]`),
		chromedp.Click("#key-form button", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector('#result')?.textContent === 'Saved'`, nil),
	); err != nil {
		t.Fatalf("edit API-key rights UI: %v", err)
	}
	apiKeyStatusAcrossNodes(t, nodes, http.MethodGet, "/auth/v1/events", secret, http.StatusForbidden, "Events read after edit")
	apiKeyStatusAcrossNodes(t, nodes, http.MethodGet, "/auth/v1/clients/goauthy-dev/scopes", secret, http.StatusOK, "Clients read after edit")

	if err := chromedp.Run(browser, chromedp.Navigate(primary+"/auth/v1/admin/api-keys"), apiKeyUIListReady()); err != nil {
		t.Fatalf("reload API-key admin UI: %v", err)
	}
	rotateSelector := `[data-rotate="` + name + `"]`
	if err := chromedp.Run(browser,
		chromedp.Click(rotateSelector, chromedp.ByQuery),
		chromedp.Poll(`document.querySelector('#secret')?.textContent?.startsWith('Rotated secret (copy now): ')`, nil),
	); err != nil {
		t.Fatalf("rotate API key UI: %v", err)
	}
	if err := chromedp.Run(browser, chromedp.TextContent("#secret", &secretText)); err != nil {
		t.Fatalf("read rotated API-key secret: %v", err)
	}
	rotated := strings.TrimPrefix(secretText, "Rotated secret (copy now): ")
	if rotated == "" || rotated == secret || !strings.HasPrefix(rotated, name+"$") {
		t.Fatalf("API-key UI returned an invalid rotated secret")
	}
	apiKeyTestAcrossNodes(t, nodes, name, secret, http.StatusUnauthorized, "old key after rotate")
	apiKeyTestAcrossNodes(t, nodes, name, rotated, http.StatusOK, "rotated key")

	dialogExpected.Store("Delete API key permanently?")
	removeSelector := `[data-remove="` + name + `"]`
	if err := chromedp.Run(browser,
		chromedp.Click(removeSelector, chromedp.ByQuery),
		chromedp.WaitNotPresent(removeSelector),
		apiKeyUIListReady(),
	); err != nil {
		t.Fatalf("delete API key UI: %v", err)
	}
	apiKeyTestAcrossNodes(t, nodes, name, rotated, http.StatusUnauthorized, "deleted key")
}

func apiKeyUIListReady() chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.WaitVisible("#table"),
		chromedp.Poll(`document.querySelector('#status')?.textContent !== 'Loading…' && document.querySelector('#status')?.textContent?.length > 0`, nil),
	}
}

func apiKeyTestAcrossNodes(t *testing.T, nodes []string, name, secret string, want int, label string) {
	t.Helper()
	for _, base := range nodes {
		apiKeyStatus(t, newBrowserClient(t), http.MethodGet, base+"/auth/v1/api_keys/"+url.PathEscape(name)+"/test", nil, map[string]string{"Authorization": "API-Key " + secret}, want, label+" node="+base)
	}
}

func apiKeyStatusAcrossNodes(t *testing.T, nodes []string, method, path, secret string, want int, label string) {
	t.Helper()
	for _, base := range nodes {
		apiKeyStatus(t, newBrowserClient(t), method, base+path, nil, map[string]string{"Authorization": "API-Key " + secret}, want, label+" node="+base)
	}
}
