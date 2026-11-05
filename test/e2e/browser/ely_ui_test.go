package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
)

func elyFixture(t *testing.T) (string, string, string) {
	t.Helper()
	if os.Getenv("GOAUTHY_E2E_ELY_UI") != "1" {
		t.Skip("use scripts/e2e-ely-standalone.sh for the disposable Ely fixture")
	}
	base, secondary, username, password, _ := browserE2EConfig(t)
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || base != secondary || os.Getenv("GOAUTHY_RHIZA_PROFILE") != "standalone" || os.Getenv("GOAUTHY_ELY_E2E_SLOT") != "granted" {
		t.Fatal("Ely tests require the reserved disposable loopback standalone fixture")
	}
	return base, username, password
}

func elyLogin(t *testing.T, ctx context.Context, base, username, password string) {
	t.Helper()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base+"/account/login"),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.SendKeys(`input[name="username"]`, username),
		chromedp.SendKeys(`input[name="password"]`, password),
	); err != nil {
		t.Fatal("browser login fields unavailable")
	}
	response, err := chromedp.RunResponse(ctx, chromedp.Click(`button[type="submit"]`))
	if err != nil || response == nil || response.Status != http.StatusOK {
		t.Fatal("browser login submit did not reach a successful page")
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(base+"/account"), chromedp.WaitVisible(`#profile`)); err != nil {
		t.Fatal("browser-authenticated account unavailable")
	}
}

func elyLogout(t *testing.T, ctx context.Context, base string) {
	t.Helper()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base+"/oidc/logout"),
		chromedp.WaitReady(`input[name="confirmation"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatal("browser logout confirmation unavailable")
	}
	response, err := chromedp.RunResponse(ctx, chromedp.Click(`button[type="submit"]`))
	if err != nil || response == nil || response.Status != http.StatusOK {
		t.Fatal("browser logout submit did not reach a successful page")
	}
	var status int
	if err := chromedp.Run(ctx, chromedp.Evaluate(`fetch('/account/data').then(r => r.status)`, &status, func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) })); err != nil || status != http.StatusUnauthorized {
		t.Fatal("logged-out browser can still access account data")
	}
}

func TestElyBrowserLoginLogout(t *testing.T) {
	base, username, password := elyFixture(t)
	ctx, cancel := newCollectionUIContext(t, nil, base)
	defer cancel()
	elyLogin(t, ctx, base, username, password)
	if err := chromedp.Run(ctx, chromedp.Navigate(base+"/auth/v1/admin/dashboard"), chromedp.WaitVisible(`#overview-identity`)); err != nil {
		t.Fatal("browser-authenticated admin dashboard unavailable")
	}
	elyLogout(t, ctx, base)

	admin, csrf := rbacAuthenticatedClient(t, base, base, username, password)
	headers := rbacMutationHeaders(csrf)
	email := "ely-service-" + randomManagedUIID(t) + "@goauthy.e2e"
	const initial = "Ely-Service-Initial-1A"
	const updated = "Ely-Service-Updated-2B"
	id := createCatalogSessionUser(t, admin, base, headers, email, initial)
	t.Cleanup(func() {
		r := do(t, admin, http.MethodDelete, base+"/auth/v1/users/"+url.PathEscape(id), nil, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("service user cleanup status=%d", r.StatusCode)
		}
	})
	elyLogin(t, ctx, base, email, initial)
	if err := chromedp.Run(ctx,
		chromedp.WaitVisible(`#password-form`),
		chromedp.SendKeys(`#password-current`, initial),
		chromedp.SendKeys(`#password-new`, updated),
		chromedp.SendKeys(`#password-confirm`, updated),
		chromedp.Click(`#password-form button[type="submit"]`),
		chromedp.Poll(`document.querySelector('#password-status')?.textContent === 'Password changed. Use the new password the next time you sign in.'`, nil),
	); err != nil {
		t.Fatal("service user browser password change failed")
	}
	elyLogout(t, ctx, base)
	elyLogin(t, ctx, base, email, updated)
	elyLogout(t, ctx, base)
}

func TestElyBrandUI(t *testing.T) {
	base, username, password := elyFixture(t)
	admin, csrf := rbacAuthenticatedClient(t, base, base, username, password)
	headers := rbacMutationHeaders(csrf)
	original := readThemeJSON(t, admin, base, branding.GlobalBrandID, headers)
	if got := readClientLogo(t, newBrowserClient(t), base, branding.GlobalBrandID, ""); got.Status != http.StatusNotFound {
		t.Fatal("brand fixture must start without an existing common logo")
	}
	t.Cleanup(func() {
		body, err := json.Marshal(original)
		if err != nil {
			t.Error(err)
			return
		}
		r := do(t, admin, http.MethodPut, base+"/auth/v1/theme/"+branding.GlobalBrandID, bytes.NewReader(body), headers)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("restore brand status=%d", r.StatusCode)
		}
		r = do(t, admin, http.MethodDelete, clientLogoURL(base, branding.GlobalBrandID, ""), nil, headers)
		r.Body.Close()
	})
	ctx, cancel := newCollectionUIContext(t, nil, base)
	defer cancel()
	elyLogin(t, ctx, base, username, password)
	const name = "Ely Synthetic Identity"
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base+"/auth/v1/admin/branding"),
		chromedp.WaitVisible(`#theme-brand-name`),
		chromedp.Clear(`#theme-brand-name`), chromedp.SendKeys(`#theme-brand-name`, name),
		chromedp.Click(`#theme-save`),
		chromedp.Poll(`document.querySelector('#theme-status')?.textContent === 'Theme saved.'`, nil),
		chromedp.Reload(), chromedp.WaitVisible(`#theme-brand-name`),
		chromedp.Poll(`document.querySelector('#theme-brand-name')?.value === 'Ely Synthetic Identity'`, nil),
		chromedp.Clear(`#theme-brand-name`), chromedp.SendKeys(`#theme-brand-name`, "Discard this draft"),
		chromedp.Click(`#theme-reload`),
		chromedp.Poll(`document.querySelector('#theme-brand-name')?.value === 'Ely Synthetic Identity' && document.querySelector('#theme-status')?.textContent === 'Saved theme reloaded.'`, nil),
	); err != nil {
		t.Fatal("brand save and reload through browser controls failed")
	}
	if readThemeJSON(t, admin, base, branding.GlobalBrandID, headers).BrandName != name {
		t.Fatal("brand name was not persisted")
	}
	logo := filepath.Join(t.TempDir(), "synthetic-logo.png")
	if err := os.WriteFile(logo, clientLogoPNG(t), 0600); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx,
		chromedp.SetUploadFiles(`#theme-logo-upload`, []string{logo}),
		chromedp.Poll(`document.querySelector('#theme-logo-status')?.textContent === 'Logo saved.' && document.querySelector('#theme-logo-image')?.naturalWidth > 0`, nil),
		chromedp.Reload(), chromedp.WaitVisible(`#theme-logo-image`),
		chromedp.Poll(`document.querySelector('#theme-logo-image')?.naturalWidth > 0`, nil),
		chromedp.Click(`#theme-logo-delete`), chromedp.Click(`#theme-logo-remove-confirm`),
		chromedp.Poll(`document.querySelector('#theme-logo-status')?.textContent === 'Logo removed.'`, nil),
	); err != nil {
		t.Fatal("brand logo upload, reload, and removal through browser controls failed")
	}
	if got := readClientLogo(t, newBrowserClient(t), base, branding.GlobalBrandID, ""); got.Status != http.StatusNotFound {
		t.Fatal("removed common logo remains public")
	}
}
