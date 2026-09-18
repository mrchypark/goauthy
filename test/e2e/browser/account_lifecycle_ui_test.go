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

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	accountbrowser "github.com/mrchypark/goauthy/internal/browser"
)

// TestAccountLifecycleUIAcrossPods covers the destructive ordinary-account
// lifecycle. It runs only against an explicitly enabled deployed fixture.
func TestAccountLifecycleUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ACCOUNT_LIFECYCLE_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ACCOUNT_LIFECYCLE_UI=1 to run account lifecycle UI E2E")
	}
	primary, secondary, adminUser, adminPassword, _ := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	nodes := []string{primary, secondary, tertiary}
	admin := newBrowserClient(t)
	_, adminCookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "account-lifecycle-admin")
	csrf, err := accountbrowser.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	email, password := "account-lifecycle-"+strings.ToLower(strings.ReplaceAll(adminUser, "@", "-"))+"@goauthy.e2e", "Account-Lifecycle-Initial-1A"
	deleted := false
	created := do(t, admin, http.MethodPost, primary+"/auth/v1/users", bytes.NewBufferString(`{"email":"`+email+`","language":"en","roles":[]}`), headers)
	var user struct {
		ID string `json:"id"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || decodeErr != nil || user.ID == "" {
		t.Fatalf("create status=%d id=%q err=%v", created.StatusCode, user.ID, decodeErr)
	}
	t.Cleanup(func() {
		if deleted {
			return
		}
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(user.ID), nil, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("lifecycle cleanup status=%d", r.StatusCode)
		}
	})
	profile, _ := json.Marshal(map[string]any{"email": email, "given_name": "Lifecycle", "family_name": "Member", "roles": []string{}, "enabled": true, "email_verified": true, "password": password})
	activated := do(t, admin, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(profile), headers)
	activated.Body.Close()
	if activated.StatusCode != http.StatusOK {
		t.Fatalf("activation status=%d", activated.StatusCode)
	}

	ordinary := newBrowserClient(t)
	_, _ = loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), email, password, "account-lifecycle-user")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	auth := newAccountPasskeyAuthenticator(t, ctx)
	var dialog atomic.Value
	dialog.Store("")
	chromedp.ListenTarget(auth.ctx, func(ev interface{}) {
		if d, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			accept := d.Message == dialog.Load().(string)
			go func() { _ = chromedp.Run(auth.ctx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	setPasskeyBrowserCookies(t, auth.ctx, primary, ordinary.Jar.Cookies(mustE2EURL(t, primary+"/account/")))
	if err := chromedp.Run(auth.ctx, chromedp.Navigate(primary+"/account"), chromedp.WaitVisible(`#passkey-add`), chromedp.Poll(`document.querySelector('#passkeys-list')?.textContent?.includes('No passkeys registered.')`, nil)); err != nil {
		t.Fatalf("dashboard load: %v", err)
	}
	if err := chromedp.Run(auth.ctx, chromedp.Poll(`document.querySelector('#passwordless-convert')?.disabled === true`, nil)); err != nil {
		t.Fatalf("password session conversion button enabled: %v", err)
	}
	addPasskeyUI(t, auth.ctx, "Lifecycle key", password, "Passkey added.")
	assertPasskeyNames(t, ordinary, nodes, user.ID, []string{"Lifecycle key"})
	// A UV registration atomically promotes this password session to MFA.
	assertAccountConversionAvailable(t, ordinary, primary, user.ID)
	if err := chromedp.Run(auth.ctx, chromedp.Poll(`document.querySelector('#passwordless-convert')?.disabled === false`, nil)); err != nil {
		var diagnostic string
		_ = chromedp.Run(auth.ctx, chromedp.Evaluate(`JSON.stringify({path:location.pathname,features:globalThis.accountDashboard?.state.account?.features,keys:globalThis.accountDashboard?.state.passkeys?.length,loaded:globalThis.accountDashboard?.state.passkeysLoaded,busy:globalThis.accountDashboard?.state.passkeyBusy,status:document.querySelector('#passkey-status')?.textContent})`, &diagnostic))
		t.Logf("MFA control state: %s", diagnostic)
		t.Fatalf("MFA account controls: %v", err)
	}

	// Conversion and restoration are real dashboard mutations; the page keeps
	// the existing browser session while each WebAuthn proof is completed.
	dialog.Store("Turn off password sign-in for this account?")
	if err := chromedp.Run(auth.ctx, chromedp.Click(`#passwordless-convert`), chromedp.Poll(`document.querySelector('#passwordless-status')?.textContent === 'Password sign-in disabled.'`, nil)); err != nil {
		t.Fatalf("passwordless conversion: %v", err)
	}
	assertPasswordLogin(t, primary, secondary, email, "old-password-after-convert", password, http.StatusUnauthorized)
	for _, node := range nodes {
		assertAccountFeatures(t, ordinary, node, user.ID, false)
	}
	if err := chromedp.Run(auth.ctx, chromedp.WaitVisible(`#password-restore-form`), chromedp.SetValue(`#password-restore-new`, "Account-Lifecycle-Restored-2B"), chromedp.SetValue(`#password-restore-confirm`, "Account-Lifecycle-Restored-2B"), chromedp.Click(`#password-restore-submit`), chromedp.Poll(`document.querySelector('#password-restore-status')?.textContent === 'Password sign-in restored.'`, nil)); err != nil {
		t.Fatalf("password restore: %v", err)
	}
	assertPasswordLogin(t, primary, secondary, email, "restored-password", "Account-Lifecycle-Restored-2B", http.StatusFound)
	for _, node := range nodes {
		assertAccountFeatures(t, ordinary, node, user.ID, true)
	}

	dialog.Store("Delete your account permanently?")
	if err := chromedp.Run(auth.ctx, chromedp.SetValue(`#self-delete-confirm`, email), chromedp.Click(`#self-delete-button`), chromedp.Poll(`document.querySelector('#account-deleted') != null`, nil)); err != nil {
		t.Fatalf("self delete: %v", err)
	}
	deleted = true
	for _, node := range nodes {
		r := do(t, ordinary, http.MethodGet, node+"/account/data", nil, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("deleted account data node=%s status=%d", node, r.StatusCode)
		}
	}
	assertPasswordLogin(t, primary, secondary, email, "deleted-account", "Account-Lifecycle-Restored-2B", http.StatusUnauthorized)
}

func assertAccountFeatures(t *testing.T, client *http.Client, base, subject string, password bool) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/account/data", nil, nil)
	defer r.Body.Close()
	var data struct {
		Subject  string `json:"subject"`
		Features struct {
			Password bool `json:"password"`
		} `json:"features"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&data)
	if r.StatusCode != http.StatusOK || err != nil || data.Subject != subject || data.Features.Password != password {
		t.Fatalf("account features node=%s status=%d subject=%q password=%t err=%v", base, r.StatusCode, data.Subject, data.Features.Password, err)
	}
}

func assertAccountConversionAvailable(t *testing.T, client *http.Client, base, subject string) {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/account/data", nil, nil)
	defer r.Body.Close()
	var data struct {
		Subject  string `json:"subject"`
		Features struct {
			Conversion bool `json:"passkey_conversion"`
		} `json:"features"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&data); err != nil || r.StatusCode != http.StatusOK || data.Subject != subject || !data.Features.Conversion {
		t.Fatalf("passkey conversion unavailable status=%d subject=%q enabled=%t err=%v", r.StatusCode, data.Subject, data.Features.Conversion, err)
	}
}
