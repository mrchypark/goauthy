package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	accountbrowser "github.com/mrchypark/goauthy/internal/browser"
)

// TestAccountPasskeyUIAcrossPods exercises the ordinary user's shipped
// dashboard, including real WebAuthn ceremonies in Chromium. It is opt-in
// because it needs a deployed passkey-enabled fixture.
func TestAccountPasskeyUIAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ACCOUNT_PASSKEY_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1 to run account passkey UI E2E")
	}
	primary, secondary, adminUser, adminPassword, clientSecret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	nodes := []string{primary, secondary, tertiary}
	admin := newBrowserClient(t)
	_, adminCookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "account-passkey-ui-admin")
	csrf, err := accountbrowser.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	email := "account-passkey-ui-" + strings.ToLower(strings.ReplaceAll(adminUser, "@", "-")) + "@goauthy.e2e"
	password := "Account-Passkey-Initial-1A"
	created := do(t, admin, http.MethodPost, primary+"/auth/v1/users", bytes.NewBufferString(`{"email":"`+email+`","language":"en","roles":[]}`), adminHeaders)
	var user struct {
		ID string `json:"id"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || decodeErr != nil || user.ID == "" {
		t.Fatalf("ordinary user create status=%d id=%q err=%v", created.StatusCode, user.ID, decodeErr)
	}
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(user.ID), nil, adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("ordinary user cleanup status=%d", response.StatusCode)
		}
	})
	profile, _ := json.Marshal(map[string]any{"email": email, "given_name": "Passkey", "family_name": "Member", "roles": []string{}, "enabled": true, "email_verified": true, "password": password})
	activated := do(t, admin, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(profile), adminHeaders)
	activated.Body.Close()
	if activated.StatusCode != http.StatusOK {
		t.Fatalf("ordinary user activation status=%d", activated.StatusCode)
	}

	ordinary := newBrowserClient(t)
	_, _ = loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), email, password, "account-passkey-ui-user")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	auth := newAccountPasskeyAuthenticator(t, ctx)
	var dialogReply atomic.Value
	dialogReply.Store("")
	chromedp.ListenTarget(auth.ctx, func(ev interface{}) {
		if dialog, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			want := dialogReply.Load().(string)
			accept := want != "" && dialog.Message == want
			go func() { _ = chromedp.Run(auth.ctx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	setPasskeyBrowserCookies(t, auth.ctx, primary, ordinary.Jar.Cookies(mustE2EURL(t, primary+"/account/")))

	if err := chromedp.Run(auth.ctx, chromedp.Navigate(primary+"/account"), chromedp.WaitVisible(`#passkeys-section`), chromedp.Poll(`!document.querySelector('#passkeys-section')?.hidden && document.querySelector('#passkeys-list')?.textContent?.includes('No passkeys registered.') && !document.querySelector('#passkey-add')?.disabled`, nil)); err != nil {
		t.Fatalf("account passkey controls: %v", err)
	}
	dialogReply.Store("Enter your current password to authorize this change:")
	addPasskeyUI(t, auth.ctx, "First UI key", password, "Passkey added.")
	assertPasskeyNames(t, ordinary, nodes, user.ID, []string{"First UI key"})
	credentials := auth.credentials(t)
	if len(credentials) != 1 {
		t.Fatalf("virtual authenticator credentials after first registration=%d, want 1", len(credentials))
	}

	dialogReply.Store("")
	addPasskeyUI(t, auth.ctx, "Second UI key", "", "Passkey added.")
	assertPasskeyNames(t, ordinary, nodes, user.ID, []string{"First UI key", "Second UI key"})
	credentials = auth.credentials(t)
	if len(credentials) != 2 {
		t.Fatalf("virtual authenticator credentials after second registration=%d, want 2", len(credentials))
	}

	// The empty-name path is a real UI validation/error result, without creating
	// a ceremony or mutating server state.
	if err := chromedp.Run(auth.ctx, chromedp.Poll(`document.querySelector('#passkey-name')?.value === '' && !document.querySelector('#passkey-add')?.disabled`, nil), chromedp.Click(`#passkey-add`), chromedp.Poll(`document.querySelector('#passkey-status')?.textContent === 'Enter a name for this passkey.'`, nil)); err != nil {
		t.Fatalf("passkey validation path: %v", err)
	}
	dialogReply.Store("Remove passkey “First UI key”?")
	deletePasskeyUI(t, auth.ctx, "First UI key")
	assertPasskeyNames(t, ordinary, nodes, user.ID, []string{"Second UI key"})
	if err := chromedp.Run(auth.ctx, chromedp.Navigate(secondary+"/account"), chromedp.WaitVisible(`#passkeys-list`), chromedp.Poll(`document.querySelector('#passkeys-list')?.textContent?.includes('Second UI key') && !document.querySelector('#passkeys-list')?.textContent?.includes('First UI key')`, nil)); err != nil {
		t.Fatalf("secondary account passkey list: %v", err)
	}

	if os.Getenv("GOAUTHY_E2E_DEVICE_LOGIN_FLOW") == "1" {
		checkPasskeyDeviceApproval(t, auth.ctx, primary, secondary, email, clientSecret)
	}
}

// Reuse the credential registered through the account UI, but remove all browser
// sessions so the approval entry must complete its own real WebAuthn ceremony.
func checkPasskeyDeviceApproval(t *testing.T, ctx context.Context, primary, secondary, username, secret string) {
	t.Helper()
	client := newBrowserClient(t)
	grant := startDeviceAuthorizationOffline(t, client, primary, "goauthy-dev", secret)
	var reviewedCode string
	if err := chromedp.Run(ctx,
		network.ClearBrowserCookies(),
		chromedp.Navigate(grant.VerificationURIComplete),
		chromedp.WaitVisible(`#passkey-btn`),
		chromedp.SetValue(`input[name="username"]`, username),
		chromedp.Click(`#passkey-btn`),
		chromedp.WaitVisible(`button[name="action"][value="approve"]`),
		chromedp.Value(`input[name="user_code"]`, &reviewedCode),
	); err != nil {
		t.Fatalf("cold Device passkey login: %v", err)
	}
	if reviewedCode != grant.UserCode {
		t.Fatal("passkey login changed the Device approval target")
	}
	assertDeviceTokenError(t, client, secondary, secret, grant.DeviceCode, "authorization_pending")
	// RFC 8628 requires the returned polling interval even after user approval.
	nextPoll := time.NewTimer(time.Duration(grant.Interval+1) * time.Second)
	defer nextPoll.Stop()
	if err := chromedp.Run(ctx,
		chromedp.Click(`button[name="action"][value="approve"]`),
		chromedp.WaitVisible(`body`),
		chromedp.Poll(`document.body.textContent.includes('Device approved')`, nil),
	); err != nil {
		t.Fatalf("explicit Device approval: %v", err)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-nextPoll.C:
	}
	tokens := deviceToken(t, client, secondary, secret, grant.DeviceCode)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("passkey-approved Device did not issue tokens")
	}
	assertDeviceTokenError(t, client, secondary, secret, grant.DeviceCode, "expired_token")
}

func requiredE2EURL(t *testing.T, name string) string {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		t.Fatalf("missing %s", name)
	}
	return raw
}

func mustE2EURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type accountPasskeyAuthenticator struct {
	ctx context.Context
	id  cdpwebauthn.AuthenticatorID
}

func newAccountPasskeyAuthenticator(t *testing.T, parent context.Context) *accountPasskeyAuthenticator {
	t.Helper()
	alloc, cancelAlloc := chromedp.NewExecAllocator(parent, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true), chromedp.Flag("no-first-run", true))...)
	ctx, cancel := chromedp.NewContext(alloc)
	a := &accountPasskeyAuthenticator{ctx: ctx}
	t.Cleanup(func() { cancel(); cancelAlloc() })
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		if _, _, _, _, _, err := cdpbrowser.GetVersion().Do(c); err != nil {
			return err
		}
		if err := cdpwebauthn.Enable().Do(c); err != nil {
			return err
		}
		var err error
		a.id, err = cdpwebauthn.AddVirtualAuthenticator(&cdpwebauthn.VirtualAuthenticatorOptions{Protocol: cdpwebauthn.AuthenticatorProtocolCtap2, Ctap2version: cdpwebauthn.Ctap2versionCtap21, Transport: cdpwebauthn.AuthenticatorTransportInternal, HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true}).Do(c)
		return err
	})); err != nil {
		t.Fatalf("Chrome virtual authenticator: %v", err)
	}
	return a
}

func (a *accountPasskeyAuthenticator) credentials(t *testing.T) []*cdpwebauthn.Credential {
	t.Helper()
	var got []*cdpwebauthn.Credential
	if err := chromedp.Run(a.ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		got, err = cdpwebauthn.GetCredentials(a.id).Do(c)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	return got
}

func setPasskeyBrowserCookies(t *testing.T, ctx context.Context, base string, cookies []*http.Cookie) {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(base)); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range cookies {
		c := cookie
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(x context.Context) error {
			return network.SetCookie(c.Name, c.Value).WithURL(base + c.Path).WithHTTPOnly(c.HttpOnly).WithSecure(c.Secure).Do(x)
		})); err != nil {
			t.Fatal(err)
		}
	}
}

func addPasskeyUI(t *testing.T, ctx context.Context, name, password, status string) {
	t.Helper()
	actions := chromedp.Tasks{chromedp.SetValue(`#passkey-name`, name)}
	if password != "" {
		actions = append(actions, chromedp.SetValue(`#passkey-current-password`, password))
	}
	actions = append(actions, chromedp.Click(`#passkey-add`), chromedp.Poll(`document.querySelector('#passkey-status')?.textContent === '`+status+`' && !document.querySelector('#passkey-add')?.disabled && document.querySelector('#passkey-name')?.value === ''`, nil))
	if err := chromedp.Run(ctx, actions); err != nil {
		t.Fatalf("add passkey %q: %v", name, err)
	}
}

func deletePasskeyUI(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	selector := `button[data-passkey-delete="` + name + `"]`
	var result string
	if err := chromedp.Run(ctx, chromedp.Click(selector), chromedp.Poll(`document.querySelector('#passkey-status')?.textContent === 'Passkey removed.' || document.querySelector('#passkey-status')?.classList.contains('error')`, nil), chromedp.TextContent(`#passkey-status`, &result)); err != nil {
		t.Fatalf("delete passkey %q: %v", name, err)
	}
	if result != "Passkey removed." {
		t.Fatalf("delete passkey %q result: %s", name, result)
	}
	if err := chromedp.Run(ctx, chromedp.WaitNotPresent(selector)); err != nil {
		t.Fatal(err)
	}
}

func assertPasskeyNames(t *testing.T, client *http.Client, nodes []string, subject string, want []string) {
	t.Helper()
	for _, base := range nodes {
		response := do(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		var rows []struct {
			Name string `json:"name"`
		}
		err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&rows)
		response.Body.Close()
		got := make([]string, 0, len(rows))
		for _, row := range rows {
			got = append(got, row.Name)
		}
		if response.StatusCode != http.StatusOK || err != nil || !slices.Equal(got, want) {
			t.Fatalf("passkey list node=%s status=%d names=%v want=%v err=%v", base, response.StatusCode, got, want, err)
		}
	}
}
