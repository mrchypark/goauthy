package browser

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestDeviceSessionsUI exercises the ordinary account's authorized-device
// screen with two public-device client families. It is opt-in because it
// requires the deployed Chromium fixture and a separate approval node.
func TestDeviceSessionsUI(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_SESSIONS_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_SESSIONS_UI=1 to run authorized-device UI E2E")
	}
	primary, secondary, adminUser, adminPassword, bootstrapSecret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	admin := newBrowserClient(t)
	_, adminCookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "device-sessions-ui-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	clientA := createDeviceSessionsUIClient(t, admin, primary, headers, "family-a")
	clientB := createDeviceSessionsUIClient(t, admin, primary, headers, "family-b")
	for _, id := range []string{clientA, clientB} {
		id := id
		t.Cleanup(func() { deleteDeviceSessionsUIClient(t, admin, primary, headers, id) })
	}
	userEmail, userPassword := "device-sessions-ui-"+randomManagedUIID(t)+"@goauthy.e2e", "Device-Sessions-UI-Initial-2B"
	userID := createCatalogSessionUser(t, admin, primary, headers, userEmail, userPassword)
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(userID), nil, headers)
		response.Body.Close()
	})
	ordinary := newBrowserClient(t)
	_, ordinaryCookie := loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), userEmail, userPassword, "device-sessions-ui-user")
	asset := do(t, ordinary, http.MethodGet, primary+"/account/devices.js", nil, nil)
	assetBody, assetErr := io.ReadAll(io.LimitReader(asset.Body, 64<<10))
	asset.Body.Close()
	if asset.StatusCode != http.StatusOK || assetErr != nil || !strings.Contains(string(assetBody), "loadDevices") {
		t.Fatalf("device UI asset status=%d err=%v", asset.StatusCode, assetErr)
	}
	grantA := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientA, "goauthy.read offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), grantA, primary, tertiary, userEmail, userPassword)
	tokenA := publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grantA.DeviceCode}, "client_id": {clientA}})
	grantB := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientB, "goauthy.read offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), grantB, primary, tertiary, userEmail, userPassword)
	tokenB := publicDeviceToken(t, newBrowserClient(t), tertiary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grantB.DeviceCode}, "client_id": {clientB}})
	devices := readDeviceSessionsUIDevices(t, ordinary, primary)
	if len(devices) != 2 {
		t.Fatalf("ordinary account devices=%d, want 2: %#v", len(devices), devices)
	}
	var first deviceSessionsUIDevice
	for _, device := range devices {
		if device.ClientID == clientA {
			first = device
		}
	}
	if first.ID == "" {
		t.Fatalf("device for client family %s missing: %#v", clientA, devices)
	}

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
	var expectedDialog atomic.Value
	expectedDialog.Store("")
	chromedp.ListenTarget(browser, func(event interface{}) {
		if dialog, ok := event.(*page.EventJavascriptDialogOpening); ok {
			accept := dialog.Message == expectedDialog.Load().(string) && dialog.Message != ""
			go func() { _ = chromedp.Run(browser, page.HandleJavaScriptDialog(accept)) }()
		}
	})
	if err := chromedp.Run(browser,
		network.SetCookie(ordinaryCookie.Name, ordinaryCookie.Value).WithDomain(parsed.Hostname()).WithPath("/").WithSecure(parsed.Scheme == "https"),
		chromedp.Navigate(primary+"/account"),
		chromedp.WaitVisible("#devices-section"),
		chromedp.Poll(`document.querySelectorAll('#devices-list [data-device-delete]').length === 2`, nil),
	); err != nil {
		t.Fatalf("authorized device UI unavailable: %v", err)
	}
	// Dismissing the exact confirmation must leave both active families intact.
	if err := chromedp.Run(browser,
		chromedp.Evaluate(`document.querySelector('[data-device-delete]').click()`, nil),
		chromedp.Poll(`document.querySelectorAll('#devices-list [data-device-delete]').length === 2`, nil),
	); err != nil {
		t.Fatalf("cancel device revoke UI: %v", err)
	}
	var cancelDOM string
	if err := chromedp.Run(browser, chromedp.OuterHTML("#devices-list", &cancelDOM)); err != nil || !strings.Contains(cancelDOM, clientA) || !strings.Contains(cancelDOM, clientB) {
		t.Fatalf("cancelled revoke DOM missing client families: err=%v html=%q", err, cancelDOM)
	}
	assertSessionIntrospection(t, primary, bootstrapSecret, tokenA.AccessToken, true)
	assertSessionIntrospection(t, primary, bootstrapSecret, tokenB.AccessToken, true)

	expectedDialog.Store(fmt.Sprintf("Revoke device %s for client %s?", first.ID, first.ClientID))
	selector := `[data-device-delete="` + strings.ReplaceAll(strings.ReplaceAll(first.ID, `\`, `\\`), `"`, `\"`) + `"]`
	if err := chromedp.Run(browser,
		chromedp.Click(selector, chromedp.ByQuery),
		chromedp.Poll(`document.querySelectorAll('#devices-list [data-device-delete]').length === 1 && document.querySelector('#devices-status')?.textContent === 'Device revoked.'`, nil),
	); err != nil {
		t.Fatalf("confirm device revoke UI: %v", err)
	}
	var confirmedDOM string
	if err := chromedp.Run(browser, chromedp.OuterHTML("#devices-list", &confirmedDOM)); err != nil || strings.Contains(confirmedDOM, `data-device-delete="`+first.ID+`"`) || !strings.Contains(confirmedDOM, clientB) {
		t.Fatalf("confirmed revoke DOM did not retain only other active family: err=%v html=%q", err, confirmedDOM)
	}
	remaining := readDeviceSessionsUIDevices(t, ordinary, primary)
	if len(remaining) != 2 { // revoked rows remain auditable; only one remains active.
		t.Fatalf("device rows disappeared after revoke: %#v", remaining)
	}
	active := 0
	for _, device := range remaining {
		if device.RevokedAt == nil {
			active++
		}
	}
	if active != 1 || remaining[0].ClientID == "" || remaining[1].ClientID == "" {
		t.Fatalf("device families after revoke=%#v active=%d", remaining, active)
	}
	assertSessionIntrospection(t, primary, bootstrapSecret, tokenA.AccessToken, false)
	assertSessionRefreshRejected(t, newBrowserClient(t), primary, clientA, tokenA.RefreshToken)
	assertSessionIntrospection(t, secondary, bootstrapSecret, tokenB.AccessToken, true)
}

type deviceSessionsUIDevice struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	RevokedAt *int64 `json:"revoked_at_unix_ms"`
}

func createDeviceSessionsUIClient(t *testing.T, client *http.Client, base string, headers map[string]string, suffix string) string {
	id := "device-sessions-ui-" + suffix + "-" + randomManagedUIID(t)
	body := `{"id":"` + id + `","name":"` + suffix + `","confidential":false,"redirect_uris":[],"scopes":["goauthy.read","offline_access"],"default_scopes":["goauthy.read","offline_access"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	response := do(t, client, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(body), headers)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("device UI client create status=%d", response.StatusCode)
	}
	return id
}

func deleteDeviceSessionsUIClient(t *testing.T, client *http.Client, base string, headers map[string]string, id string) {
	response := do(t, client, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
	var value struct {
		Revision int64 `json:"revision"`
	}
	_ = json.NewDecoder(response.Body).Decode(&value)
	response.Body.Close()
	if value.Revision == 0 {
		return
	}
	deleteHeaders := map[string]string{}
	for key, item := range headers {
		deleteHeaders[key] = item
	}
	deleteHeaders["If-Match"] = fmt.Sprintf(`"%d"`, value.Revision)
	response = do(t, client, http.MethodDelete, base+"/auth/v1/clients/"+url.PathEscape(id), nil, deleteHeaders)
	response.Body.Close()
}

func readDeviceSessionsUIDevices(t *testing.T, client *http.Client, base string) []deviceSessionsUIDevice {
	response := do(t, client, http.MethodGet, base+"/auth/v1/account/devices", nil, nil)
	defer response.Body.Close()
	var devices []deviceSessionsUIDevice
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&devices) != nil {
		t.Fatalf("account device list status=%d", response.StatusCode)
	}
	return devices
}
