package browser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestDeviceSessionsPilot(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_SESSIONS") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_SESSIONS=1 to run device-session pilot")
	}
	primary, secondary, adminUser, adminPassword, bootstrapSecret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	admin := newBrowserClient(t)
	_, adminCookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "device-sessions-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-origin"}
	clientID := "device-session-" + randomManagedUIID(t)
	create := `{"id":"` + clientID + `","name":"Device session pilot","confidential":false,"redirect_uris":[],"scopes":["goauthy.read","offline_access"],"default_scopes":["goauthy.read","offline_access"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	r := pilotSessionDo(t, admin, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(create), h)
	if r.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("client create status=%d body=%s", r.StatusCode, b)
	}
	r.Body.Close()
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodGet, primary+"/auth/v1/clients/"+url.PathEscape(clientID), nil, h)
		var v struct {
			Revision int64 `json:"revision"`
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		if v.Revision > 0 {
			r = pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(clientID), nil, sessionHeader(h, "If-Match", `"`+sessionItoa(v.Revision)+`"`))
			r.Body.Close()
		}
	}()
	aliceEmail, alicePassword := "device-sessions-alice-"+randomManagedUIID(t)+"@goauthy.e2e", "Device-Sessions-Alice-2B"
	aliceID := createCatalogSessionUser(t, admin, primary, h, aliceEmail, alicePassword)
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(aliceID), nil, h)
		r.Body.Close()
	}()
	alice := newBrowserClient(t)
	_, aliceCookie := loginForCode(t, alice, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), aliceEmail, alicePassword, "device-sessions-alice")
	before := sessionDeviceIDs(t, alice, primary)
	grant1 := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.read offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), grant1, primary, tertiary, aliceEmail, alicePassword)
	tok1 := publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant1.DeviceCode}, "client_id": {clientID}})
	afterFirst := sessionDeviceIDs(t, alice, primary)
	firstIDs := sessionDifference(afterFirst, before)
	if len(firstIDs) != 1 {
		t.Fatalf("first device snapshot=%v before=%v", afterFirst, before)
	}
	grant2 := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.read offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), grant2, primary, tertiary, aliceEmail, alicePassword)
	tok2 := publicDeviceToken(t, newBrowserClient(t), tertiary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant2.DeviceCode}, "client_id": {clientID}})
	secondIDs := sessionDifference(sessionDeviceIDs(t, alice, primary), afterFirst)
	if len(secondIDs) != 1 {
		t.Fatalf("second device snapshot=%v after-first=%v", secondIDs, afterFirst)
	}
	if err := revokeSessionDevice(t, alice, primary, firstIDs[0], aliceCookie); err != nil {
		t.Fatal(err)
	}
	assertSessionIntrospection(t, primary, bootstrapSecret, tok1.AccessToken, false)
	assertSessionRefreshRejected(t, newBrowserClient(t), primary, clientID, tok1.RefreshToken)
	assertSessionIntrospection(t, secondary, bootstrapSecret, tok2.AccessToken, true)
	_ = publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2.RefreshToken}, "client_id": {clientID}})
	// A different user cannot enumerate or revoke Alice's sessions.
	bobEmail, bobPassword := "device-sessions-bob-"+randomManagedUIID(t)+"@goauthy.e2e", "Device-Sessions-Bob-2B"
	bobID := createCatalogSessionUser(t, admin, primary, h, bobEmail, bobPassword)
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(bobID), nil, h)
		r.Body.Close()
	}()
	bob := newBrowserClient(t)
	_, bobCookie := loginForCode(t, bob, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), bobEmail, bobPassword, "device-sessions-bob")
	if got := sessionDeviceIDs(t, bob, primary); len(got) != 0 {
		t.Fatalf("bob listed alice devices: %v", got)
	}
	bobCSRF, err := browsersession.DeriveCSRFToken(bobCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	denied := pilotSessionDo(t, bob, http.MethodDelete, primary+"/auth/v1/account/devices/"+url.PathEscape(secondIDs[0]), nil, map[string]string{"X-CSRF-Token": bobCSRF})
	denied.Body.Close()
	if denied.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-owner device revoke status=%d want=404", denied.StatusCode)
	}
}

func startDeviceAuthorizationScopes(t *testing.T, c *http.Client, base, id, scope string) deviceLoginGrant {
	r := pilotSessionDo(t, c, http.MethodPost, base+"/oidc/device", strings.NewReader(url.Values{"client_id": {id}, "scope": {scope}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device grant status=%d", r.StatusCode)
	}
	var g deviceLoginGrant
	if json.NewDecoder(r.Body).Decode(&g) != nil || g.DeviceCode == "" {
		t.Fatal("invalid device grant")
	}
	g.Scope = scope
	return g
}
func pilotSessionDo(t *testing.T, c *http.Client, m, e string, b io.Reader, h map[string]string) *http.Response {
	r, err := http.NewRequestWithContext(t.Context(), m, e, b)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	out, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func sessionHeader(h map[string]string, k, v string) map[string]string {
	o := map[string]string{}
	for a, b := range h {
		o[a] = b
	}
	o[k] = v
	return o
}
func sessionItoa(v int64) string { return fmt.Sprintf("%d", v) }
func sessionDeviceIDs(t *testing.T, c *http.Client, base string) []string {
	r := pilotSessionDo(t, c, http.MethodGet, base+"/auth/v1/account/devices", nil, nil)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device list status=%d", r.StatusCode)
	}
	var v []struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		t.Fatal("invalid device list")
	}
	o := make([]string, 0, len(v))
	for _, x := range v {
		o = append(o, x.ID)
	}
	return o
}
func sessionDifference(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range b {
		m[x] = true
	}
	o := []string{}
	for _, x := range a {
		if !m[x] {
			o = append(o, x)
		}
	}
	return o
}
func revokeSessionDevice(t *testing.T, c *http.Client, base, id string, cookie *http.Cookie) error {
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		return err
	}
	r := pilotSessionDo(t, c, http.MethodDelete, base+"/auth/v1/account/devices/"+url.PathEscape(id), nil, map[string]string{"X-CSRF-Token": csrf})
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke status=%d", r.StatusCode)
	}
	return nil
}
func assertSessionIntrospection(t *testing.T, base, secret, token string, want bool) {
	r := pilotSessionDo(t, newBrowserClient(t), http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("goauthy-dev:"+secret))})
	defer r.Body.Close()
	var v struct {
		Active bool `json:"active"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&v) != nil || v.Active != want {
		t.Fatalf("introspection active=%t want=%t status=%d", v.Active, want, r.StatusCode)
	}
}
func assertSessionRefreshRejected(t *testing.T, c *http.Client, base, id, refresh string) {
	r := pilotSessionDo(t, c, http.MethodPost, base+"/oidc/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {id}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	var v struct {
		Error string `json:"error"`
	}
	if r.StatusCode != http.StatusBadRequest || json.NewDecoder(r.Body).Decode(&v) != nil || v.Error != "invalid_grant" {
		t.Fatalf("refresh rejection status=%d error=%q", r.StatusCode, v.Error)
	}
}
