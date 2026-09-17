package browser

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDeviceAuthorizationBrowserLogin exercises the user-facing RFC 8628
// handoff: a cold verification browser is sent through device login, then
// must explicitly approve before the device code can be exchanged.
func TestDeviceAuthorizationBrowserLogin(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_LOGIN_FLOW") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1 to run device login E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	var eventAdmin *http.Client
	beforeEvents := map[string]bool{}
	if os.Getenv("GOAUTHY_E2E_TOKEN_EVENTS") == "1" {
		eventAdmin, _ = rbacAuthenticatedClient(t, primary, secondary, username, password)
		for _, event := range queryLifecycleEvents(t, eventAdmin, primary) {
			beforeEvents[event.ID] = true
		}
	}
	client := newBrowserClient(t)
	grant := startDeviceAuthorizationOffline(t, client, primary, "goauthy-dev", clientSecret)
	verify := newBrowserClient(t) // intentionally unauthenticated
	response := do(t, verify, http.MethodGet, grant.VerificationURIComplete, nil, nil)
	if response.StatusCode != http.StatusSeeOther || !strings.Contains(response.Header.Get("Location"), "/oidc/device/login?") {
		response.Body.Close()
		t.Fatalf("unauthenticated verification status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	loginURL := response.Header.Get("Location")
	response.Body.Close()
	response = do(t, verify, http.MethodGet, loginURL, nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("device login page status=%d", response.StatusCode)
	}
	body := readLimitedBody(t, response)
	response.Body.Close()
	interaction, ok := hiddenInputValue(body, "interaction")
	if !ok {
		t.Fatal("device login interaction missing")
	}
	csrf, ok := hiddenInputValue(body, "csrf_token")
	if !ok {
		t.Fatal("device login CSRF missing")
	}
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}
	response = do(t, verify, http.MethodPost, primary+"/oidc/device/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary),
	})
	if response.StatusCode != http.StatusSeeOther || !strings.Contains(response.Header.Get("Location"), "/oidc/device/verify?") {
		response.Body.Close()
		t.Fatalf("device login status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	verifyURL := response.Header.Get("Location")
	response.Body.Close()
	response = do(t, verify, http.MethodGet, verifyURL, nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("verify page status=%d", response.StatusCode)
	}
	body = readLimitedBody(t, response)
	response.Body.Close()
	csrf, ok = hiddenInputValue(body, "csrf_token")
	if !ok {
		t.Fatal("verification CSRF missing")
	}
	approve := url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}
	response = do(t, verify, http.MethodPost, tertiary+"/oidc/device/verify", strings.NewReader(approve.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary),
	})
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", response.StatusCode)
	}
	tokens := deviceToken(t, client, secondary, clientSecret, grant.DeviceCode)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken != "" {
		t.Fatal("device token response is invalid")
	}
	assertDeviceTokenError(t, client, secondary, clientSecret, grant.DeviceCode, "expired_token")
	for _, base := range []string{primary, secondary, tertiary} {
		assertDeviceLoginIntrospection(t, base, clientSecret, tokens.AccessToken, grant.Scope)
	}
	assertProtectedDeviceResource(t, client, primary, clientSecret, tokens.AccessToken, grant.Scope)
	refreshed := refresh(t, client, tertiary, clientSecret, tokens.RefreshToken)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("device refresh response is incomplete")
	}
	for _, base := range []string{primary, secondary, tertiary} {
		assertDeviceLoginIntrospection(t, base, clientSecret, refreshed.AccessToken, grant.Scope)
	}
	assertDeviceRefreshRejected(t, client, primary, clientSecret, tokens.RefreshToken)

	denied := startDeviceAuthorizationOffline(t, client, primary, "goauthy-dev", clientSecret)
	approveDevice(t, verify, secondary, primary, denied.UserCode, "deny")
	assertDeviceTokenError(t, verify, tertiary, clientSecret, denied.DeviceCode, "access_denied")
	assertDeviceTokenError(t, verify, primary, clientSecret, denied.DeviceCode, "access_denied")
	if eventAdmin != nil {
		want := 1
		if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
			want = 0
		}
		for _, node := range []string{primary, secondary, tertiary} {
			count := 0
			for _, event := range queryLifecycleEvents(t, eventAdmin, node) {
				if beforeEvents[event.ID] || string(event.Type) != "TokenIssued" || event.Text == nil {
					continue
				}
				if strings.HasPrefix(*event.Text, "goauthy-dev (refresh_token) ") {
					t.Fatal("device refresh emitted an event")
				}
				if strings.HasPrefix(*event.Text, "goauthy-dev (device_code) ") {
					count++
					if event.Level != expectedTokenEventLevel(t) || event.IP != nil || event.Data != nil {
						t.Fatal("invalid device event")
					}
				}
			}
			if count != want {
				t.Fatalf("device events=%d want=%d", count, want)
			}
		}
	}

}

type deviceLoginGrant struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Scope                   string `json:"scope"`
	Interval                int    `json:"interval"`
}

func startDeviceAuthorizationOffline(t *testing.T, c *http.Client, base, clientID, clientSecret string) deviceLoginGrant {
	req, err := http.NewRequest(http.MethodPost, base+"/oidc/device", strings.NewReader(url.Values{"client_id": {clientID}, "scope": {"goauthy.read offline_access"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var g deviceLoginGrant
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&g) != nil || g.DeviceCode == "" || g.UserCode == "" || g.VerificationURIComplete == "" {
		t.Fatalf("device grant status=%d", r.StatusCode)
	}
	g.Scope = "goauthy.read offline_access"
	return g
}
func assertDeviceLoginIntrospection(t *testing.T, base, secret, token, scope string) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("goauthy-dev", secret)
	r, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var p struct {
		Active  bool   `json:"active"`
		Scope   string `json:"scope"`
		Subject string `json:"sub"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&p) != nil || !p.Active || p.Scope != scope || p.Subject == "" {
		t.Fatalf("introspection status=%d active=%t scope=%q", r.StatusCode, p.Active, p.Scope)
	}
}
func assertDeviceRefreshRejected(t *testing.T, c *http.Client, base, secret, token string) {
	r := tokenResponseFor(t, c, base, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}})
	defer r.Body.Close()
	if r.StatusCode == http.StatusOK {
		t.Fatal("old refresh token replay accepted")
	}
}

func TestDeviceAuthorizationPublicBrowserLogin(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DEVICE_LOGIN_FLOW") != "1" {
		t.Skip("set GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1 to run device login E2E")
	}
	primary, secondary, username, password, bootstrapSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required when GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1")
	}
	registration := registerPublicDeviceClient(t, primary, registrationToken)
	defer func() {
		r := do(t, newBrowserClient(t), http.MethodDelete, primary+"/oidc/register/"+url.PathEscape(registration.ClientID), nil, map[string]string{"Authorization": "Bearer " + registration.RegistrationAccessToken})
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("public device client cleanup status=%d", r.StatusCode)
		}
	}()
	client := newBrowserClient(t)
	grant := startDeviceAuthorizationOffline(t, client, primary, registration.ClientID, "")
	verify := newBrowserClient(t)
	r := do(t, verify, http.MethodGet, grant.VerificationURIComplete, nil, nil)
	if r.StatusCode != http.StatusSeeOther {
		r.Body.Close()
		t.Fatalf("public verify redirect status=%d", r.StatusCode)
	}
	loginURL := r.Header.Get("Location")
	r.Body.Close()
	r = do(t, verify, http.MethodGet, loginURL, nil, nil)
	body := readLimitedBody(t, r)
	r.Body.Close()
	interaction, ok := hiddenInputValue(body, "interaction")
	if !ok {
		t.Fatal("public device interaction missing")
	}
	csrf, ok := hiddenInputValue(body, "csrf_token")
	if !ok {
		t.Fatal("public device csrf missing")
	}
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}
	r = do(t, verify, http.MethodPost, primary+"/oidc/device/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary)})
	if r.StatusCode != http.StatusSeeOther {
		r.Body.Close()
		t.Fatalf("public device login status=%d", r.StatusCode)
	}
	verifyURL := r.Header.Get("Location")
	r.Body.Close()
	r = do(t, verify, http.MethodGet, verifyURL, nil, nil)
	body = readLimitedBody(t, r)
	r.Body.Close()
	csrf, ok = hiddenInputValue(body, "csrf_token")
	if !ok {
		t.Fatal("public verify csrf missing")
	}
	approve := url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}
	r = do(t, verify, http.MethodPost, tertiary+"/oidc/device/verify", strings.NewReader(approve.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "Origin": primaryOrigin(t, primary)})
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("public approve status=%d", r.StatusCode)
	}
	deviceForm := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {registration.ClientID}}
	tokens := publicDeviceToken(t, client, secondary, deviceForm)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken != "" {
		t.Fatal("public device token response invalid")
	}
	assertPublicDeviceError(t, client, secondary, grant.DeviceCode, registration.ClientID, "expired_token")
	assertDeviceLoginIntrospection(t, primary, bootstrapSecret, tokens.AccessToken, grant.Scope)
	assertProtectedDeviceResource(t, client, primary, bootstrapSecret, tokens.AccessToken, grant.Scope)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {registration.ClientID}}
	refreshed := publicDeviceToken(t, client, tertiary, refreshForm)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("public refresh response invalid")
	}
	assertDeviceLoginIntrospection(t, secondary, bootstrapSecret, refreshed.AccessToken, grant.Scope)
	replay := do(t, client, http.MethodPost, primary+"/oidc/token", strings.NewReader(refreshForm.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var replayError struct {
		Error string `json:"error"`
	}
	err := json.NewDecoder(io.LimitReader(replay.Body, 8<<10)).Decode(&replayError)
	replay.Body.Close()
	if err != nil || replay.StatusCode != http.StatusBadRequest || replayError.Error != "invalid_grant" {
		t.Fatalf("public refresh replay status=%d error=%q", replay.StatusCode, replayError.Error)
	}
	denied := startDeviceAuthorizationOffline(t, client, primary, registration.ClientID, "")
	approveDevice(t, verify, secondary, primary, denied.UserCode, "deny")
	assertPublicDeviceError(t, verify, tertiary, denied.DeviceCode, registration.ClientID, "access_denied")
}

func publicDeviceToken(t *testing.T, c *http.Client, base string, form url.Values) tokenResponse {
	r := do(t, c, http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("public device token status=%d", r.StatusCode)
	}
	var out tokenResponse
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func registerPublicDeviceClient(t *testing.T, base, bearer string) dynamicClientRegistration {
	// DCR scope admission is currently configured server-wide, not per request.
	body := `{"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Public Device E2E"}`
	// A new test run is a new registration, not a replay of the deleted fixture.
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/oidc/register", strings.NewReader(body), map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json", "Idempotency-Key": "device-pilot-" + rand.Text()})
	defer r.Body.Close()
	var out dynamicClientRegistration
	if r.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&out) != nil || out.ClientID == "" || out.ClientSecret != "" || out.TokenEndpointAuthMethod != "none" {
		t.Fatalf("public device registration status=%d client_id=%q secret=%t", r.StatusCode, out.ClientID, out.ClientSecret != "")
	}
	return out
}

func assertPublicDeviceError(t *testing.T, c *http.Client, base, deviceCode, clientID, want string) {
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}, "client_id": {clientID}}
	r := do(t, c, http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&out)
	if r.StatusCode != http.StatusBadRequest || out.Error != want {
		t.Fatalf("public device error status=%d error=%q want=%q", r.StatusCode, out.Error, want)
	}
}

func assertProtectedDeviceResource(t *testing.T, c *http.Client, issuer, secret, token, scope string) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		bearer = strings.TrimSpace(bearer)
		if !ok || bearer == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, issuer+"/oidc/introspect", strings.NewReader(url.Values{"token": {bearer}}.Encode()))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadGateway)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("goauthy-dev", secret)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			http.Error(w, "introspection unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var p struct {
			Active  bool   `json:"active"`
			Subject string `json:"sub"`
			Scope   string `json:"scope"`
		}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&p) != nil || !p.Active || p.Subject == "" || !strings.Contains(" "+p.Scope+" ", " goauthy.read ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": p.Subject, "scope": p.Scope})
	}))
	defer server.Close()
	r := do(t, c, http.MethodGet, server.URL, nil, map[string]string{"Authorization": "Bearer " + token})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("protected device resource status=%d", r.StatusCode)
	}
	r = do(t, c, http.MethodGet, server.URL, nil, map[string]string{"Authorization": "Bearer invalid-token"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid protected device resource status=%d", r.StatusCode)
	}
}
