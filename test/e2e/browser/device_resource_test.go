package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestManagedDeviceResourceProviderBearerLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROVIDER_BEARER") != "1" {
		t.Skip("set GOAUTHY_E2E_PROVIDER_BEARER=1 to run managed device resource E2E")
	}
	primary, secondary, adminName, adminPassword, _ := browserE2EConfig(t)
	admin := newBrowserClient(t)
	_, cookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminName, adminPassword, "managed-device-resource-admin")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	ensureProviderBearerReadScope(t, admin, primary, headers)
	id := "managed-device-resource-" + randomManagedUIID(t)
	body := `{"id":"` + id + `","name":"Managed device resource E2E","confidential":false,"redirect_uris":[],"audience":["` + providerBearerResource + `"],"scopes":["goauthy.providers.read","offline_access"],"default_scopes":["goauthy.providers.read","offline_access"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	created := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(body), headers)
	var client struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if created.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&client) != nil || client.ID != id || client.Revision <= 0 {
		created.Body.Close()
		t.Fatalf("device client create status=%d", created.StatusCode)
	}
	created.Body.Close()
	currentRevision := client.Revision
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
		r.Body.Close()
	})

	grant := startManagedDeviceResource(t, newBrowserClient(t), primary, id, "goauthy.providers.read offline_access", providerBearerResource)
	loginAndApproveDevice(t, newBrowserClient(t), grant, primary, secondary, adminName, adminPassword)
	tokens := publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {id}})
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("device resource token missing access or refresh token")
	}
	providers := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
	providers.Body.Close()
	if providers.StatusCode != http.StatusOK {
		t.Fatalf("device resource bearer status=%d", providers.StatusCode)
	}
	refreshed := publicDeviceToken(t, newBrowserClient(t), primary, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {id}})
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("device resource refresh missing token")
	}
	refreshedAccess := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Authorization": "Bearer " + refreshed.AccessToken})
	refreshedAccess.Body.Close()
	if refreshedAccess.StatusCode != http.StatusOK {
		t.Fatalf("refreshed device resource bearer status=%d", refreshedAccess.StatusCode)
	}

	updateBody := `{"name":"Managed device resource E2E","confidential":false,"enabled":true,"redirect_uris":[],"audience":[],"scopes":["goauthy.providers.read","offline_access"],"default_scopes":["goauthy.providers.read","offline_access"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	updated := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(id), strings.NewReader(updateBody), sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
	var updatedBody struct {
		Revision int64 `json:"revision"`
	}
	if updated.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(updated.Body, 4096)).Decode(&updatedBody) != nil || updatedBody.Revision <= currentRevision {
		updated.Body.Close()
		t.Fatalf("device audience update status=%d", updated.StatusCode)
	}
	updated.Body.Close()
	currentRevision = updatedBody.Revision
	old := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Authorization": "Bearer " + refreshed.AccessToken})
	old.Body.Close()
	if old.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old device resource token status=%d", old.StatusCode)
	}
	denied := do(t, newBrowserClient(t), http.MethodPost, primary+"/oidc/device", strings.NewReader(url.Values{"client_id": {id}, "scope": {"goauthy.providers.read offline_access"}, "resource": {providerBearerResource}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	deniedBody, _ := io.ReadAll(io.LimitReader(denied.Body, 4096))
	denied.Body.Close()
	if denied.StatusCode != http.StatusBadRequest || !strings.Contains(string(deniedBody), `"invalid_target"`) {
		t.Fatalf("device request with removed audience status=%d body=%s", denied.StatusCode, deniedBody)
	}

	r := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("device client cleanup status=%d", r.StatusCode)
	}
	deleted = true
}

func startManagedDeviceResource(t *testing.T, c *http.Client, base, id, scope, resource string) deviceLoginGrant {
	t.Helper()
	form := url.Values{"client_id": {id}, "scope": {scope}, "resource": {resource}}
	r := do(t, c, http.MethodPost, base+"/oidc/device", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("device resource grant status=%d", r.StatusCode)
	}
	var grant deviceLoginGrant
	if json.NewDecoder(r.Body).Decode(&grant) != nil || grant.DeviceCode == "" {
		t.Fatal("invalid device resource grant")
	}
	grant.Scope = scope
	return grant
}
