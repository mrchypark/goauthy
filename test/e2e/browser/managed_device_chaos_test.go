package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

// The exact pending grant, not a new grant issued after recovery, must survive
// replacement of its issuance Pod. This does not simulate quorum/host loss.
func TestManagedDevicePendingGrantSurvivesPodReplacement(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MANAGED_DEVICE_CHAOS") != "1" {
		t.Skip("set GOAUTHY_E2E_MANAGED_DEVICE_CHAOS=1 with the owned Kind fixture")
	}
	cluster := authCollectionsChaosConfig(t)
	primary, secondary, user, password, secret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	admin := newBrowserClient(t)
	_, cookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "managed-device-chaos")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	id := "managed-chaos-" + randomManagedUIID(t)
	payload, err := json.Marshal(map[string]any{"id": id, "name": nil, "confidential": false, "redirect_uris": []string{}, "scopes": []string{"goauthy.read", "offline_access"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}})
	if err != nil {
		t.Fatal(err)
	}
	r := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(string(payload)), headers)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("managed client create status=%d", r.StatusCode)
	}
	t.Cleanup(func() {
		// The primary port-forward dies with the Pod; cleanup uses a survivor.
		revision := managedUIRevision(t, admin, secondary, id, headers)
		h := cloneManagedUIHeaders(headers)
		h["If-Match"] = `"` + strconv.FormatInt(revision, 10) + `"`
		r := do(t, admin, http.MethodDelete, secondary+"/auth/v1/clients/"+url.PathEscape(id), nil, h)
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("managed chaos cleanup status=%d", r.StatusCode)
		}
	})
	grant := startDeviceAuthorizationOffline(t, newBrowserClient(t), primary, id, "")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	oldUID := authCollectionsChaosPodUID(t, ctx, cluster)
	authCollectionsChaosKubectl(t, ctx, cluster, "delete", "pod", "goauthy-0", "--wait=true")
	authCollectionsChaosKubectl(t, ctx, cluster, "wait", "--for=condition=Ready", "pod/goauthy-0", "pod/goauthy-1", "pod/goauthy-2", "--timeout=180s")
	if newUID := authCollectionsChaosPodUID(t, ctx, cluster); newUID == oldUID {
		t.Fatal("managed device chaos did not replace the issuance Pod")
	}
	approveDevice(t, admin, secondary, tertiary, grant.UserCode, "approve")
	client := newBrowserClient(t)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {id}}
	tokens := publicDeviceToken(t, client, tertiary, form)
	assertDeviceLoginIntrospection(t, secondary, secret, tokens.AccessToken, grant.Scope)
	r = do(t, client, http.MethodPost, secondary+"/oidc/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var failure struct {
		Error string `json:"error"`
	}
	err = json.NewDecoder(r.Body).Decode(&failure)
	r.Body.Close()
	if err != nil || r.StatusCode != http.StatusBadRequest || failure.Error != "expired_token" {
		t.Fatalf("same device code replay status=%d error=%q decode=%v", r.StatusCode, failure.Error, err)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("missing managed device refresh token")
	}
	refreshed := publicDeviceToken(t, client, secondary, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {id}})
	assertDeviceLoginIntrospection(t, tertiary, secret, refreshed.AccessToken, grant.Scope)
}
