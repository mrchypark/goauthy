package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestConnectionResourcesPilot(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CONNECTION_RESOURCES") != "1" {
		t.Skip("set GOAUTHY_E2E_CONNECTION_RESOURCES=1 to run connection-resource pilot")
	}
	primary, secondary, adminUser, adminPassword, bootstrapSecret := browserE2EConfig(t)
	tertiary := requiredE2EURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	admin := newBrowserClient(t)
	_, cookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "connection-resources-admin")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-origin"}
	collectionID := "resource-pilot-" + randomManagedUIID(t)
	clientID := collectionID + "-client"
	createResource(t, admin, primary+"/auth/v1/auth-collections", `{"id":"`+collectionID+`","name":"Resource pilot","auth_method":"api_key","enabled":true,"fields":[]}`, h, http.StatusCreated)
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/auth-collections/"+url.PathEscape(collectionID), nil, sessionHeader(h, "If-Match", `"1"`))
		r.Body.Close()
	}()
	createResource(t, admin, primary+"/auth/v1/clients", `{"id":"`+clientID+`","name":"Resource pilot client","confidential":false,"redirect_uris":[],"scopes":["goauthy.connections.read","goauthy.connections.write","offline_access"],"default_scopes":["goauthy.connections.read","goauthy.connections.write","offline_access"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`, h, http.StatusCreated)
	defer cleanupResourceClient(t, admin, primary, clientID, h)
	aliceEmail, alicePassword := "resource-pilot-alice-"+randomManagedUIID(t)+"@goauthy.e2e", "Resource-Pilot-Alice-2B"
	aliceID := createCatalogSessionUser(t, admin, primary, h, aliceEmail, alicePassword)
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(aliceID), nil, h)
		r.Body.Close()
	}()
	grant := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.connections.read goauthy.connections.write offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), grant, primary, tertiary, aliceEmail, alicePassword)
	tok := publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "client_id": {clientID}})
	if tok.AccessToken == "" {
		t.Fatal("missing Alice bearer token")
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok.AccessToken, "Content-Type": "application/json"}
	r := pilotSessionDo(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/connections/"+url.PathEscape(collectionID), nil, bearer)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d", r.StatusCode)
	}
	r.Body.Close()
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connections/"+url.PathEscape(collectionID), strings.NewReader(`{"definition_revision":1,"metadata":{}}`), bearer)
	if r.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("create status=%d body=%s", r.StatusCode, b)
	}
	var conn struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	_ = json.NewDecoder(r.Body).Decode(&conn)
	r.Body.Close()
	path := primary + "/auth/v1/connections/" + url.PathEscape(collectionID) + "/" + url.PathEscape(conn.ID)
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodGet, path, nil, bearer)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d", r.StatusCode)
	}
	r.Body.Close()
	put := sessionHeader(bearer, "If-Match", `"`+sessionItoa(conn.Revision)+`"`)
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodPut, secondary+"/auth/v1/connections/"+url.PathEscape(collectionID)+"/"+url.PathEscape(conn.ID), strings.NewReader(`{"definition_revision":1,"metadata":{}}`), put)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("update status=%d", r.StatusCode)
	}
	r.Body.Close()
	currentRevision := conn.Revision + 1
	stale := sessionHeader(bearer, "If-Match", `"1"`)
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodDelete, path, nil, stale)
	r.Body.Close()
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("stale delete status=%d", r.StatusCode)
	}
	// Read-only tokens cannot mutate; write-only tokens cannot enumerate/read.
	rg := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.connections.read offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), rg, primary, tertiary, aliceEmail, alicePassword)
	rt := publicDeviceToken(t, newBrowserClient(t), primary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {rg.DeviceCode}, "client_id": {clientID}})
	if rt.AccessToken == "" {
		t.Fatal("read-only token missing access token")
	}
	assertDeviceLoginIntrospection(t, primary, bootstrapSecret, rt.AccessToken, "goauthy.connections.read offline_access")
	readOnly := map[string]string{"Authorization": "Bearer " + rt.AccessToken, "Content-Type": "application/json"}
	readOnlyChecks := []struct{ method, target, body, match string }{
		{http.MethodPost, primary + "/auth/v1/connections/" + url.PathEscape(collectionID), `{"definition_revision":1,"metadata":{}}`, ""},
		{http.MethodPut, path, `{"definition_revision":1,"metadata":{}}`, `"` + sessionItoa(currentRevision) + `"`},
		{http.MethodDelete, path, "", `"` + sessionItoa(currentRevision) + `"`},
	}
	for _, check := range readOnlyChecks {
		body := strings.NewReader(check.body)
		r = pilotSessionDo(t, newBrowserClient(t), check.method, check.target, body, sessionHeader(readOnly, "If-Match", check.match))
		status := r.StatusCode
		r.Body.Close()
		if status != http.StatusUnauthorized {
			t.Fatalf("read-only %s status=%d", check.method, status)
		}
	}
	wg := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.connections.write offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), wg, primary, tertiary, aliceEmail, alicePassword)
	wt := publicDeviceToken(t, newBrowserClient(t), secondary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {wg.DeviceCode}, "client_id": {clientID}})
	if wt.AccessToken == "" {
		t.Fatal("write-only token missing access token")
	}
	assertDeviceLoginIntrospection(t, secondary, bootstrapSecret, wt.AccessToken, "goauthy.connections.write offline_access")
	writeOnly := map[string]string{"Authorization": "Bearer " + wt.AccessToken}
	for _, target := range []string{primary + "/auth/v1/connections/" + url.PathEscape(collectionID), path} {
		r = pilotSessionDo(t, newBrowserClient(t), http.MethodGet, target, nil, writeOnly)
		status := r.StatusCode
		r.Body.Close()
		if status != http.StatusUnauthorized {
			t.Fatalf("write-only GET %s status=%d", target, status)
		}
	}
	ownerInjection := pilotSessionDo(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connections/"+url.PathEscape(collectionID), strings.NewReader(`{"definition_revision":1,"metadata":{},"owner":"attacker"}`), bearer)
	status := ownerInjection.StatusCode
	ownerInjection.Body.Close()
	if status != http.StatusBadRequest {
		t.Fatalf("owner injection status=%d", status)
	}
	// A second user with the same client and read/write scopes cannot see Alice's record.
	bobEmail, bobPassword := "resource-pilot-bob-"+randomManagedUIID(t)+"@goauthy.e2e", "Resource-Pilot-Bob-2B"
	bobID := createCatalogSessionUser(t, admin, primary, h, bobEmail, bobPassword)
	defer func() {
		r := pilotSessionDo(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(bobID), nil, h)
		r.Body.Close()
	}()
	bg := startDeviceAuthorizationScopes(t, newBrowserClient(t), primary, clientID, "goauthy.connections.read goauthy.connections.write offline_access")
	loginAndApproveDevice(t, newBrowserClient(t), bg, primary, tertiary, bobEmail, bobPassword)
	bt := publicDeviceToken(t, newBrowserClient(t), primary, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {bg.DeviceCode}, "client_id": {clientID}})
	br := map[string]string{"Authorization": "Bearer " + bt.AccessToken}
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodGet, path, nil, br)
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-owner get status=%d", r.StatusCode)
	}
	// Alice can delete only with the current revision.
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodGet, path, nil, bearer)
	var latest struct {
		Revision int64 `json:"revision"`
	}
	_ = json.NewDecoder(r.Body).Decode(&latest)
	r.Body.Close()
	r = pilotSessionDo(t, newBrowserClient(t), http.MethodDelete, path, nil, sessionHeader(bearer, "If-Match", `"`+sessionItoa(latest.Revision)+`"`))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", r.StatusCode)
	}
}

func createResource(t *testing.T, c *http.Client, e, b string, h map[string]string, want int) {
	r := pilotSessionDo(t, c, http.MethodPost, e, strings.NewReader(b), h)
	defer r.Body.Close()
	if r.StatusCode != want {
		body, _ := io.ReadAll(r.Body)
		t.Fatalf("create status=%d body=%s", r.StatusCode, body)
	}
}
func cleanupResourceClient(t *testing.T, c *http.Client, base, id string, h map[string]string) {
	r := pilotSessionDo(t, c, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(id), nil, h)
	var v struct {
		Revision int64 `json:"revision"`
	}
	_ = json.NewDecoder(r.Body).Decode(&v)
	r.Body.Close()
	if v.Revision > 0 {
		r = pilotSessionDo(t, c, http.MethodDelete, base+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(h, "If-Match", `"`+sessionItoa(v.Revision)+`"`))
		r.Body.Close()
	}
}
