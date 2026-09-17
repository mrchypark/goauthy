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
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const useGrantResource = "https://goauthy.connections.local.test"

func TestConnectionUseGrantLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_USE_GRANTS") != "1" {
		t.Skip("set GOAUTHY_E2E_USE_GRANTS=1 to run connection-use grant E2E")
	}
	connectorID := uniqueCollectionID(t)
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "connection-use-grant")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	prefix := "Bearer "
	if os.Getenv("GOAUTHY_E2E_RAW_AUTHORIZATION") == "1" {
		prefix = ""
	}
	providerBody := `{"id":"` + connectorID + `","name":"Use grant provider","kind":"api_key","enabled":true,"callback_uri":"","scopes":[],"connector":{"id":"` + connectorID + `","header":"Authorization","prefix":"` + prefix + `","operations":[{"id":"account","url":"https://api.example.com/account","response_fields":{"id":"string"}}]}}`
	if os.Getenv("GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR") != "" {
		if prefix != "" {
			t.Fatal("Conductor delivery fixture requires raw Authorization")
		}
		providerBody = strings.Replace(providerBody, "https://api.example.com/account", "https://openapi.gowid.com/v2/expense-statements", 1)
	}
	provider := do(t, client, http.MethodPost, primary+"/auth/v1/saas/providers", strings.NewReader(providerBody), headers)
	provider.Body.Close()
	if provider.StatusCode != http.StatusCreated {
		t.Fatalf("provider create status=%d", provider.StatusCode)
	}
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/saas/providers/"+connectorID, nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
	})

	collectionID := uniqueCollectionID(t)
	collectionBody := `{"id":"` + collectionID + `","name":"Use grant E2E","auth_method":"api_key","enabled":true,"fields":[],"provider_ids":["` + connectorID + `"]}`
	collection := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", strings.NewReader(collectionBody), headers)
	_, collectionRevision := readCollection(t, collection, http.StatusCreated)
	connection := do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+collectionID, strings.NewReader(`{"definition_revision":1,"metadata":{}}`), headers)
	connectionDoc, connectionRevision := readCollection(t, connection, http.StatusCreated)
	connectionID, ok := connectionDoc["id"].(string)
	if !ok || connectionID == "" {
		t.Fatal("connection ID missing")
	}
	connectionBase := primary + "/auth/v1/account/connections/" + collectionID + "/" + connectionID
	connector := do(t, client, http.MethodGet, connectionBase+"/api-key/connector", nil, headers)
	var connectorDoc struct {
		Digest string `json:"digest"`
		Prefix string `json:"prefix"`
	}
	if connector.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(connector.Body, 4096)).Decode(&connectorDoc) != nil || connectorDoc.Digest == "" {
		connector.Body.Close()
		t.Fatalf("connector metadata status=%d", connector.StatusCode)
	}
	connector.Body.Close()
	if connectorDoc.Prefix != prefix {
		t.Fatalf("connector prefix=%q want=%q", connectorDoc.Prefix, prefix)
	}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"api_key":"synthetic-key","version":0}`, http.StatusConflict},
		{`{"api_key":"synthetic-key","version":0,"connector_digest":"wrong"}`, http.StatusBadRequest},
		{`{"api_key":"synthetic-key","version":0,"connector_digest":null}`, http.StatusBadRequest},
	} {
		r := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(tc.body), headers)
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("invalid bound registration status=%d want=%d", r.StatusCode, tc.status)
		}
	}
	anonymousConnector := do(t, newBrowserClient(t), http.MethodGet, connectionBase+"/api-key/connector", nil, nil)
	anonymousConnector.Body.Close()
	if anonymousConnector.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous connector status=%d", anonymousConnector.StatusCode)
	}
	bound := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(`{"api_key":"e2e-bound-api-key","version":0,"connector_digest":"`+connectorDoc.Digest+`"}`), headers)
	bound.Body.Close()
	if bound.StatusCode != http.StatusOK {
		t.Fatalf("bound API key status=%d", bound.StatusCode)
	}

	managedID := "use-grant-consumer-" + randomManagedUIID(t)
	managedBody := `{"id":"` + managedID + `","name":"Use grant consumer","confidential":false,"redirect_uris":["https://rp.example.test/use-grant"],"audience":["` + useGrantResource + `"],"scopes":["goauthy.connections.use"],"default_scopes":["goauthy.connections.use"],"enabled_flows":["authorization_code"]}`
	managed := do(t, client, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(managedBody), headers)
	var managedDoc struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if managed.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(managed.Body, 4096)).Decode(&managedDoc) != nil || managedDoc.ID != managedID || managedDoc.Revision <= 0 {
		managed.Body.Close()
		t.Fatalf("consumer create status=%d", managed.StatusCode)
	}
	managed.Body.Close()
	expires := time.Now().Add(time.Hour).UnixMilli()
	grantBody := `{"consumer_client_id":"` + managedID + `","mode":"proxy","purpose":"sync","expires_at_unix_ms":` + strconv.FormatInt(expires, 10) + `}`
	for _, tc := range []struct {
		digest string
		status int
	}{
		{`null`, http.StatusBadRequest},
		{`"bad"`, http.StatusBadRequest},
		{`"` + strings.Repeat("A", 43) + `"`, http.StatusConflict},
	} {
		body := strings.TrimSuffix(grantBody, "}") + `,"connector_digest":` + tc.digest + `}`
		r := do(t, client, http.MethodPost, connectionBase+"/grants", strings.NewReader(body), headers)
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("reviewed grant rejection=%d want=%d", r.StatusCode, tc.status)
		}
	}
	grant := do(t, client, http.MethodPost, connectionBase+"/grants", strings.NewReader(grantBody), headers)
	var grantDoc struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
		Revoked  bool   `json:"revoked"`
	}
	if grant.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(grant.Body, 16<<10)).Decode(&grantDoc) != nil || grantDoc.ID == "" || grantDoc.Revision != 1 || grantDoc.Revoked {
		grant.Body.Close()
		t.Fatalf("grant create status=%d", grant.StatusCode)
	}
	grant.Body.Close()
	var checkGrantStatus func(bool)
	if os.Getenv("GOAUTHY_E2E_GRANT_STATUS") == "1" {
		checkGrantStatus = grantStatusObserver(t, client, primary, headers, collectionID, connectionID, grantDoc.ID, managedID)
		checkGrantStatus(false)
	}
	var invokeToken string
	if os.Getenv("GOAUTHY_E2E_GRANT_INVOKE") == "1" {
		ensureResourcePermissionScope(t, client, primary, headers, "goauthy.connections.use")
		invokeToken = issueGrantInvokeToken(t, client, primary, managedID, useGrantResource)
		if checkGrantStatus != nil {
			r := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/connections/"+collectionID+"/"+connectionID+"/grants/"+grantDoc.ID, nil, map[string]string{"Authorization": "Bearer " + invokeToken})
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("use-only token read grant status=%d", r.StatusCode)
			}
		}
		assertGrantInvokeStatus(t, primary, grantDoc.ID, invokeToken, `{"operation":"unknown"}`, http.StatusBadRequest)
		assertGrantInvokeStatus(t, primary, "missing-grant", invokeToken, `{"operation":"account"}`, http.StatusNotFound)
		assertGrantInvokeStatus(t, primary, grantDoc.ID, "", `{"operation":"account"}`, http.StatusUnauthorized)
		wrongAudience := issueGrantInvokeToken(t, client, primary, managedID, "")
		assertGrantInvokeStatus(t, primary, grantDoc.ID, wrongAudience, `{"operation":"account"}`, http.StatusUnauthorized)
	}
	list := do(t, client, http.MethodGet, connectionBase+"/grants", nil, headers)
	var grants []map[string]any
	if list.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(list.Body, 32<<10)).Decode(&grants) != nil || len(grants) != 1 {
		list.Body.Close()
		t.Fatalf("grant list status=%d", list.StatusCode)
	}
	list.Body.Close()
	if strings.Contains(string(mustGrantList(t, client, connectionBase, headers)), "e2e-bound-api-key") {
		t.Fatal("grant list exposed raw API key")
	}
	rotateBody := `{"api_key":"e2e-rotated-key","version":1,"connector_digest":"` + connectorDoc.Digest + `"}`
	rotate := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(rotateBody), headers)
	rotate.Body.Close()
	if rotate.StatusCode != http.StatusOK {
		t.Fatalf("rotation status=%d", rotate.StatusCode)
	}
	stale := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(rotateBody), headers)
	stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale rotation status=%d", stale.StatusCode)
	}
	revokePath := connectionBase + "/grants/" + url.PathEscape(grantDoc.ID)
	revoke := do(t, client, http.MethodDelete, revokePath, nil, sessionHeader(headers, "If-Match", `"1"`))
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("grant revoke status=%d", revoke.StatusCode)
	}
	if checkGrantStatus != nil {
		checkGrantStatus(true)
	}
	if invokeToken != "" {
		assertGrantInvokeStatus(t, primary, grantDoc.ID, invokeToken, `{"operation":"account"}`, http.StatusNotFound)
	}
	if os.Getenv("GOAUTHY_E2E_CREDENTIAL_DELIVERY") == "1" {
		t.Run("credential-delivery", func(t *testing.T) {
			testCredentialDeliveryLive(t, client, primary, cookie, headers, collectionID, connectionID, managedID, connectorDoc.Digest)
		})
	}
	replay := do(t, client, http.MethodDelete, revokePath, nil, sessionHeader(headers, "If-Match", `"1"`))
	replay.Body.Close()
	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("grant revoke replay status=%d", replay.StatusCode)
	}
	revoked := mustGrantList(t, client, connectionBase, headers)
	if !strings.Contains(string(revoked), `"revoked":true`) {
		t.Fatalf("grant list missing revoked state: %s", revoked)
	}
	anonymous := do(t, newBrowserClient(t), http.MethodGet, connectionBase+"/grants", nil, nil)
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous grant list status=%d", anonymous.StatusCode)
	}
	if os.Getenv("GOAUTHY_E2E_GRANT_UI") == "1" {
		t.Run("service-access-browser", func(t *testing.T) {
			testConnectionGrantUI(t, client, primary, cookie, headers, collectionID, connectionID, managedID)
		})
	}
	if os.Getenv("GOAUTHY_E2E_HANDOFF") == "1" {
		t.Run("handoff-http", func(t *testing.T) {
			testUseHandoffLive(t, client, primary, cookie, headers, collectionID, connectionID, managedID)
		})
	}
	keyRevoke := do(t, client, http.MethodDelete, connectionBase+"/api-key", strings.NewReader(`{"version":2}`), headers)
	keyRevoke.Body.Close()
	if keyRevoke.StatusCode != http.StatusNoContent {
		t.Fatalf("key revoke status=%d", keyRevoke.StatusCode)
	}

	if os.Getenv("GOAUTHY_E2E_REGISTERED_KEY_UI") == "1" {
		t.Run("registered-key-browser", func(t *testing.T) {
			testConnectionAPIKeyUI(t, client, primary, cookie, headers, collectionID, collectionRevision, connectorDoc.Digest)
		})
	}
	connectionDelete := do(t, client, http.MethodDelete, connectionBase, nil, cloneCollectionHeaders(headers, connectionRevision))
	connectionDelete.Body.Close()
	if connectionDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("connection cleanup status=%d", connectionDelete.StatusCode)
	}
	collectionDelete := do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+collectionID, nil, cloneCollectionHeaders(headers, collectionRevision))
	collectionDelete.Body.Close()
	if collectionDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("collection cleanup status=%d", collectionDelete.StatusCode)
	}
	managedDelete := do(t, client, http.MethodDelete, primary+"/auth/v1/clients/"+managedID, nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(managedDoc.Revision, 10))))
	managedDelete.Body.Close()
	if managedDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("consumer cleanup status=%d", managedDelete.StatusCode)
	}
}

func mustGrantList(t *testing.T, client *http.Client, base string, headers map[string]string) []byte {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/grants", nil, headers)
	b, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	r.Body.Close()
	if r.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("grant list status=%d err=%v", r.StatusCode, err)
	}
	return b
}
