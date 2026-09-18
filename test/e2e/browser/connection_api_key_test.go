package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestConnectionAPIKeyPilot(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CONNECTION_API_KEY") != "1" {
		t.Skip("API-key connection pilot disabled")
	}
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "connection-api-key")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	id := uniqueCollectionID(t)
	body, _ := json.Marshal(map[string]any{"id": id, "name": "API-key E2E", "auth_method": "api_key", "enabled": true, "fields": []any{}, "provider_ids": []string{}})
	response := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", bytes.NewReader(body), headers)
	_, defRevision := readCollection(t, response, http.StatusCreated)
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+id, nil, cloneCollectionHeaders(headers, defRevision))
		r.Body.Close()
		if r.StatusCode != 204 {
			t.Errorf("collection cleanup=%d", r.StatusCode)
		}
	})
	response = do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+id, bytes.NewBufferString(`{"definition_revision":1,"metadata":{}}`), headers)
	connection, revision := readCollection(t, response, http.StatusCreated)
	connectionID, ok := connection["id"].(string)
	if !ok || connectionID == "" {
		t.Fatal("missing connection ID")
	}
	base := primary + "/auth/v1/account/connections/" + id + "/" + connectionID
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, base, nil, cloneCollectionHeaders(headers, revision))
		r.Body.Close()
		if r.StatusCode != 204 {
			t.Errorf("connection cleanup=%d", r.StatusCode)
		}
	})
	keyURL := base + "/api-key"
	check := func(method, body string, wantStatus int, registered bool, version int64) {
		t.Helper()
		r := do(t, client, method, keyURL, bytes.NewBufferString(body), headers)
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil || r.StatusCode != wantStatus {
			t.Fatalf("%s status=%d want=%d err=%v", method, r.StatusCode, wantStatus, err)
		}
		if bytes.Contains(raw, []byte("synthetic-saas-key")) || bytes.Contains(raw, []byte(`"api_key"`)) {
			t.Fatal("credential leaked in response")
		}
		if wantStatus == 200 {
			var status struct {
				Registered bool  `json:"registered"`
				Version    int64 `json:"version"`
			}
			if err := json.Unmarshal(raw, &status); err != nil || status.Registered != registered || status.Version != version {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		}
	}
	check(http.MethodGet, "", 200, false, 0)
	check(http.MethodPut, `{"api_key":"synthetic-saas-key-first","version":0}`, 200, true, 1)
	response = do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+id, bytes.NewBufferString(`{"name":"API-key E2E renamed","auth_method":"api_key","enabled":true,"fields":[],"provider_ids":[]}`), cloneCollectionHeaders(headers, defRevision))
	_, defRevision = readCollection(t, response, http.StatusOK)
	check(http.MethodGet, "", 200, true, 1)
	check(http.MethodPut, `{"api_key":"synthetic-saas-key-stale","version":0}`, 409, false, 0)
	check(http.MethodPut, `{"api_key":"synthetic-saas-key-rotated","version":1}`, 200, true, 2)
	check(http.MethodDelete, `{"version":1}`, 409, false, 0)
	check(http.MethodDelete, `{"version":2}`, 204, false, 0)
	check(http.MethodGet, "", 200, false, 2)
	check(http.MethodPut, `{"api_key":"synthetic-saas-key-revive","version":2}`, 409, false, 0)
	t.Run("browser", func(t *testing.T) {
		testConnectionAPIKeyUI(t, client, primary, cookie, headers, id, defRevision, "")
	})
}
