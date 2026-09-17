package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
)

func TestManagedClientHTTPAudienceCRUD(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	createBody := `{"id":"audience-http-client","name":"Audience","confidential":true,"redirect_uris":["https://app.example/cb"],"audience":["https://api.example.test"]}`
	response := httptest.NewRecorder()
	h.Clients(response, managedRequest(http.MethodPost, "/auth/v1/clients", createBody, cookie, csrf, ""))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var created clients.Client
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || len(created.Audiences) != 1 || created.Audiences[0] != "https://api.example.test" {
		t.Fatalf("create audience=%v err=%v", created.Audiences, err)
	}

	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodGet, "/auth/v1/clients/audience-http-client", "", cookie, "", ""))
	var got clients.Client
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &got) != nil || len(got.Audiences) != 1 {
		t.Fatalf("get status=%d audience=%v body=%s", response.Code, got.Audiences, response.Body.String())
	}
	etag := response.Header().Get("ETag")
	update := `{"name":"Audience 2","confidential":true,"redirect_uris":["https://app.example/cb"],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"]}`
	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodPut, "/auth/v1/clients/audience-http-client", update, cookie, csrf, etag))
	if response.Code != http.StatusOK {
		t.Fatalf("preserve update status=%d body=%s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || len(got.Audiences) != 1 {
		t.Fatalf("omitted audience did not preserve: %v", got.Audiences)
	}
	etag = response.Header().Get("ETag")
	clear := strings.Replace(update, `"enabled_flows":["authorization_code"]}`, `"enabled_flows":["authorization_code"],"audience":[]}`, 1)
	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodPut, "/auth/v1/clients/audience-http-client", clear, cookie, csrf, etag))
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &got) != nil || got.Audiences == nil || len(got.Audiences) != 0 {
		t.Fatalf("clear audience status=%d audience=%v body=%s", response.Code, got.Audiences, response.Body.String())
	}
}

func TestManagedClientHTTPAudienceValidationAndGuards(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	for _, body := range []string{
		`{"id":"audience-null","confidential":true,"redirect_uris":["https://app.example/cb"],"audience":null}`,
		`{"id":"audience-duplicate","confidential":true,"redirect_uris":["https://app.example/cb"],"audience":["https://api.example.test","https://api.example.test"]}`,
		`{"id":"audience-query","confidential":true,"redirect_uris":["https://app.example/cb"],"audience":["https://api.example.test/path?q=1"]}`,
	} {
		r := httptest.NewRecorder()
		h.Clients(r, managedRequest(http.MethodPost, "/auth/v1/clients", body, cookie, csrf, ""))
		if r.Code != http.StatusBadRequest {
			t.Fatalf("invalid audience status=%d body=%s", r.Code, r.Body.String())
		}
	}
	missingCSRF := httptest.NewRecorder()
	h.Clients(missingCSRF, managedRequest(http.MethodPost, "/auth/v1/clients", `{"id":"audience-csrf","confidential":true,"redirect_uris":["https://app.example/cb"]}`, cookie, "", ""))
	if missingCSRF.Code != http.StatusUnauthorized {
		t.Fatalf("missing CSRF status=%d", missingCSRF.Code)
	}
	missingCAS := httptest.NewRecorder()
	h.Client(missingCAS, audienceRequest(http.MethodPut, "/auth/v1/clients/audience-csrf", `{"confidential":true,"redirect_uris":["https://app.example/cb"],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"]}`, cookie, csrf, ""))
	if missingCAS.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing CAS status=%d", missingCAS.Code)
	}
}

func audienceRequest(method, path, body string, cookie *http.Cookie, csrf, etag string) *http.Request {
	r := managedRequest(method, path, body, cookie, csrf, etag)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	r.SetPathValue("id", parts[len(parts)-1])
	return r
}
