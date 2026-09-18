package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
)

func TestManagedClientHTTPDefaultAudienceCRUD(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	managed := managedHTTPStore(t, store)
	h.BindClients(managed)
	const id = "default-audience-http-client"
	create := `{"id":"` + id + `","name":"Exchange","confidential":true,"redirect_uris":[],"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["urn:ietf:params:oauth:grant-type:token-exchange"],"audience":["https://target.example.test/api"],"default_aud":["https://default.example.test/api"]}`
	response := httptest.NewRecorder()
	h.Clients(response, managedRequest(http.MethodPost, "/auth/v1/clients", create, cookie, csrf, ""))
	var created clients.Client
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || !slices.Equal(created.DefaultAudiences, []string{"https://default.example.test/api"}) || slices.Contains(created.Audiences, created.DefaultAudiences[0]) {
		t.Fatalf("create status=%d defaults=%v audience=%v", response.Code, created.DefaultAudiences, created.Audiences)
	}
	stored, err := managed.GetWithGuard(t.Context(), id, func() (string, []any) { return "1", nil })
	if err != nil {
		t.Fatal(err)
	}
	initialGeneration := stored.Generation

	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodGet, "/auth/v1/clients/"+id, "", cookie, "", ""))
	var got clients.Client
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &got) != nil || !slices.Equal(got.DefaultAudiences, created.DefaultAudiences) {
		t.Fatalf("get status=%d defaults=%v", response.Code, got.DefaultAudiences)
	}
	etag := response.Header().Get("ETag")
	update := `{"name":"Exchange","confidential":true,"redirect_uris":[],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["urn:ietf:params:oauth:grant-type:token-exchange"],"audience":["https://target.example.test/api"]}`
	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodPut, "/auth/v1/clients/"+id, update, cookie, csrf, etag))
	stored, err = managed.GetWithGuard(t.Context(), id, func() (string, []any) { return "1", nil })
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &got) != nil || !slices.Equal(got.DefaultAudiences, created.DefaultAudiences) || err != nil || stored.Generation != initialGeneration {
		t.Fatalf("preserve status=%d defaults=%v generation_matches=%t err=%v", response.Code, got.DefaultAudiences, err == nil && stored.Generation == initialGeneration, err)
	}
	etag = response.Header().Get("ETag")
	clear := update[:len(update)-1] + `,"default_aud":[]}`
	response = httptest.NewRecorder()
	h.Client(response, audienceRequest(http.MethodPut, "/auth/v1/clients/"+id, clear, cookie, csrf, etag))
	stored, err = managed.GetWithGuard(t.Context(), id, func() (string, []any) { return "1", nil })
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &got) != nil || got.DefaultAudiences == nil || len(got.DefaultAudiences) != 0 || err != nil || stored.Generation == initialGeneration {
		t.Fatalf("clear status=%d defaults=%v generation_rotated=%t err=%v", response.Code, got.DefaultAudiences, err == nil && stored.Generation != initialGeneration, err)
	}
}

func TestManagedClientHTTPDefaultAudienceValidation(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	for _, body := range []string{
		`{"id":"default-audience-null","confidential":true,"redirect_uris":[],"enabled_flows":["urn:ietf:params:oauth:grant-type:token-exchange"],"default_aud":null}`,
		`{"id":"default-audience-duplicate","confidential":true,"redirect_uris":[],"enabled_flows":["urn:ietf:params:oauth:grant-type:token-exchange"],"default_aud":["https://default.example.test/api","https://default.example.test/api"]}`,
	} {
		response := httptest.NewRecorder()
		h.Clients(response, managedRequest(http.MethodPost, "/auth/v1/clients", body, cookie, csrf, ""))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid default_aud status=%d body=%s", response.Code, response.Body.String())
		}
	}
}
