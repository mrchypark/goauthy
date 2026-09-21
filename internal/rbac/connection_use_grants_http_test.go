package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestConnectionUseGrantHTTPCRUDAndOwnerBoundary(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	cookie, csrf = memberSession(t, store)
	credentials := oauthCredentialHTTPStore(t, store)
	if err := h.BindSaaSCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	connector, err := saas.NewAPIKeyConnector(saas.APIKeyConnectorConfig{ID: "grant-provider", Header: "X-API-Key", Operations: []saas.APIKeyOperationConfig{{ID: "whoami", URL: "https://provider.example/me", ResponseFields: map[string]string{"id": "string"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for i, statement := range []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"grant-collection", "Grant", "api_key", 1, 1, "definition-generation", "[]", `[]`}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"grant-connection", "grant-collection", "member", "draft", 1, 1, "{}", "connection-generation"}},
		{SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?,?,?,?,?,?)`, Args: []any{"grant-consumer", "consumer-generation", 1, 1, 0, `{"name":"Consumer","confidential":true,"redirect_uris":[],"scopes":["goauthy.connections.use"],"default_scopes":["goauthy.connections.use"],"enabled_flows":["client_credentials"],"audience":["https://resource.example.test"]}`}},
	} {
		if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "grant-http-fixture-" + strconv.Itoa(i), SQL: statement.SQL, Args: statement.Args}); err != nil {
			t.Fatalf("fixture statement %d: %v", i, err)
		}
	}
	if _, err := credentials.PutBoundAPIKey(t.Context(), "member", "grant-collection", "grant-connection", 0, "bound-api-key", connector, connector.Digest(), func() (string, []any) { return "1", nil }); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, token, etag string, c *http.Cookie) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.SetPathValue("collection_id", "grant-collection")
		r.SetPathValue("connection_id", "grant-connection")
		if c != nil {
			r.AddCookie(c)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		return r
	}
	expires := time.Now().Add(time.Hour).UnixMilli()
	body := `{"consumer_client_id":"grant-consumer","mode":"proxy","purpose":"read","expires_at_unix_ms":` + strconv.FormatInt(expires, 10) + `}`
	w := httptest.NewRecorder()
	h.AccountConnectionUseGrants(w, request(http.MethodPost, "/auth/v1/account/connections/grant-collection/grant-connection/grants", body, csrf, "", cookie))
	if w.Code != http.StatusCreated || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("create status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}
	var grant saas.UseGrant
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil || grant.ID == "" {
		t.Fatalf("grant body=%s err=%v", w.Body.String(), err)
	}
	w = httptest.NewRecorder()
	h.AccountConnectionUseGrants(w, request(http.MethodGet, "/auth/v1/account/connections/grant-collection/grant-connection/grants", "", "", `"1"`, cookie))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("list If-Match status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.AccountConnectionUseGrants(w, request(http.MethodGet, "/auth/v1/account/connections/grant-collection/grant-connection/grants", "", "", "", cookie))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), grant.ID) {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	missingCAS := request(http.MethodDelete, "/auth/v1/account/connections/grant-collection/grant-connection/grants/"+grant.ID, "", csrf, "", cookie)
	missingCAS.SetPathValue("grant_id", grant.ID)
	w = httptest.NewRecorder()
	h.AccountConnectionUseGrant(w, missingCAS)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing CAS delete status=%d", w.Code)
	}
	del := request(http.MethodDelete, "/auth/v1/account/connections/grant-collection/grant-connection/grants/"+grant.ID, "", csrf, `"99"`, cookie)
	del.SetPathValue("grant_id", grant.ID)
	w = httptest.NewRecorder()
	h.AccountConnectionUseGrant(w, del)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d", w.Code)
	}
	del = request(http.MethodDelete, "/auth/v1/account/connections/grant-collection/grant-connection/grants/"+grant.ID, "", csrf, `"1"`, cookie)
	del.SetPathValue("grant_id", grant.ID)
	w = httptest.NewRecorder()
	h.AccountConnectionUseGrant(w, del)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d", w.Code)
	}
	for name, alter := range map[string]func(*http.Request){"no cookie": func(r *http.Request) { r.Header.Del("Cookie") }, "bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") }, "no csrf": func(r *http.Request) { r.Header.Del("X-CSRF-Token") }} {
		t.Run(name, func(t *testing.T) {
			r := request(http.MethodPost, "/auth/v1/account/connections/grant-collection/grant-connection/grants", body, csrf, "", cookie)
			alter(r)
			w := httptest.NewRecorder()
			h.AccountConnectionUseGrants(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

func TestConnectionUseGrantHTTPStrictJSONAndResourceGuard(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	path := "/auth/v1/account/connections/c/g/grants"
	for _, body := range []string{
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"unknown":true}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"mode":"proxy"}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1} trailing`,
		`{"consumer_client_id":null,"mode":"proxy","purpose":"p","expires_at_unix_ms":1}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"credential_version":null}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"credential_version":1.5}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"credential_version":"1"}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"credential_version":9223372036854775808}`,
		`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1,"credential_version":1,"credential_version":1}`,
	} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.SetPathValue("collection_id", "c")
		r.SetPathValue("connection_id", "g")
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.AccountConnectionUseGrants(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("strict body status=%d", w.Code)
		}
	}
	savedResource := h.connectionUseResource
	h.connectionUseResource = ""
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"consumer_client_id":"c","mode":"proxy","purpose":"p","expires_at_unix_ms":1}`))
	r.SetPathValue("collection_id", "c")
	r.SetPathValue("connection_id", "g")
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h.AccountConnectionUseGrants(w, r)
	h.connectionUseResource = savedResource
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing resource status=%d", w.Code)
	}
	for _, resource := range []string{"http://insecure.example.test", "https://resource.example.test#", "https://resource.example.test?", "https://resource.example.test/\u00a0", "https://user@resource.example.test", "https://resource.example.test/" + strings.Repeat("x", 2048)} {
		if err := h.BindConnectionUseResource(resource); err == nil {
			t.Fatalf("accepted invalid resource %q", resource)
		}
		if h.connectionUseResource != savedResource {
			t.Fatal("invalid configuration replaced the current resource")
		}
	}
}
