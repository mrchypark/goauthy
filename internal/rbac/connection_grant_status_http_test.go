package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserResourceConnectionUseGrantStatusBoundary(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	credentials := oauthCredentialHTTPStore(t, store)
	if err := h.BindSaaSCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://status-resource.example"); err != nil {
		t.Fatal(err)
	}
	_, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "grant-status-http-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"status-collection", "Status", "api_key", 1, 1, "definition-generation", "[]", `[]`}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"status-connection", "status-collection", "member", "draft", 1, 1, "{}", "connection-generation"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "grant-status-client", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?,?,?,?,?,?)`, Args: []any{"other-consumer", "consumer-generation", 1, 1, 0, `{"confidential":true,"scopes":["goauthy.connections.use"],"audience":["https://status-resource.example"]}`}})
	if err != nil {
		t.Fatal(err)
	}
	grant := saas.UseGrant{ID: "status-grant", Owner: "member", CollectionID: "status-collection", ConnectionID: "status-connection", ConsumerClientID: "other-consumer", Mode: "proxy", Purpose: "read", Resource: "https://status-resource.example", Generation: "connection-generation", ConsumerGeneration: "consumer-generation", ProviderID: "api-key", Revision: 1, ProviderRevision: 0, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
	_, err = storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "grant-status-row", SQL: `INSERT INTO saas_use_grants(id,owner_subject,collection_id,connection_id,consumer_client_id,mode,purpose,resource,generation,consumer_generation,provider_id,connector_digest,revision,provider_revision,expires_at_unix_ms,revoked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{grant.ID, grant.Owner, grant.CollectionID, grant.ConnectionID, grant.ConsumerClientID, grant.Mode, grant.Purpose, grant.Resource, grant.Generation, grant.ConsumerGeneration, grant.ProviderID, "", grant.Revision, grant.ProviderRevision, grant.ExpiresAt, 0}})
	if err != nil {
		t.Fatal(err)
	}

	var scopes []string
	if err := h.BindConnectionResourceAuthorizer(func(_ *http.Request, scope string) (string, func() (string, []any), error) {
		scopes = append(scopes, scope)
		return "member", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(""))
		r.SetPathValue("collection_id", "status-collection")
		r.SetPathValue("connection_id", "status-connection")
		r.SetPathValue("grant_id", grant.ID)
		r.Header.Set("Authorization", "Bearer external-token")
		return r
	}
	r := request(http.MethodGet, "/auth/v1/connections/status-collection/status-connection/grants/"+grant.ID)
	w := httptest.NewRecorder()
	h.UserResourceConnectionUseGrant(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	var body struct {
		Grant struct {
			Consumer string `json:"consumer_client_id"`
			Resource string `json:"resource"`
		} `json:"grant"`
		Generation string `json:"connection_generation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Grant.Consumer != "other-consumer" || body.Grant.Resource != "https://status-resource.example" || body.Generation != "connection-generation" {
		t.Fatalf("body=%s err=%v", w.Body.String(), err)
	}
	if len(scopes) != 1 || scopes[0] != "goauthy.connections.read" {
		t.Fatalf("scopes=%v", scopes)
	}

	for name, alter := range map[string]func(*http.Request){
		"query":                 func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":           func(r *http.Request) { r.URL.ForceQuery = true },
		"empty cookie":          func(r *http.Request) { r.Header["Cookie"] = []string{""} },
		"cookie":                func(r *http.Request) { r.Header.Set("Cookie", "sid=token") },
		"if-match":              func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
		"missing authorization": func(r *http.Request) { r.Header.Del("Authorization") },
		"body":                  func(r *http.Request) { r.Body = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x")).Body },
	} {
		t.Run(name, func(t *testing.T) {
			r := request(http.MethodGet, "/auth/v1/connections/status-collection/status-connection/grants/"+grant.ID)
			alter(r)
			w := httptest.NewRecorder()
			h.UserResourceConnectionUseGrant(w, r)
			want := http.StatusUnauthorized
			if name == "body" || name == "if-match" {
				want = http.StatusBadRequest
			}
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
		})
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := request(method, "/auth/v1/connections/status-collection/status-connection/grants/"+grant.ID)
		w := httptest.NewRecorder()
		h.UserResourceConnectionUseGrant(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
	h2, _, _, _ := membershipHTTPFixture(t)
	r = request(http.MethodGet, "/auth/v1/connections/status-collection/status-connection/grants/"+grant.ID)
	w = httptest.NewRecorder()
	h2.UserResourceConnectionUseGrant(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing config status=%d", w.Code)
	}
}
