package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestBootstrapCredentialBodylessHTTP(t *testing.T) {
	h, store, _, _ := membershipHTTPFixture(t)
	memberSession(t, store)
	credentials := oauthCredentialHTTPStore(t, store)
	const resource = "https://resource.example.test"
	const clientID = "bootstrap-http-consumer"
	allow := func() (string, []any) { return "1", nil }
	cs := clients.NewStore(store.db, nil)
	if err := cs.EnsureBootstrap(t.Context(), clientID); err != nil {
		t.Fatal(err)
	}
	if err := cs.PinBootstrapConnections(t.Context(), clients.BootstrapConnectionConfig{Issuer: h.issuer, Resource: resource, AuthMethods: []string{"client_secret_basic", "client_secret_post"}, Client: clients.ConnectionPolicy{ID: clientID, Enabled: true, Confidential: true, Scopes: []string{"goauthy.connections.use"}, Audiences: []string{resource}}}); err != nil {
		t.Fatal(err)
	}
	for i, statement := range []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES('bootstrap-keys','Keys','api_key',1,1,'definition','[]','["http-key"]')`},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES('bootstrap-key','bootstrap-keys','member','draft',1,1,'{}','connection')`},
	} {
		if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "bootstrap-http-fixture-" + strconv.Itoa(i), SQL: statement.SQL}); err != nil {
			t.Fatal(err)
		}
	}
	connectorConfig := saas.APIKeyConnectorConfig{ID: "http-key", Header: "X-API-Key", Operations: []saas.APIKeyOperationConfig{{ID: "whoami", URL: "https://provider.example/me", ResponseFields: map[string]string{"id": "string"}}}}
	providers := providerHTTPStore(t, store)
	if _, err := providers.Create(t.Context(), saas.ProviderInput{ID: connectorConfig.ID, Name: "Synthetic provider", Kind: "api_key", Enabled: true, Connector: &connectorConfig}, allow); err != nil {
		t.Fatal(err)
	}
	connector, err := saas.NewAPIKeyConnector(connectorConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.PutBoundAPIKey(t.Context(), "member", "bootstrap-keys", "bootstrap-key", 0, "synthetic-http-key", connector, connector.Digest(), allow); err != nil {
		t.Fatal(err)
	}
	grant, err := credentials.CreateUseGrant(t.Context(), "member", "bootstrap-keys", "bootstrap-key", resource, saas.UseGrantInput{ConsumerClientID: clientID, Mode: "credential_delivery", Purpose: "synthetic HTTP test", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}, allow)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource(resource); err != nil {
		t.Fatal(err)
	}
	// Token verification is the existing injected boundary. This test exercises
	// the real HTTP handler and Rhiza policy/decryption, not OAuth issuance.
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "member", clientID, allow, nil
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v1/connection-grants/{grant_id}/credential", h.DeliverConnectionCredential)
	for _, tc := range []struct {
		body   string
		status int
	}{{"", 200}, {"{}", 400}} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/"+grant.ID+"/credential", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer synthetic-authority")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("bodyless contract: status=%d want=%d", w.Code, tc.status)
		}
		if tc.status == 200 {
			var response struct {
				Kind   string `json:"kind"`
				APIKey string `json:"api_key"`
			}
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Kind != "api_key" || response.APIKey != "synthetic-http-key" {
				t.Fatal("incorrect credential delivery")
			}
		}
	}
}
