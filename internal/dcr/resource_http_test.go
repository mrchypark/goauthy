package dcr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistrationHTTPAudienceMetadata(t *testing.T) {
	t.Parallel()
	h := testHandlerWithHandlerConfig(t, testGlobalToken, Config{}, HandlerConfig{AllowedResources: []string{"https://api.example.test"}})
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Audience RP","audience":["https://api.example.test"]}`
	first := httptest.NewRecorder()
	h.ServeHTTP(first, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, "audience-create"))
	if first.Code != http.StatusCreated || !strings.Contains(first.Body.String(), `"audience":["https://api.example.test"]`) {
		t.Fatalf("create status=%d body=%s", first.Code, first.Body.String())
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, "audience-create"))
	if replay.Code != http.StatusCreated || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var created registrationResponse
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	read := httptest.NewRecorder()
	h.ServeHTTP(read, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"audience":["https://api.example.test"]`) {
		t.Fatalf("read status=%d body=%s", read.Code, read.Body.String())
	}
	updateBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Audience RP","audience":[]}`
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updateBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusOK || strings.Contains(updated.Body.String(), `"audience"`) {
		t.Fatalf("clear status=%d body=%s", updated.Code, updated.Body.String())
	}
}

func TestRegistrationHTTPAudiencePolicy(t *testing.T) {
	t.Parallel()
	h := testHandlerWithHandlerConfig(t, testGlobalToken, Config{}, HandlerConfig{AllowedResources: []string{"https://api.example.test"}})
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Audience RP","audience":["https://api.example.test"]}`
	response := httptest.NewRecorder()
	forbiddenBody := strings.Replace(body, "https://api.example.test", "https://other.example.test", 1)
	h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, forbiddenBody, testGlobalToken, "audience-forbidden"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("forbidden audience status=%d body=%s", response.Code, response.Body.String())
	}
	for i, value := range []string{`"audience":null`, `"audience":["http://api.example.test"]`, `"audience":["https://api.example.test?x=1"]`, `"audience":["https://api.example.test","https://api.example.test"]`} {
		invalid := httptest.NewRecorder()
		h.ServeHTTP(invalid, requestWithKey(http.MethodPost, registrationPath, strings.Replace(body, `"audience":["https://api.example.test"]`, value, 1), testGlobalToken, "audience-invalid-"+string(rune('a'+i))))
		if invalid.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s status=%d body=%s", value, invalid.Code, invalid.Body.String())
		}
	}
}

func TestAnonymousRegistrationRejectsAudienceField(t *testing.T) {
	t.Parallel()
	h := testAnonymousHandler(t, time.Minute)
	for i, value := range []string{`"audience":null`, `"audience":[]`, `"audience":["https://api.example.test"]`} {
		body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Anonymous RP",` + value + `}`
		response := httptest.NewRecorder()
		h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, "", "anonymous-audience-"+string(rune('a'+i))))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("audience=%s status=%d body=%s", value, response.Code, response.Body.String())
		}
	}
}
