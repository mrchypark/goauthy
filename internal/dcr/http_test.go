package dcr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
)

const testGlobalToken = "0123456789abcdef0123456789abcdef"

func TestRegistrationHTTPCreateAndGet(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post","client_name":"Example RP","client_uri":"https://rp.example.test"}`
	post := request(http.MethodPost, "/oidc/register", body, testGlobalToken)
	created := httptest.NewRecorder()
	h.ServeHTTP(created, post)
	if created.Code != http.StatusCreated || created.Header().Get("Cache-Control") != "no-store" || created.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("create status=%d headers=%v body=%s", created.Code, created.Header(), created.Body.String())
	}
	var registration registrationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	if registration.ClientID == "" || registration.ClientSecret == "" || registration.ClientSecretExpiresAt != 0 || !strings.Contains(created.Body.String(), `"client_secret_expires_at":0`) || registration.ClientURI != "https://rp.example.test" || registration.RegistrationAccessToken == "" || registration.RegistrationClientURI != "https://id.example.test/oidc/register/"+registration.ClientID || strings.Contains(created.Body.String(), `"force_mfa"`) {
		t.Fatalf("create response=%+v", registration)
	}

	get := httptest.NewRequest(http.MethodGet, registration.RegistrationClientURI, nil)
	get.Header.Set("Authorization", "Bearer "+registration.RegistrationAccessToken)
	read := httptest.NewRecorder()
	h.ServeHTTP(read, get)
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), registration.ClientSecret) || strings.Contains(read.Body.String(), registration.RegistrationAccessToken) {
		t.Fatalf("get status=%d body=%s", read.Code, read.Body.String())
	}
	var loaded registrationResponse
	if err := json.Unmarshal(read.Body.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.ClientID != registration.ClientID || loaded.ClientSecretExpiresAt != 0 || !strings.Contains(read.Body.String(), `"client_secret_expires_at":0`) || loaded.ClientURI != registration.ClientURI || loaded.RegistrationClientURI != "" || loaded.RegistrationAccessToken != "" || loaded.ClientSecret != "" || strings.Contains(read.Body.String(), `"force_mfa"`) {
		t.Fatalf("get response=%+v", loaded)
	}

	wrong := httptest.NewRequest(http.MethodGet, registration.RegistrationClientURI, nil)
	wrong.Header.Set("Authorization", "Bearer wrong")
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, wrong)
	if denied.Code != http.StatusUnauthorized || denied.Header().Get("WWW-Authenticate") == "" || strings.Contains(denied.Body.String(), registration.ClientSecret) || strings.Contains(denied.Body.String(), registration.RegistrationAccessToken) {
		t.Fatalf("wrong get status=%d headers=%v body=%s", denied.Code, denied.Header(), denied.Body.String())
	}
}

func TestRegistrationHTTPContactsCanonicalAndReplacementSemantics(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Contacts RP","contacts":["support@example.test","mailto:z@example.test"]}`
	created := registerClientWithKey(t, h, body, "contacts-create")
	if len(created.Contacts) != 2 || created.Contacts[0] != "mailto:z@example.test" || created.Contacts[1] != "support@example.test" {
		t.Fatalf("created contacts=%v", created.Contacts)
	}
	get := httptest.NewRecorder()
	h.ServeHTTP(get, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
	if get.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", get.Code, get.Body.String())
	}
	var loaded registrationResponse
	if err := json.Unmarshal(get.Body.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Contacts) != 2 || loaded.Contacts[0] != "mailto:z@example.test" || loaded.Contacts[1] != "support@example.test" {
		t.Fatalf("loaded contacts=%v", loaded.Contacts)
	}

	putBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Contacts RP","contacts":["support@example.test","mailto:z@example.test"]}`
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, putBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusOK {
		t.Fatalf("reordered update status=%d body=%s", updated.Code, updated.Body.String())
	}
	var afterUpdate registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &afterUpdate); err != nil {
		t.Fatal(err)
	}
	if len(afterUpdate.Contacts) != 2 || afterUpdate.Contacts[0] != "mailto:z@example.test" || afterUpdate.Contacts[1] != "support@example.test" {
		t.Fatalf("updated contacts=%v", afterUpdate.Contacts)
	}

	for _, body := range []string{
		`{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Contacts RP"}`,
		`{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Contacts RP","contacts":null}`,
		`{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Contacts RP","contacts":[]}`,
	} {
		updated = httptest.NewRecorder()
		h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, body, afterUpdate.RegistrationAccessToken))
		if updated.Code != http.StatusOK {
			t.Fatalf("clear update status=%d body=%s", updated.Code, updated.Body.String())
		}
		if strings.Contains(updated.Body.String(), `"contacts"`) {
			t.Fatalf("cleared contacts were returned: %s", updated.Body.String())
		}
		if err := json.Unmarshal(updated.Body.Bytes(), &afterUpdate); err != nil {
			t.Fatal(err)
		}
	}

	postNull := httptest.NewRecorder()
	h.ServeHTTP(postNull, requestWithKey(http.MethodPost, registrationPath, strings.Replace(body, `,"contacts":["support@example.test","mailto:z@example.test"]`, `,"contacts":null`, 1), testGlobalToken, "contacts-null"))
	if postNull.Code != http.StatusBadRequest {
		t.Fatalf("POST contacts null status=%d body=%s", postNull.Code, postNull.Body.String())
	}
	postEmpty := httptest.NewRecorder()
	h.ServeHTTP(postEmpty, requestWithKey(http.MethodPost, registrationPath, strings.Replace(body, `,"contacts":["support@example.test","mailto:z@example.test"]`, `,"contacts":[]`, 1), testGlobalToken, "contacts-empty"))
	if postEmpty.Code != http.StatusCreated || strings.Contains(postEmpty.Body.String(), `"contacts"`) {
		t.Fatalf("POST contacts empty status=%d body=%s", postEmpty.Code, postEmpty.Body.String())
	}
}

func TestRegistrationHTTPURIMetadataCanonicalAndReplacementSemantics(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"URI RP","logo_uri":"https://rp.example.test/logo.svg","tos_uri":"https://rp.example.test/terms","policy_uri":"https://rp.example.test/privacy"}`
	created := registerClientWithKey(t, h, body, "uri-create")
	if created.LogoURI != "https://rp.example.test/logo.svg" || created.TOSURI != "https://rp.example.test/terms" || created.PolicyURI != "https://rp.example.test/privacy" {
		t.Fatalf("created URI metadata=%+v", created)
	}
	get := httptest.NewRecorder()
	h.ServeHTTP(get, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"logo_uri":"https://rp.example.test/logo.svg"`) || !strings.Contains(get.Body.String(), `"tos_uri":"https://rp.example.test/terms"`) || !strings.Contains(get.Body.String(), `"policy_uri":"https://rp.example.test/privacy"`) {
		t.Fatalf("get status=%d body=%s", get.Code, get.Body.String())
	}
	updatedBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"URI RP","logo_uri":"https://cdn.example.test/logo.svg","tos_uri":"https://cdn.example.test/terms","policy_uri":"https://cdn.example.test/privacy"}`
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updatedBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"logo_uri":"https://cdn.example.test/logo.svg"`) || !strings.Contains(updated.Body.String(), `"tos_uri":"https://cdn.example.test/terms"`) || !strings.Contains(updated.Body.String(), `"policy_uri":"https://cdn.example.test/privacy"`) {
		t.Fatalf("updated status=%d body=%s", updated.Code, updated.Body.String())
	}
	var updatedRegistration registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &updatedRegistration); err != nil {
		t.Fatal(err)
	}
	clearBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"URI RP","logo_uri":null,"tos_uri":null,"policy_uri":null}`
	cleared := httptest.NewRecorder()
	h.ServeHTTP(cleared, request(http.MethodPut, registrationPath+"/"+created.ClientID, clearBody, updatedRegistration.RegistrationAccessToken))
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), `"logo_uri"`) || strings.Contains(cleared.Body.String(), `"tos_uri"`) || strings.Contains(cleared.Body.String(), `"policy_uri"`) {
		t.Fatalf("null clear status=%d body=%s", cleared.Code, cleared.Body.String())
	}
	var clearedRegistration registrationResponse
	if err := json.Unmarshal(cleared.Body.Bytes(), &clearedRegistration); err != nil {
		t.Fatal(err)
	}
	omissionBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"URI RP"}`
	omitted := httptest.NewRecorder()
	h.ServeHTTP(omitted, request(http.MethodPut, registrationPath+"/"+created.ClientID, omissionBody, clearedRegistration.RegistrationAccessToken))
	if omitted.Code != http.StatusOK || strings.Contains(omitted.Body.String(), `"logo_uri"`) || strings.Contains(omitted.Body.String(), `"tos_uri"`) || strings.Contains(omitted.Body.String(), `"policy_uri"`) {
		t.Fatalf("omission clear status=%d body=%s", omitted.Code, omitted.Body.String())
	}

	for _, field := range []string{"logo_uri", "tos_uri", "policy_uri"} {
		invalid := strings.Replace(body, `"`+field+`":"https://rp.example.test/`+map[string]string{"logo_uri": "logo.svg", "tos_uri": "terms", "policy_uri": "privacy"}[field]+`"`, `"`+field+`":"http://rp.example.test/value?next=bad"`, 1)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, invalid, testGlobalToken, "uri-invalid-"+field))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s status=%d body=%s", field, response.Code, response.Body.String())
		}
	}
	for _, field := range []string{"logo_uri", "tos_uri", "policy_uri"} {
		invalidNull := strings.Replace(body, `"`+field+`":"https://rp.example.test/`+map[string]string{"logo_uri": "logo.svg", "tos_uri": "terms", "policy_uri": "privacy"}[field]+`"`, `"`+field+`":null`, 1)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, invalidNull, testGlobalToken, "uri-null-"+field))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("POST null %s status=%d body=%s", field, response.Code, response.Body.String())
		}
	}
}

func TestRegistrationHTTPDeviceGrantMetadata(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	for _, test := range []struct {
		name, body                   string
		wantRedirects, wantResponses int
	}{
		{
			name: "device only",
			body: `{"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Device RP"}`,
		},
		{
			name: "device with refresh",
			body: `{"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Device Refresh RP"}`,
		},
		{
			name:          "authorization code and device",
			body:          `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Hybrid RP"}`,
			wantRedirects: 1, wantResponses: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			post := request(http.MethodPost, registrationPath, test.body, testGlobalToken)
			post.Header.Set("Idempotency-Key", "test-"+strings.ReplaceAll(test.name, " ", "-"))
			h.ServeHTTP(response, post)
			if response.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var registration registrationResponse
			if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
				t.Fatal(err)
			}
			if len(registration.RedirectURIs) != test.wantRedirects || len(registration.ResponseTypes) != test.wantResponses || (test.name == "authorization code and device" && len(registration.GrantTypes) != 2) {
				t.Fatalf("registration=%+v", registration)
			}
			if test.name == "device only" && (len(registration.GrantTypes) != 1 || registration.GrantTypes[0] != deviceGrantType) {
				t.Fatalf("device registration=%+v", registration)
			}
			if test.name == "device with refresh" && (len(registration.GrantTypes) != 2 || !contains(registration.GrantTypes, "refresh_token")) {
				t.Fatalf("device refresh registration=%+v", registration)
			}
		})
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request(http.MethodPost, registrationPath, `{"grant_types":["refresh_token"],"token_endpoint_auth_method":"none","client_name":"Invalid Refresh Only"}`, testGlobalToken))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("refresh-only registration status=%d", response.Code)
	}
}

func TestRegistrationHTTPDeviceGrantUpdateUsesSameMetadataRules(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	created := registerClient(t, h, `{"redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Device RP"}`)
	updatedBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Hybrid RP"}`
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updatedBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	var registration registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	if len(registration.RedirectURIs) != 1 || len(registration.ResponseTypes) != 1 || len(registration.GrantTypes) != 2 {
		t.Fatalf("updated registration=%+v", registration)
	}
	for _, body := range []string{
		`{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"response_types":[],"token_endpoint_auth_method":"none","client_name":"Device RP"}`,
		`{"client_id":"` + created.ClientID + `","redirect_uris":[],"grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Device RP"}`,
	} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request(http.MethodPut, registrationPath+"/"+created.ClientID, body, registration.RegistrationAccessToken))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid update status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestRegistrationHTTPDelete(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	created := registerClient(t, h, `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Delete me"}`)
	path := registrationPath + "/" + created.ClientID

	for _, test := range []struct {
		name, method, path, token, body string
		duplicateAuth                   bool
		want                            int
	}{
		{"wrong method", http.MethodPost, path, created.RegistrationAccessToken, "", false, http.StatusNotFound},
		{"collection", http.MethodDelete, registrationPath, created.RegistrationAccessToken, "", false, http.StatusNotFound},
		{"nested", http.MethodDelete, path + "/extra", created.RegistrationAccessToken, "", false, http.StatusNotFound},
		{"escaped nested", http.MethodDelete, registrationPath + "/" + created.ClientID + "%2Fextra", created.RegistrationAccessToken, "", false, http.StatusNotFound},
		{"query", http.MethodDelete, path + "?next=bad", created.RegistrationAccessToken, "", false, http.StatusBadRequest},
		{"body", http.MethodDelete, path, created.RegistrationAccessToken, `{}`, false, http.StatusBadRequest},
		{"missing token", http.MethodDelete, path, "", "", false, http.StatusUnauthorized},
		{"malformed token", http.MethodDelete, path, created.RegistrationAccessToken + " extra", "", false, http.StatusUnauthorized},
		{"repeated token", http.MethodDelete, path, created.RegistrationAccessToken, "", true, http.StatusUnauthorized},
		{"global DCR token", http.MethodDelete, path, testGlobalToken, "", false, http.StatusUnauthorized},
		{"wrong token", http.MethodDelete, path, "wrong", "", false, http.StatusUnauthorized},
		{"unknown client", http.MethodDelete, registrationPath + "/missing", created.RegistrationAccessToken, "", false, http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			req := request(test.method, test.path, test.body, test.token)
			if test.duplicateAuth {
				req.Header.Add("Authorization", "Bearer another-token")
			}
			h.ServeHTTP(response, req)
			if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if test.want == http.StatusUnauthorized && (response.Header().Get("WWW-Authenticate") == "" || strings.Contains(response.Body.String(), created.ClientID) || strings.Contains(response.Body.String(), created.RegistrationAccessToken)) {
				t.Fatalf("authentication failure leaked registration: headers=%v body=%s", response.Header(), response.Body.String())
			}
		})
	}
	forceQuery := httptest.NewRecorder()
	forceQueryRequest := request(http.MethodDelete, path, "", created.RegistrationAccessToken)
	forceQueryRequest.URL.ForceQuery = true
	h.ServeHTTP(forceQuery, forceQueryRequest)
	if forceQuery.Code != http.StatusBadRequest {
		t.Fatalf("empty query status=%d body=%s", forceQuery.Code, forceQuery.Body.String())
	}

	deleted := httptest.NewRecorder()
	h.ServeHTTP(deleted, request(http.MethodDelete, path, "", created.RegistrationAccessToken))
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 || deleted.Header().Get("Cache-Control") != "no-store" || deleted.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("delete status=%d headers=%v body=%q", deleted.Code, deleted.Header(), deleted.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		body := ""
		if method == http.MethodPut {
			body = `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Delete me"}`
		}
		h.ServeHTTP(response, request(method, path, body, created.RegistrationAccessToken))
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" || strings.Contains(response.Body.String(), created.ClientID) {
			t.Fatalf("post-delete %s status=%d headers=%v body=%s", method, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestRegistrationHTTPRejectsForceMFA(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	base := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Example RP"}`
	created := registerClient(t, h, base)
	for _, body := range []string{
		strings.Replace(base, `}`, `,"force_mfa":true}`, 1),
		strings.Replace(base, `}`, `,"force_mfa":null}`, 1),
		strings.Replace(base, `}`, `,"force_mfa":"true"}`, 1),
	} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request(http.MethodPost, registrationPath, body, testGlobalToken))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("force_mfa status=%d body=%s", response.Code, response.Body.String())
		}
	}
	updatedBody := strings.Replace(base, `}`, `,"force_mfa":true}`, 1)
	updated := httptest.NewRecorder()
	updatedBody = strings.Replace(updatedBody, `{`, `{"client_id":"`+created.ClientID+`",`, 1)
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updatedBody, created.RegistrationAccessToken))
	if updated.Code != http.StatusBadRequest {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
}

func TestRegistrationHTTPRejectsUntrustedInput(t *testing.T) {
	t.Parallel()
	valid := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Example RP"}`
	for _, test := range []struct {
		name, method, path, contentType, token, body string
		want                                         int
	}{
		{"disabled", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid, http.StatusNotFound},
		{"method", http.MethodPut, registrationPath, "application/json", testGlobalToken, valid, http.StatusNotFound},
		{"post item path", http.MethodPost, registrationPath + "/client", "application/json", testGlobalToken, valid, http.StatusNotFound},
		{"get collection path", http.MethodGet, registrationPath, "application/json", testGlobalToken, "", http.StatusNotFound},
		{"get nested item path", http.MethodGet, registrationPath + "/client/extra", "application/json", testGlobalToken, "", http.StatusNotFound},
		{"get encoded nested item path", http.MethodGet, registrationPath + "/client%2Fextra", "application/json", testGlobalToken, "", http.StatusNotFound},
		{"missing auth", http.MethodPost, registrationPath, "application/json", "", valid, http.StatusUnauthorized},
		{"wrong auth", http.MethodPost, registrationPath, "application/json", "wrong", valid, http.StatusUnauthorized},
		{"content type", http.MethodPost, registrationPath, "text/plain", testGlobalToken, valid, http.StatusBadRequest},
		{"duplicate content type", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid, http.StatusBadRequest},
		{"unknown field", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"jwks_uri":"https://bad.example"}`, http.StatusBadRequest},
		{"client ID supplied", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_id":"client"}`, http.StatusBadRequest},
		{"client URI null", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_uri":null}`, http.StatusBadRequest},
		{"client URI http", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_uri":"http://rp.example.test"}`, http.StatusBadRequest},
		{"client URI query", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_uri":"https://rp.example.test/info?next=bad"}`, http.StatusBadRequest},
		{"client URI empty", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_uri":""}`, http.StatusBadRequest},
		{"contacts null", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":null}`, http.StatusBadRequest},
		{"contacts scalar", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":"support@example.test"}`, http.StatusBadRequest},
		{"contacts empty item", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":[""]}`, http.StatusBadRequest},
		{"contacts too long", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":["` + strings.Repeat("a", 49) + `"]}`, http.StatusBadRequest},
		{"contacts invalid character", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":["support@example.test?x=1"]}`, http.StatusBadRequest},
		{"contacts duplicate", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":["support@example.test","support@example.test"]}`, http.StatusBadRequest},
		{"contacts too many", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"contacts":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","aa","ab","ac","ad","ae","af","ag"]}`, http.StatusBadRequest},
		{"duplicate field", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid[:len(valid)-1] + `,"client_name":"Other RP"}`, http.StatusBadRequest},
		{"multiple objects", http.MethodPost, registrationPath, "application/json", testGlobalToken, valid + `{}`, http.StatusBadRequest},
		{"http redirect", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, "https://rp.example.test/callback", "http://localhost/callback", 1), http.StatusBadRequest},
		{"redirect query", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, "https://rp.example.test/callback", "https://rp.example.test/callback?next=https://evil.example", 1), http.StatusBadRequest},
		{"redirect userinfo", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, "https://rp.example.test/callback", "https://good@evil.example/callback", 1), http.StatusBadRequest},
		{"duplicate redirect", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, `["https://rp.example.test/callback"]`, `["https://rp.example.test/callback","https://rp.example.test/callback"]`, 1), http.StatusBadRequest},
		{"unknown grant", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, "authorization_code", "unsupported", 1), http.StatusBadRequest},
		{"wrong response", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, `"code"`, `"token"`, 1), http.StatusBadRequest},
		{"client selected scope", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Replace(valid, `"client_name"`, `"scope":"admin","client_name"`, 1), http.StatusBadRequest},
		{"oversized", http.MethodPost, registrationPath, "application/json", testGlobalToken, strings.Repeat("x", registrationBodyLimit+1), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			var h http.Handler
			if test.name == "disabled" {
				h = testHandler(t, "")
			} else {
				h = testHandler(t, testGlobalToken)
			}
			req := request(test.method, test.path, test.body, test.token)
			req.Header.Set("Content-Type", test.contentType)
			if test.name == "duplicate content type" {
				req.Header.Add("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" && test.want != http.StatusNotFound {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if test.body != "" && strings.Contains(response.Body.String(), test.body) {
				t.Fatalf("error reflected request body: %s", response.Body.String())
			}
		})
	}
}

func TestClientURIValidationIsStrictAndBounded(t *testing.T) {
	t.Parallel()
	store := NewStore(nil)
	base := validRequest("client-uri", TokenEndpointAuthClientBasic)
	for _, uri := range []string{
		"http://rp.example.test",
		"https://",
		"https://user:pass@rp.example.test",
		"https://rp.example.test/info?next=bad",
		"https://rp.example.test/info#fragment",
		"https://RP.example.test/info",
		"https://rp.example.test/" + strings.Repeat("a", 2048),
	} {
		request := base
		request.ClientURI = uri
		if err := store.validateCreateRequest(request); err == nil {
			t.Fatalf("client URI %q was accepted", uri)
		}
	}
	base.ClientURI = "https://rp.example.test/info"
	if err := store.validateCreateRequest(base); err != nil {
		t.Fatalf("valid client URI rejected: %v", err)
	}
}

func TestRegistrationHTTPPublicClientDoesNotReceiveSecret(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request(http.MethodPost, "/oidc/register", `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Public RP"}`, testGlobalToken))
	var registration registrationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil || response.Code != http.StatusCreated || registration.ClientSecret != "" || registration.RegistrationAccessToken == "" {
		t.Fatalf("status=%d registration=%+v err=%v", response.Code, registration, err)
	}
}

func TestRegistrationHTTPAnonymousCreate(t *testing.T) {
	t.Parallel()
	h := testAnonymousHandler(t, time.Minute)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Anonymous RP"}`
	metadataBody := strings.Replace(body, `}`, `,"logo_uri":"https://rp.example.test/logo.svg"}`, 1)
	rejectedMetadata := httptest.NewRecorder()
	h.ServeHTTP(rejectedMetadata, requestWithKey(http.MethodPost, registrationPath, metadataBody, "", "metadata-key").WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.10")))
	if rejectedMetadata.Code != http.StatusBadRequest {
		t.Fatalf("anonymous metadata create status=%d body=%s", rejectedMetadata.Code, rejectedMetadata.Body.String())
	}
	clientURIBody := strings.Replace(body, `}`, `,"client_uri":"https://rp.example.test"}`, 1)
	rejectedClientURI := httptest.NewRecorder()
	h.ServeHTTP(rejectedClientURI, requestWithKey(http.MethodPost, registrationPath, clientURIBody, "", "client-uri-key").WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.10")))
	if rejectedClientURI.Code != http.StatusBadRequest {
		t.Fatalf("anonymous client URI create status=%d body=%s", rejectedClientURI.Code, rejectedClientURI.Body.String())
	}

	missingPeer := httptest.NewRecorder()
	h.ServeHTTP(missingPeer, request(http.MethodPost, registrationPath, body, ""))
	if missingPeer.Code != http.StatusBadRequest {
		t.Fatalf("missing peer status=%d body=%s", missingPeer.Code, missingPeer.Body.String())
	}

	withBearer := httptest.NewRecorder()
	h.ServeHTTP(withBearer, request(http.MethodPost, registrationPath, body, testGlobalToken).WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.9")))
	if withBearer.Code != http.StatusUnauthorized {
		t.Fatalf("bearer status=%d body=%s", withBearer.Code, withBearer.Body.String())
	}

	created := httptest.NewRecorder()
	first := request(http.MethodPost, registrationPath, body, "").WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.9"))
	h.ServeHTTP(created, first)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var registration registrationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	read := httptest.NewRecorder()
	h.ServeHTTP(read, request(http.MethodGet, registrationPath+"/"+registration.ClientID, "", registration.RegistrationAccessToken))
	if read.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", read.Code, read.Body.String())
	}
	updateWithMetadata := strings.Replace(metadataBody, `{`, `{"client_id":"`+registration.ClientID+`",`, 1)
	rejectedUpdate := httptest.NewRecorder()
	h.ServeHTTP(rejectedUpdate, request(http.MethodPut, registrationPath+"/"+registration.ClientID, updateWithMetadata, registration.RegistrationAccessToken))
	if rejectedUpdate.Code != http.StatusBadRequest {
		t.Fatalf("anonymous metadata update status=%d body=%s", rejectedUpdate.Code, rejectedUpdate.Body.String())
	}
	updateWithClientURI := strings.Replace(clientURIBody, `{`, `{"client_id":"`+registration.ClientID+`",`, 1)
	rejectedClientURIUpdate := httptest.NewRecorder()
	h.ServeHTTP(rejectedClientURIUpdate, request(http.MethodPut, registrationPath+"/"+registration.ClientID, updateWithClientURI, registration.RegistrationAccessToken))
	if rejectedClientURIUpdate.Code != http.StatusBadRequest {
		t.Fatalf("anonymous client URI update status=%d body=%s", rejectedClientURIUpdate.Code, rejectedClientURIUpdate.Body.String())
	}
	readAfter := httptest.NewRecorder()
	h.ServeHTTP(readAfter, request(http.MethodGet, registrationPath+"/"+registration.ClientID, "", registration.RegistrationAccessToken))
	if readAfter.Code != http.StatusOK || strings.Contains(readAfter.Body.String(), `"logo_uri"`) || strings.Contains(readAfter.Body.String(), `"client_uri"`) {
		t.Fatalf("anonymous metadata persisted status=%d body=%s", readAfter.Code, readAfter.Body.String())
	}

	limited := httptest.NewRecorder()
	second := request(http.MethodPost, registrationPath, strings.Replace(body, "Anonymous RP", "Second RP", 1), "").WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.9"))
	second.Header.Set("Idempotency-Key", "second-key")
	if key, ok := idempotencyKey(second); !ok || key != "second-key" {
		t.Fatalf("idempotency key=%q ok=%t", key, ok)
	}
	h.ServeHTTP(limited, second)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("X-Retry-Not-Before") == "" || limited.Header().Get("Retry-After") != "" || limited.Header().Get("Cache-Control") != "no-store" || limited.Header().Get("X-Content-Type-Options") != "nosniff" || limited.Body.String() != "Too Many Requests\n" {
		t.Fatalf("limited status=%d headers=%v body=%q", limited.Code, limited.Header(), limited.Body.String())
	}
}

func TestRegistrationHTTPPublicUpdateRotatesOnlyAccessToken(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Public RP"}`
	created := registerClient(t, h, body)
	body = strings.Replace(body, `{`, `{"client_id":"`+created.ClientID+`",`, 1)
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, body, created.RegistrationAccessToken))
	var response registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &response); err != nil || updated.Code != http.StatusOK || response.ClientSecret != "" || response.RegistrationAccessToken == "" || response.RegistrationAccessToken == created.RegistrationAccessToken || response.RegistrationClientURI == "" {
		t.Fatalf("status=%d registration=%+v err=%v", updated.Code, response, err)
	}
	read := httptest.NewRecorder()
	h.ServeHTTP(read, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", response.RegistrationAccessToken))
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), response.RegistrationAccessToken) || strings.Contains(read.Body.String(), created.RegistrationAccessToken) {
		t.Fatalf("GET status=%d body=%s", read.Code, read.Body.String())
	}
}

func TestRegistrationHTTPUpdate(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	created := registerClient(t, h, `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Before Update","client_uri":"https://rp.example.test"}`)
	updatedBody := `{"client_id":"` + created.ClientID + `","redirect_uris":["https://rp.example.test/updated"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"After Update","client_uri":"https://updated.example.test"}`
	put := request(http.MethodPut, registrationPath+"/"+created.ClientID, updatedBody, created.RegistrationAccessToken)
	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, put)
	if updated.Code != http.StatusOK || updated.Header().Get("Cache-Control") != "no-store" || strings.Contains(updated.Body.String(), created.ClientSecret) || strings.Contains(updated.Body.String(), created.RegistrationAccessToken) {
		t.Fatalf("update status=%d headers=%v body=%s", updated.Code, updated.Header(), updated.Body.String())
	}
	var response registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ClientID != created.ClientID || response.ClientName != "After Update" || response.ClientURI != "https://updated.example.test" || len(response.RedirectURIs) != 1 || response.RedirectURIs[0] != "https://rp.example.test/updated" || response.ClientSecret == "" || response.ClientSecret == created.ClientSecret || response.RegistrationAccessToken == "" || response.RegistrationAccessToken == created.RegistrationAccessToken || response.RegistrationClientURI != "https://id.example.test/oidc/register/"+created.ClientID {
		t.Fatalf("update response=%+v", response)
	}
	oldGet := httptest.NewRecorder()
	h.ServeHTTP(oldGet, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
	if oldGet.Code != http.StatusUnauthorized {
		t.Fatalf("old token GET=%d", oldGet.Code)
	}
	newGet := httptest.NewRecorder()
	h.ServeHTTP(newGet, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", response.RegistrationAccessToken))
	if newGet.Code != http.StatusOK || !strings.Contains(newGet.Body.String(), `"client_uri":"https://updated.example.test"`) || strings.Contains(newGet.Body.String(), response.ClientSecret) || strings.Contains(newGet.Body.String(), response.RegistrationAccessToken) {
		t.Fatalf("new token GET=%d body=%s", newGet.Code, newGet.Body.String())
	}
	clearBody := strings.Replace(updatedBody, `,"client_uri":"https://updated.example.test"`, `,"client_uri":null`, 1)
	cleared := httptest.NewRecorder()
	h.ServeHTTP(cleared, request(http.MethodPut, registrationPath+"/"+created.ClientID, clearBody, response.RegistrationAccessToken))
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), `"client_uri"`) {
		t.Fatalf("null client URI clear status=%d body=%s", cleared.Code, cleared.Body.String())
	}
	var clearedRegistration registrationResponse
	if err := json.Unmarshal(cleared.Body.Bytes(), &clearedRegistration); err != nil {
		t.Fatal(err)
	}

	missingID := strings.Replace(updatedBody, `"client_id":"`+created.ClientID+`",`, "", 1)
	mismatchedID := strings.Replace(updatedBody, created.ClientID, "other-client", 1)
	for _, test := range []struct {
		name, path, token, body string
		want                    int
	}{
		{"wrong token", registrationPath + "/" + created.ClientID, "wrong", updatedBody, http.StatusUnauthorized},
		{"unknown id", registrationPath + "/missing", created.RegistrationAccessToken, updatedBody, http.StatusUnauthorized},
		{"query", registrationPath + "/" + created.ClientID + "?x=1", created.RegistrationAccessToken, updatedBody, http.StatusBadRequest},
		{"wrong path", registrationPath, created.RegistrationAccessToken, updatedBody, http.StatusNotFound},
		{"missing client id", registrationPath + "/" + created.ClientID, clearedRegistration.RegistrationAccessToken, missingID, http.StatusBadRequest},
		{"mismatched client id", registrationPath + "/" + created.ClientID, clearedRegistration.RegistrationAccessToken, mismatchedID, http.StatusBadRequest},
		{"method change", registrationPath + "/" + created.ClientID, clearedRegistration.RegistrationAccessToken, strings.Replace(updatedBody, "client_secret_basic", "none", 1), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request(http.MethodPut, test.path, test.body, test.token))
			if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if strings.Contains(response.Body.String(), created.ClientSecret) || strings.Contains(response.Body.String(), created.RegistrationAccessToken) {
				t.Fatalf("credential leaked: %s", response.Body.String())
			}
		})
	}
}

func TestRegistrationHTTPLoopbackRedirectOptIn(t *testing.T) {
	t.Parallel()
	valid := `{"redirect_uris":["http://127.0.0.1/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Native app"}`
	for _, test := range []struct {
		name    string
		allow   bool
		payload string
		want    int
	}{
		{"disabled", false, valid, http.StatusBadRequest},
		{"enabled public", true, valid, http.StatusCreated},
		{"confidential", true, strings.Replace(valid, `"none"`, `"client_secret_basic"`, 1), http.StatusBadRequest},
		{"localhost without port", true, strings.Replace(valid, "127.0.0.1", "localhost", 1), http.StatusBadRequest},
		{"localhost exact port", true, strings.Replace(valid, "127.0.0.1", "localhost:43123", 1), http.StatusCreated},
		{"uppercase host", true, strings.Replace(valid, "127.0.0.1", "LOCALHOST", 1), http.StatusBadRequest},
		{"trailing dot", true, strings.Replace(valid, "127.0.0.1", "localhost.", 1), http.StatusBadRequest},
		{"subdomain", true, strings.Replace(valid, "127.0.0.1", "sub.localhost", 1), http.StatusBadRequest},
		{"query", true, strings.Replace(valid, "/callback", "/callback?next=bad", 1), http.StatusBadRequest},
		{"fragment", true, strings.Replace(valid, "/callback", "/callback#bad", 1), http.StatusBadRequest},
		{"empty fragment", true, strings.Replace(valid, "/callback", "/callback#", 1), http.StatusBadRequest},
		{"bad port", true, strings.Replace(valid, "127.0.0.1", "127.0.0.1:0", 1), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testHandlerWithConfig(t, testGlobalToken, Config{AllowRFC8252LoopbackRedirects: test.allow})
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request(http.MethodPost, registrationPath, test.payload, testGlobalToken))
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	h := testHandlerWithConfig(t, testGlobalToken, Config{AllowRFC8252LoopbackRedirects: true})
	created := registerClient(t, h, valid)
	update := `{"client_id":"` + created.ClientID + `","redirect_uris":["http://[::1]:43123/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Native app updated"}`
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request(http.MethodPut, registrationPath+"/"+created.ClientID, update, created.RegistrationAccessToken))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "[::1]:43123") {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRegistrationHTTPUpdateErrorStatus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"unauthorized", ErrUnauthorized, http.StatusUnauthorized},
		{"conflict", ErrConflict, http.StatusConflict},
		{"invalid", ErrInvalid, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeUpdateError(response, test.err)
			if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" || strings.Contains(response.Body.String(), test.err.Error()) {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestLoadRegistrationToken(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/dcr-token"
	if err := os.WriteFile(path, []byte("\n"+testGlobalToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadRegistrationToken(path); err != nil || got != testGlobalToken {
		t.Fatalf("token=%q err=%v", got, err)
	}
	for _, token := range []string{"", "short", testGlobalToken + " x", strings.Repeat("x", 257)} {
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := LoadRegistrationToken(path); err == nil || got != "" {
			t.Fatalf("invalid token accepted: %q", token)
		}
	}
}

func testHandler(t *testing.T, token string) http.Handler {
	return testHandlerWithConfig(t, token, Config{})
}

func testHandlerWithConfig(t *testing.T, token string, config Config) http.Handler {
	return testHandlerWithHandlerConfig(t, token, config, HandlerConfig{})
}

func testHandlerWithHandlerConfig(t *testing.T, token string, config Config, handlerConfig HandlerConfig) http.Handler {
	t.Helper()
	if config.Keyring == nil {
		config.Keyring = testEnvelopeKeyring(t)
	}
	db := openTestDB(t, "dcr-http-test")
	h, err := NewHandler(NewStore(db, config), "https://id.example.test", token, handlerConfig)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testAnonymousHandler(t *testing.T, window time.Duration) http.Handler {
	t.Helper()
	db := openTestDB(t, "dcr-anonymous-http-test")
	h, err := NewHandler(NewStore(db, Config{Keyring: testEnvelopeKeyring(t), Now: func() time.Time {
		return time.Date(2026, 9, 4, 12, 0, 30, 0, time.UTC)
	}}), "https://id.example.test", "", HandlerConfig{Anonymous: true, AnonymousRateLimitWindow: window})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(method, path, body, token string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Idempotency-Key", "test-key")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func requestWithKey(method, path, body, token, key string) *http.Request {
	req := request(method, path, body, token)
	if method == http.MethodPost {
		req.Header.Set("Idempotency-Key", key)
	}
	return req
}

func registerClient(t *testing.T, h http.Handler, body string) registrationResponse {
	return registerClientWithKey(t, h, body, "test-key")
}

func registerClientWithKey(t *testing.T, h http.Handler, body, key string) registrationResponse {
	t.Helper()
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, key))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var registration registrationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func TestRegistrationUsesConfiguredScopePolicy(t *testing.T) {
	t.Parallel()
	policy, err := NewScopePolicy([]string{"openid", "custom"}, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	h := testHandlerWithConfig(t, testGlobalToken, Config{ScopePolicy: policy})
	created := registerClient(t, h, `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Example RP"}`)
	if created.Scope != "openid custom" {
		t.Fatalf("scope=%q", created.Scope)
	}
}

func TestRegistrationHTTPBackchannelReplacement(t *testing.T) {
	t.Parallel()
	for _, clear := range []string{`,"backchannel_logout_uri":null`, ""} {
		t.Run(clear, func(t *testing.T) {
			h := testHandler(t, testGlobalToken)
			base := `"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Logout RP"`
			created := registerClientWithKey(t, h, `{`+base+`,"backchannel_logout_uri":"https://rp.example.test/logout"}`, "logout-create")
			if created.BackchannelLogoutURI != "https://rp.example.test/logout" {
				t.Fatal("create omitted logout URI")
			}
			for _, field := range []string{`,"backchannel_logout_uri":"https://rp.example.test/new"`, clear} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request(http.MethodPut, registrationPath+"/"+created.ClientID, `{"client_id":"`+created.ClientID+`",`+base+field+`}`, created.RegistrationAccessToken))
				if w.Code != http.StatusOK {
					t.Fatalf("update status=%d", w.Code)
				}
				if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
					t.Fatal(err)
				}
				if field == clear {
					if _, ok := fields["backchannel_logout_uri"]; ok {
						t.Fatal("clear retained URI")
					}
				} else if created.BackchannelLogoutURI != "https://rp.example.test/new" {
					t.Fatal("update lost URI")
				}
				get := httptest.NewRecorder()
				h.ServeHTTP(get, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
				if get.Code != http.StatusOK {
					t.Fatalf("get status=%d", get.Code)
				}
				var readFields map[string]json.RawMessage
				if err := json.Unmarshal(get.Body.Bytes(), &readFields); err != nil {
					t.Fatal(err)
				}
				if string(readFields["backchannel_logout_uri"]) != string(fields["backchannel_logout_uri"]) {
					t.Fatal("GET disagrees with PUT")
				}
			}
		})
	}
}

func TestBackchannelURIMetadataMatchesPinnedPattern(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"https://rp.example.test/logout?tenant=a&next=b#fragment", true},
		{"http://localhost:8080/logout", true},
		{"", false}, {"https://rp.example.test/bad path", false}, {"https://rp.example.test/\\bad", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			r := registrationRequest{ClientName: "Logout RP", RedirectURIs: []string{"https://rp.example.test/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, BackchannelLogoutURI: &tc.value}
			_, err := r.createRequest(false, ScopePolicy{Allowed: []string{"openid"}})
			if (err == nil) != tc.valid {
				t.Fatalf("validation=%v want valid=%v", err, tc.valid)
			}
		})
	}
}
