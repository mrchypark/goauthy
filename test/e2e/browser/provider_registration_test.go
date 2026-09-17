package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestProviderRegistrationLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROVIDER_REGISTRATION") != "1" {
		t.Skip("provider registration E2E disabled")
	}
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "provider-registration")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-origin"}
	id := "provider-" + randomManagedUIID(t)
	endpoint := primary + "/auth/v1/saas/providers"
	// Test-only configuration: registering never calls the remote provider.
	input := `{"id":"` + id + `","name":"Provider registration E2E","kind":"oauth2","enabled":true,"client_id":"e2e-client","client_secret":"e2e-provider-secret-not-real","callback_uri":"https://identity.example.test/callback","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"header","identity_endpoint":"https://identity.example.test/me","subject_field":"sub"}`
	request := func(method, target, body string, h map[string]string, want int) (string, string) {
		t.Helper()
		r := do(t, client, method, target, strings.NewReader(body), h)
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != want {
			t.Fatalf("%s status=%d want=%d", method, r.StatusCode, want)
		}
		if strings.Contains(string(data), "e2e-provider-secret-not-real") || strings.Contains(string(data), "secret_envelope") || strings.Contains(string(data), `"client_secret"`) {
			t.Fatal("provider response exposed secret")
		}
		return string(data), r.Header.Get("ETag")
	}
	created, revision := request(http.MethodPost, endpoint, input, headers, http.StatusCreated)
	var createdMetadata map[string]any
	if json.Unmarshal([]byte(created), &createdMetadata) != nil || createdMetadata["identity_endpoint"] != "https://identity.example.test/me" || createdMetadata["subject_field"] != "sub" {
		t.Fatal("created identity metadata mismatch")
	}
	if revision != `"1"` {
		t.Fatalf("initial revision=%q", revision)
	}
	path := endpoint + "/" + id
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		r := do(t, client, http.MethodDelete, path, nil, sessionHeader(headers, "If-Match", revision))
		r.Body.Close()
	})
	body, _ := request(http.MethodGet, path, "", nil, http.StatusOK)
	var got struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		IdentityEndpoint string `json:"identity_endpoint"`
		SubjectField     string `json:"subject_field"`
	}
	if json.Unmarshal([]byte(body), &got) != nil || got.ID != id || got.IdentityEndpoint != "https://identity.example.test/me" || got.SubjectField != "sub" {
		t.Fatal("provider metadata mismatch")
	}
	list, _ := request(http.MethodGet, endpoint, "", nil, http.StatusOK)
	var catalog []map[string]any
	if json.Unmarshal([]byte(list), &catalog) != nil {
		t.Fatal("invalid provider catalog")
	}
	found := false
	for _, provider := range catalog {
		if provider["id"] == id {
			found = provider["identity_endpoint"] == "https://identity.example.test/me" && provider["subject_field"] == "sub"
		}
	}
	if !found {
		t.Fatal("provider identity metadata missing from catalog")
	}
	request(http.MethodPost, endpoint, input, map[string]string{"Content-Type": "application/json"}, http.StatusUnauthorized)
	for name, fields := range map[string]string{
		"unpaired identity endpoint": `"identity_endpoint":"https://identity.example.test/me"`,
		"unpaired subject field":     `"subject_field":"sub"`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := strings.Replace(input, `"id":"`+id+`"`, `"id":"`+id+`-`+strings.ReplaceAll(name, " ", "-")+`"`, 1)
			invalid = strings.Replace(invalid, `,"identity_endpoint":"https://identity.example.test/me","subject_field":"sub"`, ","+fields, 1)
			request(http.MethodPost, endpoint, invalid, headers, http.StatusBadRequest)
		})
	}
	request(http.MethodDelete, path, "", headers, http.StatusPreconditionRequired)
	update := strings.Replace(input, `"id":"`+id+`",`, "", 1)
	update = strings.Replace(update, `"client_secret":"e2e-provider-secret-not-real",`, "", 1)
	_, revision = request(http.MethodPut, path, update, sessionHeader(headers, "If-Match", revision), http.StatusOK)
	if revision != `"2"` {
		t.Fatalf("updated revision=%q", revision)
	}
	body, _ = request(http.MethodGet, path, "", nil, http.StatusOK)
	got = struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		IdentityEndpoint string `json:"identity_endpoint"`
		SubjectField     string `json:"subject_field"`
	}{}
	if json.Unmarshal([]byte(body), &got) != nil || got.IdentityEndpoint != "https://identity.example.test/me" || got.SubjectField != "sub" {
		t.Fatal("identity metadata not retained by update")
	}
	request(http.MethodDelete, path, "", sessionHeader(headers, "If-Match", `"1"`), http.StatusConflict)
	request(http.MethodDelete, path, "", sessionHeader(headers, "If-Match", revision), http.StatusNoContent)
	deleted = true
	request(http.MethodGet, path, "", nil, http.StatusNotFound)
	request(http.MethodPost, endpoint, input, headers, http.StatusConflict)
	apiID := id + "-api"
	apiBody := `{"id":"` + apiID + `","name":"API key provider E2E","kind":"api_key","enabled":true,"identity_endpoint":"https://identity.example.test/me","subject_field":"sub","connector":{"id":"` + apiID + `","header":"X-API-Key","prefix":"","operations":[{"id":"account","url":"https://api.example.test/account","response_fields":{"id":"string"}}]}}`
	request(http.MethodPost, endpoint, apiBody, headers, http.StatusBadRequest)
	apiBody = strings.Replace(apiBody, `,"identity_endpoint":"https://identity.example.test/me","subject_field":"sub"`, "", 1)
	_, apiRevision := request(http.MethodPost, endpoint, apiBody, headers, http.StatusCreated)
	apiPath := endpoint + "/" + apiID
	apiDeleted := false
	t.Cleanup(func() {
		if !apiDeleted {
			r := do(t, client, http.MethodDelete, apiPath, nil, sessionHeader(headers, "If-Match", apiRevision))
			r.Body.Close()
		}
	})
	request(http.MethodGet, apiPath, "", nil, http.StatusOK)
	apiUpdate := strings.Replace(apiBody, `"id":"`+apiID+`",`, "", 1)
	_, apiRevision = request(http.MethodPut, apiPath, apiUpdate, sessionHeader(headers, "If-Match", apiRevision), http.StatusOK)
	request(http.MethodDelete, apiPath, "", sessionHeader(headers, "If-Match", apiRevision), http.StatusNoContent)
	apiDeleted = true
}
