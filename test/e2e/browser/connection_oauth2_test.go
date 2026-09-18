package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestConnectionOAuth2ProviderRegistrationBoundary(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROVIDER_REGISTRATION") != "1" {
		t.Skip("provider registration E2E disabled")
	}
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "provider-connection-oauth2")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-origin"}
	providerID := "provider-" + randomManagedUIID(t)
	collectionID := uniqueCollectionID(t)
	callback := primary + "/auth/v1/saas/callback/" + providerID
	providerBody := `{"id":"` + providerID + `","name":"OAuth2 connection boundary","kind":"oauth2","enabled":true,"client_id":"e2e-client","client_secret":"e2e-provider-secret-not-real","callback_uri":"` + callback + `","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"header","identity_endpoint":"https://provider.example.test/me","subject_field":"sub"}`
	providerResponse := do(t, client, http.MethodPost, primary+"/auth/v1/saas/providers", strings.NewReader(providerBody), headers)
	if providerResponse.StatusCode != http.StatusCreated {
		providerResponse.Body.Close()
		t.Fatalf("provider create status=%d", providerResponse.StatusCode)
	}
	providerRevision := providerResponse.Header.Get("ETag")
	providerResponse.Body.Close()
	if providerRevision == "" {
		t.Fatal("provider create missing ETag")
	}
	providerDeleted := false
	t.Cleanup(func() {
		if providerDeleted {
			return
		}
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/saas/providers/"+providerID, nil, cloneCollectionHeaders(headers, 1))
		r.Body.Close()
	})

	collectionBody := []byte(`{"id":"` + collectionID + `","name":"OAuth2 connection boundary","auth_method":"oauth2","enabled":true,"fields":[],"provider_ids":["` + providerID + `"]}`)
	collectionResponse := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", bytes.NewReader(collectionBody), headers)
	_, collectionRevision := readCollection(t, collectionResponse, http.StatusCreated)
	collectionDeleted := false
	t.Cleanup(func() {
		if collectionDeleted {
			return
		}
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+collectionID, nil, cloneCollectionHeaders(headers, collectionRevision))
		r.Body.Close()
	})

	connectionResponse := do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+collectionID, strings.NewReader(`{"definition_revision":1,"metadata":{}}`), headers)
	connection, connectionRevision := readCollection(t, connectionResponse, http.StatusCreated)
	connectionID, ok := connection["id"].(string)
	if !ok || connectionID == "" {
		t.Fatal("connection ID missing")
	}
	connectionDeleted := false
	t.Cleanup(func() {
		if connectionDeleted {
			return
		}
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/account/connections/"+collectionID+"/"+connectionID, nil, cloneCollectionHeaders(headers, connectionRevision))
		r.Body.Close()
	})
	statusURL := primary + "/auth/v1/account/connections/" + collectionID + "/" + connectionID + "/oauth2"
	statusResponse := do(t, client, http.MethodGet, statusURL, nil, headers)
	var status struct {
		Connected bool     `json:"connected"`
		State     string   `json:"state"`
		Version   int64    `json:"version"`
		Scopes    []string `json:"scopes"`
	}
	if statusResponse.StatusCode != http.StatusOK || json.NewDecoder(statusResponse.Body).Decode(&status) != nil || status.Connected || status.State != "draft" || status.Version != 0 || status.Scopes == nil {
		statusResponse.Body.Close()
		t.Fatal("invalid draft OAuth status")
	}
	statusResponse.Body.Close()
	for _, tc := range []struct {
		body    string
		headers map[string]string
		want    int
	}{
		{`{"version":1}`, map[string]string{"Content-Type": "application/json"}, http.StatusUnauthorized},
		{`{"version":0}`, headers, http.StatusBadRequest},
		{`{"version":1}`, headers, http.StatusConflict},
	} {
		r := do(t, client, http.MethodDelete, statusURL, strings.NewReader(tc.body), tc.headers)
		r.Body.Close()
		if r.StatusCode != tc.want {
			t.Fatalf("revoke status=%d want=%d", r.StatusCode, tc.want)
		}
		r = do(t, client, http.MethodPost, statusURL+"/reconnect", strings.NewReader(tc.body), tc.headers)
		r.Body.Close()
		if r.StatusCode != tc.want {
			t.Fatalf("reconnect status=%d want=%d", r.StatusCode, tc.want)
		}
	}

	for _, tc := range []struct {
		path, body string
		headers    map[string]string
		want       int
	}{
		{statusURL + "/refresh", `{"version":1}`, map[string]string{"Content-Type": "application/json"}, http.StatusUnauthorized},
		{statusURL + "/refresh", `{"version":0}`, headers, http.StatusBadRequest},
		{statusURL + "/refresh?", `{"version":1}`, headers, http.StatusBadRequest},
		{statusURL + "/refresh", `{"version":1}`, headers, http.StatusNotFound},
	} {
		r := do(t, client, http.MethodPost, tc.path, strings.NewReader(tc.body), tc.headers)
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		r.Body.Close()
		if err != nil || r.StatusCode != tc.want || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("refresh boundary status=%d want=%d", r.StatusCode, tc.want)
		}
		if bytes.Contains(body, []byte("e2e-provider-secret-not-real")) || bytes.Contains(body, []byte("access_token")) || bytes.Contains(body, []byte("refresh_token")) {
			t.Fatal("refresh denial exposed credential material")
		}
	}

	start := do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+collectionID+"/"+connectionID+"/oauth2", strings.NewReader(`{"provider_id":"`+providerID+`"}`), headers)
	var startBody struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if start.StatusCode != http.StatusOK || json.NewDecoder(start.Body).Decode(&startBody) != nil {
		start.Body.Close()
		t.Fatalf("oauth2 start status=%d", start.StatusCode)
	}
	start.Body.Close()
	authorizationURL, err := url.Parse(startBody.AuthorizationURL)
	if err != nil || authorizationURL.Query().Get("redirect_uri") != callback || authorizationURL.Query().Get("scope") != "read" || authorizationURL.Query().Get("code_challenge_method") != "S256" || authorizationURL.Query().Get("state") == "" || authorizationURL.Query().Get("code_challenge") == "" {
		t.Fatalf("authorization URL=%q", startBody.AuthorizationURL)
	}

	callbackURL := primary + "/auth/v1/saas/callback/" + providerID
	invalid := do(t, client, http.MethodGet, callbackURL+"?state=invalid&code=not-real", nil, headers)
	invalid.Body.Close()
	if invalid.StatusCode != http.StatusNotFound {
		t.Fatalf("invalid callback status=%d want=404", invalid.StatusCode)
	}
	duplicate := do(t, client, http.MethodGet, callbackURL+"?state=a&state=b&code=not-real", nil, headers)
	duplicate.Body.Close()
	if duplicate.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate callback status=%d want=400", duplicate.StatusCode)
	}
	denial := do(t, client, http.MethodGet, callbackURL+"?error=access_denied&error_description=cancelled", nil, headers)
	denial.Body.Close()
	if denial.StatusCode != http.StatusBadRequest {
		t.Fatalf("denial callback status=%d want=400", denial.StatusCode)
	}

	r := do(t, client, http.MethodDelete, primary+"/auth/v1/account/connections/"+collectionID+"/"+connectionID, nil, cloneCollectionHeaders(headers, connectionRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("connection cleanup status=%d", r.StatusCode)
	}
	connectionDeleted = true
	r = do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+collectionID, nil, cloneCollectionHeaders(headers, collectionRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("collection cleanup status=%d", r.StatusCode)
	}
	collectionDeleted = true
	r = do(t, client, http.MethodDelete, primary+"/auth/v1/saas/providers/"+providerID, nil, sessionHeader(headers, "If-Match", providerRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("provider cleanup status=%d", r.StatusCode)
	}
	providerDeleted = true
}
