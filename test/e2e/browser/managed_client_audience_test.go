package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestManagedClientAudienceProviderBearerLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROVIDER_BEARER") != "1" {
		t.Skip("set GOAUTHY_E2E_PROVIDER_BEARER=1 to run managed audience E2E")
	}
	primary, secondary, adminName, adminPassword, _ := browserE2EConfig(t)
	admin := newBrowserClient(t)
	_, cookie := loginForCode(t, admin, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminName, adminPassword, "managed-audience-admin")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	ensureProviderBearerReadScope(t, admin, primary, headers)

	id := "managed-audience-" + randomManagedUIID(t)
	redirectURI := "https://rp.example.test/managed-audience/callback"
	createBody := `{"id":"` + id + `","name":"Managed audience E2E","confidential":true,"redirect_uris":["` + redirectURI + `"],"audience":["` + providerBearerResource + `"],"scopes":["openid","profile","goauthy.providers.read"],"default_scopes":["openid","profile","goauthy.providers.read"],"enabled_flows":["authorization_code"]}`
	created := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(createBody), headers)
	var client struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if created.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&client) != nil || client.ID != id || client.Revision <= 0 {
		created.Body.Close()
		t.Fatalf("managed client create status=%d", created.StatusCode)
	}
	created.Body.Close()
	currentRevision := client.Revision
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
		r.Body.Close()
	})

	secretResponse := do(t, admin, http.MethodPost, primary+"/auth/v1/clients/"+url.PathEscape(id)+"/secret", nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
	var secretBody struct {
		Secret string `json:"secret"`
	}
	if secretResponse.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(secretResponse.Body, 4096)).Decode(&secretBody) != nil || secretBody.Secret == "" {
		secretResponse.Body.Close()
		t.Fatalf("managed secret status=%d", secretResponse.StatusCode)
	}
	secretResponse.Body.Close()
	currentRevision = revisionFromETag(t, secretResponse.Header.Get("ETag"), currentRevision)

	issue := func(state string) tokenResponse {
		c := newBrowserClient(t)
		verifier := pkceVerifier(t)
		authorize := oidcAuthorizationURLForClient(t, primary, id, redirectURI, pkceChallenge(verifier), state, state+"-nonce", "openid profile goauthy.providers.read")
		u, err := url.Parse(authorize)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("resource", providerBearerResource)
		u.RawQuery = q.Encode()
		code, _ := loginForAuthorizationURL(t, c, u.String(), primary, secondary, adminName, adminPassword, state)
		return exchangeCodeForClient(t, c, primary, id, secretBody.Secret, redirectURI, code, verifier)
	}
	tokens := issue("managed-audience-positive")
	if tokens.AccessToken == "" {
		t.Fatal("managed audience token missing")
	}
	providers := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
	providers.Body.Close()
	if providers.StatusCode != http.StatusOK {
		t.Fatalf("provider bearer status=%d", providers.StatusCode)
	}

	updateBody := `{"name":"Managed audience E2E","confidential":true,"enabled":true,"redirect_uris":["` + redirectURI + `"],"audience":[],"scopes":["openid","profile","goauthy.providers.read"],"default_scopes":["openid","profile","goauthy.providers.read"],"enabled_flows":["authorization_code"]}`
	updated := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(id), strings.NewReader(updateBody), sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
	var updatedBody struct {
		Revision int64 `json:"revision"`
	}
	if updated.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(updated.Body, 4096)).Decode(&updatedBody) != nil || updatedBody.Revision <= currentRevision {
		updated.Body.Close()
		t.Fatalf("audience update status=%d", updated.StatusCode)
	}
	updated.Body.Close()
	currentRevision = updatedBody.Revision
	old := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
	old.Body.Close()
	if old.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old audience token status=%d", old.StatusCode)
	}

	fresh := newBrowserClient(t)
	verifier := pkceVerifier(t)
	authorize := oidcAuthorizationURLForClient(t, primary, id, redirectURI, pkceChallenge(verifier), "managed-audience-denied", "managed-audience-denied-nonce", "openid profile goauthy.providers.read")
	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("resource", providerBearerResource)
	u.RawQuery = q.Encode()
	denied := do(t, fresh, http.MethodGet, u.String(), nil, nil)
	location, parseErr := url.Parse(denied.Header.Get("Location"))
	denied.Body.Close()
	if parseErr != nil || location.Query().Get("code") != "" || (denied.StatusCode != http.StatusBadRequest && ((denied.StatusCode != http.StatusFound && denied.StatusCode != http.StatusSeeOther) || location.Query().Get("error") == "")) {
		t.Fatalf("removed resource authorization status=%d did not fail closed", denied.StatusCode)
	}

	r := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(currentRevision, 10))))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("managed client cleanup status=%d", r.StatusCode)
	}
	deleted = true
}

func revisionFromETag(t *testing.T, etag string, fallback int64) int64 {
	t.Helper()
	if etag == "" {
		return fallback
	}
	value, err := strconv.ParseInt(strings.Trim(etag, `"`), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func ensureProviderBearerReadScope(t *testing.T, admin *http.Client, primary string, headers map[string]string) {
	ensureResourcePermissionScope(t, admin, primary, headers, "goauthy.providers.read")
}

func ensureResourcePermissionScope(t *testing.T, admin *http.Client, primary string, headers map[string]string, name string) {
	t.Helper()
	r := do(t, admin, http.MethodGet, primary+"/auth/v1/scopes", nil, nil)
	var catalog []struct {
		Scope string `json:"scope"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&catalog) != nil {
		r.Body.Close()
		t.Fatal("read scope catalog failed")
	}
	r.Body.Close()
	for _, scope := range catalog {
		if scope.Scope == name {
			return
		}
	}
	body, err := json.Marshal(map[string]any{"scope": name, "attr_include_id": []string{}, "attr_include_access": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	r = do(t, admin, http.MethodPost, primary+"/auth/v1/scopes", bytes.NewReader(body), headers)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("create provider read scope status=%d", r.StatusCode)
	}
}
