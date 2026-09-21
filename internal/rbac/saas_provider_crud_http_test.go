package rbac

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/saas"
)

func providerHTTPStore(t *testing.T, store *Store) *saas.ProviderStore {
	t.Helper()
	d := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(d, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	kr, err := oidc.LoadKeyring(d, "master")
	if err != nil {
		t.Fatal(err)
	}
	providers, err := saas.NewProviderStore(store.db, kr)
	if err != nil {
		t.Fatal(err)
	}
	return providers
}

func providerRequest(method, path, body string, cookie *http.Cookie, csrf, etag string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	if strings.Contains(path, "/providers/") {
		r.SetPathValue("provider_id", path[strings.LastIndex(path, "/")+1:])
	}
	return r
}

const oauthProviderBody = `{"id":"managed-oauth","name":"Managed OAuth","kind":"oauth2","enabled":true,"client_id":"client","client_secret":"secret-value","callback_uri":"https://app.example/callback","auth_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","scopes":["openid"],"auth_style":"header"}`

const oauthProviderUpdateBody = `{"name":"Managed OAuth 2","kind":"oauth2","enabled":false,"client_id":"client-2","callback_uri":"https://app.example/callback-2","auth_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","scopes":["openid","profile"],"auth_style":"params"}`

const apiKeyProviderBody = `{"id":"managed-api","name":"Managed API","kind":"api_key","enabled":true,"connector":{"id":"managed-api","header":"X-API-Key","prefix":"","operations":[{"id":"whoami","url":"https://provider.example/me","response_fields":{"id":"string"}}]}}`

func TestManagedSaaSProviderHTTPOAuthCRUDAndSecretOmission(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "github", Kind: "github", CallbackURI: "https://app.example/github"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.SaaSProviders(w, providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, cookie, csrf, ""))
	if w.Code != http.StatusCreated || w.Header().Get("ETag") != `"1"` || strings.Contains(w.Body.String(), "client_secret") {
		t.Fatalf("create status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}

	w = httptest.NewRecorder()
	h.SaaSProviders(w, providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", cookie, "", ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "client_secret") || !strings.Contains(w.Body.String(), "managed-oauth") || !strings.Contains(w.Body.String(), "github") {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.SaaSProvider(w, providerRequest(http.MethodGet, "/auth/v1/saas/providers/managed-oauth", "", cookie, "", ""))
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"1"` || strings.Contains(w.Body.String(), "client_secret") {
		t.Fatalf("get status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}

	w = httptest.NewRecorder()
	h.SaaSProvider(w, providerRequest(http.MethodPut, "/auth/v1/saas/providers/managed-oauth", oauthProviderUpdateBody, cookie, csrf, `"1"`))
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"2"` || strings.Contains(w.Body.String(), "client_secret") {
		t.Fatalf("update status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}

	w = httptest.NewRecorder()
	h.SaaSProvider(w, providerRequest(http.MethodDelete, "/auth/v1/saas/providers/managed-oauth", "", cookie, csrf, `"2"`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestManagedSaaSProviderHTTPBoundariesAndJSON(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "github", Kind: "github", CallbackURI: "https://app.example/github"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"unknown":   `{"id":"bad","name":"Bad","kind":"oauth2","enabled":true,"unknown":true}`,
		"duplicate": `{"id":"bad","name":"Bad","name":"Again","kind":"oauth2","enabled":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.SaaSProviders(w, providerRequest(http.MethodPost, "/auth/v1/saas/providers", body, cookie, csrf, ""))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	w := httptest.NewRecorder()
	h.SaaSProviders(w, providerRequest(http.MethodPost, "/auth/v1/saas/providers", strings.Replace(oauthProviderBody, "managed-oauth", "github", 1), cookie, csrf, ""))
	if w.Code != http.StatusConflict {
		t.Fatalf("static conflict status=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.SaaSProviders(w, providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, cookie, csrf, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("seed provider status=%d body=%s", w.Code, w.Body.String())
	}

	for name, mutate := range map[string]func(*http.Request){
		"missing csrf":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"duplicate csrf": func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) },
		"query":          func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"cross site":     func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		t.Run(name, func(t *testing.T) {
			r := providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, cookie, csrf, "")
			mutate(r)
			w := httptest.NewRecorder()
			h.SaaSProviders(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	for name, setup := range map[string]func(*http.Request){
		"anonymous": func(*http.Request) {},
		"member": func(r *http.Request) {
			member, memberCSRF := memberSession(t, store)
			r.AddCookie(member)
			r.Header.Set("X-CSRF-Token", memberCSRF)
		},
		"mixed bearer": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer invalid")
			r.AddCookie(cookie)
		},
		"mixed api key": func(r *http.Request) {
			r.Header.Set("Authorization", "API-Key malformed")
			r.AddCookie(cookie)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", nil, "", "")
			setup(r)
			w := httptest.NewRecorder()
			h.SaaSProviders(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	for _, test := range []struct {
		name, path, etag string
		want             int
	}{
		{"missing If-Match", "/auth/v1/saas/providers/missing", "", http.StatusPreconditionRequired},
		{"missing resource", "/auth/v1/saas/providers/missing", `"99"`, http.StatusNotFound},
		{"stale revision", "/auth/v1/saas/providers/managed-oauth", `"99"`, http.StatusConflict},
	} {
		r := providerRequest(http.MethodPut, test.path, oauthProviderUpdateBody, cookie, csrf, test.etag)
		w := httptest.NewRecorder()
		h.SaaSProvider(w, r)
		if w.Code != test.want {
			t.Fatalf("%s status=%d body=%s", test.name, w.Code, w.Body.String())
		}
	}
}

func TestManagedSaaSProviderHTTPAPIKeyCRUD(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if in, err := decodeProvider(providerRequest(http.MethodPost, "/auth/v1/saas/providers", apiKeyProviderBody, cookie, csrf, ""), true); err != nil {
		t.Fatalf("decode api provider: %v input=%+v", err, in)
	} else if _, err := saas.NewAPIKeyConnector(*in.Connector); err != nil {
		t.Fatalf("connector: %v input=%+v", err, in.Connector)
	}
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	auth := func(method, path, body, etag string) *httptest.ResponseRecorder {
		r := providerRequest(method, path, body, cookie, csrf, etag)
		w := httptest.NewRecorder()
		if strings.Contains(path, "/providers/") {
			h.SaaSProvider(w, r)
		} else {
			h.SaaSProviders(w, r)
		}
		return w
	}
	if w := auth(http.MethodPost, "/auth/v1/saas/providers", apiKeyProviderBody, ""); w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	if w := auth(http.MethodGet, "/auth/v1/saas/providers", "", ""); w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	update := `{"name":"Managed API 2","kind":"api_key","enabled":false,"connector":{"id":"managed-api","header":"X-API-Key","prefix":"","operations":[{"id":"whoami","url":"https://provider.example/me","response_fields":{"id":"string"}}]}}`
	if w := auth(http.MethodPut, "/auth/v1/saas/providers/managed-api", update, `"1"`); w.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}
	if w := auth(http.MethodDelete, "/auth/v1/saas/providers/managed-api", "", `"2"`); w.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}

	// Authorization headers are never accepted as management authority.
	r := providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", cookie, "", "")
	r.Header.Set("Authorization", "API-Key malformed")
	w := httptest.NewRecorder()
	h.SaaSProviders(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("api-key management status=%d", w.Code)
	}
}
