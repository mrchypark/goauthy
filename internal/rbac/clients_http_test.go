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

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func managedHTTPStore(t *testing.T, dbStore *Store) *clients.Store {
	t.Helper()
	d := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(d, "master"), []byte(base64.RawURLEncoding.EncodeToString(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	kr, err := oidc.LoadKeyring(d, "master")
	if err != nil {
		t.Fatal(err)
	}
	return clients.NewStore(dbStore.db, kr, "bootstrap-client")
}

func managedRequest(method, path string, body string, cookie *http.Cookie, csrf, etag string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.SetPathValue("id", "managed-http-client")
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
	return r
}

func TestManagedClientHTTPAdminCRUDAndSecretTransition(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	create := managedRequest(http.MethodPost, "/auth/v1/clients", `{"id":"managed-http-client","name":"HTTP","confidential":true,"redirect_uris":["https://app.example/cb"]}`, cookie, csrf, "")
	response := httptest.NewRecorder()
	h.Clients(response, create)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("create status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	var c clients.Client
	if json.Unmarshal(response.Body.Bytes(), &c) != nil || c.ID == "" {
		t.Fatalf("create body=%s", response.Body.String())
	}
	secret := managedRequest(http.MethodPost, "/auth/v1/clients/managed-http-client/secret", "", cookie, csrf, "")
	response = httptest.NewRecorder()
	h.ClientSecret(response, secret)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"secret"`) {
		t.Fatalf("secret status=%d body=%s", response.Code, response.Body.String())
	}
	update := managedRequest(http.MethodPut, "/auth/v1/clients/managed-http-client", `{"name":"HTTP2","confidential":true,"redirect_uris":["https://app.example/cb"],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"]}`, cookie, csrf, `"1"`)
	response = httptest.NewRecorder()
	h.Client(response, update)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("update status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
}

func TestManagedClientHTTPAPIKeyLeastPrivilegeAndRevokedBrowser(t *testing.T) {
	t.Parallel()
	h, store, cookie, _ := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, clientsToken, err := keys.Create(t.Context(), nil, apikey.Request{Name: "managed-clients", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, secretsToken, err := keys.Create(t.Context(), nil, apikey.Request{Name: "managed-secrets", Access: []apikey.Access{{Group: "Secrets", AccessRights: []apikey.Right{apikey.Read, apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	create := managedRequest(http.MethodPost, "/auth/v1/clients", `{"id":"managed-http-client","name":"HTTP","confidential":true,"redirect_uris":["https://app.example/cb"]}`, nil, "", "")
	create.Header.Set("Authorization", "API-Key "+clientsToken)
	response := httptest.NewRecorder()
	h.Clients(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("key create status=%d body=%s", response.Code, response.Body.String())
	}
	read := managedRequest(http.MethodPost, "/auth/v1/clients/managed-http-client/secret", "", nil, "", "")
	read.Header.Set("Authorization", "API-Key "+secretsToken)
	response = httptest.NewRecorder()
	h.ClientSecret(response, read)
	if response.Code != http.StatusOK {
		t.Fatalf("secret read status=%d body=%s", response.Code, response.Body.String())
	}
	noClients := managedRequest(http.MethodGet, "/auth/v1/clients/managed-http-client", "", nil, "", "")
	noClients.Header.Set("Authorization", "API-Key "+secretsToken)
	response = httptest.NewRecorder()
	h.Client(response, noClients)
	if response.Code != http.StatusForbidden {
		t.Fatalf("secret key client read status=%d", response.Code)
	}
	rotate := managedRequest(http.MethodPut, "/auth/v1/clients/managed-http-client/secret", "", nil, "", `"1"`)
	rotate.Header.Set("Authorization", "API-Key "+secretsToken)
	response = httptest.NewRecorder()
	h.RotateClientSecret(response, rotate)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("secret key rotate status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	if err := h.browser.RevokeSession(t.Context(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	revoked := managedRequest(http.MethodGet, "/auth/v1/clients/managed-http-client", "", cookie, "", "")
	response = httptest.NewRecorder()
	h.Client(response, revoked)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked browser status=%d", response.Code)
	}
}

func TestManagedClientHTTPStrictBodies(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("POST", "/auth/v1/clients", strings.NewReader(`{"id":"app","name":"App","confidential":true,"redirect_uris":["https://app.example/cb"]}`))
	r.Header.Set("Content-Type", "application/json")
	v, err := decodeManagedClient(r)
	if err != nil || v.ID != "app" || !v.Confidential {
		t.Fatalf("decode=%+v err=%v", v, err)
	}
	r = httptest.NewRequest("POST", "/auth/v1/clients", strings.NewReader(`{"id":"app","name":null,"confidential":true,"redirect_uris":[]}`))
	r.Header.Set("Content-Type", "application/json")
	if got, err := decodeManagedClient(r); err != nil || got.Name != nil {
		t.Fatalf("nullable create name decode=%+v err=%v", got, err)
	}
	for _, body := range []string{`{"id":"app","unknown":true}`, `{"id":"app"}{}`, `null`} {
		r = httptest.NewRequest("POST", "/auth/v1/clients", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, err = decodeManagedClient(r); err == nil {
			t.Fatalf("accepted invalid body %s", body)
		}
	}
	r = httptest.NewRequest("PUT", "/auth/v1/clients/app", strings.NewReader(`{"confidential":true,"redirect_uris":[],"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"]}`))
	r.Header.Set("Content-Type", "application/json")
	if _, err = decodeManagedUpdate(r); err == nil {
		t.Fatal("accepted update with missing enabled field")
	}
	r = httptest.NewRequest("PUT", "/auth/v1/clients/app", strings.NewReader(`{"name":null,"confidential":true,"redirect_uris":[],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"]}`))
	r.Header.Set("Content-Type", "application/json")
	if got, err := decodeManagedUpdate(r); err != nil || got.Name != nil {
		t.Fatalf("nullable name decode=%+v err=%v", got, err)
	}
}

func TestManagedClientHTTPIfMatch(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("PUT", "/auth/v1/clients/app", nil)
	if _, err := clientRevision(r); err == nil {
		t.Fatal("missing If-Match accepted")
	}
	r.Header.Set("If-Match", `"7"`)
	if got, err := clientRevision(r); err != nil || got != 7 {
		t.Fatalf("revision=%d err=%v", got, err)
	}
}

func TestManagedClientHTTPBackchannelMetadata(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	w := httptest.NewRecorder()
	h.Clients(w, managedRequest(http.MethodPost, "/auth/v1/clients", `{"id":"managed-http-client","confidential":false,"redirect_uris":["https://app.example/cb"],"backchannel_logout_uri":"https://rp.example/logout"}`, cookie, csrf, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d", w.Code)
	}
	var c clients.Client
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || c.BackchannelLogoutURI == nil || *c.BackchannelLogoutURI != "https://rp.example/logout" {
		t.Fatal("create lost URI", err)
	}
	etag := w.Header().Get("ETag")
	for _, value := range []string{`"https://rp.example/new"`, `null`} {
		w = httptest.NewRecorder()
		h.Client(w, managedRequest(http.MethodPut, "/auth/v1/clients/managed-http-client", `{"confidential":false,"redirect_uris":["https://app.example/cb"],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"],"backchannel_logout_uri":`+value+`}`, cookie, csrf, etag))
		if w.Code != http.StatusOK {
			t.Fatalf("update status=%d", w.Code)
		}
		c = clients.Client{}
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if value == `null` {
			if c.BackchannelLogoutURI != nil {
				t.Fatal("URI not cleared")
			}
		} else if c.BackchannelLogoutURI == nil || *c.BackchannelLogoutURI != "https://rp.example/new" {
			t.Fatal("URI not updated")
		}
		etag = w.Header().Get("ETag")
	}
}

func TestManagedClientHTTPGroupPrefixMetadata(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.BindClients(managedHTTPStore(t, store))
	w := httptest.NewRecorder()
	h.Clients(w, managedRequest(http.MethodPost, "/auth/v1/clients", `{"id":"managed-http-client","confidential":false,"redirect_uris":["https://app.example/cb"],"restrict_group_prefix":"team/"}`, cookie, csrf, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d", w.Code)
	}
	var c clients.Client
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || c.RestrictGroupPrefix == nil || *c.RestrictGroupPrefix != "team/" {
		t.Fatal("create lost group prefix", err)
	}
	etag := w.Header().Get("ETag")
	for _, value := range []string{`"engineering/"`, `null`} {
		w = httptest.NewRecorder()
		h.Client(w, managedRequest(http.MethodPut, "/auth/v1/clients/managed-http-client", `{"confidential":false,"redirect_uris":["https://app.example/cb"],"enabled":true,"scopes":["openid"],"default_scopes":["openid"],"enabled_flows":["authorization_code"],"restrict_group_prefix":`+value+`}`, cookie, csrf, etag))
		if w.Code != http.StatusOK {
			t.Fatalf("update status=%d", w.Code)
		}
		c = clients.Client{}
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if value == `null` {
			if c.RestrictGroupPrefix != nil {
				t.Fatal("group prefix not cleared")
			}
		} else if c.RestrictGroupPrefix == nil || *c.RestrictGroupPrefix != "engineering/" {
			t.Fatal("group prefix not updated")
		}
		etag = w.Header().Get("ETag")
	}
}
