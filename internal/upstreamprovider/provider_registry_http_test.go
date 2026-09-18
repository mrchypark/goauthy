package upstreamprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type httpFixture struct {
	t         *testing.T
	ctx       context.Context
	db        *rhiza.DB
	store     *RegistryStore
	keys      *apikey.Store
	token     string
	principal *apikey.Principal
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "http-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := NewRegistryStore(db, &fakeEnvelopeKeyring{})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   "http-admin",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return &httpFixture{t: t, ctx: ctx, db: db, store: store, keys: keys, token: token, principal: &p}
}

func (f *httpFixture) seedProvider(id, name string, enabled bool) {
	f.t.Helper()
	enabledVal := int64(0)
	if enabled {
		enabledVal = 1
	}
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-http-" + id,
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{id, enabledVal, name, "oidc", "https://issuer-" + id + ".test", "https://auth-" + id + ".test", "https://token-" + id + ".test", "https://userinfo-" + id + ".test", "cid-" + id, "openid", int64(1)},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *httpFixture) newRequestID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		f.t.Fatal(err)
	}
	return prefix + "/" + base64.RawURLEncoding.EncodeToString(b)
}

func (f *httpFixture) seedIdentityUser(subject string) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-user-" + subject,
		SQL:       "INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)",
		Args:      []any{subject, subject, ""},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *httpFixture) seedProfile(subject, email string) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-profile-" + subject,
		SQL:       "INSERT INTO identity_user_profiles(subject,email,email_verified) VALUES(?,?,1)",
		Args:      []any{subject, email},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *httpFixture) seedLink(providerID, extKey, localSubject string) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-link-" + providerID + "-" + extKey,
		SQL:       "INSERT INTO identity_external_links(provider_id,external_key,local_subject,linked_at_unix_ms) VALUES(?,?,?,?)",
		Args:      []any{providerID, extKey, localSubject, int64(2000)},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *httpFixture) seedProviderLogo(providerID, resolution, contentType string, data []byte, updated int64) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "provider-logo-row-" + providerID + "-" + resolution,
		SQL:       "INSERT INTO auth_provider_logos(auth_provider_id,res,content_type,data,updated) VALUES(?,?,?,?,?)",
		Args:      []any{providerID, resolution, contentType, data, updated},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *httpFixture) disableUser(subject string) {
	f.t.Helper()
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "disable-" + subject,
		SQL:       "UPDATE identity_users SET disabled=1 WHERE subject=?",
		Args:      []any{subject},
	}); err != nil {
		f.t.Fatal(err)
	}
}


// --- PostProviders tests ---

func TestPostProvidersReturnsDecryptedSecretList(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("hp-1", "Alpha", true)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1", len(resp))
	}
	if resp[0].ID != "hp-1" || resp[0].Name != "Alpha" {
		t.Fatalf("provider=%+v", resp[0])
	}
}

func TestPostProvidersUnauthorizedWithoutKey(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestPostProvidersForbiddenWrongGroup(t *testing.T) {
	f := newHTTPFixture(t)
	// Create a key with wrong group
	_, token, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name:   "wrong-group-key",
		Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	req.Header.Set("Authorization", "API-Key "+token)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
}

func TestPostProvidersRevokedKey(t *testing.T) {
	f := newHTTPFixture(t)
	// Revoke the key by overwriting secret_digest
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-http-key",
		SQL:       "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args:      []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil {
		t.Fatal(err)
	}
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

// --- GetProvidersMinimal tests ---

func TestGetProvidersMinimalPublicNeverLeaksSecret(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("min-1", "Visible", true)
	f.seedProvider("min-2", "Disabled", false)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Must never contain secret-related fields
	if strings.Contains(body, "client_secret") {
		t.Error("response leaks client_secret")
	}
	if strings.Contains(body, "secret") {
		t.Error("response leaks secret")
	}
	if strings.Contains(body, "cid-min") {
		t.Error("response leaks client_id")
	}

	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1 (only enabled)", len(resp))
	}
	if resp[0].ID != "min-1" || resp[0].Name != "Visible" {
		t.Fatalf("provider=%+v", resp[0])
	}
}

func TestGetProvidersMinimalMethodNotAllowed(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

// --- GetProviderDeleteSafe tests ---

func TestDeleteSafeEmptyReturns200(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ds-1", "Safe", true)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ds-1/delete_safe", nil)
	req.SetPathValue("id", "ds-1")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderLinkedUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 0 {
		t.Fatalf("count=%d, want 0", len(resp))
	}
}

func TestDeleteSafeLinkedReturns406(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ds-2", "Linked", true)
	f.seedIdentityUser("u-ds-1")
	f.seedProfile("u-ds-1", "user1@test.test")
	f.seedLink("ds-2", testExtKey("00001"), "u-ds-1")

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ds-2/delete_safe", nil)
	req.SetPathValue("id", "ds-2")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("status=%d, want 406", rec.Code)
	}
	var resp []ProviderLinkedUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1", len(resp))
	}
	if resp[0].ID != "u-ds-1" || resp[0].Email != "user1@test.test" {
		t.Fatalf("user=%+v", resp[0])
	}
}

func TestDeleteSafeIncludesDisabledUsers(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ds-3", "DisabledLink", true)
	f.seedIdentityUser("u-ds-dis")
	f.seedProfile("u-ds-dis", "dis@test.test")
	f.seedLink("ds-3", testExtKey("00002"), "u-ds-dis")
	f.disableUser("u-ds-dis")

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ds-3/delete_safe", nil)
	req.SetPathValue("id", "ds-3")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("status=%d, want 406", rec.Code)
	}
	var resp []ProviderLinkedUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1 (disabled user listed)", len(resp))
	}
}

func TestDeleteSafeUnauthorized(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ds-4/delete_safe", nil)
	req.SetPathValue("id", "ds-4")
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestDeleteSafeMethodNotAllowed(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/ds-5/delete_safe", nil)
	req.SetPathValue("id", "ds-5")
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

func TestDeleteSafeBrowserAdmin(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ds-browser", "Browser", true)

	called := false
	browserAdmin := func(w http.ResponseWriter, r *http.Request, _ bool) bool {
		called = true
		return true
	}
	h, err := NewRegistryHandler(f.store, f.keys, browserAdmin)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ds-browser/delete_safe", nil)
	req.SetPathValue("id", "ds-browser")
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if !called {
		t.Error("browserAdmin not called")
	}
}

// --- Constructor tests ---

func TestNewRegistryHandlerRequiresStore(t *testing.T) {
	f := newHTTPFixture(t)
	_, err := NewRegistryHandler(nil, f.keys, nil)
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestNewRegistryHandlerRequiresKeys(t *testing.T) {
	f := newHTTPFixture(t)
	_, err := NewRegistryHandler(f.store, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil apiKeys")
	}
}

func TestNewRegistryHandlerAcceptsNilBrowserAdmin(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.browserAdmin != nil {
		t.Fatal("browserAdmin should be nil")
	}
}

func TestPostProvidersEmptyList(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 0 {
		t.Fatalf("count=%d, want 0", len(resp))
	}
}

func TestPostProvidersMultipleWithSecrets(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("mp-1", "First", true)
	f.seedProvider("mp-2", "Second", false)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("count=%d, want 2", len(resp))
	}
	// Both providers returned; secret is nil (NULL in DB)
	for _, p := range resp {
		if p.ClientSecret != nil {
			t.Errorf("provider %s: secret should be nil", p.ID)
		}
	}
}

// --- Browser admin tests ---

func TestPostProvidersBrowserAdminRead(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ba-1", "BrowserAdmin", true)

	called := false
	browserAdmin := func(w http.ResponseWriter, r *http.Request, write bool) bool {
		called = true
		if write {
			t.Error("browser admin should not require CSRF for read")
		}
		return true
	}
	h, err := NewRegistryHandler(f.store, f.keys, browserAdmin)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if !called {
		t.Error("browserAdmin not called")
	}
}

func TestDeleteSafeBrowserAdminReadCSFFalse(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("ba-ds", "BrowserCSF", true)

	var sawWrite bool
	browserAdmin := func(w http.ResponseWriter, r *http.Request, write bool) bool {
		sawWrite = write
		return true
	}
	h, err := NewRegistryHandler(f.store, f.keys, browserAdmin)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/ba-ds/delete_safe", nil)
	req.SetPathValue("id", "ba-ds")
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if sawWrite {
		t.Error("browser admin should pass write=false for read endpoint")
	}
}

func TestPostProvidersNoBrowserAdmin(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.PostProviders(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestDeleteSafeNonExistentProvider(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/does-not-exist/delete_safe", nil)
	req.SetPathValue("id", "does-not-exist")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	// Non-existent provider has no linked users, so 200 with empty array
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
}

func TestDeleteSafeEmptyBodyIsJSON(t *testing.T) {
	f := newHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/empty/delete_safe", nil)
	req.SetPathValue("id", "empty")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.GetProviderDeleteSafe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("content-type=%q, want application/json", ct)
	}
}

func TestGetProvidersMinimalUpdatedNonzeroWithOwnLogo(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("logo-rast", "RasterProvider", true)
	f.seedProviderLogo("logo-rast", "small", "image/webp", []byte("raster-data"), 42)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1", len(resp))
	}
	if resp[0].Updated != 42 {
		t.Fatalf("updated=%d, want 42", resp[0].Updated)
	}
}

func TestGetProvidersMinimalUpdatedNonzeroWithOwnSVG(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("logo-svg", "SVGProvider", true)
	f.seedProviderLogo("logo-svg", "svg", "image/svg+xml", []byte("<svg/>"), 99)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1", len(resp))
	}
	if resp[0].Updated != 99 {
		t.Fatalf("updated=%d, want 99 (SVG via small fallback)", resp[0].Updated)
	}
}

func TestGetProvidersMinimalUpdatedZeroWhenAbsent(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("no-logo", "NoLogoProvider", true)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("count=%d, want 1", len(resp))
	}
	if resp[0].Updated != 0 {
		t.Fatalf("updated=%d, want 0 for absent logo", resp[0].Updated)
	}
}

func TestGetProvidersMinimalDisabledExcludedEvenWithLogo(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("dis-logo", "DisabledLogo", false)
	f.seedProviderLogo("dis-logo", "small", "image/webp", []byte("should-not-appear"), 55)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 0 {
		t.Fatalf("count=%d, want 0 (disabled excluded)", len(resp))
	}
}

func TestGetProvidersMinimalOtherProviderLogoNotUsed(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("target-p", "Target", true)
	f.seedProvider("other-p", "Other", true)
	f.seedProviderLogo("other-p", "small", "image/webp", []byte("other-logo"), 77)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("count=%d, want 2", len(resp))
	}
	for _, p := range resp {
		if p.ID == "target-p" && p.Updated != 0 {
			t.Fatalf("target-p updated=%d, want 0 (other provider logo not used)", p.Updated)
		}
		if p.ID == "other-p" && p.Updated != 77 {
			t.Fatalf("other-p updated=%d, want 77", p.Updated)
		}
	}
}

func TestGetProvidersMinimalSecretNeverLeaks(t *testing.T) {
	f := newHTTPFixture(t)
	f.seedProvider("leak-test", "LeakTest", true)
	f.seedProviderLogo("leak-test", "small", "image/webp", []byte("secret-logo"), 88)

	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil)
	rec := httptest.NewRecorder()
	h.GetProvidersMinimal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"client_secret", "secret", "cid-leak", "issuer", "token_endpoint"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q", leak)
		}
	}
	var resp []ProviderMinimalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].Updated != 88 {
		t.Fatalf("provider=%+v", resp)
	}
}
