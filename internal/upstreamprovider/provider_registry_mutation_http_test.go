package upstreamprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type mutationHTTPFixture struct {
	t         *testing.T
	ctx       context.Context
	db        *rhiza.DB
	keyring   EnvelopeKeyring
	store     *RegistryStore
	keys      *apikey.Store
	token     string
	principal *apikey.Principal
}

func newMutationHTTPFixture(t *testing.T) *mutationHTTPFixture {
	t.Helper()
	ctx := context.Background()
	db := openTestDB(t, "mutation-http-test")
	dir := t.TempDir()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, 32))
	if err := os.WriteFile(filepath.Join(dir, "test-key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	rStore, err := NewRegistryStore(db, keyring)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := apiKeys.Create(ctx, nil, apikey.Request{
		Name:   "mutation-http-manager",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Create, apikey.Update, apikey.Delete, apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := apiKeys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return &mutationHTTPFixture{
		t:         t,
		ctx:       ctx,
		db:        db,
		keyring:   keyring,
		store:     rStore,
		keys:      apiKeys,
		token:     token,
		principal: &p,
	}
}

func (f *mutationHTTPFixture) seedProvider(id string) {
	f.t.Helper()
	_, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "seed-http-mut-" + id,
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		Args: []any{id, int64(1), "seed-" + id, "oidc",
			"https://issuer-" + id + ".test", "https://auth-" + id + ".test",
			"https://token-" + id + ".test", "https://userinfo-" + id + ".test",
			"cid-" + id, nil, "openid", "$.admin", "true",
			nil, nil, int64(1), int64(1), int64(0), nil, int64(0), int64(0)},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func validMutationHTTPJSON() []byte {
	req := ProviderRequest{
		Name: "HTTP Test Provider", Typ: AuthProviderTypeOIDC, Enabled: true,
		Issuer: "https://issuer.http-test", AuthorizationEndpoint: "https://issuer.http-test/auth",
		TokenEndpoint: "https://issuer.http-test/token", UserinfoEndpoint: "https://issuer.http-test/userinfo",
		ClientID: "http-test-client", Scope: "openid",
		UsePKCE: true, ClientSecretBasic: true, ClientSecretPost: false,
		AutoOnboarding: false, AutoLink: false,
	}
	b, _ := json.Marshal(req)
	return b
}

func validMutationHTTPJSONWithSecret() []byte {
	secret := "my-client-secret"
	req := ProviderRequest{
		Name: "HTTP Test Provider", Typ: AuthProviderTypeOIDC, Enabled: true,
		Issuer: "https://issuer.http-test", AuthorizationEndpoint: "https://issuer.http-test/auth",
		TokenEndpoint: "https://issuer.http-test/token", UserinfoEndpoint: "https://issuer.http-test/userinfo",
		ClientID: "http-test-client", ClientSecret: &secret, Scope: "openid",
		UsePKCE: true, ClientSecretBasic: true, ClientSecretPost: false,
		AutoOnboarding: false, AutoLink: false,
	}
	b, _ := json.Marshal(req)
	return b
}

// --- Create tests ---

func TestCreateProviderSuccess(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil { t.Fatalf("decode: %v", err) }
	if resp.ID == "" { t.Fatal("provider ID empty") }
	if resp.Name != "HTTP Test Provider" { t.Fatalf("name=%q", resp.Name) }
	if resp.Typ != AuthProviderTypeOIDC { t.Fatalf("typ=%q", resp.Typ) }
}

func TestCreateProviderWithSecret(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSONWithSecret()))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String())
	}
	var resp ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil { t.Fatalf("decode: %v", err) }
	if resp.ClientSecret == nil { t.Fatal("expected non-nil client_secret") }
	if *resp.ClientSecret != "my-client-secret" { t.Fatalf("secret=%q", *resp.ClientSecret) }
	doc, err := f.store.Get(f.ctx, resp.ID)
	if err != nil { t.Fatalf("Get: %v", err) }
	if doc.Secret == nil { t.Fatal("expected non-nil encrypted secret") }
	purpose := ProviderSecretPurpose(resp.ID)
	cleartext, err := f.keyring.OpenEnvelope(purpose, doc.Secret)
	if err != nil { t.Fatalf("OpenEnvelope: %v", err) }
	if string(cleartext) != "my-client-secret" { t.Fatalf("cleartext=%q", cleartext) }
}

func TestCreateProviderReturnsDecryptedSecret(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSONWithSecret()))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d", rec.Code) }
	var resp ProviderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil { t.Fatalf("decode: %v", err) }
	if resp.ClientSecret == nil || *resp.ClientSecret != "my-client-secret" {
		t.Fatalf("expected decrypted secret, got %v", resp.ClientSecret)
	}
}

func TestCreateProviderInvalidRequestNoMutation(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("setup: status=%d", rec.Code) }
	var resp ProviderResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	providerID := resp.ID
	invalidBody := []byte(`{"name":"","typ":"oidc","enabled":true,"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t","userinfo_endpoint":"https://x/u","client_id":"c","scope":"openid","use_pkce":true,"client_secret_basic":true,"client_secret_post":false,"auto_onboarding":false,"auto_link":false}`)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(invalidBody))
	req2.Header.Set("Authorization", "API-Key "+f.token)
	rec2 := httptest.NewRecorder()
	h.CreateProvider(rec2, req2)
	if rec2.Code != http.StatusBadRequest { t.Fatalf("invalid status=%d", rec2.Code) }
	doc, err := f.store.Get(f.ctx, providerID)
	if err != nil { t.Fatalf("Get: %v", err) }
	if doc.Name != "HTTP Test Provider" { t.Fatalf("name changed to %q", doc.Name) }
}

func TestCreateProviderReservedIssuer(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := []byte(`{"name":"Reserved","typ":"oidc","enabled":true,"issuer":"atproto","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t","userinfo_endpoint":"https://x/u","client_id":"c","scope":"openid","use_pkce":true,"client_secret_basic":true,"client_secret_post":false,"auto_onboarding":false,"auto_link":false}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderPKCEOrSecretRequired(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := []byte(`{"name":"NoPKCE","typ":"oidc","enabled":true,"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t","userinfo_endpoint":"https://x/u","client_id":"c","scope":"openid","use_pkce":false,"client_secret_basic":true,"client_secret_post":false,"auto_onboarding":false,"auto_link":false}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderSecretRequiresMethod(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	secret := "s"
	body, _ := json.Marshal(ProviderRequest{
		Name: "NoBasicPost", Typ: AuthProviderTypeOIDC, Enabled: true,
		Issuer: "https://x", AuthorizationEndpoint: "https://x/a",
		TokenEndpoint: "https://x/t", UserinfoEndpoint: "https://x/u",
		ClientID: "c", ClientSecret: &secret, Scope: "openid",
		UsePKCE: false, ClientSecretBasic: false, ClientSecretPost: false,
		AutoOnboarding: false, AutoLink: false,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	// POST create does NOT enforce basic|post (PUT-only per pinned rauthy v0.36.2).
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
}

func TestCreateProviderMethodNotAllowed(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/create", nil)
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusMethodNotAllowed { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderUnauthorized(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderWrongRight(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	_, token, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name: "read-only-key", Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	req.Header.Set("Authorization", "API-Key "+token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusForbidden { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderRevokedKey(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-mut-key", SQL: "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args: []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

// --- Update tests ---

func TestUpdateProviderSuccess(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-ok")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-ok", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "upd-ok")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
}

func TestUpdateProviderWithSecret(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-sec")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-sec", bytes.NewReader(validMutationHTTPJSONWithSecret()))
	req.SetPathValue("id", "upd-sec")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
	doc, err := f.store.Get(f.ctx, "upd-sec")
	if err != nil { t.Fatalf("Get: %v", err) }
	if doc.Secret == nil { t.Fatal("expected non-nil secret") }
	purpose := ProviderSecretPurpose("upd-sec")
	cleartext, err := f.keyring.OpenEnvelope(purpose, doc.Secret)
	if err != nil { t.Fatalf("OpenEnvelope: %v", err) }
	if string(cleartext) != "my-client-secret" { t.Fatalf("cleartext=%q", cleartext) }
}

func TestUpdateProviderClearSecret(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-clear")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-clear", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "upd-clear")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
	doc, err := f.store.Get(f.ctx, "upd-clear")
	if err != nil { t.Fatalf("Get: %v", err) }
	if doc.Secret != nil { t.Fatalf("expected nil secret, got %x", doc.Secret) }
}

func TestUpdateProviderInvalidRequestNoMutation(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-inv")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	orig, err := f.store.Get(f.ctx, "upd-inv")
	if err != nil { t.Fatal(err) }
	invalidBody := []byte(`{"name":"","typ":"oidc","enabled":true,"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t","userinfo_endpoint":"https://x/u","client_id":"c","scope":"openid","use_pkce":true,"client_secret_basic":true,"client_secret_post":false,"auto_onboarding":false,"auto_link":false}`)
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-inv", bytes.NewReader(invalidBody))
	req.SetPathValue("id", "upd-inv")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
	after, err := f.store.Get(f.ctx, "upd-inv")
	if err != nil { t.Fatal(err) }
	if after.Name != orig.Name { t.Fatalf("name changed from %q to %q", orig.Name, after.Name) }
}

func TestUpdateProviderNotFound(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/no-such-id", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "no-such-id")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusNotFound { t.Fatalf("status=%d", rec.Code) }
}

func TestUpdateProviderMethodNotAllowed(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/x", nil)
	req.SetPathValue("id", "x")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusMethodNotAllowed { t.Fatalf("status=%d", rec.Code) }
}

func TestUpdateProviderUnauthorized(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/x", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "x")
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

func TestUpdateProviderWrongRight(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-wr")
	_, token, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name: "read-only-key-upd", Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-wr", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "upd-wr")
	req.Header.Set("Authorization", "API-Key "+token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusForbidden { t.Fatalf("status=%d", rec.Code) }
}

func TestUpdateProviderRevokedKey(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("upd-rv")
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-upd-key", SQL: "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args: []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/upd-rv", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "upd-rv")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

// --- Delete tests ---

func TestDeleteProviderSuccess(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("del-ok")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/del-ok", nil)
	req.SetPathValue("id", "del-ok")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
	_, err = f.store.Get(f.ctx, "del-ok")
	if !errors.Is(err, ErrProviderNotFound) { t.Fatalf("expected ErrProviderNotFound, got %v", err) }
}

func TestDeleteProviderMissingIDSucceeds(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d", rec.Code) }
}

func TestDeleteProviderWithSecret(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	createReq := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSONWithSecret()))
	createReq.Header.Set("Authorization", "API-Key "+f.token)
	createRec := httptest.NewRecorder()
	h.CreateProvider(createRec, createReq)
	if createRec.Code != http.StatusOK { t.Fatalf("create status=%d", createRec.Code) }
	var created ProviderResponse
	json.Unmarshal(createRec.Body.Bytes(), &created)
	deleteReq := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/"+created.ID, nil)
	deleteReq.SetPathValue("id", created.ID)
	deleteReq.Header.Set("Authorization", "API-Key "+f.token)
	deleteRec := httptest.NewRecorder()
	h.DeleteProvider(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK { t.Fatalf("delete status=%d", deleteRec.Code) }
	_, err = f.store.Get(f.ctx, created.ID)
	if !errors.Is(err, ErrProviderNotFound) { t.Fatalf("expected ErrProviderNotFound, got %v", err) }
}

func TestDeleteProviderInvalidRequestNoMutation(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/", nil)
	req.SetPathValue("id", "")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

func TestDeleteProviderMethodNotAllowed(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/x", nil)
	req.SetPathValue("id", "x")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusMethodNotAllowed { t.Fatalf("status=%d", rec.Code) }
}

func TestDeleteProviderUnauthorized(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/x", nil)
	req.SetPathValue("id", "x")
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

func TestDeleteProviderWrongRight(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	_, token, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name: "read-only-key-del", Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/x", nil)
	req.SetPathValue("id", "x")
	req.Header.Set("Authorization", "API-Key "+token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusForbidden { t.Fatalf("status=%d", rec.Code) }
}

func TestDeleteProviderRevokedKey(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-del-key", SQL: "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args: []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil { t.Fatal(err) }
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/x", nil)
	req.SetPathValue("id", "x")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

// --- Provider ID generation ---

func TestGenerateProviderIDLength(t *testing.T) {
	t.Parallel()
	id, err := GenerateProviderID()
	if err != nil { t.Fatal(err) }
	if len(id) != 24 { t.Fatalf("len=%d", len(id)) }
}

func TestGenerateProviderIDAlphanumeric(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		id, err := GenerateProviderID()
		if err != nil { t.Fatal(err) }
		for _, c := range id {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				t.Fatalf("non-alphanumeric char %q in %q", c, id)
			}
		}
	}
}

func TestGenerateProviderIDUnique(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := GenerateProviderID()
		if err != nil { t.Fatal(err) }
		if seen[id] { t.Fatalf("duplicate ID: %q", id) }
		seen[id] = true
	}
}

// --- Cross-provider secret binding ---

func TestCreateCrossProviderSecretBinding(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := validMutationHTTPJSONWithSecret()
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
		req.Header.Set("Authorization", "API-Key "+f.token)
		rec := httptest.NewRecorder()
		h.CreateProvider(rec, req)
		if rec.Code != http.StatusOK { t.Fatalf("create %d: status=%d; body=%s", i, rec.Code, rec.Body.String()) }
	}
	providers, err := f.store.List(f.ctx)
	if err != nil { t.Fatal(err) }
	if len(providers) != 2 { t.Fatalf("count=%d", len(providers)) }
	for _, doc := range providers {
		if doc.Secret == nil { t.Fatalf("provider %s: expected non-nil secret", doc.ID) }
		purpose := ProviderSecretPurpose(doc.ID)
		cleartext, err := f.keyring.OpenEnvelope(purpose, doc.Secret)
		if err != nil { t.Fatalf("provider %s: OpenEnvelope: %v", doc.ID, err) }
		if string(cleartext) != "my-client-secret" { t.Fatalf("provider %s: cleartext=%q", doc.ID, cleartext) }
	}
}

// --- Lifecycle ---

func TestProviderLifecycleCreateUpdateDelete(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	createReq := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	createReq.Header.Set("Authorization", "API-Key "+f.token)
	createRec := httptest.NewRecorder()
	h.CreateProvider(createRec, createReq)
	if createRec.Code != http.StatusOK { t.Fatalf("create: %d", createRec.Code) }
	var created ProviderResponse
	json.Unmarshal(createRec.Body.Bytes(), &created)
	updateReq := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/"+created.ID, bytes.NewReader(validMutationHTTPJSON()))
	updateReq.SetPathValue("id", created.ID)
	updateReq.Header.Set("Authorization", "API-Key "+f.token)
	updateRec := httptest.NewRecorder()
	h.UpdateProvider(updateRec, updateReq)
	if updateRec.Code != http.StatusOK { t.Fatalf("update: %d", updateRec.Code) }
	doc, err := f.store.Get(f.ctx, created.ID)
	if err != nil { t.Fatalf("Get: %v", err) }
	if doc.Name != "HTTP Test Provider" { t.Fatalf("name=%q", doc.Name) }
	deleteReq := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/"+created.ID, nil)
	deleteReq.SetPathValue("id", created.ID)
	deleteReq.Header.Set("Authorization", "API-Key "+f.token)
	deleteRec := httptest.NewRecorder()
	h.DeleteProvider(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK { t.Fatalf("delete: %d", deleteRec.Code) }
	_, err = f.store.Get(f.ctx, created.ID)
	if !errors.Is(err, ErrProviderNotFound) { t.Fatalf("expected ErrProviderNotFound, got %v", err) }
}

// --- Browser admin ---

func TestCreateProviderBrowserAdmin(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	called := false
	ba := func(w http.ResponseWriter, r *http.Request, write bool) bool { called = true; if !write { t.Error("expected CSRF") }; return true }
	h, err := NewRegistryHandler(f.store, f.keys, ba)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
	if !called { t.Error("browserAdmin not called") }
}

func TestUpdateProviderBrowserAdmin(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("ba-upd")
	called := false
	ba := func(w http.ResponseWriter, r *http.Request, write bool) bool { called = true; if !write { t.Error("expected CSRF") }; return true }
	h, err := NewRegistryHandler(f.store, f.keys, ba)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/ba-upd", bytes.NewReader(validMutationHTTPJSON()))
	req.SetPathValue("id", "ba-upd")
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d; body=%s", rec.Code, rec.Body.String()) }
	if !called { t.Error("browserAdmin not called") }
}

func TestDeleteProviderBrowserAdmin(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("ba-del")
	called := false
	ba := func(w http.ResponseWriter, r *http.Request, write bool) bool { called = true; if !write { t.Error("expected CSRF") }; return true }
	h, err := NewRegistryHandler(f.store, f.keys, ba)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/ba-del", nil)
	req.SetPathValue("id", "ba-del")
	rec := httptest.NewRecorder()
	h.DeleteProvider(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("status=%d", rec.Code) }
	if !called { t.Error("browserAdmin not called") }
}

func TestCreateProviderNoBrowserAdmin(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(validMutationHTTPJSON()))
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}

// --- Invalid JSON ---

func TestCreateProviderInvalidJSON(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader([]byte("{not json}")))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

func TestUpdateProviderInvalidJSON(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/x", bytes.NewReader([]byte("{not json}")))
	req.SetPathValue("id", "x")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

func TestCreateProviderUnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := append(validMutationHTTPJSON(), []byte(`,"unknown_field":"x"`)...)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d", rec.Code) }
}

// --- Bounded JSON body ---

func TestCreateProviderTrailingJSONRejected(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := append(validMutationHTTPJSON(), []byte(`{}`)...)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(body))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d; trailing JSON should be rejected", rec.Code) }
}

func TestUpdateProviderTrailingJSONRejected(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	f.seedProvider("trail-upd")
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	body := append(validMutationHTTPJSON(), []byte(`{}`)...)
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/providers/trail-upd", bytes.NewReader(body))
	req.SetPathValue("id", "trail-upd")
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.UpdateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d; trailing JSON should be rejected", rec.Code) }
}

func TestCreateProviderOversizeBodyRejected(t *testing.T) {
	t.Parallel()
	f := newMutationHTTPFixture(t)
	h, err := NewRegistryHandler(f.store, f.keys, nil)
	if err != nil { t.Fatal(err) }
	oversize := bytes.Repeat([]byte("x"), 128*1024)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", bytes.NewReader(oversize))
	req.Header.Set("Authorization", "API-Key "+f.token)
	rec := httptest.NewRecorder()
	h.CreateProvider(rec, req)
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d; oversize body should be rejected", rec.Code) }
}
