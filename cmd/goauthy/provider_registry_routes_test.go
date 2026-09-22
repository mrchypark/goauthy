package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func providerRegistryTestDB(t *testing.T) (*rhiza.DB, *apikey.Store) {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "provider-registry-route-test", DataDir: migratedDataDir(t, "provider-registry-route-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, keys
}

func providerRegistrySeedProvider(t *testing.T, db *rhiza.DB, id, name string, enabled bool) {
	t.Helper()
	enabledVal := int64(0)
	if enabled {
		enabledVal = 1
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{
		RequestID: "registry-route-seed-" + id,
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{id, enabledVal, name, "oidc", "https://" + id + ".test", "https://" + id + ".test/auth", "https://" + id + ".test/token", "https://" + id + ".test/userinfo", "cid-" + id, "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
}

func providerRegistryTestKey(t *testing.T, keys *apikey.Store, rights ...apikey.Right) string {
	t.Helper()
	if len(rights) == 0 {
		rights = []apikey.Right{apikey.Read}
	}
	_, token, err := keys.Create(t.Context(), nil, apikey.Request{
		Name:   "prov-reg-route-key",
		Access: []apikey.Access{{Group: "AuthProviders", AccessRights: rights}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// providerRegistryTestKeyring creates a real oidc.Keyring backed by a
// temporary master-key directory, following the same pattern used by
// cmd/goauthy key tests.
func providerRegistryTestKeyring(t *testing.T) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dev-1"), []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

// testRegistryActualMux uses mountProviderRegistryRoutes, same as main.
func testRegistryActualMux(t *testing.T, h *upstreamprovider.RegistryHandler) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mountProviderRegistryRoutes(mux, h)
	return mux
}

// --- Read route tests (preserved) ---

func TestRegistryRoutePostProvidersUnauthorized(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("POST /providers status=%d want 401", resp.Code)
	}
}

func TestRegistryRouteGetMinimalPublic(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	providerRegistrySeedProvider(t, db, "rm-1", "MinimalPub", true)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /providers/minimal status=%d want 200", resp.Code)
	}
}

func TestRegistryRouteDeleteSafeUnauthorized(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/rm-x/delete_safe", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("GET /providers/{id}/delete_safe status=%d want 401", resp.Code)
	}
}

func TestRegistryRouteAllMethodsRegistered(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)

	// POST /auth/v1/providers — returns 401 without auth.
	post := httptest.NewRecorder()
	mux.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/auth/v1/providers", nil))
	if post.Code == http.StatusMethodNotAllowed {
		t.Fatal("POST /providers returned 405 — route not registered")
	}
	if post.Code != http.StatusUnauthorized {
		t.Fatalf("POST /providers status=%d want 401", post.Code)
	}

	// GET /auth/v1/providers/minimal — public, returns 200.
	minimal := httptest.NewRecorder()
	mux.ServeHTTP(minimal, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil))
	if minimal.Code == http.StatusMethodNotAllowed {
		t.Fatal("GET /providers/minimal returned 405 — route not registered")
	}
	if minimal.Code != http.StatusOK {
		t.Fatalf("GET /providers/minimal status=%d want 200", minimal.Code)
	}

	// GET /auth/v1/providers/{id}/delete_safe — returns 401 without auth.
	ds := httptest.NewRecorder()
	mux.ServeHTTP(ds, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/x/delete_safe", nil))
	if ds.Code == http.StatusMethodNotAllowed {
		t.Fatal("GET /providers/{id}/delete_safe returned 405 — route not registered")
	}
	if ds.Code != http.StatusUnauthorized {
		t.Fatalf("GET /providers/{id}/delete_safe status=%d want 401", ds.Code)
	}
}

// --- Write route tests ---

func TestRegistryRouteCreateUnauthorized(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/auth/v1/providers/create", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("POST /providers/create status=%d want 401", resp.Code)
	}
}

func TestRegistryRouteUpdateUnauthorized(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/auth/v1/providers/prov-x", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("PUT /providers/{id} status=%d want 401", resp.Code)
	}
}

func TestRegistryRouteDeleteUnauthorized(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testRegistryActualMux(t, handler)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/prov-x", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE /providers/{id} status=%d want 401", resp.Code)
	}
}

func TestRegistryRouteWriteCoexistWithReadAndLogo(t *testing.T) {
	t.Parallel()
	db, keys := providerRegistryTestDB(t)
	store, err := upstreamprovider.NewRegistryStore(db, providerRegistryTestKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := upstreamprovider.NewRegistryHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountProviderRegistryRoutes(mux, handler)

	// Stub logo and link handlers to verify routing isolation.
	logoCalled := false
	mux.HandleFunc("GET /auth/v1/providers/{providerID}/img", func(w http.ResponseWriter, r *http.Request) {
		logoCalled = true
		w.WriteHeader(http.StatusNotFound)
	})
	linkCalled := false
	mux.HandleFunc("DELETE /auth/v1/providers/{providerID}/link", func(w http.ResponseWriter, r *http.Request) {
		linkCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	// Write routes hit their handlers, not logo/link stubs.
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/auth/v1/providers/create", http.StatusUnauthorized},
		{http.MethodPut, "/auth/v1/providers/rw-x", http.StatusUnauthorized},
		{http.MethodDelete, "/auth/v1/providers/rw-x", http.StatusUnauthorized},
	} {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest(tc.method, tc.path, nil))
		if resp.Code == http.StatusMethodNotAllowed {
			t.Fatalf("%s %s returned 405 — route not registered", tc.method, tc.path)
		}
		if resp.Code != tc.want {
			t.Fatalf("%s %s status=%d want %d", tc.method, tc.path, resp.Code, tc.want)
		}
	}
	if logoCalled {
		t.Fatal("write route reached logo handler")
	}
	if linkCalled {
		t.Fatal("write route reached link handler")
	}

	// Read routes still work.
	minimal := httptest.NewRecorder()
	mux.ServeHTTP(minimal, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/minimal", nil))
	if minimal.Code != http.StatusOK {
		t.Fatalf("GET /providers/minimal status=%d want 200 after write mount", minimal.Code)
	}

	// Logo and link stubs are reachable on their own paths.
	imgResp := httptest.NewRecorder()
	mux.ServeHTTP(imgResp, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/prov-x/img", nil))
	if !logoCalled {
		t.Fatal("GET /providers/{id}/img did not reach logo handler")
	}
	linkResp := httptest.NewRecorder()
	mux.ServeHTTP(linkResp, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/prov-x/link", nil))
	if !linkCalled {
		t.Fatal("DELETE /providers/{id}/link did not reach link handler")
	}
}

