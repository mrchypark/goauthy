package main

import (
	"bytes"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func providerLogoTestDB(t *testing.T) (*rhiza.DB, *apikey.Store) {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "provider-logo-route-test", DataDir: migratedDataDir(t, "provider-logo-route-test")})
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

func testProviderLogoPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 256, 256))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// testActualMux uses the shared mountProviderLogoRoutes helper, same as main.
func testActualMux(t *testing.T, h *branding.ProviderLogoHandler) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mountProviderLogoRoutes(mux, h)
	return mux
}

func providerLogoTestKey(t *testing.T, keys *apikey.Store) string {
	t.Helper()
	_, token, err := keys.Create(t.Context(), nil, apikey.Request{
		Name:   "prov-logo-route-test",
		Access: []apikey.Access{{Group: "AuthProviders", AccessRights: []apikey.Right{apikey.Update}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func providerLogoMultipartUpload(t *testing.T, path, contentType string, data []byte, id, token string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="logo"; filename="logo"`)
	h.Set("Content-Type", contentType)
	p, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "API-Key "+token)
	return req
}

func TestProviderLogoRouteGETMissingReturns404(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/missing/img", nil))
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", resp.Code)
	}
}

func TestProviderLogoRoutePUTUnauthorizedReturns401(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/auth/v1/providers/prov-a/img", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.Code)
	}
}

func TestProviderLogoRouteDELETEReturns401WithoutAuth(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/prov-b/img", nil))
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.Code)
	}
}

func TestProviderLogoRouteAuthorizedUploadAndGet(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	ctx := t.Context()
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	// Seed auth provider.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "provider-logo-route-seed-up",
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{"up-provider", int64(1), "up-provider", "oidc", "https://up-provider.example", "https://up-provider.example/auth", "https://up-provider.example/token", "https://up-provider.example/userinfo", "client-up-provider", "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
	token := providerLogoTestKey(t, keys)
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	putResp := httptest.NewRecorder()
	mux.ServeHTTP(putResp, providerLogoMultipartUpload(t, "/auth/v1/providers/up-provider/img", "image/png", testProviderLogoPNG(t), "up-provider", token))
	if putResp.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%q", putResp.Code, putResp.Body.String())
	}

	getResp := httptest.NewRecorder()
	mux.ServeHTTP(getResp, httptest.NewRequest(http.MethodGet, "/auth/v1/providers/up-provider/img", nil))
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET status=%d", getResp.Code)
	}
	if getResp.Header().Get("Content-Type") != "image/webp" {
		t.Fatalf("Content-Type=%q want image/webp", getResp.Header().Get("Content-Type"))
	}
	if len(getResp.Body.Bytes()) == 0 {
		t.Fatal("GET body is empty")
	}
}

// TestProviderLogoRouteAllMethodsAvailable verifies GET/PUT/DELETE are all
// registered unconditionally by mountProviderLogoRoutes.
func TestProviderLogoRouteAllMethodsAvailable(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest(method, "/auth/v1/providers/x/img", nil))
		// GET returns 404 (no logo); PUT/DELETE return 401 (no auth).
		// A missing route would return 405 Method Not Allowed.
		if resp.Code == http.StatusMethodNotAllowed {
			t.Fatalf("%s /img returned 405 Method Not Allowed — route not registered", method)
		}
	}
}

// TestProviderLogoAndLinkDeleteRoutesCoexist verifies that DELETE /img and
// DELETE /link are distinct routes that select their intended handlers.
func TestProviderLogoAndLinkDeleteRoutesCoexist(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Shared mux with both logo routes AND a stub link handler.
	mux := http.NewServeMux()
	mountProviderLogoRoutes(mux, handler)
	linkCalled := false
	mux.HandleFunc("DELETE /auth/v1/providers/{providerID}/link", func(w http.ResponseWriter, r *http.Request) {
		linkCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	// DELETE /img hits the logo handler (401 without auth).
	imgResp := httptest.NewRecorder()
	mux.ServeHTTP(imgResp, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/prov-x/img", nil))
	if imgResp.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE /img status=%d want 401", imgResp.Code)
	}
	if linkCalled {
		t.Fatal("DELETE /img incorrectly routed to link handler")
	}

	// DELETE /link hits the link handler.
	linkResp := httptest.NewRecorder()
	mux.ServeHTTP(linkResp, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/prov-x/link", nil))
	if !linkCalled {
		t.Fatal("DELETE /link did not reach its handler")
	}
	if linkResp.Code != http.StatusNoContent {
		t.Fatalf("DELETE /link status=%d want 204", linkResp.Code)
	}
}

// TestProviderLogoRouteMuxNilRuntimeMountAll confirms that with no upstream
// runtime, all three logo methods are mounted. This is the non-nil runtime
// counterpart; the gate was removed so the behavior is identical.
func TestProviderLogoRouteMuxNilRuntimeMountAll(t *testing.T) {
	t.Parallel()
	db, keys := providerLogoTestDB(t)
	store, err := branding.NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := branding.NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := testActualMux(t, handler)

	for _, tc := range []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusNotFound},
		{http.MethodPut, http.StatusUnauthorized},
		{http.MethodDelete, http.StatusUnauthorized},
	} {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest(tc.method, "/auth/v1/providers/nilrt/img", nil))
		if resp.Code == http.StatusMethodNotAllowed {
			t.Fatalf("%s returned 405 — route missing", tc.method)
		}
		if resp.Code != tc.want {
			t.Fatalf("%s status=%d want %d", tc.method, resp.Code, tc.want)
		}
	}
}
