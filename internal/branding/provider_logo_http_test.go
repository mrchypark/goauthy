package branding

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

func TestProviderLogoHandlerGetReturnsPNG(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-a")
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-png", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	put := httptest.NewRecorder()
	request := providerLogoMultipartRequest(t, http.MethodPut, "/auth/v1/providers/prov-a/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-a")
	request.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(put, request)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%q", put.Code, put.Body.String())
	}

	get := httptest.NewRecorder()
	handler.Logo(get, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-a/img", nil, "prov-a"))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d", get.Code)
	}
	if get.Header().Get("Content-Type") != "image/webp" {
		t.Fatalf("Content-Type=%q want image/webp", get.Header().Get("Content-Type"))
	}
	if len(get.Body.Bytes()) == 0 {
		t.Fatal("GET body is empty")
	}
	if get.Header().Get("Cache-Control") != "" {
		t.Fatalf("unexpected Cache-Control=%q", get.Header().Get("Cache-Control"))
	}

	// Public GET returns small 20x20.
	assertDecodedSize(t, get.Body.Bytes(), 20, 20)

	// Stored medium is 128x128.
	medium, err := store.Find(ctx, "prov-a", "medium")
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedSize(t, medium.Data, 128, 128)
}

func TestProviderLogoHandlerGetReturnsSVG(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-b")
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-svg", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Input includes <script> which sanitizer must strip.
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><rect width="20" height="20" fill="blue"/><script>alert(1)</script></svg>`)
	put := httptest.NewRecorder()
	request := providerLogoMultipartRequest(t, http.MethodPut, "/auth/v1/providers/prov-b/img", "image/svg+xml", svg, "prov-b")
	request.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(put, request)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%q", put.Code, put.Body.String())
	}

	get := httptest.NewRecorder()
	handler.Logo(get, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-b/img", nil, "prov-b"))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d", get.Code)
	}
	if get.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("Content-Type=%q want image/svg+xml", get.Header().Get("Content-Type"))
	}
	if len(get.Body.Bytes()) == 0 {
		t.Fatal("GET body is empty")
	}

	// Sanitizer must strip <script>.
	if bytes.Contains(get.Body.Bytes(), []byte("<script")) {
		t.Fatalf("sanitizer did not remove <script>: %s", get.Body.String())
	}
	// Sanitizer must preserve <rect>.
	if !bytes.Contains(get.Body.Bytes(), []byte("<rect")) {
		t.Fatal("sanitizer removed <rect>")
	}
}

func TestProviderLogoHandlerGetCacheControl(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-c")
	seedProviderLogo(t, ctx, db, "prov-c", "small", "image/webp", []byte("prov-logo"), 31)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	noCache := httptest.NewRecorder()
	handler.Logo(noCache, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-c/img", nil, "prov-c"))
	if noCache.Code != http.StatusOK || noCache.Header().Get("Cache-Control") != "" {
		t.Fatalf("no-cache status=%d Cache-Control=%q", noCache.Code, noCache.Header().Get("Cache-Control"))
	}

	cached := httptest.NewRecorder()
	handler.Logo(cached, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-c/img?updated=%2B7", nil, "prov-c"))
	if cached.Code != http.StatusOK || cached.Header().Get("Cache-Control") != "max-age=31104000, stale-while-revalidate=2592000, public" {
		t.Fatalf("cached status=%d Cache-Control=%q", cached.Code, cached.Header().Get("Cache-Control"))
	}

	invalid := httptest.NewRecorder()
	handler.Logo(invalid, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-c/img?updated=bad", nil, "prov-c"))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid updated status=%d", invalid.Code)
	}
}

func TestProviderLogoHandlerPutUnauthorized(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-d")
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	unauth := httptest.NewRecorder()
	handler.Logo(unauth, providerLogoMultipartRequest(t, http.MethodPut, "/auth/v1/providers/prov-d/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-d"))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized PUT status=%d", unauth.Code)
	}
}

func TestProviderLogoHandlerPutRevokedKey(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-e")
	seedProviderLogo(t, ctx, db, "prov-e", "small", "image/webp", []byte("old-logo"), 41)
	keys, token, principal := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-revoked", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	revoked := httptest.NewRecorder()
	revokedReq := providerLogoMultipartRequest(t, http.MethodPut, "/auth/v1/providers/prov-e/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-e")
	revokedReq.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(revoked, revokedReq)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked PUT status=%d", revoked.Code)
	}
	old, err := store.Find(ctx, "prov-e", "small")
	if err != nil || !bytes.Equal(old.Data, []byte("old-logo")) {
		t.Fatalf("revoked PUT changed logo=%#v err=%v", old, err)
	}
}

func TestProviderLogoHandlerPutWrongGroup(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-f")
	seedProviderLogo(t, ctx, db, "prov-f", "small", "image/webp", []byte("old-logo"), 51)
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-wrong", "Clients", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	wrong := httptest.NewRecorder()
	wrongReq := providerLogoMultipartRequest(t, http.MethodPut, "/auth/v1/providers/prov-f/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-f")
	wrongReq.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(wrong, wrongReq)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong group PUT status=%d", wrong.Code)
	}
	old, err := store.Find(ctx, "prov-f", "small")
	if err != nil || !bytes.Equal(old.Data, []byte("old-logo")) {
		t.Fatalf("wrong group PUT changed logo=%#v err=%v", old, err)
	}
}

func TestProviderLogoHandlerMalformedPreservesPrior(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-g")
	seedProviderLogo(t, ctx, db, "prov-g", "small", "image/webp", []byte("old-logo"), 61)
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-malformed", "AuthProviders", apikey.Update)
	browserAdmin := func(w http.ResponseWriter, _ *http.Request, _ bool) bool {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	handler, err := NewProviderLogoHandler(store, keys, browserAdmin)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{name: "json", request: providerLogoRequestWithAuth(http.MethodPut, "/auth/v1/providers/prov-g/img", strings.NewReader(`{"data":"x"}`), "prov-g", token), wantStatus: http.StatusBadRequest},
		{name: "unsupported type", request: providerLogoMultipartRequestWithAuth(t, http.MethodPut, "/auth/v1/providers/prov-g/img", "image/gif", []byte("gif"), "prov-g", token), wantStatus: http.StatusBadRequest},
		{name: "invalid png", request: providerLogoMultipartRequestWithAuth(t, http.MethodPut, "/auth/v1/providers/prov-g/img", "image/png", []byte("not png"), "prov-g", token), wantStatus: http.StatusBadRequest},
		{name: "invalid svg", request: providerLogoMultipartRequestWithAuth(t, http.MethodPut, "/auth/v1/providers/prov-g/img", "image/svg+xml", []byte("<not-svg/>"), "prov-g", token), wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.Logo(response, tc.request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}

	old, err := store.Find(ctx, "prov-g", "small")
	if err != nil || !bytes.Equal(old.Data, []byte("old-logo")) {
		t.Fatalf("malformed uploads changed logo=%#v err=%v", old, err)
	}
}

func TestProviderLogoHandlerUploadLimitRejectsPreservesPrior(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-limit")
	seedProviderLogo(t, ctx, db, "prov-limit", "small", "image/webp", []byte("prior-logo"), 81)
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-limit", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Content-Length exceeds 10 MiB limit.
	oversize := httptest.NewRecorder()
	oversizeReq := providerLogoMultipartRequestWithAuth(t, http.MethodPut, "/auth/v1/providers/prov-limit/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-limit", token)
	oversizeReq.ContentLength = providerLogoUploadLimit + 1
	handler.Logo(oversize, oversizeReq)
	if oversize.Code != http.StatusBadRequest {
		t.Fatalf("oversize Content-Length status=%d", oversize.Code)
	}
	prior, err := store.Find(ctx, "prov-limit", "small")
	if err != nil || !bytes.Equal(prior.Data, []byte("prior-logo")) {
		t.Fatalf("oversize changed prior=%#v err=%v", prior, err)
	}

	// Body exceeds claimed Content-Length (MaxBytesReader enforces upload limit).
	var body bytes.Buffer
	w3 := multipart.NewWriter(&body)
	h3 := make(textproto.MIMEHeader)
	h3.Set("Content-Disposition", `form-data; name="logo"; filename="logo"`)
	h3.Set("Content-Type", "image/png")
	p3, _ := w3.CreatePart(h3)
	p3.Write(make([]byte, providerLogoUploadLimit+1))
	w3.Close()

	overBody := httptest.NewRecorder()
	overBodyReq := providerLogoRequestWithAuth(http.MethodPut, "/auth/v1/providers/prov-limit/img", &body, "prov-limit", token)
	overBodyReq.Header.Set("Content-Type", w3.FormDataContentType())
	// Claim a small Content-Length; actual body is > 10 MiB.
	overBodyReq.ContentLength = 100
	handler.Logo(overBody, overBodyReq)
	if overBody.Code == http.StatusOK {
		t.Fatalf("body-exceeds-claimed should not succeed")
	}
	prior2, err := store.Find(ctx, "prov-limit", "small")
	if err != nil || !bytes.Equal(prior2.Data, []byte("prior-logo")) {
		t.Fatalf("body-exceeds-claimed changed prior=%#v err=%v", prior2, err)
	}
}

func TestProviderLogoHandlerDelete(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-h")
	seedProviderLogo(t, ctx, db, "prov-h", "small", "image/webp", []byte("del-logo"), 71)
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-del", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRecorder()
	handler.Logo(get, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-h/img", nil, "prov-h"))
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), []byte("del-logo")) {
		t.Fatalf("pre-delete GET status=%d body=%q", get.Code, get.Body.String())
	}

	del := httptest.NewRecorder()
	delReq := providerLogoRequestWithAuth(http.MethodDelete, "/auth/v1/providers/prov-h/img", nil, "prov-h", token)
	handler.Logo(del, delReq)
	if del.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d", del.Code)
	}

	notFound := httptest.NewRecorder()
	handler.Logo(notFound, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-h/img", nil, "prov-h"))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("post-delete GET status=%d", notFound.Code)
	}
}

func TestProviderLogoHandlerNoCrossProviderFallback(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-i1")
	seedAuthProvider(t, ctx, db, "prov-i2")
	keys, token, _ := providerLogoHTTPKey(t, ctx, db, "prov-logo-http-cross", "AuthProviders", apikey.Update)
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	put := httptest.NewRecorder()
	putReq := providerLogoMultipartRequestWithAuth(t, http.MethodPut, "/auth/v1/providers/prov-i1/img", "image/png", encodePNG(t, logoFixture(256, 256)), "prov-i1", token)
	handler.Logo(put, putReq)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT prov-i1 status=%d", put.Code)
	}

	getI1 := httptest.NewRecorder()
	handler.Logo(getI1, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-i1/img", nil, "prov-i1"))
	if getI1.Code != http.StatusOK {
		t.Fatalf("GET prov-i1 status=%d", getI1.Code)
	}

	getI2 := httptest.NewRecorder()
	handler.Logo(getI2, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-i2/img", nil, "prov-i2"))
	if getI2.Code != http.StatusNotFound {
		t.Fatalf("GET prov-i2 status=%d want 404", getI2.Code)
	}
}

func TestProviderLogoHandlerNoGlobalFallback(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "prov-j")
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewProviderLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRecorder()
	handler.Logo(get, providerLogoRequest(http.MethodGet, "/auth/v1/providers/prov-j/img", nil, "prov-j"))
	if get.Code != http.StatusNotFound {
		t.Fatalf("GET no-logo status=%d want 404", get.Code)
	}
}

func providerLogoHTTPKey(t *testing.T, ctx context.Context, db *rhiza.DB, name, group string, rights ...apikey.Right) (*apikey.Store, string, *apikey.Principal) {
	t.Helper()
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   name,
		Access: []apikey.Access{{Group: group, AccessRights: rights}},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return keys, token, &principal
}

func providerLogoRequest(method, path string, body io.Reader, id string) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.SetPathValue("id", id)
	return request
}

func providerLogoRequestWithAuth(method, path string, body io.Reader, id, token string) *http.Request {
	request := providerLogoRequest(method, path, body, id)
	request.Header.Set("Authorization", "API-Key "+token)
	return request
}

func providerLogoMultipartRequest(t *testing.T, method, path, contentType string, data []byte, id string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="logo"; filename="logo"`)
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := providerLogoRequest(method, path, &body, id)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func providerLogoMultipartRequestWithAuth(t *testing.T, method, path, contentType string, data []byte, id, token string) *http.Request {
	t.Helper()
	request := providerLogoMultipartRequest(t, method, path, contentType, data, id)
	request.Header.Set("Authorization", "API-Key "+token)
	return request
}
