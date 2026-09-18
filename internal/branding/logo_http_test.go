package branding

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

func TestClientLogoHandlerPublicFallbackCacheAndCSP(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("client-logo"), 11)
	seedLogo(t, ctx, db, "rauthy", "small", "image/webp", []byte("global-logo"), 12)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewClientLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	public := httptest.NewRecorder()
	handler.Logo(public, clientLogoRequest(http.MethodGet, "/auth/v1/clients/client-a/logo", nil, "client-a"))
	if public.Code != http.StatusOK || public.Header().Get("Content-Type") != "image/webp" || public.Header().Get("Content-Length") != "11" || public.Header().Get("Cache-Control") != "" || public.Header().Get("Content-Security-Policy") != clientLogoCSP || !bytes.Equal(public.Body.Bytes(), []byte("client-logo")) {
		t.Fatalf("public logo status=%d headers=%v body=%q", public.Code, public.Header(), public.Body.String())
	}

	fallback := httptest.NewRecorder()
	handler.Logo(fallback, clientLogoRequest(http.MethodGet, "/auth/v1/clients/missing/logo", nil, "missing"))
	if fallback.Code != http.StatusOK || !bytes.Equal(fallback.Body.Bytes(), []byte("global-logo")) {
		t.Fatalf("fallback status=%d body=%q", fallback.Code, fallback.Body.String())
	}

	cached := httptest.NewRecorder()
	request := clientLogoRequest(http.MethodGet, "/auth/v1/clients/client-a/logo?"+url.Values{"updated": {"+7"}}.Encode(), nil, "client-a")
	handler.Logo(cached, request)
	if cached.Code != http.StatusOK || cached.Header().Get("Cache-Control") != "max-age=31104000, stale-while-revalidate=2592000, public" {
		t.Fatalf("cached logo status=%d headers=%v", cached.Code, cached.Header())
	}

	invalid := httptest.NewRecorder()
	handler.Logo(invalid, clientLogoRequest(http.MethodGet, "/auth/v1/clients/client-a/logo?updated=bad", nil, "client-a"))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid updated status=%d", invalid.Code)
	}

	unknownInvalid := httptest.NewRecorder()
	handler.Logo(unknownInvalid, clientLogoRequest(http.MethodGet, "/auth/v1/clients/missing/logo?updated=bad", nil, "missing"))
	if unknownInvalid.Code != http.StatusBadRequest {
		t.Fatalf("unknown client with invalid updated status=%d", unknownInvalid.Code)
	}

	head := httptest.NewRecorder()
	handler.Logo(head, clientLogoRequest(http.MethodHead, "/auth/v1/clients/client-a/logo", nil, "client-a"))
	if head.Code != http.StatusMethodNotAllowed || head.Header().Get("Allow") != "GET, PUT, DELETE" {
		t.Fatalf("HEAD status=%d headers=%v", head.Code, head.Header())
	}
}

func TestClientLogoHandlerAPIKeyMutationsPreserveFavicon(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-logo"), 21)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-favicon"), 22)
	keys, token, _ := logoHTTPKey(t, ctx, db, "logo-http-update", apikey.Update)
	handler, err := NewClientLogoHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool {
		t.Fatal("browser admin fallback used for API-key mutation")
		return false
	})
	if err != nil {
		t.Fatal(err)
	}

	put := httptest.NewRecorder()
	request := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", encodePNG(t, logoFixture(100, 90)))
	request.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(put, request)
	if put.Code != http.StatusOK || put.Header().Get("Clear-Site-Data") != `"cache"` {
		t.Fatalf("API-key PUT status=%d headers=%v body=%q", put.Code, put.Header(), put.Body.String())
	}
	updated, err := store.Find(ctx, "client-a", "small")
	if err != nil || updated.ContentType != "image/webp" || len(updated.Data) == 0 || bytes.Equal(updated.Data, []byte("old-logo")) {
		t.Fatalf("updated logo=%#v err=%v", updated, err)
	}
	favicon, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("favicon changed on replace=%#v err=%v", favicon, err)
	}

	delete := httptest.NewRecorder()
	deleteRequest := clientLogoRequest(http.MethodDelete, "/auth/v1/clients/client-a/logo", nil, "client-a")
	deleteRequest.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(delete, deleteRequest)
	if delete.Code != http.StatusOK {
		t.Fatalf("API-key DELETE status=%d", delete.Code)
	}
	if _, err := store.Find(ctx, "client-a", "small"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("deleted logo err=%v", err)
	}
	favicon, err = store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("favicon changed on delete=%#v err=%v", favicon, err)
	}
}

func TestClientLogoHandlerRejectsUnauthorizedRevokedAndMalformedMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-logo"), 31)
	keys, token, principal := logoHTTPKey(t, ctx, db, "logo-http-revoked", apikey.Update)
	handler, err := NewClientLogoHandler(store, keys, func(w http.ResponseWriter, _ *http.Request, _ bool) bool {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	})
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	handler.Logo(unauthorized, logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", encodePNG(t, logoFixture(100, 90))))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized PUT status=%d", unauthorized.Code)
	}

	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	revoked := httptest.NewRecorder()
	revokedRequest := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", encodePNG(t, logoFixture(100, 90)))
	revokedRequest.Header.Set("Authorization", "API-Key "+token)
	handler.Logo(revoked, revokedRequest)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked PUT status=%d", revoked.Code)
	}
	old, err := store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(old.Data, []byte("old-logo")) {
		t.Fatalf("revoked PUT changed logo=%#v err=%v", old, err)
	}
	malformedHandler, err := NewClientLogoHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool {
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{name: "json", request: clientLogoRequest(http.MethodPut, "/auth/v1/clients/client-a/logo", strings.NewReader(`{"data":"x"}`), "client-a"), wantStatus: http.StatusBadRequest},
		{name: "unsupported type", request: logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/gif", []byte("gif")), wantStatus: http.StatusBadRequest},
		{name: "invalid png", request: logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", []byte("not png")), wantStatus: http.StatusBadRequest},
		{name: "invalid svg", request: logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/svg+xml", []byte("<not-svg/>")), wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			malformedHandler.Logo(response, tc.request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}

	missingLength := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", encodePNG(t, logoFixture(100, 90)))
	missingLength.ContentLength = -1
	response := httptest.NewRecorder()
	malformedHandler.Logo(response, missingLength)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing Content-Length status=%d", response.Code)
	}

	tooLarge := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/logo", "image/png", []byte("small body"))
	tooLarge.ContentLength = clientLogoUploadLimit + 1
	response = httptest.NewRecorder()
	malformedHandler.Logo(response, tooLarge)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversize Content-Length status=%d", response.Code)
	}

	old, err = store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(old.Data, []byte("old-logo")) {
		t.Fatalf("malformed uploads changed logo=%#v err=%v", old, err)
	}
}

func logoHTTPKey(t *testing.T, ctx context.Context, db *rhiza.DB, name string, rights ...apikey.Right) (*apikey.Store, string, *apikey.Principal) {
	t.Helper()
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   name,
		Access: []apikey.Access{{Group: "Clients", AccessRights: rights}},
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

func clientLogoRequest(method, path string, body io.Reader, id string) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.SetPathValue("id", id)
	return request
}

func logoHTTPMultipartRequest(t *testing.T, method, path, contentType string, data []byte) *http.Request {
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
	request := clientLogoRequest(method, path, &body, "client-a")
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func TestClientLogoMultipartFaviconProcessing(t *testing.T) {
	for _, contentType := range []string{"image/png", "image/svg+xml"} {
		var data []byte
		if contentType == "image/png" {
			data = encodePNG(t, logoFixture(60, 40))
		} else {
			data = []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="32" height="32"/></svg>`)
		}
		r := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", contentType, data)
		assets, err := decodeClientLogoMultipart(httptest.NewRecorder(), r, true)
		if err != nil || len(assets) != 1 || assets[0].Resolution != "favicon" {
			t.Fatalf("favicon assets=%v err=%v", assets, err)
		}
		if contentType == "image/png" {
			assertDecodedSize(t, assets[0].Data, 32, 32)
		}
	}
}
