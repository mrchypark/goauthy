package branding

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestClientFaviconStorePutGetReplaceDelete(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	first := mustAsset(t, testPNG(t))
	second := mustAsset(t, alternatePNG(t))
	if _, err := store.Get(ctx, "client-a"); err != ErrClientFaviconNotFound {
		t.Fatalf("missing get err=%v", err)
	}
	if err := store.Put(ctx, "client-a", first); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT client_id, content_type, length(data), updated_at_unix_ms FROM client_favicons`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || len(row.Rows[0]) != 4 || row.Rows[0][0] != "client-a" || row.Rows[0][1] != "image/png" || row.Rows[0][2] != int64(len(first.bytes)) || row.Rows[0][3] != now.UnixMilli() {
		t.Fatalf("durable favicon row=%#v err=%v", row.Rows, err)
	}
	got, err := store.Get(ctx, "client-a")
	if err != nil || !bytes.Equal(got.bytes, first.bytes) || got.etag != first.etag {
		t.Fatalf("first get asset=%v err=%v", got, err)
	}
	if err := store.Put(ctx, "client-a", second); err != nil {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, "client-a")
	if err != nil || !bytes.Equal(got.bytes, second.bytes) || got.etag != second.etag {
		t.Fatalf("replacement asset=%v err=%v", got, err)
	}
	if _, err := store.Get(ctx, "client-b"); err != ErrClientFaviconNotFound {
		t.Fatalf("client isolation err=%v", err)
	}
	if err := store.Delete(ctx, "client-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "client-a"); err != ErrClientFaviconNotFound {
		t.Fatalf("deleted get err=%v", err)
	}
}

func TestClientFaviconHandlerUsesPublicGETAndClientsUpdate(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "client-a", mustAsset(t, testPNG(t))); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	admin := false
	handler, err := NewClientFaviconHandler(store, keys, func(w http.ResponseWriter, _ *http.Request, _ bool) bool {
		if !admin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		return admin
	}, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRecorder()
	handler.Favicon(get, clientFaviconRequest(http.MethodGet, "/auth/v1/clients/client-a/favicon", nil))
	if get.Code != http.StatusOK || get.Header().Get("Content-Type") != "image/png" || get.Header().Get("Content-Security-Policy") != "default-src 'none'" || get.Header().Get("Cache-Control") != "public, max-age=300, must-revalidate" || get.Header().Get("ETag") == "" {
		t.Fatalf("public get status=%d headers=%v", get.Code, get.Header())
	}
	head := httptest.NewRecorder()
	request := clientFaviconRequest(http.MethodHead, "/auth/v1/clients/client-a/favicon", nil)
	handler.Favicon(head, request)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("public head status=%d body=%q", head.Code, head.Body.String())
	}
	conditional := httptest.NewRecorder()
	request = clientFaviconRequest(http.MethodGet, "/auth/v1/clients/client-a/favicon", nil)
	request.Header.Set("If-None-Match", get.Header().Get("ETag"))
	handler.Favicon(conditional, request)
	if conditional.Code != http.StatusNotModified {
		t.Fatalf("conditional get status=%d", conditional.Code)
	}
	put := httptest.NewRecorder()
	adminRequest := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	adminRequest.Header.Set("X-CSRF-Token", "test")
	handler.Favicon(put, adminRequest)
	if put.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized put status=%d", put.Code)
	}
	admin = true
	put = httptest.NewRecorder()
	putRequest := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	putRequest.Header.Set("If-Match", get.Header().Get("ETag"))
	handler.Favicon(put, putRequest)
	if put.Code != http.StatusOK || put.Header().Get("Clear-Site-Data") != `"cache"` {
		t.Fatalf("admin put status=%d headers=%v", put.Code, put.Header())
	}
	unknown := httptest.NewRecorder()
	unknownRequest := httptest.NewRequest(http.MethodGet, "/auth/v1/clients/client-b/favicon", nil)
	unknownRequest.SetPathValue("id", "client-b")
	handler.Favicon(unknown, unknownRequest)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown client status=%d", unknown.Code)
	}
	delete := httptest.NewRecorder()
	updated, err := store.Get(ctx, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest := clientFaviconRequest(http.MethodDelete, "/auth/v1/clients/client-a/favicon", nil)
	deleteRequest.Header.Set("If-Match", updated.etag)
	handler.Favicon(delete, deleteRequest)
	if delete.Code != http.StatusOK || delete.Header().Get("Clear-Site-Data") != `"cache"` {
		t.Fatalf("admin delete status=%d headers=%v", delete.Code, delete.Header())
	}
}

func TestClientFaviconHandlerUsesAPIKeyClientsUpdate(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   "favicon-key",
		Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewClientFaviconHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool {
		t.Fatal("browser admin fallback used for API key")
		return false
	}, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	request := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	request.Header.Set("Authorization", "API-Key "+token)
	request.Header.Set("If-None-Match", "*")
	response := httptest.NewRecorder()
	handler.Favicon(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("API-key put status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestClientFaviconHandlerRequiresStrongConditionalMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewClientFaviconHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, "client-a")
	if err != nil {
		t.Fatal(err)
	}

	withoutCreateCondition := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", testPNG(t))
	response := httptest.NewRecorder()
	handler.Favicon(response, withoutCreateCondition)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("unconditional create status=%d", response.Code)
	}
	if _, err := store.Get(ctx, "client-a"); !errors.Is(err, ErrClientFaviconNotFound) {
		t.Fatalf("unconditional create persisted err=%v", err)
	}

	create := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", testPNG(t))
	create.Header.Set("If-None-Match", "*")
	response = httptest.NewRecorder()
	handler.Favicon(response, create)
	if response.Code != http.StatusOK {
		t.Fatalf("conditional create status=%d", response.Code)
	}
	current, err := store.Get(ctx, "client-a")
	if err != nil {
		t.Fatal(err)
	}

	stale := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	stale.Header.Set("If-Match", `"stale"`)
	response = httptest.NewRecorder()
	handler.Favicon(response, stale)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale replacement status=%d", response.Code)
	}
	weak := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	weak.Header.Set("If-Match", "W/"+current.etag)
	response = httptest.NewRecorder()
	handler.Favicon(response, weak)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("weak replacement status=%d", response.Code)
	}

	replace := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", alternatePNG(t))
	replace.Header.Set("If-Match", current.etag)
	response = httptest.NewRecorder()
	handler.Favicon(response, replace)
	if response.Code != http.StatusOK {
		t.Fatalf("replacement status=%d", response.Code)
	}
	staleDelete := clientFaviconRequest(http.MethodDelete, "/auth/v1/clients/client-a/favicon", nil)
	staleDelete.Header.Set("If-Match", current.etag)
	response = httptest.NewRecorder()
	handler.Favicon(response, staleDelete)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale delete status=%d", response.Code)
	}
}

func TestClientFaviconStoreRechecksAPIKeyAtCommit(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "favicon-key", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	if err := store.PutConditional(ctx, "client-a", mustAsset(t, testPNG(t)), nil, keys, &principal); !errors.Is(err, ErrClientFaviconForbidden) {
		t.Fatalf("revoked API-key mutation err=%v", err)
	}
	if _, err := store.Get(ctx, "client-a"); !errors.Is(err, ErrClientFaviconNotFound) {
		t.Fatalf("revoked API-key mutation persisted err=%v", err)
	}
}

func TestClientFaviconHandlerRejectsMalformedUploads(t *testing.T) {
	_, db := clientFaviconDB(t)
	store, err := NewClientFaviconStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewClientFaviconHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{name: "json", req: clientFaviconRequest(http.MethodPut, "/auth/v1/clients/client-a/favicon", strings.NewReader(`{"data":"x"}`))},
		{name: "empty multipart", req: emptyMultipartRequest(t)},
		{name: "invalid image", req: multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", []byte("not an image"))},
		{name: "oversize", req: multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", bytes.Repeat([]byte{'x'}, maxFaviconBytes+1))},
		{name: "oversize dimensions", req: multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", testPNGHeader(^uint32(0), ^uint32(0)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.Favicon(response, tc.req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
	queryRequest := multipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon?updated=1", testPNG(t))
	queryResponse := httptest.NewRecorder()
	handler.Favicon(queryResponse, queryRequest)
	if queryResponse.Code != http.StatusBadRequest {
		t.Fatalf("mutation query status=%d", queryResponse.Code)
	}
}

func clientFaviconDB(t *testing.T) (context.Context, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "client-favicon-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return ctx, db
}

func mustAsset(t *testing.T, data []byte) *Asset {
	t.Helper()
	asset, err := NewAsset(data)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

func alternatePNG(t *testing.T) []byte {
	t.Helper()
	imageData := image.NewRGBA(image.Rect(0, 0, 1, 1))
	imageData.SetRGBA(0, 0, color.RGBA{R: 255, A: 255})
	var data bytes.Buffer
	if err := png.Encode(&data, imageData); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func multipartRequest(t *testing.T, method, path string, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("favicon.png", "favicon.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, &body)
	req.SetPathValue("id", "client-a")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func emptyMultipartRequest(t *testing.T) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/clients/client-a/favicon?"+url.Values{"x": {"1"}}.Encode(), &body)
	req.SetPathValue("id", "client-a")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func clientFaviconRequest(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.SetPathValue("id", "client-a")
	return req
}
