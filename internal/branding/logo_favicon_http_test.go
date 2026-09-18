package branding

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestClientLogoHandlerFaviconReadsSchema94CopyAndHasNoFallback(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	legacy := encodePNG(t, logoFixture(40, 40))
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLegacyFavicon(t, ctx, db, "client-a", "image/png", legacy, 100)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/png", legacy, 100)
	seedLogo(t, ctx, db, "rauthy", "favicon", "image/webp", []byte("global-favicon"), 101)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewClientLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	read := httptest.NewRecorder()
	h.Favicon(read, clientLogoRequest(http.MethodGet, "/auth/v1/clients/client-a/favicon", nil, "client-a"))
	if read.Code != http.StatusOK || read.Header().Get("Content-Type") != "image/png" || read.Header().Get("Cache-Control") != "" || !bytes.Equal(read.Body.Bytes(), legacy) {
		t.Fatalf("legacy favicon response status=%d headers=%v body=%d", read.Code, read.Header(), read.Body.Len())
	}

	cached := httptest.NewRecorder()
	h.Favicon(cached, clientLogoRequest(http.MethodGet, "/auth/v1/clients/client-a/favicon?"+url.Values{"updated": {"100"}}.Encode(), nil, "client-a"))
	if cached.Code != http.StatusOK || cached.Header().Get("Cache-Control") != "max-age=31104000, stale-while-revalidate=2592000, public" {
		t.Fatalf("cached favicon status=%d headers=%v", cached.Code, cached.Header())
	}

	invalidQuery := httptest.NewRecorder()
	h.Favicon(invalidQuery, clientLogoRequest(http.MethodGet, "/auth/v1/clients/missing/favicon?updated=bad", nil, "missing"))
	if invalidQuery.Code != http.StatusBadRequest {
		t.Fatalf("invalid query status=%d, want lookup-independent bad request", invalidQuery.Code)
	}

	missing := httptest.NewRecorder()
	h.Favicon(missing, clientLogoRequest(http.MethodGet, "/auth/v1/clients/missing/favicon", nil, "missing"))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing favicon status=%d", missing.Code)
	}
}

func TestClientLogoHandlerFaviconProcessesPNGJPEGAndSVG(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		data        func(*testing.T) []byte
	}{
		{name: "png", contentType: "image/png", data: func(t *testing.T) []byte { return encodePNG(t, logoFixture(100, 90)) }},
		{name: "jpeg", contentType: "image/jpeg", data: func(t *testing.T) []byte { return encodeJPEG(t, logoFixture(100, 90)) }},
		{name: "svg", contentType: "image/svg+xml", data: func(*testing.T) []byte {
			return []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="32" height="32"/></svg>`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := clientFaviconDB(t)
			store, err := NewClientLogoStore(db)
			if err != nil {
				t.Fatal(err)
			}
			seedLogoClient(t, ctx, db, "client-a", false)
			seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("keep-small"), 1)
			old := []byte("old-favicon")
			seedLegacyFavicon(t, ctx, db, "client-a", "image/png", old, 2)
			seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", old, 2)
			keys, token, _ := logoHTTPKey(t, ctx, db, "favicon-http-"+tc.name, apikey.Update)
			h, err := NewClientLogoHandler(store, keys, nil)
			if err != nil {
				t.Fatal(err)
			}

			request := logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", tc.contentType, tc.data(t))
			request.Header.Set("Authorization", "API-Key "+token)
			response := httptest.NewRecorder()
			h.Favicon(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Clear-Site-Data") != `"cache"` {
				t.Fatalf("PUT status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}

			got, err := store.Find(ctx, "client-a", "favicon")
			if err != nil || got.Resolution != "favicon" {
				t.Fatalf("stored favicon=%#v err=%v", got, err)
			}
			if tc.contentType == "image/svg+xml" {
				if got.ContentType != "image/svg+xml" || !bytes.Contains(got.Data, []byte("<rect")) {
					t.Fatalf("stored SVG=%#v", got)
				}
			} else {
				if got.ContentType != "image/webp" {
					t.Fatalf("stored raster content type=%q", got.ContentType)
				}
				assertDecodedSize(t, got.Data, 32, 32)
			}
			kept, err := store.Find(ctx, "client-a", "small")
			if err != nil || !bytes.Equal(kept.Data, []byte("keep-small")) {
				t.Fatalf("nonfavicon asset changed=%#v err=%v", kept, err)
			}
			legacyRows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM client_favicons WHERE client_id=?`, Args: []any{"client-a"}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(legacyRows.Rows) != 1 || legacyRows.Rows[0][0] != int64(0) {
				t.Fatalf("legacy favicon rows=%v err=%v", legacyRows.Rows, err)
			}
		})
	}
}

func TestClientLogoHandlerFaviconDeleteAndDeniedMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("keep-small"), 1)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("favicon"), 2)
	seedLegacyFavicon(t, ctx, db, "client-a", "image/png", []byte("legacy"), 2)
	keys, token, _ := logoHTTPKey(t, ctx, db, "favicon-delete", apikey.Update)
	h, err := NewClientLogoHandler(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	denied := httptest.NewRecorder()
	h.Favicon(denied, logoHTTPMultipartRequest(t, http.MethodPut, "/auth/v1/clients/client-a/favicon", "image/png", encodePNG(t, logoFixture(40, 40))))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("denied PUT status=%d", denied.Code)
	}

	delete := httptest.NewRecorder()
	deleteRequest := clientLogoRequest(http.MethodDelete, "/auth/v1/clients/client-a/favicon", nil, "client-a")
	deleteRequest.Header.Set("Authorization", "API-Key "+token)
	h.Favicon(delete, deleteRequest)
	if delete.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%q", delete.Code, delete.Body.String())
	}
	if _, err := store.Find(ctx, "client-a", "favicon"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("deleted favicon err=%v", err)
	}
	kept, err := store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(kept.Data, []byte("keep-small")) {
		t.Fatalf("DELETE changed nonfavicon=%#v err=%v", kept, err)
	}
}

func seedLegacyFavicon(t *testing.T, ctx context.Context, db *rhiza.DB, clientID, contentType string, data []byte, updated int64) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "legacy-favicon-" + clientID,
		SQL:       `INSERT INTO client_favicons(client_id,content_type,data,updated_at_unix_ms) VALUES(?,?,?,?)`,
		Args:      []any{clientID, contentType, data, updated},
	}); err != nil {
		t.Fatal(err)
	}
}
