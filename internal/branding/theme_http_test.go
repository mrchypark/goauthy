package branding

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestThemeHandlerPublicGetFallbackTimestampAndGzip(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	theme := DefaultTheme("client-a")
	theme.BorderRadius = "12px"
	if err := store.Put(ctx, theme); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewThemeHandler(store, keys, nil, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := themeRequest(http.MethodGet, "/auth/v1/theme/client-a/123", nil, "client-a", "123")
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.Theme(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/css" || response.Header().Get("Content-Encoding") != "gzip" || response.Header().Get("Cache-Control") != "max-age=31104000, public" {
		t.Fatalf("GET status=%d headers=%v", response.Code, response.Header())
	}
	reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), theme.CSS(); got != want {
		t.Fatalf("gzip CSS differs from validated theme")
	}

	brRequest := themeRequest(http.MethodGet, "/auth/v1/theme/client-a/123", nil, "client-a", "123")
	brRequest.Header.Set("Accept-Encoding", "br, gzip")
	brResponse := httptest.NewRecorder()
	handler.Theme(brResponse, brRequest)
	if brResponse.Code != http.StatusOK || brResponse.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("Brotli GET status=%d headers=%v", brResponse.Code, brResponse.Header())
	}
	brReader := brotli.NewReader(bytes.NewReader(brResponse.Body.Bytes()))
	brBody, err := io.ReadAll(brReader)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(brBody), theme.CSS(); got != want {
		t.Fatalf("Brotli CSS differs from validated theme")
	}

	invalidTimestamp := httptest.NewRecorder()
	invalidRequest := themeRequest(http.MethodGet, "/auth/v1/theme/client-a/not-a-timestamp", nil, "client-a", "not-a-timestamp")
	handler.Theme(invalidTimestamp, invalidRequest)
	if invalidTimestamp.Code != http.StatusBadRequest {
		t.Fatalf("invalid timestamp status=%d", invalidTimestamp.Code)
	}
}

func TestThemeHandlerBrowserAdminReadAndGuardedMutations(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "theme-http-client-seed", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json) VALUES('client-a','test',1,0,'{}')`}); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	var mutationCalls []bool
	clientChecks := 0
	handler, err := NewThemeHandler(store, keys, func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
		mutationCalls = append(mutationCalls, mutation)
		return true
	}, func(context.Context, string) error {
		clientChecks++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	post := httptest.NewRecorder()
	handler.Theme(post, themeRequest(http.MethodPost, "/auth/v1/theme/client-a", nil, "client-a", ""))
	if post.Code != http.StatusOK || post.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("POST status=%d headers=%v", post.Code, post.Header())
	}
	var got Theme
	if err := json.Unmarshal(post.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, DefaultTheme("rauthy")) {
		t.Fatalf("POST default theme=%#v err=%v", got, err)
	}

	updated := DefaultTheme("client-a")
	updated.BorderRadius = "14px"
	body, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	put := httptest.NewRecorder()
	handler.Theme(put, themeRequest(http.MethodPut, "/auth/v1/theme/client-a", bytes.NewReader(body), "client-a", ""))
	if put.Code != http.StatusOK || put.Header().Get("Clear-Site-Data") != `"cache"` || clientChecks != 1 {
		t.Fatalf("PUT status=%d headers=%v clientChecks=%d", put.Code, put.Header(), clientChecks)
	}
	got, err = store.GetDefault(ctx, "client-a")
	if err != nil || got.BorderRadius != "14px" {
		t.Fatalf("PUT was not persisted: %#v err=%v", got, err)
	}

	delete := httptest.NewRecorder()
	handler.Theme(delete, themeRequest(http.MethodDelete, "/auth/v1/theme/client-a", nil, "client-a", ""))
	if delete.Code != http.StatusOK || delete.Header().Get("Clear-Site-Data") != `"cache"` {
		t.Fatalf("DELETE status=%d headers=%v", delete.Code, delete.Header())
	}
	got, err = store.GetDefault(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, DefaultTheme("rauthy")) {
		t.Fatalf("DELETE did not reveal default theme: %#v err=%v", got, err)
	}
	if len(mutationCalls) != 3 || mutationCalls[0] || !mutationCalls[1] || !mutationCalls[2] {
		t.Fatalf("browser authorization mutation flags=%v", mutationCalls)
	}
}

func TestThemeHandlerValidatesPutPathPayloadAndClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewThemeHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, func(context.Context, string) error {
		return clients.ErrNotFound
	})
	if err != nil {
		t.Fatal(err)
	}
	theme := DefaultTheme("other-client")
	body, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := httptest.NewRecorder()
	handler.Theme(mismatch, themeRequest(http.MethodPut, "/auth/v1/theme/client-a", bytes.NewReader(body), "client-a", ""))
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("path mismatch status=%d", mismatch.Code)
	}
	unknown := DefaultTheme("client-a")
	body, _ = json.Marshal(unknown)
	missing := httptest.NewRecorder()
	handler.Theme(missing, themeRequest(http.MethodPut, "/auth/v1/theme/client-a", bytes.NewReader(body), "client-a", ""))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing client status=%d", missing.Code)
	}
	if _, err := store.GetDefault(ctx, "client-a"); err != nil {
		t.Fatal(err)
	}
}

func TestThemeHandlerAPIKeyRightAndForbiddenMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   "theme-read-key",
		Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewThemeHandler(store, keys, func(http.ResponseWriter, *http.Request, bool) bool {
		t.Fatal("browser admin fallback used for API key")
		return false
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	postRequest := themeRequest(http.MethodPost, "/auth/v1/theme/client-a", nil, "client-a", "")
	postRequest.Header.Set("Authorization", "API-Key "+token)
	post := httptest.NewRecorder()
	handler.Theme(post, postRequest)
	if post.Code != http.StatusOK {
		t.Fatalf("API-key POST status=%d", post.Code)
	}
	putRequest := themeRequest(http.MethodPut, "/auth/v1/theme/client-a", bytes.NewReader([]byte(`{}`)), "client-a", "")
	putRequest.Header.Set("Authorization", "API-Key "+token)
	put := httptest.NewRecorder()
	handler.Theme(put, putRequest)
	if put.Code != http.StatusForbidden {
		t.Fatalf("read-only API-key PUT status=%d", put.Code)
	}
}

func themeRequest(method, path string, body io.Reader, clientID, timestamp string) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.SetPathValue("client_id", clientID)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if timestamp != "" {
		request.SetPathValue("timestamp", timestamp)
	}
	return request
}

func TestThemeHandlerIgnoresNonTextAcceptEncoding(t *testing.T) {
	_, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewThemeHandler(store, keys, nil, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := themeRequest(http.MethodGet, "/auth/v1/theme/missing/1", nil, "missing", "1")
	request.Header.Set("Accept-Encoding", "br, \u0080")
	response := httptest.NewRecorder()
	handler.Theme(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "none" || response.Body.String() != DefaultTheme("rauthy").CSS() {
		t.Fatal("invalid header text selected compressed encoding")
	}
}
