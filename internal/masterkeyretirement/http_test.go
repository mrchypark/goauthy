package masterkeyretirement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestOperatorRetirementAPIUsesSecretsRightsAndServerTime(t *testing.T) {
	db := testDB(t)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "operator", Access: []apikey.Access{
		{Group: "Secrets", AccessRights: []apikey.Right{apikey.Read, apikey.Create, apikey.Update, apikey.Delete}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_900_000_000_123).UTC()
	handler := NewHandler(db, keys, []string{"node-0"})
	handler.now = func() time.Time { return now }

	prepare := operatorRequest(http.MethodPost, basePath+"/prepare", token, `{"epoch":1,"old_key_id":"key-a","replacement_key_id":"key-b"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, prepare)
	if response.Code != http.StatusOK {
		t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
	}
	var prepared barrierJSON
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.PreparedAt != now.UnixMilli() || len(prepared.Membership) != 1 || prepared.Membership[0] != "node-0" {
		t.Fatalf("prepared=%+v", prepared)
	}

	get := operatorRequest(http.MethodGet, basePath, token, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, get)
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatal("response leaked API-key bearer token")
	}

	for _, action := range []string{"fence", "abort"} {
		request := operatorRequest(http.MethodPost, basePath+"/"+action, token, `{"epoch":1}`)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
		}
	}
}

func TestOperatorRetirementAPIRejectsAmbiguousOrUnsafeRequests(t *testing.T) {
	db := testDB(t)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "operator", Access: []apikey.Access{{Group: "Secrets", AccessRights: []apikey.Right{apikey.Read, apikey.Create, apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, keys, []string{"node-0"})
	for _, request := range []*http.Request{
		operatorRequest(http.MethodPost, basePath+"/prepare", token, `{"epoch":1,"epoch":1,"old_key_id":"a","replacement_key_id":"b"}`),
		operatorRequest(http.MethodPost, basePath+"/fence", token, `{"epoch":1,"old_key_id":"a"}`),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}

	request := operatorRequest(http.MethodGet, basePath, token, "")
	request.Header.Add("Authorization", "API-Key "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("repeated authorization status=%d", response.Code)
	}

	request = operatorRequest(http.MethodGet, basePath, token, "")
	request.URL.RawQuery = "unexpected=1"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("query status=%d", response.Code)
	}

	request = operatorRequest(http.MethodGet, basePath, token, "")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-site status=%d", response.Code)
	}

	request = operatorRequest(http.MethodGet, basePath+"/prepare", token, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET action status=%d", response.Code)
	}

	request = operatorRequest(http.MethodPost, basePath+"/prepare", token, `{"Epoch":1,"old_key_id":"a","replacement_key_id":"b"}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical JSON status=%d", response.Code)
	}
	request = operatorRequest(http.MethodPost, basePath+"/prepare", token, strings.Repeat("x", bodyLimit+1))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status=%d", response.Code)
	}
	request = operatorRequest(http.MethodGet, basePath, token, "")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Add("Sec-Fetch-Site", "same-origin")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("repeated fetch-site status=%d", response.Code)
	}
	for _, site := range []string{"same-origin, cross-site", "unknown-site"} {
		request = operatorRequest(http.MethodGet, basePath, token, "")
		request.Header.Set("Sec-Fetch-Site", site)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("unsafe fetch-site %q status=%d", site, response.Code)
		}
	}
	for _, site := range []string{"same-origin", "same-site", "none"} {
		request = operatorRequest(http.MethodGet, basePath, token, "")
		request.Header.Set("Sec-Fetch-Site", site)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("safe fetch-site %q status=%d", site, response.Code)
		}
	}

	response = httptest.NewRecorder()
	NewHandler(db, keys, []string{"node-0", "node-1"}).ServeHTTP(response, operatorRequest(http.MethodGet, basePath, token, ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid topology status=%d", response.Code)
	}
	response = httptest.NewRecorder()
	NewHandler(db, keys, []string{"node-0", "node-1"}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, basePath, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated invalid topology status=%d", response.Code)
	}
}

func TestOperatorRetirementAPIRejectsRevokedRead(t *testing.T) {
	db := testDB(t)
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "reader", Access: []apikey.Access{{Group: "Secrets", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PrepareMasterKeyRetirement(context.Background(), db, storage.MasterKeyRetirementPrepareRequest{
		Epoch: 1, OldKeyID: "key-a", ReplacementKeyID: "key-b", MemberIDs: []string{"node-0"}, PreparedAt: time.UnixMilli(1_900_000_000_000).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "retirement-http-revoke-read", SQL: `DELETE FROM api_key_access WHERE key_name=? AND group_name='Secrets' AND right_name='read'`, Args: []any{"reader"}}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	NewHandler(db, keys, []string{"node-0"}).ServeHTTP(response, operatorRequest(http.MethodGet, basePath, token, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("revoked read status=%d", response.Code)
	}
}

func operatorRequest(method, path, token, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "API-Key "+token)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func testDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "retirement-http", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
