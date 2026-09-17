package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/browser"
)

func TestAuthCollectionsHTTPAdminUserOwnershipAndRevision(t *testing.T) {
	h, store, adminCookie, adminCSRF := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	createBody := `{"id":"login-prod","name":"Login","auth_method":"oauth2","enabled":true,"fields":[{"name":"tenant","type":"string","required":true,"max_length":64}]}`
	r := authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", createBody, adminCookie, adminCSRF)
	w := httptest.NewRecorder()
	h.AuthCollections(w, r)
	if w.Code != http.StatusCreated || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("create status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}
	var def authcollection.Definition
	if err := json.Unmarshal(w.Body.Bytes(), &def); err != nil {
		t.Fatal(err)
	}

	// Ordinary users can enumerate definitions but cannot administer them.
	memberCookie, memberCSRF := memberSession(t, store)
	w = httptest.NewRecorder()
	h.AccountAuthCollections(w, authCollectionRequest(http.MethodGet, "/auth/v1/account/auth-collections", "", memberCookie, ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "login-prod") {
		t.Fatalf("user definitions status=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodGet, "/auth/v1/auth-collections", "", memberCookie, ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("user admin list status=%d", w.Code)
	}

	connBody := `{"definition_revision":1,"metadata":{"tenant":"acme"}}`
	w = httptest.NewRecorder()
	h.AccountConnections(w, authCollectionRequestWithPath(http.MethodPost, "/auth/v1/account/connections/login-prod", connBody, memberCookie, memberCSRF, map[string]string{"collection_id": "login-prod"}))
	if w.Code != http.StatusCreated {
		t.Fatalf("connection create status=%d body=%s", w.Code, w.Body.String())
	}
	var conn authcollection.Connection
	if err := json.Unmarshal(w.Body.Bytes(), &conn); err != nil {
		t.Fatal(err)
	}
	if conn.OwnerSubject != "member" || conn.State != "draft" {
		t.Fatalf("connection=%+v", conn)
	}

	// Owner isolation and stale revision are enforced at the HTTP boundary/store guard.
	insertActive(t, store.db, "other-member")
	otherCookie, otherCSRF := memberSessionFor(t, store, "other-member")
	w = httptest.NewRecorder()
	h.AccountConnection(w, authCollectionRequestWithPath(http.MethodGet, "/auth/v1/account/connections/login-prod/"+conn.ID, "", otherCookie, "", map[string]string{"collection_id": "login-prod", "connection_id": conn.ID}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-owner get status=%d", w.Code)
	}
	otherPut := authCollectionRequestWithPath(http.MethodPut, "/auth/v1/account/connections/login-prod/"+conn.ID, connBody, otherCookie, otherCSRF, map[string]string{"collection_id": "login-prod", "connection_id": conn.ID})
	otherPut.Header.Set("If-Match", `"1"`)
	w = httptest.NewRecorder()
	h.AccountConnection(w, otherPut)
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("cross-owner put status=%d", w.Code)
	}
	otherDelete := authCollectionRequestWithPath(http.MethodDelete, "/auth/v1/account/connections/login-prod/"+conn.ID, "", otherCookie, otherCSRF, map[string]string{"collection_id": "login-prod", "connection_id": conn.ID})
	otherDelete.Header.Set("If-Match", `"1"`)
	w = httptest.NewRecorder()
	h.AccountConnection(w, otherDelete)
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("cross-owner delete status=%d", w.Code)
	}
	put := authCollectionRequestWithPath(http.MethodPut, "/auth/v1/account/connections/login-prod/"+conn.ID, `{"definition_revision":1,"metadata":{"tenant":"new"}}`, memberCookie, memberCSRF, map[string]string{"collection_id": "login-prod", "connection_id": conn.ID})
	put.Header.Set("If-Match", `"99"`)
	w = httptest.NewRecorder()
	h.AccountConnection(w, put)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale put status=%d body=%s", w.Code, w.Body.String())
	}
	_ = otherCSRF
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.RevokeSession(context.Background(), adminCookie.Value); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodGet, "/auth/v1/auth-collections", "", adminCookie, ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked admin status=%d", w.Code)
	}
}

func TestAuthCollectionsHTTPStrictJSONCSRFAndImmutableUsedDefinition(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	base := `{"id":"strict-one","name":"Strict","auth_method":"api_key","enabled":true,"fields":[]}`
	for _, body := range []string{`{"id":"strict-one","name":"Strict","auth_method":"api_key","enabled":true,"fields":[],"unknown":1}`, `{"id":"strict-one","name":null,"auth_method":"api_key","enabled":true,"fields":[]}`} {
		w := httptest.NewRecorder()
		h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", body, cookie, csrf))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("strict body status=%d", w.Code)
		}
	}
	dupField := `{"id":"strict-one","name":"Strict","auth_method":"api_key","enabled":true,"fields":[{"name":"x","type":"string","required":true,"required":false}]}`
	w := httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", dupField, cookie, csrf))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate nested field status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", base, cookie, ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", base, cookie, csrf))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}

	// A used definition cannot mutate its auth method or fields; disable remains allowed.
	memberCookie, memberCSRF := memberSession(t, store)
	w = httptest.NewRecorder()
	h.AccountConnections(w, authCollectionRequestWithPath(http.MethodPost, "/auth/v1/account/connections/strict-one", `{"definition_revision":1,"metadata":{}}`, memberCookie, memberCSRF, map[string]string{"collection_id": "strict-one"}))
	if w.Code != http.StatusCreated {
		t.Fatalf("use status=%d body=%s", w.Code, w.Body.String())
	}
	put := authCollectionRequestWithPath(http.MethodPut, "/auth/v1/auth-collections/strict-one", `{"name":"Strict","auth_method":"oauth2","enabled":true,"fields":[]}`, cookie, csrf, map[string]string{"collection_id": "strict-one"})
	put.Header.Set("If-Match", `"1"`)
	w = httptest.NewRecorder()
	h.AuthCollection(w, put)
	if w.Code != http.StatusConflict {
		t.Fatalf("immutable status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAuthCollectionsHTTPBoundaryAndRevisionFailures(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	memberCookie, memberCSRF := memberSession(t, store)
	checks := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		req     *http.Request
		want    int
	}{
		{"admin authorization fallback", h.AuthCollections, authCollectionRequest(http.MethodGet, "/auth/v1/auth-collections", "", cookie, ""), http.StatusOK},
		{"user authorization fallback", h.AccountAuthCollections, authCollectionRequest(http.MethodGet, "/auth/v1/account/auth-collections", "", memberCookie, ""), http.StatusOK},
	}
	for _, tc := range checks {
		tc.req.Header.Set("Authorization", "Bearer malformed")
		w := httptest.NewRecorder()
		tc.handler(w, tc.req)
		if w.Code == tc.want {
			t.Fatalf("%s accepted Authorization", tc.name)
		}
	}

	// Query strings, cross-site writes, duplicate CSRF headers, and missing If-Match fail closed.
	r := authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections?x=1", `{"id":"boundary-one","name":"Boundary","auth_method":"oauth2","enabled":true,"fields":[]}`, cookie, csrf)
	w := httptest.NewRecorder()
	h.AuthCollections(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query status=%d", w.Code)
	}
	r = authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", `{"id":"boundary-one","name":"Boundary","auth_method":"oauth2","enabled":true,"fields":[]}`, cookie, csrf)
	r.Header.Add("X-CSRF-Token", csrf)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.AuthCollections(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-site status=%d", w.Code)
	}
	r = authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", `{"id":"boundary-one","name":"Boundary","auth_method":"oauth2","enabled":true,"fields":[]}`, cookie, csrf)
	r.Header.Add("X-CSRF-Token", csrf)
	w = httptest.NewRecorder()
	h.AuthCollections(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate csrf status=%d", w.Code)
	}

	create := authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", `{"id":"boundary-one","name":"Boundary","auth_method":"oauth2","enabled":true,"fields":[]}`, cookie, csrf)
	w = httptest.NewRecorder()
	h.AuthCollections(w, create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d", w.Code)
	}
	put := authCollectionRequestWithPath(http.MethodPut, "/auth/v1/auth-collections/boundary-one", `{"name":"Boundary","auth_method":"oauth2","enabled":false,"fields":[]}`, cookie, csrf, map[string]string{"collection_id": "boundary-one"})
	w = httptest.NewRecorder()
	h.AuthCollection(w, put)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing etag status=%d", w.Code)
	}
	put.Header.Set("If-Match", `"1"`)
	w = httptest.NewRecorder()
	h.AuthCollection(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.AccountConnections(w, authCollectionRequestWithPath(http.MethodPost, "/auth/v1/account/connections/boundary-one", `{"definition_revision":2,"metadata":{}}`, memberCookie, memberCSRF, map[string]string{"collection_id": "boundary-one"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("disabled create status=%d", w.Code)
	}
}

func memberSession(t *testing.T, store *Store) (*http.Cookie, string) {
	return memberSessionFor(t, store, "member")
}
func memberSessionFor(t *testing.T, store *Store, subject string) (*http.Cookie, string) {
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(context.Background(), subject, "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, csrf
}

func authCollectionRequest(method, path, body string, cookie *http.Cookie, csrf string) *http.Request {
	return authCollectionRequestWithPath(method, path, body, cookie, csrf, nil)
}
func authCollectionRequestWithPath(method, path, body string, cookie *http.Cookie, csrf string, values map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for k, v := range values {
		r.SetPathValue(k, v)
	}
	return r
}
