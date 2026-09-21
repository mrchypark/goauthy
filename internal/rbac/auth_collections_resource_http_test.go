package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/authcollection"
)

func TestUserResourceAuthCollectionsBearerBoundaryAndOwnership(t *testing.T) {
	t.Parallel()
	h, store, adminCookie, adminCSRF := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionResourceAuthorizer(nil); err == nil {
		t.Fatal("nil resource authorizer accepted")
	}
	seenScopes := []string{}
	if err := h.BindConnectionResourceAuthorizer(func(_ *http.Request, scope string) (string, func() (string, []any), error) {
		seenScopes = append(seenScopes, scope)
		return "member", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	create := authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", `{"id":"resource-one","name":"Resource","auth_method":"api_key","enabled":true,"fields":[]}`, adminCookie, adminCSRF)
	w := httptest.NewRecorder()
	h.AuthCollections(w, create)
	if w.Code != http.StatusCreated {
		t.Fatalf("definition status=%d", w.Code)
	}

	request := resourceRequest(http.MethodGet, "/auth/v1/connection-collections", "", nil)
	w = httptest.NewRecorder()
	h.UserResourceAuthCollections(w, request)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer status=%d", w.Code)
	}
	request = resourceRequest(http.MethodGet, "/auth/v1/connection-collections", "Bearer token", nil)
	w = httptest.NewRecorder()
	h.UserResourceAuthCollections(w, request)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "resource-one") {
		t.Fatalf("resource list status=%d body=%s", w.Code, w.Body.String())
	}
	request = resourceRequest(http.MethodGet, "/auth/v1/connection-collections", "Bearer token", adminCookie)
	w = httptest.NewRecorder()
	h.UserResourceAuthCollections(w, request)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mixed cookie status=%d", w.Code)
	}

	request = resourceRequestWithPath(http.MethodPost, "/auth/v1/connections/resource-one", "Bearer token", `{"definition_revision":1,"metadata":{}}`, map[string]string{"collection_id": "resource-one"})
	w = httptest.NewRecorder()
	h.UserResourceConnections(w, request)
	if w.Code != http.StatusCreated {
		t.Fatalf("resource create status=%d body=%s", w.Code, w.Body.String())
	}
	var conn authcollection.Connection
	if err := json.Unmarshal(w.Body.Bytes(), &conn); err != nil {
		t.Fatal(err)
	}
	if conn.OwnerSubject != "member" {
		t.Fatalf("owner injection/callback mismatch: %+v", conn)
	}
	bad := resourceRequestWithPath(http.MethodPost, "/auth/v1/connections/resource-one", "Basic token", `{"definition_revision":1,"metadata":{}}`, map[string]string{"collection_id": "resource-one"})
	w = httptest.NewRecorder()
	h.UserResourceConnections(w, bad)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid authorization status=%d", w.Code)
	}
	ownerInjection := resourceRequestWithPath(http.MethodPost, "/auth/v1/connections/resource-one", "Bearer token", `{"definition_revision":1,"metadata":{},"owner":"attacker"}`, map[string]string{"collection_id": "resource-one"})
	w = httptest.NewRecorder()
	h.UserResourceConnections(w, ownerInjection)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("owner injection status=%d", w.Code)
	}
	get := resourceRequestWithPath(http.MethodGet, "/auth/v1/connections/resource-one/"+conn.ID, "Bearer token", "", map[string]string{"collection_id": "resource-one", "connection_id": conn.ID})
	w = httptest.NewRecorder()
	h.UserResourceConnection(w, get)
	if w.Code != http.StatusOK {
		t.Fatalf("resource get status=%d", w.Code)
	}
	if len(seenScopes) < 3 || seenScopes[0] != "goauthy.connections.read" || seenScopes[1] != "goauthy.connections.write" {
		t.Fatalf("scope callbacks=%v", seenScopes)
	}
}

func resourceRequest(method, path, authorization string, cookie *http.Cookie) *http.Request {
	r := resourceRequestWithPath(method, path, authorization, "", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}
func resourceRequestWithPath(method, path, authorization, body string, values map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	for k, v := range values {
		r.SetPathValue(k, v)
	}
	return r
}
