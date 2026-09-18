package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountConnectionAPIKeyRejectsUnauthenticatedAndStrictBodies(t *testing.T) {
	h, _, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(nil); err == nil {
		t.Fatal("nil credential store accepted")
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, "/auth/v1/account/connections/c/conn/api-key", strings.NewReader(`{"api_key":"secret","version":0}`))
		r.SetPathValue("collection_id", "c")
		r.SetPathValue("connection_id", "conn")
		w := httptest.NewRecorder()
		h.AccountConnectionAPIKey(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
}

func TestAPIKeyVersionAcceptsIfMatchOrStrictBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(`{"version":3}`))
	r.Header.Set("Content-Type", "application/json")
	if got, err := apiKeyVersion(r); err != nil || got != 3 {
		t.Fatalf("body version=%d err=%v", got, err)
	}
	r = httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(`{"version":0}`))
	r.Header.Set("Content-Type", "application/json")
	if got, err := apiKeyVersion(r); err == nil || got != 0 {
		t.Fatalf("zero version=%d err=%v", got, err)
	}
}
