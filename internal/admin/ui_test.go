package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIServesSameOriginAssetsAndCSRFProvider(t *testing.T) {
	h, err := NewUI(func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
		if mutation {
			t.Fatal("UI page auth must be read-only")
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	h.SetCSRFTokenProvider(func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"test-token"}`))
		return true
	})
	for _, path := range []string{"/auth/v1/admin/users", "/auth/v1/admin/clients", "/auth/v1/admin/collections", "/auth/v1/admin/app.js", "/auth/v1/admin/admin.css", "/auth/v1/admin/csrf"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-") {
			t.Fatalf("path=%s status=%d csp=%q", path, w.Code, w.Header().Get("Content-Security-Policy"))
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/v1/admin/app.js", nil))
	for _, function := range []string{"function catalog(", "function sessions(", "function collections(", "function clients(", "function route("} {
		if !strings.Contains(w.Body.String(), function) {
			t.Fatalf("served bundle missing %s", function)
		}
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Fatal("admin bundle must be served as JavaScript")
	}
}

func TestUIRejectsAuthorizationHeader(t *testing.T) {
	h, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { t.Fatal("auth callback called"); return true })
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/admin/users", nil)
	r.Header.Set("Authorization", "Bearer nope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}
