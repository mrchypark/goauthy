package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectionCredentialStatusBoundary(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "admin", "consumer", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	h.issuer = "https://issuer.example.test"
	path := "/auth/v1/connection-grants/missing/credential-status"
	for name, alter := range map[string]func(*http.Request){
		"query":          func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":    func(r *http.Request) { r.URL.ForceQuery = true },
		"cookie":         func(r *http.Request) { r.Header.Set("Cookie", "x=y") },
		"origin":         func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"fetch":          func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"if-match":       func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
		"csrf":           func(r *http.Request) { r.Header.Set("X-CSRF-Token", "x") },
		"duplicate auth": func(r *http.Request) { r.Header.Add("Authorization", "Bearer two") },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.SetPathValue("grant_id", "missing")
			r.Header.Set("Authorization", "Bearer one")
			alter(r)
			w := httptest.NewRecorder()
			h.ConnectionCredentialStatus(w, r)
			if w.Code != http.StatusUnauthorized && name != "if-match" && name != "csrf" {
				t.Fatalf("status=%d", w.Code)
			}
			if (name == "if-match" || name == "csrf") && w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, path, strings.NewReader("body"))
	r.SetPathValue("grant_id", "missing")
	r.Header.Set("Authorization", "Bearer one")
	w := httptest.NewRecorder()
	h.ConnectionCredentialStatus(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("body status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, path, nil)
	r.SetPathValue("grant_id", "missing")
	r.Header.Set("Authorization", "Bearer one")
	w = httptest.NewRecorder()
	h.ConnectionCredentialStatus(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("valid request status=%d", w.Code)
	}
	r.SetPathValue("grant_id", "invalid\rgrant")
	w = httptest.NewRecorder()
	h.ConnectionCredentialStatus(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid grant status=%d", w.Code)
	}
}
