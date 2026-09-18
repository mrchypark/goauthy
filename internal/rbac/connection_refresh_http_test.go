package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefreshConnectionCredentialHTTPBoundary(t *testing.T) {
	h, cookie, csrf := oauth2RefreshHTTPFixture(t)
	h.issuer = "https://issuer.example.test"
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "admin", "consumer", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	path := "/auth/v1/connection-grants/missing/refresh"
	for name, alter := range map[string]func(*http.Request){
		"query":    func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"cookie":   func(r *http.Request) { r.AddCookie(cookie) },
		"origin":   func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"fetch":    func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"if-match": func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
		"csrf":     func(r *http.Request) { r.Header.Set("X-CSRF-Token", csrf) },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"credential_version":1}`))
			r.SetPathValue("grant_id", "missing")
			r.Header.Set("Authorization", "Bearer token")
			r.Header.Set("Content-Type", "application/json")
			alter(r)
			w := httptest.NewRecorder()
			h.RefreshConnectionCredential(w, r)
			if w.Code != http.StatusUnauthorized && name != "if-match" && name != "csrf" {
				t.Fatalf("status=%d", w.Code)
			}
			if (name == "if-match" || name == "csrf") && w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	for _, body := range []string{`{}`, `{"credential_version":0}`, `{"credential_version":-1}`, `{"credential_version":1.5}`, `{"credential_version":9223372036854775808}`, `{"credential_version":"1"}`, `{"credential_version":null}`, `{"credential_version":1,"credential_version":1}`, `{"credential_version":1,"unknown":true}`, `null`} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.SetPathValue("grant_id", "missing")
		r.Header.Set("Authorization", "Bearer token")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.RefreshConnectionCredential(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"credential_version":1}`))
	r.SetPathValue("grant_id", "missing")
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RefreshConnectionCredential(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("valid request status=%d", w.Code)
	}
}
