package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func oauth2RefreshHTTPFixture(t *testing.T) (*Handler, *http.Cookie, string) {
	t.Helper()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	return h, cookie, csrf
}

func TestAccountConnectionOAuth2RefreshBoundary(t *testing.T) {
	t.Parallel()
	h, cookie, csrf := oauth2RefreshHTTPFixture(t)
	path := "/auth/v1/account/connections/c/g/oauth2/refresh"
	for name, alter := range map[string]func(*http.Request){
		"query":        func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":  func(r *http.Request) { r.URL.ForceQuery = true },
		"cross site":   func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"if match":     func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
		"bearer":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") },
		"api key":      func(r *http.Request) { r.Header.Set("Authorization", "API-Key token") },
		"missing csrf": func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"version":1}`))
			r.SetPathValue("collection_id", "c")
			r.SetPathValue("connection_id", "g")
			r.AddCookie(cookie)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			alter(r)
			w := httptest.NewRecorder()
			h.AccountConnectionOAuth2Refresh(w, r)
			want := http.StatusBadRequest
			if name == "bearer" || name == "api key" || name == "missing csrf" {
				want = http.StatusUnauthorized
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
		})
	}
	for _, body := range []string{`{}`, `{"version":0}`, `{"version":-1}`, `{"version":1.5}`, `{"version":9223372036854775808}`, `{"version":1,"version":1}`, `{"version":1,"secret":"x"}`, `null`} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.SetPathValue("collection_id", "c")
		r.SetPathValue("connection_id", "g")
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.AccountConnectionOAuth2Refresh(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		h.AccountConnectionOAuth2Refresh(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
}

func TestAccountConnectionOAuth2RefreshHTTPSAndAuthFailure(t *testing.T) {
	t.Parallel()
	h, _, csrf := oauth2RefreshHTTPFixture(t)
	h.issuer = "http://issuer.example.test"
	w := httptest.NewRecorder()
	h.AccountConnectionOAuth2Refresh(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("http issuer status=%d", w.Code)
	}
	h.issuer = "https://issuer.example.test"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"version":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w = httptest.NewRecorder()
	h.AccountConnectionOAuth2Refresh(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("auth failure status=%d", w.Code)
	}
}

func TestAccountConnectionOAuth2RefreshMissingConfigAndResource(t *testing.T) {
	t.Parallel()
	h, cookie, csrf := oauth2RefreshHTTPFixture(t)
	path := "/auth/v1/account/connections/missing/unknown/oauth2/refresh"
	validRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"version":1}`))
		r.SetPathValue("collection_id", "missing")
		r.SetPathValue("connection_id", "unknown")
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		return r
	}
	h.saasProviderStore = nil
	w := httptest.NewRecorder()
	h.AccountConnectionOAuth2Refresh(w, validRequest())
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing provider store status=%d", w.Code)
	}
	h.saasProviderStore = providerHTTPStore(t, h.store)
	w = httptest.NewRecorder()
	h.AccountConnectionOAuth2Refresh(w, validRequest())
	if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(strings.ToLower(w.Body.String()), "secret") {
		t.Fatalf("missing resource status=%d cache=%q body=%q", w.Code, w.Header().Get("Cache-Control"), w.Body.String())
	}
}
