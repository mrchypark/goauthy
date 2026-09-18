package apidocs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocsAuthAssetsAndLocalSpec(t *testing.T) {
	called := 0
	h, err := NewHandler("http://localhost:8080", []byte(`{"openapi":"3.0.3"}`), false, func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
		called++
		if mutation {
			t.Fatal("docs requested mutation auth")
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewRecorder()
	h.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/auth/v1/docs", nil))
	if redirect.Code != http.StatusPermanentRedirect || redirect.Header().Get("Location") != "/auth/v1/docs/" {
		t.Fatalf("docs redirect status=%d location=%q", redirect.Code, redirect.Header().Get("Location"))
	}
	for _, path := range []string{"/auth/v1/docs/", "/auth/v1/docs/index.html", "/auth/v1/docs/openapi.json", "/auth/v1/docs/swagger-ui.css", "/auth/v1/docs/swagger-initializer.js"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, path, nil))
		if r.Code != http.StatusOK || r.Body.Len() == 0 {
			t.Fatalf("%s status=%d body=%d", path, r.Code, r.Body.Len())
		}
		if r.Header().Get("Content-Security-Policy") == "" || r.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("security headers missing for %s", path)
		}
	}
	if called != 6 {
		t.Fatalf("auth callback calls=%d want=6", called)
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/auth/v1/docs/swagger-initializer.js", nil))
	if !strings.Contains(r.Body.String(), `url:"./openapi.json"`) || !strings.Contains(r.Body.String(), `validatorUrl:null`) || !strings.Contains(r.Body.String(), `queryConfigEnabled:false`) || strings.Contains(r.Body.String(), "petstore") || strings.Contains(r.Body.String(), "DownloadUrl") {
		t.Fatalf("initializer is not local: %q", r.Body.String())
	}
	if called != 7 {
		t.Fatalf("initializer auth callback calls=%d want=7", called)
	}
}

func TestDocsUsesIssuerPathPrefix(t *testing.T) {
	h, err := NewHandler("https://id.example.test/tenant/auth/v1/", []byte("{}"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/auth/v1/docs/openapi.json", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d", r.Code)
	}
	redirect := httptest.NewRecorder()
	h.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/auth/v1/docs", nil))
	if redirect.Header().Get("Location") != "/tenant/auth/v1/auth/v1/docs/" {
		t.Fatalf("redirect=%q", redirect.Header().Get("Location"))
	}
}

func TestDocsRejectsQueriesMethodsAndUnknownAssets(t *testing.T) {
	h, err := NewHandler("https://id.example.test/auth/v1", []byte("{}"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/auth/v1/docs/?url=https://evil.test", http.StatusBadRequest},
		{http.MethodPost, "/auth/v1/docs/", http.StatusMethodNotAllowed},
		{http.MethodGet, "/auth/v1/docs/nope.js", http.StatusNotFound},
	} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(tc.method, tc.target, nil))
		if r.Code != tc.status {
			t.Errorf("%s %s status=%d want=%d", tc.method, tc.target, r.Code, tc.status)
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodHead, "/auth/v1/docs/openapi.json", nil))
	if r.Code != http.StatusOK || r.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%d", r.Code, r.Body.Len())
	}
}

func TestNewHandlerValidatesIssuerAndPrivateAuth(t *testing.T) {
	for _, issuer := range []string{"", "/relative", "ftp://example.test", "https://user:pass@example.test", "https://example.test?x=1", "https://example.test#x"} {
		if _, err := NewHandler(issuer, nil, true, nil); err == nil {
			t.Errorf("issuer %q accepted", issuer)
		}
	}
	if _, err := NewHandler("https://example.test", nil, false, nil); err == nil {
		t.Fatal("private docs accepted nil auth")
	}
}
