package rbac

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func credentialDeliveryHTTPFixture(t *testing.T) *Handler {
	t.Helper()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "owner", "consumer", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDeliverConnectionCredentialHTTPBoundary(t *testing.T) {
	t.Parallel()
	h := credentialDeliveryHTTPFixture(t)
	path := "/auth/v1/connection-grants/grant/credential"
	for name, alter := range map[string]func(*http.Request){
		"cookie":         func(r *http.Request) { r.Header.Set("Cookie", "") },
		"origin":         func(r *http.Request) { r.Header.Set("Origin", "") },
		"fetch site":     func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
		"query":          func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":    func(r *http.Request) { r.URL.ForceQuery = true },
		"duplicate auth": func(r *http.Request) { r.Header.Add("Authorization", "Bearer second") },
		"missing auth":   func(r *http.Request) { r.Header.Del("Authorization") },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, nil)
			r.SetPathValue("grant_id", "grant")
			r.Header.Set("Authorization", "Bearer token")
			alter(r)
			w := httptest.NewRecorder()
			h.DeliverConnectionCredential(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	for name, alter := range map[string]func(*http.Request){
		"if match": func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
		"csrf":     func(r *http.Request) { r.Header.Set("X-CSRF-Token", "x") },
		"empty object": func(r *http.Request) {
			r.Body = httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")).Body
		},
		"body": func(r *http.Request) {
			r.Body = httptest.NewRequest(http.MethodPost, path, strings.NewReader("x")).Body
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, nil)
			r.SetPathValue("grant_id", "grant")
			r.Header.Set("Authorization", "Bearer token")
			alter(r)
			w := httptest.NewRecorder()
			h.DeliverConnectionCredential(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		h.DeliverConnectionCredential(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
}

func TestDeliverConnectionCredentialRequiresHTTPSAndConfig(t *testing.T) {
	t.Parallel()
	h := credentialDeliveryHTTPFixture(t)
	h.issuer = "http://issuer.example.test"
	w := httptest.NewRecorder()
	h.DeliverConnectionCredential(w, httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/g/credential", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("http issuer status=%d", w.Code)
	}
	missing, _, _, _ := membershipHTTPFixture(t)
	w = httptest.NewRecorder()
	missing.DeliverConnectionCredential(w, httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/g/credential", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing config status=%d", w.Code)
	}
}

func TestDeliverConnectionCredentialAuthorizerFailure(t *testing.T) {
	t.Parallel()
	h := credentialDeliveryHTTPFixture(t)
	h.connectionUseAuthorizer = func(*http.Request) (string, string, func() (string, []any), error) {
		return "", "", nil, errors.New("invalid bearer")
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/g/credential", nil)
	r.SetPathValue("grant_id", "grant")
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	h.DeliverConnectionCredential(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}
