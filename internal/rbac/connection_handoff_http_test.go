package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBindConnectionHandoffAuthorizerRejectsNil(t *testing.T) {
	h, _, _, _ := membershipHTTPFixture(t)
	if err := h.BindConnectionHandoffAuthorizer(nil); err == nil {
		t.Fatal("nil authorizer accepted")
	}
	var nilHandler *Handler
	if err := nilHandler.BindConnectionHandoffAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "", "", nil, nil
	}); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func handoffHTTPFixture(t *testing.T) (*Handler, *http.Cookie, string) {
	t.Helper()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionHandoffAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "admin", "requester", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	return h, cookie, csrf
}

func TestCreateConnectionHandoffHTTPBoundary(t *testing.T) {
	h, _, _ := handoffHTTPFixture(t)
	valid := `{"collection_id":"c","connection_id":"g","consumer_client_id":"client","mode":"proxy","purpose":"use","expires_at_unix_ms":4102444800000,"return_uri":"https://client.example/callback","state":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12"}`
	for name, alter := range map[string]func(*http.Request){
		"empty cookie":            func(r *http.Request) { r.Header.Set("Cookie", "") },
		"query":                   func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":             func(r *http.Request) { r.URL.ForceQuery = true },
		"cross site":              func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"duplicate authorization": func(r *http.Request) { r.Header.Add("Authorization", "Bearer second") },
		"if match":                func(r *http.Request) { r.Header.Set("If-Match", `"1"`) },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-handoffs", strings.NewReader(valid))
			r.Header.Set("Authorization", "Bearer token")
			r.Header.Set("Content-Type", "application/json")
			alter(r)
			w := httptest.NewRecorder()
			h.CreateConnectionHandoff(w, r)
			want := http.StatusUnauthorized
			if name == "if match" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
		})
	}
	for _, body := range []string{
		strings.Replace(valid, `,"state":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12"`, `,"unknown":true,"state":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12"`, 1),
		strings.Replace(valid, `"purpose":"use"`, `"purpose":null`, 1),
		strings.Replace(valid, `"mode":"proxy"`, `"mode":"proxy","mode":"proxy"`, 1),
	} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-handoffs", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.CreateConnectionHandoff(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("strict status=%d body=%s", w.Code, w.Body.String())
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		r := httptest.NewRequest(method, "/auth/v1/connection-handoffs", strings.NewReader(valid))
		w := httptest.NewRecorder()
		h.CreateConnectionHandoff(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
	missing, _, _, _ := membershipHTTPFixture(t)
	w := httptest.NewRecorder()
	missing.CreateConnectionHandoff(w, httptest.NewRequest(http.MethodPost, "/auth/v1/connection-handoffs", strings.NewReader(valid)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing config status=%d", w.Code)
	}
}

func TestOwnerConnectionHandoffHTTPAuthenticationBoundary(t *testing.T) {
	h, cookie, csrf := handoffHTTPFixture(t)
	path := "/auth/v1/account/connection-handoffs/missing"
	for name, alter := range map[string]func(*http.Request){
		"no cookie":    func(r *http.Request) {},
		"bearer":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") },
		"missing csrf": func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"approve":false}`))
			if name != "no cookie" {
				r.AddCookie(cookie)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			alter(r)
			w := httptest.NewRecorder()
			h.OwnerConnectionHandoff(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.OwnerConnectionHandoff(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("authenticated GET status=%d", w.Code)
	}
}

func TestOwnerConnectionHandoffDigestInput(t *testing.T) {
	h, cookie, csrf := handoffHTTPFixture(t)
	path := "/auth/v1/account/connection-handoffs/missing"
	for name, body := range map[string]string{
		"both":        `{"approve":true,"review_digest":"new","connector_digest":"old"}`,
		"empty new":   `{"approve":true,"review_digest":""}`,
		"empty old":   `{"approve":true,"connector_digest":""}`,
		"null new":    `{"approve":true,"review_digest":null}`,
		"null old":    `{"approve":true,"connector_digest":null}`,
		"deny digest": `{"approve":false,"review_digest":"new"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.SetPathValue("handoff_id", "missing")
			r.AddCookie(cookie)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			w := httptest.NewRecorder()
			h.OwnerConnectionHandoff(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want=%d", w.Code, http.StatusBadRequest)
			}
		})
	}
}
