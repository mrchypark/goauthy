package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexRendersConfiguredRoutesWithSecurityHeaders(t *testing.T) {
	called := false
	h, err := NewIndexHandler(func(w http.ResponseWriter, r *http.Request, mutation bool) bool {
		called = true
		if mutation {
			t.Fatal("index invoked browser administrator as mutation")
		}
		return true
	}, Route{Label: "Roles", Path: "/auth/v1/roles"}, Route{Label: "Groups", Path: "/auth/v1/groups"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.Index(response, httptest.NewRequest(http.MethodGet, "/auth/v1/admin", nil))
	if response.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v body=%q", response.Code, called, response.Body.String())
	}
	for name, want := range map[string]string{
		"cache":   "no-store",
		"csp":     "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
		"frame":   "DENY",
		"nosniff": "nosniff",
		"type":    "text/html; charset=utf-8",
	} {
		var got string
		switch name {
		case "cache":
			got = response.Header().Get("Cache-Control")
		case "csp":
			got = response.Header().Get("Content-Security-Policy")
		case "frame":
			got = response.Header().Get("X-Frame-Options")
		case "nosniff":
			got = response.Header().Get("X-Content-Type-Options")
		default:
			got = response.Header().Get("Content-Type")
		}
		if got != want {
			t.Fatalf("%s header=%q want %q", name, got, want)
		}
	}
	body := response.Body.String()
	if !strings.Contains(body, `href="/auth/v1/roles"`) || !strings.Contains(body, `href="/auth/v1/groups"`) {
		t.Fatalf("configured links missing from body: %q", body)
	}
}

func TestIndexEscapesRouteLabels(t *testing.T) {
	h, err := NewIndexHandler(func(http.ResponseWriter, *http.Request, bool) bool { return true }, Route{Label: `<script>alert(1)</script>`, Path: "/auth/v1/roles"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.Index(response, httptest.NewRequest(http.MethodGet, "/auth/v1/admin", nil))
	body := response.Body.String()
	if strings.Contains(body, `<script>alert(1)</script>`) || !strings.Contains(body, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Fatalf("route label was not escaped: %q", body)
	}
}

func TestIndexRejectsAuthorizationAndNonGET(t *testing.T) {
	called := 0
	h, err := NewIndexHandler(func(w http.ResponseWriter, _ *http.Request, _ bool) bool {
		called++
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}, Route{Label: "Roles", Path: "/auth/v1/roles"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/v1/admin", nil)
	request.Header.Set("Authorization", "Bearer not-a-browser-session")
	response := httptest.NewRecorder()
	h.Index(response, request)
	if response.Code != http.StatusUnauthorized || called != 0 {
		t.Fatalf("authorization fallback status=%d callback_calls=%d", response.Code, called)
	}
	response = httptest.NewRecorder()
	h.Index(response, httptest.NewRequest(http.MethodPost, "/auth/v1/admin", nil))
	if response.Code != http.StatusMethodNotAllowed || called != 0 || response.Header().Get("Allow") != "GET" {
		t.Fatalf("non-GET status=%d allow=%q callback_calls=%d", response.Code, response.Header().Get("Allow"), called)
	}
}

func TestIndexDelegatesSameOriginRejectionToBrowserAdministrator(t *testing.T) {
	called := false
	h, err := NewIndexHandler(func(w http.ResponseWriter, r *http.Request, mutation bool) bool {
		called = true
		if mutation || r.URL.RawQuery != "x=1" {
			t.Fatal("unexpected authorization request")
		}
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}, Route{Label: "Roles", Path: "/auth/v1/roles"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.Index(response, httptest.NewRequest(http.MethodGet, "/auth/v1/admin?x=1", nil))
	if response.Code != http.StatusUnauthorized || !called {
		t.Fatalf("query auth status=%d called=%v", response.Code, called)
	}
}

func TestNewIndexHandlerRejectsUntrustedOrDuplicateRoutes(t *testing.T) {
	authorize := func(http.ResponseWriter, *http.Request, bool) bool { return true }
	for _, routes := range [][]Route{
		{{Label: "external", Path: "https://attacker.example/"}},
		{{Label: "query", Path: "/auth/v1/roles?admin=true"}},
		{{Label: "dynamic", Path: "/auth/v1/roles/{id}"}},
		{{Label: "duplicate-a", Path: "/auth/v1/roles"}, {Label: "duplicate-b", Path: "/auth/v1/roles"}},
	} {
		if _, err := NewIndexHandler(authorize, routes...); err == nil {
			t.Fatalf("routes unexpectedly accepted: %+v", routes)
		}
	}
}
