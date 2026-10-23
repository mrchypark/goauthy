package branding

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestBrowserErrorNavigationPreservesWriteDeadline(t *testing.T) {
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, "/account/login", nil)
	r.Header.Set("Accept", "text/html")
	deadline := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	BrowserPageErrors("https://auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		http.Error(w, "Invalid user credentials", http.StatusUnauthorized)
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || !w.deadline.Equal(deadline) {
		t.Fatalf("status=%d deadline=%s", w.Code, w.deadline)
	}
}

func TestBrowserErrorNavigationPreservesAuthority(t *testing.T) {
	for _, tc := range []struct {
		path, accept, media string
		status              int
		wrapped             bool
	}{
		{"/account/login", "text/html", "text/plain", 401, true},
		{"/account/login", "application/json", "application/json", 401, false},
		{"/oidc/token", "text/html", "application/json", 400, false},
		{"/oidc/authorize", "text/html", "text/html", 403, false},
		{"/account/login", "text/html", "text/plain", 303, false},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Header.Set("Accept", tc.accept)
		r.Header.Set("Accept-Language", "ko")
		w := httptest.NewRecorder()
		BrowserPageErrors("https://auth.test/tenant", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.media)
			w.WriteHeader(tc.status)
			w.Write([]byte("original"))
		})).ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("status changed", w.Code)
		}
		if tc.wrapped {
			if !strings.Contains(w.Body.String(), `href="/tenant/"`) || strings.Contains(w.Body.String(), "original") {
				t.Fatal(w.Body.String())
			}
		} else if w.Body.String() != "original" {
			t.Fatal("protocol response changed")
		}
	}
}

func TestBrowserErrorsUseOnlyResolvedGlobalBrand(t *testing.T) {
	resolved := 0
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login?client_id=attacker", nil)
	r.Header.Set("Accept", "text/html")
	BrowserPageErrorsWithBrand("https://auth.test/tenant", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid interaction", http.StatusForbidden)
	}), func(_ context.Context) (Brand, error) {
		resolved++
		return Brand{Name: "Trusted IAM", LogoURL: "/auth/v1/clients/goauthy/logo?v=2", ThemeURL: "/auth/v1/theme/goauthy/9"}, nil
	}).ServeHTTP(w, r)

	if resolved != 1 || w.Code != http.StatusForbidden {
		t.Fatalf("resolver calls=%d status=%d", resolved, w.Code)
	}
	for _, directive := range []string{"default-src 'none'", "style-src 'self'", "font-src 'self'", "img-src 'self'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), directive) {
			t.Errorf("global error CSP missing %q: %q", directive, w.Header().Get("Content-Security-Policy"))
		}
	}
	for _, want := range []string{
		`<title>Trusted IAM</title>`,
		`href="/tenant/auth/v1/theme/goauthy/9"`,
		`src="/tenant/auth/v1/clients/goauthy/logo?v=2"`,
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("global-branded error page missing %q: %s", want, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), "attacker") {
		t.Fatal("request-supplied client ID appeared in error branding")
	}
}

func TestBrowserErrorsFallBackWhenGlobalBrandUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r.Header.Set("Accept", "text/html")
	BrowserPageErrorsWithBrand("https://auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid interaction", http.StatusForbidden)
	}), func(context.Context) (Brand, error) {
		return Brand{}, errors.New("global brand unavailable")
	}).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "GoAuthy") || strings.Contains(w.Body.String(), "/auth/v1/theme/goauthy/") {
		t.Fatalf("fallback status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLoginErrorRuleWinsOverPanelParagraphStyle(t *testing.T) {
	css := string(globalCSS)
	if !strings.Contains(css, `.auth-panel > p.auth-error { color: hsl(var(--error)); }`) {
		t.Fatal("login error color selector must outrank the panel paragraph selector and use the theme error color")
	}
}
