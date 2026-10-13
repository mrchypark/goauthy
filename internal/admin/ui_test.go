package admin

import (
	"context"
	"github.com/mrchypark/goauthy/internal/branding"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUICommonBrandEscapingAndIssuerPaths(t *testing.T) {
	u, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	u.SetIssuer("https://id.example/tenant")
	u.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: `ID "<operator>"`, LogoURL: "/auth/v1/clients/rauthy/logo?updated=7", ThemeURL: "/auth/v1/theme/rauthy/9"}, nil
	})
	w := httptest.NewRecorder()
	u.ServeHTTP(w, httptest.NewRequest("GET", "/auth/v1/admin/branding", nil))
	for _, want := range []string{`ID &#34;&lt;operator&gt;&#34;`, `href="/tenant/auth/v1/admin/branding"`, `src="/tenant/auth/v1/clients/rauthy/logo?updated=7"`, `href="/tenant/auth/v1/theme/rauthy/9"`} {
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("status=%d missing %q body=%s", w.Code, want, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), `<operator>`) {
		t.Fatal("brand name rendered as HTML")
	}
}

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
	for _, path := range []string{"/auth/v1/admin/users", "/auth/v1/admin/clients", "/auth/v1/admin/clients/test/theme", "/auth/v1/admin/collections", "/auth/v1/admin/app.js", "/auth/v1/admin/admin.css", "/auth/v1/admin/csrf"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src 'self'") || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-") {
			t.Fatalf("path=%s status=%d csp=%q", path, w.Code, w.Header().Get("Content-Security-Policy"))
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/v1/admin/app.js", nil))
	for _, function := range []string{"function catalog(", "function sessions(", "function collections(", "function clients(", "function clientTheme(", "function route("} {
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

func TestEmailPreviewAllowsOnlySameOriginFraming(t *testing.T) {
	h, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	for _, path := range []string{"/auth/v1/admin/email-templates/preview?type=password_reset&lang=en", "/auth/v1/admin/templates"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		frame, ancestor := "DENY", "frame-ancestors 'none'"
		if strings.Contains(path, "/preview?") {
			frame, ancestor = "SAMEORIGIN", "frame-ancestors 'self'"
		}
		if w.Header().Get("X-Frame-Options") != frame || !strings.Contains(w.Header().Get("Content-Security-Policy"), ancestor) || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-") {
			t.Fatalf("path=%s headers=%v", path, w.Header())
		}
	}
}

func TestUIPresentationQueryDoesNotChangeAuthorization(t *testing.T) {
	h, _ := NewUI(func(_ http.ResponseWriter, r *http.Request, mutation bool) bool {
		if mutation || r.URL.RawQuery != "" || r.URL.ForceQuery {
			t.Fatal("unexpected authorization context")
		}
		return true
	})
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/admin/email-templates/preview?type=password_reset&lang=en", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || r.URL.Query().Get("type") != "password_reset" {
		t.Fatalf("preview parameters lost: status=%d query=%s", w.Code, r.URL.RawQuery)
	}
}

func TestUILanguageAndIssuerNavigation(t *testing.T) {
	h, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.SetIssuer("https://auth.test/tenant")
	r := httptest.NewRequest("GET", "/auth/v1/admin/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for _, value := range []string{`lang="ko"`, `data-base-path="/tenant"`, `href="/tenant/account"`, `href="/tenant/"`, `src="/tenant/auth/v1/branding/locale.js"`} {
		if !strings.Contains(w.Body.String(), value) {
			t.Fatalf("missing %s", value)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/v1/admin/app.js", nil))
	if !strings.Contains(w.Body.String(), "/tenant/auth/v1/admin/csrf") {
		t.Fatal("API request lost issuer path")
	}
}

func TestUnauthorizedBrowserKeepsNavigationAndDenial(t *testing.T) {
	h, _ := NewUI(func(w http.ResponseWriter, _ *http.Request, _ bool) bool { w.WriteHeader(401); return false })
	h.SetIssuer("https://auth.test/tenant")
	r := httptest.NewRequest("GET", "/auth/v1/admin/users", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `href="/tenant/account/login"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `id="app"`) {
		t.Fatal("denied user received admin UI")
	}
}

func TestElyAdminScreensPreserveNavigationAndAssets(t *testing.T) {
	h, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.SetIssuer("https://auth.test/tenant")
	for _, screen := range []string{"dashboard", "users", "users/new", "users/subject", "branding", "clients", "clients/new", "clients/client/theme", "roles", "groups", "api-keys", "scopes", "attributes", "collections", "collections/new", "providers", "sessions", "events", "blacklist", "templates"} {
		t.Run(screen, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/admin/"+screen, nil)
			r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			for _, want := range []string{`lang="ko"`, `href="/tenant/auth/v1/ui/app.css"`, `data-slot="select"`, `data-slot="button"`, `id="admin-menu-toggle"`, `aria-controls="admin-navigation"`, `aria-expanded="false"`, `data-i18n="Menu"`, `id="app"`, `src="/tenant/auth/v1/admin/app.js"`, `</html>`} {
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
					t.Errorf("status=%d missing %s", w.Code, want)
				}
			}
			if strings.Contains(w.Body.String(), "/assets/") || strings.Contains(w.Body.String(), "hx-post") {
				t.Fatal("Ely introduced an alternate mutation or unprefixed asset path")
			}
		})
	}
	h.browserAdmin = func(w http.ResponseWriter, _ *http.Request, _ bool) bool { w.WriteHeader(401); return false }
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/admin/users", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `data-slot="button"`) || !strings.Contains(w.Body.String(), `href="/tenant/auth/v1/ui/app.css"`) || !strings.Contains(w.Body.String(), "</html>") {
		t.Fatal("denied page lost Ely controls, assets, or complete rendering", w.Body.String())
	}
}

type elyPreviewProvider struct{}

func (elyPreviewProvider) Types() []string           { return []string{"otp"} }
func (elyPreviewProvider) Languages(string) []string { return []string{"en"} }
func (elyPreviewProvider) Render(string, string) (EmailTemplateInfo, error) {
	return EmailTemplateInfo{Header: "Preview <header>", Text: "Sample", Footer: "Footer"}, nil
}

func TestElyEmailPreviewAssetsAndEscaping(t *testing.T) {
	h, _ := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	h.SetIssuer("https://auth.test/tenant")
	h.SetTemplateProvider(elyPreviewProvider{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/v1/admin/email-templates/preview?type=otp&lang=en", nil))
	for _, want := range []string{`href="/tenant/auth/v1/ui/app.css"`, `Preview &lt;header&gt;`, `123456`, `</html>`} {
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("status=%d missing %s", w.Code, want)
		}
	}
	if strings.Contains(w.Body.String(), "<script") || w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("preview changed script or frame contract")
	}
}
