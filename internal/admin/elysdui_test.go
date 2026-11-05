package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestElysduiAdminIntegration(t *testing.T) {
	allowed := true
	h, err := NewUI(func(w http.ResponseWriter, _ *http.Request, _ bool) bool {
		if !allowed {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return allowed
	})
	if err != nil {
		t.Fatal(err)
	}
	h.SetIssuer("https://example.test/tenant")
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/auth/v1/admin/dashboard", nil))
	for _, want := range []string{`href="/tenant/auth/v1/admin/elysdui.css"`, `href="/tenant/auth/v1/admin/elysdui-patterns.css"`, `id="admin-menu-toggle"`, `aria-controls="admin-navigation"`, `aria-expanded="false"`, `data-i18n="Menu"`, `data-slot="button"`, `data-slot="input"`, `class="ui-table"`} {
		if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), want) {
			t.Fatalf("status=%d missing %s", page.Code, want)
		}
	}
	for path, marker := range map[string]string{"/auth/v1/admin/elysdui.css": "[data-slot=button]", "/auth/v1/admin/elysdui-patterns.css": ".ui-table"} {
		css := httptest.NewRecorder()
		h.ServeHTTP(css, httptest.NewRequest(http.MethodGet, path, nil))
		if css.Code != http.StatusOK || !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") || !strings.Contains(css.Body.String(), marker) || strings.Contains(css.Header().Get("Content-Security-Policy"), "unsafe-") {
			t.Fatalf("asset %s status=%d headers=%v", path, css.Code, css.Header())
		}
	}
	allowed = false
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/auth/v1/admin/elysdui.css", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("asset authorization status=%d", denied.Code)
	}
}
