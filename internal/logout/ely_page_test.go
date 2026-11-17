package logout

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/i18n"
)

func TestElyLogoutConfirmationPreservesNativeForm(t *testing.T) {
	for _, language := range []string{"en", "ko"} {
		t.Run(language, func(t *testing.T) {
			w := httptest.NewRecorder()
			logoutSecurityHeaders(w)
			if err := confirmationPage.Execute(w, confirmationPageData{BasePath: "/tenant", Interaction: `confirmation"<script>`, Messages: i18n.MessagesFor(language)}); err != nil {
				t.Fatal(err)
			}
			body := w.Body.String()
			for _, want := range []string{`/tenant/auth/v1/ui/app.css`, `/tenant/auth/v1/ui/brand.css`, `/tenant/auth/v1/theme/global.css`, `method="post" action="logout"`, `name="confirmation" value="confirmation&#34;&lt;script&gt;"`, `data-slot="button"`, `type="submit"`, `href="/tenant/account"`, `lang="` + language + `"`} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %s", want)
				}
			}
			if strings.Contains(body, "<script") || strings.Contains(body, "hx-") {
				t.Fatal("script or enhanced submission added")
			}
			if w.Header().Get("Content-Security-Policy") != "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'" {
				t.Fatal("logout CSP changed")
			}
		})
	}
}

func TestLogoutConfirmationCommonBrand(t *testing.T) {
	h, sessions, _ := testLogoutHandler(t)
	h.issuer = "https://id.example/tenant"
	session, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	cookieToken := session.Token

	h.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: "Acme ID", LogoURL: "/auth/v1/clients/acme/logo?v=1", ThemeURL: "/auth/v1/theme/acme/2"}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/tenant/oidc/logout", nil)
	w := httptest.NewRecorder()
	logoutSecurityHeaders(w)
	h.renderConfirmation(w, req, cookieToken, confirmationPayload{})
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatalf("status=%d csp=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	body := w.Body.String()
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}

	h.SetBrandResolver(nil)
	wDefault := httptest.NewRecorder()
	logoutSecurityHeaders(wDefault)
	h.renderConfirmation(wDefault, req, cookieToken, confirmationPayload{})
	if wDefault.Code != http.StatusOK || !strings.Contains(wDefault.Body.String(), `<span>GoAuthy</span>`) {
		t.Fatalf("expected GoAuthy fallback status=%d body=%s", wDefault.Code, wDefault.Body.String())
	}
}
