package logout

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

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
	h := &Handler{issuer: "https://id.example/tenant"}
	h.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: "Acme ID", LogoURL: "/auth/v1/clients/acme/logo?v=1", ThemeURL: "/auth/v1/theme/acme/2"}, nil
	})
	w := httptest.NewRecorder()
	logoutSecurityHeaders(w)
	err := confirmationPage.Execute(w, confirmationPageData{
		BasePath:    "/tenant",
		Interaction: "tok",
		Brand:       branding.ResolveOptional(context.Background(), h.brand),
		Messages:    i18n.MessagesFor("en"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := w.Body.String()
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}

	wDefault := httptest.NewRecorder()
	if err := confirmationPage.Execute(wDefault, confirmationPageData{BasePath: "/tenant", Interaction: "tok", Messages: i18n.MessagesFor("en")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wDefault.Body.String(), `<span>GoAuthy</span>`) {
		t.Fatalf("expected GoAuthy fallback in %s", wDefault.Body.String())
	}
}
