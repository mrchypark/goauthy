package logout

import (
	"net/http/httptest"
	"strings"
	"testing"

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
			if w.Header().Get("Content-Security-Policy") != "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'" {
				t.Fatal("logout CSP changed")
			}
		})
	}
}
