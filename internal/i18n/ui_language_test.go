package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUILanguagePreference(t *testing.T) {
	for _, tc := range []struct{ cookie, header, want string }{
		{"ko", "en", "ko"}, {"en", "ko", "en"}, {"fr", "ko-KR", "ko"}, {"", "fr,ko;q=0.8", "ko"}, {"<script>", "en", "en"},
	} {
		r := httptest.NewRequest("GET", "/account", nil)
		r.Header.Set("Accept-Language", tc.header)
		r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: tc.cookie})
		r.AddCookie(&http.Cookie{Name: "locale", Value: "de"})
		if got := UILanguageFromRequest(r); got != tc.want {
			t.Fatalf("%+v: %q", tc, got)
		}
		if got := UserLanguageFromRequest(r); got != "de" {
			t.Fatalf("UI locale changed mail language: %q", got)
		}
	}
}
