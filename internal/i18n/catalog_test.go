package i18n

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserLanguageFromRequest(t *testing.T) {
	for _, tc := range []struct{ cookie, header, want string }{
		{"", "", "en"}, {"ko-KR", "fr", "ko"}, {"unknown", "ko", "en"},
		{"", "de-DE", "de"}, {"", "fr-FR", "fr"}, {"", "ko-KR", "ko"},
		{"", "no-NO", "nb"}, {"", "nl-NL", "nl"}, {"", "ru-RU", "ru"},
		{"", "uk-UA", "uk"}, {"", "zh-Hans", "zhhans"}, {"zhhans", "en", "zhhans"},
		{"", "de;q=0.1,fr;q=0.9", "fr"}, {"", "en;q=0,*", "de"},
		{"", "ko;q=0,ko;q=1,fr;q=0.5", "fr"}, {"", "ko;q=wat", "en"},
		{"", strings.Repeat("fr,", 16) + "ko", "en"},
		{"", strings.Repeat("x", maxAcceptLanguageLength+1), "en"},
	} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Accept-Language", tc.header)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: "locale", Value: tc.cookie})
		}
		if got := UserLanguageFromRequest(r); got != tc.want {
			t.Fatalf("cookie=%q header=%q got=%q want=%q", tc.cookie, tc.header, got, tc.want)
		}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Add("Accept-Language", "fr;q=0.5")
	r.Header.Add("Accept-Language", "ko;q=0.9")
	if got := UserLanguageFromRequest(r); got != "ko" {
		t.Fatalf("multiple fields=%s", got)
	}
	r.Header.Add("Accept-Language", strings.Repeat("x", maxAcceptLanguageLength))
	if got := UserLanguageFromRequest(r); got != "en" {
		t.Fatalf("aggregate bound=%s", got)
	}
	for _, value := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		if !ValidUserLanguage(value) {
			t.Fatalf("canonical language rejected: %s", value)
		}
	}
	for _, value := range []string{"", "zh_hans", "en-US", "EN", "xx"} {
		if ValidUserLanguage(value) {
			t.Fatalf("noncanonical language accepted: %s", value)
		}
	}
}

func TestResolve(t *testing.T) {
	for _, test := range []struct {
		header string
		want   string
	}{
		{"", "en"},
		{"ko-KR, en;q=0.8", "ko"},
		{"en;q=0.8, ko;q=0.9", "ko"},
		{"en;q=0.8, ko;q=0.8", "en"},
		{"en;q=0,*", "ko"},
		{"ko;q=0,*", "en"},
		{"fr, de", "en"},
		{"*;q=0.5, ko;q=0.4", "en"},
		{"ko;q=0, en;q=0.5", "en"},
		{"ko;q=wat", "en"},
		{"ko;q=.5", "en"},
		{"ko;q=1.", "en"},
		{"ko;q=01", "en"},
		{"ko;q=1e0", "en"},
		{"ko;q=+1", "en"},
		{"1ko", "en"},
		{"ko;;q=1", "en"},
		{"ko,", "en"},
	} {
		if got := Resolve(test.header); got != test.want {
			t.Fatalf("Resolve(%q)=%q want %q", test.header, got, test.want)
		}
	}
}

func TestMessagesFor(t *testing.T) {
	if messages := MessagesFor("ko-KR"); messages.Language != "ko" || messages.SignIn != "로그인" || messages.ConfirmSignOut == "" {
		t.Fatalf("Korean catalog=%#v", messages)
	}
	if messages := MessagesFor("malformed;q=not-a-number"); messages.Language != "en" || messages.SignIn != "Sign in" {
		t.Fatalf("English fallback=%#v", messages)
	}
}

func TestResolveBoundsAndStrictEmbeddedCatalog(t *testing.T) {
	if got := Resolve("ko," + "en,ko,en,ko,en,ko,en,ko,en,ko,en,ko,en,ko,en,ko,en"); got != "en" {
		t.Fatalf("range limit result=%q", got)
	}
	if got := Resolve(string(make([]byte, maxAcceptLanguageLength+1))); got != "en" {
		t.Fatalf("header limit result=%q", got)
	}
	for _, data := range [][]byte{
		[]byte(`{"sign_in":"a","sign_in":"b","continue_to":"a","username":"a","password":"a","sign_out":"a","confirm_sign_out":"a","signed_in":"a"}`),
		[]byte(`{"sign_in":"a","continue_to":"a","username":"a","password":"a","sign_out":"a","confirm_sign_out":"a","signed_in":"a","unknown":"a"}`),
		[]byte(`{"sign_in":"a","continue_to":"a","username":"a","password":"a","sign_out":"a","confirm_sign_out":"a","signed_in":"a"} null`),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("accepted invalid catalog")
				}
			}()
			mustCatalog(data, "en")
		}()
	}
}
