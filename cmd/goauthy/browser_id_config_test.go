package main

import (
	"github.com/mrchypark/goauthy/internal/browser"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserIDPolicyConfigAndPasswordReader(t *testing.T) {
	for _, tc := range []struct {
		mode, path, name, cookiePath string
		valid                        bool
	}{
		{"", "false", "__Host-rbid", "/", true},
		{"secure", "true", "__Secure-rbid", "/auth", true},
		{"danger-insecure", "true", "rbid", "/auth", true},
		{"host", "true", "__Host-rbid", "/", true},
		{"unknown", "false", "", "", false},
		{"host", "invalid", "", "", false},
	} {
		t.Run(tc.mode+tc.path, func(t *testing.T) {
			p, err := browserIDPolicyFromEnv(func(k string) string {
				return map[string]string{"GOAUTHY_BROWSER_ID_COOKIE_MODE": tc.mode, "GOAUTHY_BROWSER_ID_COOKIE_SET_PATH": tc.path}[k]
			}, "https://issuer.test")
			if (err == nil) != tc.valid {
				t.Fatalf("config error=%v", err)
			}
			if !tc.valid {
				return
			}
			cookie, err := p.BrowserIDCookie("https://issuer.test")
			if err != nil || cookie.Name != tc.name || cookie.Path != tc.cookiePath {
				t.Fatalf("cookie shape error=%v", err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://issuer.test/auth/v1/token", nil)
			r = r.WithContext(browser.ContextWithPeerIP(r.Context(), "192.0.2.1"))
			r.Header.Set("User-Agent", "Browser")
			r.AddCookie(cookie)
			called := false
			observer := passwordLoginLocationObserver("https://issuer.test", p, func(_ *http.Request, subject, id, ip, ua string) error {
				called = true
				if id != cookie.Value {
					t.Fatal("cookie policy reader mismatch")
				}
				return nil
			})
			if err := observer(httptest.NewRecorder(), r, "alice"); err != nil || !called {
				t.Fatalf("observer error=%v called=%t", err, called)
			}
		})
	}
}
