package browser

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestBrowserIDCookieContract(t *testing.T) {
	for _, issuer := range []string{"https://issuer.example.test", "http://127.0.0.1:8080"} {
		cookie, err := BrowserIDCookie(issuer)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(cookie.Value) || cookie.MaxAge != 157680000 || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("invalid correlation cookie shape")
		}
		if cookie.Secure != (issuer == "https://issuer.example.test") {
			t.Fatal("wrong secure flag")
		}
		r := httptest.NewRequest("GET", issuer, nil)
		if got, err := BrowserID(r, issuer); err != nil || got != "" {
			t.Fatal("missing correlation cookie")
		}
		r.AddCookie(cookie)
		if got, err := BrowserID(r, issuer); err != nil || got != cookie.Value {
			t.Fatal("correlation cookie round trip")
		}
	}
}

func TestBrowserIDPolicyCookieModes(t *testing.T) {
	for _, test := range []struct {
		mode, name, path string
		secure           bool
		setPath          bool
	}{
		{mode: BrowserIDHost, name: "__Host-rbid", path: "/", secure: true, setPath: true},
		{mode: BrowserIDSecure, name: "__Secure-rbid", path: "/auth", secure: true, setPath: true},
		{mode: BrowserIDSecure, name: "__Secure-rbid", path: "/", secure: true},
		{mode: BrowserIDDangerInsecure, name: "rbid", path: "/auth", setPath: true},
		{mode: BrowserIDDangerInsecure, name: "rbid", path: "/"},
	} {
		t.Run(test.mode+test.path, func(t *testing.T) {
			policy, err := NewBrowserIDPolicy(test.mode, test.setPath)
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := policy.BrowserIDCookie("https://issuer.example.test")
			if err != nil {
				t.Fatal(err)
			}
			if cookie.Name != test.name || cookie.Path != test.path || cookie.Secure != test.secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 157680000 {
				t.Fatalf("cookie=%#v", cookie)
			}
			r := httptest.NewRequest(http.MethodGet, "https://issuer.example.test/auth", nil)
			r.AddCookie(cookie)
			if got, err := policy.BrowserID(r, "https://issuer.example.test"); err != nil || got != cookie.Value {
				t.Fatalf("BrowserID()=%q, %v; want %q", got, err, cookie.Value)
			}
		})
	}
}

func TestBrowserIDPolicyRejectsInvalidModeAndIssuer(t *testing.T) {
	if _, err := NewBrowserIDPolicy("invalid", false); !errors.Is(err, ErrInvalidBrowserIDMode) {
		t.Fatalf("invalid mode error=%v", err)
	}
	policy := &BrowserIDPolicy{Mode: BrowserIDHost}
	if _, err := policy.BrowserIDCookie("http://issuer.example.test"); err == nil {
		t.Fatal("non-loopback HTTP issuer accepted")
	}
}
