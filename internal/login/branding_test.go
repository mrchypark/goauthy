package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/branding"
)

func TestClientLoginBrandingEscapesCopyAndKeepsAuthenticationFields(t *testing.T) {
	h := testHandler(t)
	h.SetLoginBrandingResolver(func(_ context.Context, id string) (LoginBranding, error) {
		if id != "browser-client" {
			t.Fatalf("client=%q", id)
		}
		return LoginBranding{LogoURL: "/auth/v1/clients/browser-client/logo?updated=1", English: branding.LoginCopy{Title: `Welcome <script>alert(1)</script>`, Description: "Your team", Button: "Continue"}, Korean: branding.LoginCopy{Title: "환영합니다", Description: "팀 로그인", Button: "계속"}}, nil
	})
	r := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
	r.RemoteAddr = "198.51.100.10:1234"
	w := httptest.NewRecorder()
	h.Authorize(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, s := range []string{`class="client-login-logo"`, `data-brand-ko="환영합니다"`, `Welcome &lt;script&gt;`, `name="interaction"`, `name="username"`, `name="password"`, `method="post" action="/auth/login"`, `>계속</button>`} {
		if !strings.Contains(body, s) {
			t.Errorf("missing %q", s)
		}
	}
	if strings.Contains(body, `<script>alert(1)</script>`) {
		t.Fatal("unescaped copy")
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal("CSP weakened")
	}
}

func TestAccountLoginCommonBrandAndCopy(t *testing.T) {
	h := testHandler(t)
	h.SetLoginBrandingResolver(func(_ context.Context, id string) (LoginBranding, error) {
		if id != branding.GlobalBrandID {
			t.Fatalf("account brand=%q", id)
		}
		return LoginBranding{Name: `ID "<operator>"`, LogoURL: "/auth/v1/clients/" + branding.GlobalBrandID + "/logo?updated=7", English: branding.LoginCopy{Title: "Your common account", Description: "One account for both apps", Button: "Continue"}}, nil
	})
	r := httptest.NewRequest("GET", "/account/login", nil)
	r.RemoteAddr = "203.0.113.8:1234"
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, r)
	for _, want := range []string{`ID &#34;&lt;operator&gt;&#34;`, `Your common account`, `One account for both apps`, `data-brand-en="Your common account"`, `name="csrf_token"`, `action="/account/login"`, `src="/auth/v1/clients/` + branding.GlobalBrandID + `/logo?updated=7"`} {
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("status=%d missing %q body=%s", w.Code, want, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), `<operator>`) {
		t.Fatal("unescaped brand")
	}
}

func TestClientLoginBrandingFailureDoesNotRenderPartialForm(t *testing.T) {
	h := testHandler(t)
	h.SetLoginBrandingResolver(func(context.Context, string) (LoginBranding, error) {
		return LoginBranding{}, errors.New("unavailable")
	})
	r := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	r.RemoteAddr = "198.51.100.10:1234"
	w := httptest.NewRecorder()
	h.Authorize(w, r)
	if w.Code != 503 || strings.Contains(w.Body.String(), "login-form") {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
}

func TestClientLoginBrandingLeavesDirectLoginInstructions(t *testing.T) {
	h := testHandler(t)
	h.SetLoginBrandingResolver(func(_ context.Context, id string) (LoginBranding, error) {
		if id != branding.GlobalBrandID {
			t.Fatalf("direct login brand=%q", id)
		}
		return LoginBranding{Name: "Common ID", English: branding.LoginCopy{Title: "Custom title", Description: "Wrong security instructions", Button: "Custom button"}}, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	r.RemoteAddr = "198.51.100.12:1234"
	w := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Signing in does not approve it.") || !strings.Contains(w.Body.String(), "Common ID") || strings.Contains(w.Body.String(), "Wrong security instructions") {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
}
