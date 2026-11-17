package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/oauth"
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
	for _, s := range []string{`class="client-login-logo"`, `data-brand-ko="환영합니다"`, `Welcome &lt;script&gt;`, `name="interaction"`, `name="username"`, `name="password"`, `method="post" action="/auth/login"`, `>계속</button>`, `data-slot="button"`, `/auth/v1/ui/app.css`} {
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
		if id != "" {
			t.Fatalf("account brand=%q", id)
		}
		return LoginBranding{Name: `ID "<operator>"`, LogoURL: "/auth/v1/branding/logo?updated=7", English: branding.LoginCopy{Title: "Your common account", Description: "One account for both apps", Button: "Continue"}}, nil
	})
	r := httptest.NewRequest("GET", "/account/login", nil)
	r.RemoteAddr = "203.0.113.8:1234"
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, r)
	for _, want := range []string{`ID &#34;&lt;operator&gt;&#34;`, `Your common account`, `One account for both apps`, `data-brand-en="Your common account"`, `name="csrf_token"`, `action="/account/login"`, `src="/auth/v1/branding/logo?updated=7"`} {
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
		if id != "" {
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

func TestContinuationPagesRenderBrandLogoAndTheme(t *testing.T) {
	brand := LoginBranding{Name: "Acme ID", LogoURL: "/tenant/auth/v1/clients/acme/logo?v=1"}
	themeURL := "/tenant/auth/v1/theme/acme/2"

	for _, tc := range []struct {
		name   string
		render func(*strings.Builder) error
	}{
		{
			name: "otpStepUpPage",
			render: func(b *strings.Builder) error {
				return otpStepUpPage.Execute(b, loginPageData{IssuerPath: "/tenant", ThemeURL: themeURL, Brand: brand})
			},
		},
		{
			name: "fedCMLandingPage",
			render: func(b *strings.Builder) error {
				return fedCMLandingPage.Execute(b, fedCMLandingPageData{IssuerPath: "/tenant", ThemeURL: themeURL, Brand: brand})
			},
		},
		{
			name: "fedCMSuccessPage",
			render: func(b *strings.Builder) error {
				return fedCMSuccessPage.Execute(b, fedCMSuccessPageData{IssuerPath: "/tenant", ThemeURL: themeURL, Brand: brand})
			},
		},
		{
			name: "profilePage",
			render: func(b *strings.Builder) error {
				return profilePage.Execute(b, profilePageData{IssuerPath: "/tenant", ThemeURL: themeURL, Brand: brand})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			if err := tc.render(&out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
				if !strings.Contains(body, want) {
					t.Fatalf("missing %q in %s", want, body)
				}
			}
		})
	}

	h := testHandler(t)
	h.issuer = "https://id.example/tenant"
	h.fedcmEnabled = true
	h.SetThemeURLResolver(func(context.Context, string) (string, error) {
		return "/tenant/auth/v1/theme/acme/2", nil
	})
	h.SetLoginBrandingResolver(func(context.Context, string) (LoginBranding, error) {
		return LoginBranding{Name: "Acme ID", LogoURL: "/tenant/auth/v1/clients/acme/logo?v=1"}, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/tenant/auth/fedcm/login", nil)
	r.RemoteAddr = "198.51.100.14:1234"
	w := httptest.NewRecorder()
	h.FedCMLanding(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatalf("status=%d csp=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("fedcm missing %q in %s", want, w.Body.String())
		}
	}

	successW := httptest.NewRecorder()
	h.writeFedCMSuccess(successW, r)
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(successW.Body.String(), want) {
			t.Fatalf("fedcm success missing %q in %s", want, successW.Body.String())
		}
	}

	otpW := httptest.NewRecorder()
	h.renderOTPStepUp(otpW, r, oauth.AuthorizationRequest{ClientID: "c1", RedirectURI: "https://app.example/cb"}, http.StatusOK)
	if !strings.Contains(otpW.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatalf("otp csp=%q", otpW.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(otpW.Body.String(), want) {
			t.Fatalf("otp missing %q in %s", want, otpW.Body.String())
		}
	}

	profileW := httptest.NewRecorder()
	h.renderProfilePage(profileW, r, http.StatusOK, "https://app.example/cb", "c1", "tok", "csrf", "en", "", nil)
	if !strings.Contains(profileW.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatalf("profile csp=%q", profileW.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(profileW.Body.String(), want) {
			t.Fatalf("profile missing %q in %s", want, profileW.Body.String())
		}
	}

	hFail := testHandler(t)
	hFail.SetThemeURLResolver(func(context.Context, string) (string, error) {
		return "", errors.New("unavailable")
	})
	failW := httptest.NewRecorder()
	hFail.renderProfilePage(failW, r, http.StatusOK, "https://app.example/cb", "c1", "tok", "csrf", "en", "", nil)
	if failW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on profile theme failure, got %d", failW.Code)
	}
}
