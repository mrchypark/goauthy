package device

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/browser"
)

func TestElyDevicePagePreservesNativeDecision(t *testing.T) {
	for _, review := range []*Review{nil, {ClientID: "client<script>"}} {
		var out bytes.Buffer
		if err := verificationPage.Execute(&out, verificationPageData{BasePath: "/tenant", UserCode: "CODE", CSRFToken: "csrf", Review: review}); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		for _, want := range []string{`/tenant/auth/v1/ui/`, `data-slot="input"`, `data-slot="button"`, `name="user_code"`, `action="verify"`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
		if strings.Contains(body, "<script") || strings.Contains(body, "hx-") {
			t.Fatal("script or enhanced submission added")
		}
		if review != nil {
			for _, want := range []string{`method="post"`, `name="csrf_token" value="csrf"`, `name="action" value="approve"`, `name="action" value="deny"`, `value="CODE" required readonly`, `client&lt;script&gt;`} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %s", want)
				}
			}
		}
	}
}

func TestDeviceVerificationPageCommonBrand(t *testing.T) {
	issuerURL, _ := url.Parse("https://id.example/tenant")
	h := &Handler{
		issuer: issuerURL,
		subject: func(*http.Request) (AuthenticatedSubject, bool) {
			return AuthenticatedSubject{
				Session: browser.Session{ID: "sess-1", Subject: "user-1", AuthenticationMethod: "pwd"},
				SessionGuard: func() (string, []any) {
					return "SELECT 1", nil
				},
			}, true
		},
	}
	h.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: "Acme ID", LogoURL: "/auth/v1/clients/acme/logo?v=1", ThemeURL: "/auth/v1/theme/acme/2"}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/oidc/device/verify", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
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
	h.ServeHTTP(wDefault, req)
	if wDefault.Code != http.StatusOK || !strings.Contains(wDefault.Body.String(), `<span>GoAuthy</span>`) {
		t.Fatalf("expected GoAuthy fallback status=%d body=%s", wDefault.Code, wDefault.Body.String())
	}
}
