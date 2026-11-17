package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/branding"
)

func TestResetHTMLNavigationDoesNotReplaceAPIBinding(t *testing.T) {
	t.Parallel()
	service, _ := testService(t, "subject-1", "alice")
	token, _, err := service.identity.IssuePasswordReset(context.Background(), "subject-1", passwordResetLifetime)
	if err != nil {
		t.Fatal(err)
	}
	wrongMethodHTML := httptest.NewRequest(http.MethodPost, "/auth/v1/users/subject-1/reset/unused", nil)
	wrongMethodHTML.Header.Set("Accept", "text/html")
	wrongMethodHTMLResponse := httptest.NewRecorder()
	service.GetReset(wrongMethodHTMLResponse, wrongMethodHTML)
	if wrongMethodHTMLResponse.Code != http.StatusMethodNotAllowed || wrongMethodHTMLResponse.Header().Get("Allow") != http.MethodGet || len(wrongMethodHTMLResponse.Result().Cookies()) != 0 {
		t.Fatal("HTML Accept bypassed the GET-only reset navigation")
	}
	crossSiteAPIRequest := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/unused", nil)
	crossSiteAPIRequest.SetPathValue("subject", "subject-1")
	crossSiteAPIRequest.SetPathValue("token", "unused")
	crossSiteAPIRequest.Header.Set("Sec-Fetch-Site", "cross-site")
	crossSiteAPIResponse := httptest.NewRecorder()
	service.GetReset(crossSiteAPIResponse, crossSiteAPIRequest)
	if crossSiteAPIResponse.Code != http.StatusForbidden || len(crossSiteAPIResponse.Result().Cookies()) != 0 {
		t.Fatal("cross-site JSON bootstrap was not rejected")
	}
	first := httptest.NewRecorder()
	apiRequest := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/"+token, nil)
	apiRequest.SetPathValue("subject", "subject-1")
	apiRequest.SetPathValue("token", token)
	service.GetReset(first, apiRequest)
	var bootstrap resetResponse
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &bootstrap) != nil {
		t.Fatal("JSON bootstrap failed")
	}
	request := httptest.NewRequest(http.MethodGet, service.issuer+"/auth/v1/users/subject-1/reset/"+token, nil)
	request.SetPathValue("subject", "subject-1")
	request.SetPathValue("token", token)
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response := httptest.NewRecorder()
	service.GetReset(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "reset-start") || len(response.Result().Cookies()) != 0 || strings.Contains(response.Body.String(), token) {
		t.Fatal("HTML navigation leaked or bound reset authority")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing sensitive page headers")
	}
	payload, err := json.Marshal(putReset{MagicLinkID: token, Password: "UpdatedPassword2"})
	if err != nil {
		t.Fatal(err)
	}
	crossSitePut := httptest.NewRequest(http.MethodPut, "/auth/v1/users/subject-1/reset", bytes.NewReader(payload))
	crossSitePut.Header.Set("Content-Type", "application/json")
	crossSitePut.Header.Set("Sec-Fetch-Site", "cross-site")
	crossSitePut.SetPathValue("subject", "subject-1")
	crossSitePut.Header.Set("X-Pwd-CSRF-Token", bootstrap.CSRFToken)
	crossSitePut.AddCookie(first.Result().Cookies()[0])
	crossSitePutResponse := httptest.NewRecorder()
	service.PutReset(crossSitePutResponse, crossSitePut)
	if crossSitePutResponse.Code != http.StatusForbidden {
		t.Fatal("cross-site password reset submission was not rejected")
	}
	// A scanner/navigation after JSON bootstrap must not invalidate its cookie.
	result := putResetRequest(t, service, "subject-1", putReset{MagicLinkID: token, Password: "UpdatedPassword2"}, first.Result().Cookies()[0], bootstrap.CSRFToken)
	if result.Code != http.StatusAccepted {
		t.Fatalf("binding replaced: %d", result.Code)
	}
	if _, err := service.identity.Authenticate(context.Background(), "alice", []byte("UpdatedPassword2")); err != nil {
		t.Fatal(err)
	}
}

func TestElyRecoveryControlsAndScripts(t *testing.T) {
	for _, mode := range []string{"request", "register", "reset"} {
		t.Run(mode, func(t *testing.T) {
			var out strings.Builder
			if err := recoveryPage.Execute(&out, recoveryPageData{Base: "/tenant", Mode: mode, Language: "ko"}); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			for _, want := range []string{`/tenant/auth/v1/ui/`, `data-slot="input"`, `data-slot="button"`, `/tenant/auth/v1/branding/locale.js`, `/tenant/auth/v1/users/recovery.js`} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %s", want)
				}
			}
			if strings.Count(body, "<script") != 2 || strings.Contains(body, "hx-") {
				t.Fatal("added script or enhanced submission")
			}
			if mode == "register" && !strings.Contains(body, `id="registration-input"`) {
				t.Fatal("dynamic inputs need Ely prototype")
			}
			if mode == "reset" {
				for _, want := range []string{`id="reset-form" hidden`, `name="password"`, `name="confirm"`, `autocomplete="new-password"`, `maxlength="256"`, `id="reset-start"`} {
					if !strings.Contains(body, want) {
						t.Errorf("missing %s", want)
					}
				}
			}
		})
	}
}

func TestRecoveryPagesAndRevokeCommonBrand(t *testing.T) {
	s := &Service{issuer: "https://id.example/tenant"}
	s.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: "Acme ID", LogoURL: "/auth/v1/clients/acme/logo?v=1", ThemeURL: "/auth/v1/theme/acme/2"}, nil
	})
	pageReq := httptest.NewRequest(http.MethodGet, "/auth/v1/users/password_reset", nil)
	pageW := httptest.NewRecorder()
	s.Page(pageW, pageReq)
	if !strings.Contains(pageW.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatalf("missing img-src 'self' in recovery CSP: %q", pageW.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{`Account recovery · Acme ID`, `href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`, `<footer class="auth-footer"><span>Acme ID</span>`} {
		if !strings.Contains(pageW.Body.String(), want) {
			t.Fatalf("missing %q in %s", want, pageW.Body.String())
		}
	}

	h := NewLoginRevokeHandlerWithBrand(nil, nil, func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: "Acme ID", LogoURL: "/auth/v1/clients/acme/logo?v=1", ThemeURL: "/auth/v1/theme/acme/2"}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/users/u1/revoke/c1?ip=192.0.2.1", nil)
	req.RequestURI = "/tenant/auth/v1/users/u1/revoke/c1?ip=192.0.2.1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	for _, want := range []string{`href="/tenant/auth/v1/theme/acme/2"`, `src="/tenant/auth/v1/clients/acme/logo?v=1"`, `alt="Acme ID"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %q in revoke page: %s", want, w.Body.String())
		}
	}
}
