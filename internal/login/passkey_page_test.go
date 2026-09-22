package login

import (
	"github.com/mrchypark/goauthy/internal/oauth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizeRendersPasskeyButtonWhenPasskeysEnabled(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, `id="passkey-btn"`) {
		t.Fatalf("passkey button missing from page")
	}
	if !strings.Contains(body, `id="passkey-error"`) {
		t.Fatalf("passkey error div missing from page")
	}
	if !strings.Contains(body, `role="status"`) {
		t.Fatalf("passkey error div missing role=status")
	}
	if !strings.Contains(body, `aria-live="polite"`) {
		t.Fatalf("passkey error div missing aria-live")
	}
	if !strings.Contains(body, `<script nonce="`) {
		t.Fatalf("passkey script missing nonce")
	}
	csp := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Fatalf("CSP missing script-src nonce: %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP missing connect-src self: %q", csp)
	}
}

func TestAuthorizePasskeyScriptCapturesStartJSON(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	body := page.Body.String()
	if !strings.Contains(body, "/auth/v1/users/webauthn_start") {
		t.Fatalf("script missing webauthn_start endpoint")
	}
	if !strings.Contains(body, "/auth/v1/users/webauthn_finish") {
		t.Fatalf("script missing webauthn_finish endpoint")
	}
	if !strings.Contains(body, "startJSON.rcr") {
		t.Fatalf("script missing startJSON.rcr reference")
	}
	if !strings.Contains(body, "rcr.publicKey") {
		t.Fatalf("script must use rcr.publicKey for challenge/allowCredentials, got: %q", body)
	}
	if !strings.Contains(body, "{publicKey:pk}") {
		t.Fatalf("script must pass {publicKey:pk} to navigator.credentials.get, got: %q", body)
	}
	if !strings.Contains(body, "navigator.credentials.get") {
		t.Fatalf("script missing navigator.credentials.get call")
	}
	if !strings.Contains(body, "credentials:'same-origin'") {
		t.Fatalf("script missing credentials:'same-origin'")
	}
	if strings.Contains(body, "Sec-Fetch-Site") {
		t.Fatalf("script should not set Sec-Fetch-Site header")
	}
	if strings.Contains(body, "new TextEncoder") {
		t.Fatalf("script should not contain unused TextEncoder")
	}
	if strings.Contains(body, "Array.from(new Uint8Array(assertion.response.") {
		t.Fatalf("response binary fields must be base64url strings, not numeric arrays")
	}
	if strings.Contains(body, "Array.from(new Uint8Array(assertion.rawId))") {
		t.Fatalf("rawId must be base64url string via toBase64URL, not numeric array")
	}
}

func TestAuthorizePasskeyNonceNotSetWhenPasskeysDisabled(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.passkeys = nil
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	body := page.Body.String()
	if strings.Contains(body, `id="passkey-btn"`) {
		t.Fatalf("passkey button rendered when passkeys disabled")
	}
	if strings.Contains(body, `<script nonce="`) {
		t.Fatalf("passkey script rendered when passkeys disabled")
	}
	csp := page.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "script-src") {
		t.Fatalf("CSP should not contain script-src when passkeys disabled: %q", csp)
	}
}

func TestAuthorizeCSPContainsBasePolicyWhenPasskeysEnabled(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	csp := page.Header().Get("Content-Security-Policy")
	basePolicy := authorizationFormCSP(authorizeValues().Get("redirect_uri"))
	if !strings.Contains(csp, basePolicy) {
		t.Fatalf("CSP should contain base policy: %q", csp)
	}
}

// Shared login rendering must not resolve authentication endpoints relative to
// the deeper Device/handoff URL; issuer prefixes must survive every method.
func TestLoginPageEndpointsDoNotDependOnEntryPath(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.issuer = "https://id.example.test/identity"
	for _, entry := range []string{"/identity/oidc/device/login", "/identity/account/connection-login"} {
		r := httptest.NewRequest(http.MethodGet, entry, nil)
		w := httptest.NewRecorder()
		h.renderLoginPage(w, r, oauth.AuthorizationRequest{ClientID: "review", RedirectURI: h.issuer}, "interaction", "")
		if w.Code != http.StatusOK {
			t.Fatalf("render: %d", w.Code)
		}
		body := w.Body.String()
		for _, endpoint := range []string{"/identity/auth/login", "/identity/auth/v1/users/webauthn_start", "/identity/auth/v1/users/webauthn_finish", "/identity/auth/v1/theme/global.css"} {
			if !strings.Contains(body, endpoint) {
				t.Fatalf("entry %s missing %s", entry, endpoint)
			}
		}
		if strings.Contains(body, "../auth/") {
			t.Fatalf("entry %s retained depth-dependent endpoints", entry)
		}
	}
}

func TestOTPStepUpEndpointsDoNotDependOnEntryPath(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.issuer = "https://id.example.test/identity"
	for _, entry := range []string{"/identity/auth/login", "/identity/oidc/device/login", "/identity/account/connection-login"} {
		r := httptest.NewRequest(http.MethodPost, entry, nil)
		w := httptest.NewRecorder()
		h.renderOTPStepUp(w, r, oauth.AuthorizationRequest{ClientID: "review", RedirectURI: h.issuer})
		if w.Code != http.StatusOK {
			t.Fatalf("render: %d", w.Code)
		}
		for _, endpoint := range []string{`action="/identity/auth/v1/users/otp/verify"`, `href="/identity/auth/v1/theme/global.css"`} {
			if !strings.Contains(w.Body.String(), endpoint) {
				t.Fatalf("entry %s missing %s", entry, endpoint)
			}
		}
	}
}
