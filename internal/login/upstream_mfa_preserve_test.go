package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
)

// TestCompleteUpstreamAuthenticationMFAPassedPreservesMFAWithoutForceMFA proves
// that verified upstream MFA is preserved in the session even when the current
// authorization request does not force MFA.
func TestCompleteUpstreamAuthenticationMFAPassedPreservesMFAWithoutForceMFA(t *testing.T) {
	h := testHandler(t) // ForceMFA=false
	init, _, interactionDigest := externalAuthorization(t, h)
	binding := browser.UpstreamSessionBinding{
		Issuer:    "https://upstream.example.test",
		ClientID:  "goauthy-client",
		Subject:   "upstream-user",
		SessionID: "upstream-session",
		MFAPassed: true,
	}
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", &binding)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want SeeOther", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v, want 1 cookie", cookies)
	}
	replacement, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if replacement.AuthenticationMethod != "mfa" {
		t.Fatalf("AuthenticationMethod=%q, want mfa", replacement.AuthenticationMethod)
	}
}

// TestCompleteUpstreamAuthenticationNilBindingWithoutForceMFAUsesExternal proves
// that a nil binding produces an "external" session when ForceMFA is false.
func TestCompleteUpstreamAuthenticationNilBindingWithoutForceMFAUsesExternal(t *testing.T) {
	h := testHandler(t) // ForceMFA=false
	init, _, interactionDigest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", nil)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want SeeOther", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v, want 1 cookie", cookies)
	}
	replacement, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if replacement.AuthenticationMethod != "external" {
		t.Fatalf("AuthenticationMethod=%q, want external", replacement.AuthenticationMethod)
	}
}

// TestCompleteUpstreamAuthenticationMFAPassedFalseWithoutForceMFAUsesExternal
// proves that MFAPassed=false with ForceMFA=false produces "external".
func TestCompleteUpstreamAuthenticationMFAPassedFalseWithoutForceMFAUsesExternal(t *testing.T) {
	h := testHandler(t) // ForceMFA=false
	init, _, interactionDigest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", &browser.UpstreamSessionBinding{
		Issuer:    "https://upstream.example.test",
		ClientID:  "goauthy-client",
		Subject:   "upstream-user",
		SessionID: "upstream-sid",
		MFAPassed: false,
	})
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want SeeOther", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v, want 1 cookie", cookies)
	}
	replacement, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if replacement.AuthenticationMethod != "external" {
		t.Fatalf("AuthenticationMethod=%q, want external", replacement.AuthenticationMethod)
	}
}
