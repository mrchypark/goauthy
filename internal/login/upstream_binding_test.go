package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/rhiza"
)

func TestCompleteUpstreamAuthenticationCreatesBoundReplacementSession(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	init, _, interactionDigest := externalAuthorization(t, h)
	initial, err := h.browser.LoadSession(context.Background(), init.Value)
	if err != nil {
		t.Fatal(err)
	}
	binding := browser.UpstreamSessionBinding{
		Issuer:    "https://upstream.example.test",
		ClientID:  "goauthy-client",
		Subject:   "upstream-user",
		SessionID: "upstream-session",
	}

	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", &binding)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusSeeOther || location.Query().Get("code") == "" {
		t.Fatalf("completion status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == init.Value {
		t.Fatalf("replacement cookies=%#v", cookies)
	}
	replacement, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil || replacement.AuthenticationMethod != "external" || replacement.ID == initial.ID {
		t.Fatalf("replacement=%#v initial=%#v err=%v", replacement, initial, err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT session_digest, issuer, client_id, upstream_subject, upstream_sid FROM browser_upstream_session_bindings`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 5 || rows.Rows[0][0] != replacement.ID || rows.Rows[0][0] == initial.ID || rows.Rows[0][1] != binding.Issuer || rows.Rows[0][2] != binding.ClientID || rows.Rows[0][3] != binding.Subject || rows.Rows[0][4] != binding.SessionID {
		t.Fatalf("upstream binding rows=%#v replacement=%#v initial=%#v err=%v", rows.Rows, replacement, initial, err)
	}
}

func TestCompleteUpstreamAuthenticationBindingFailurePublishesNothing(t *testing.T) {
	h := testHandler(t)
	init, _, interactionDigest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", &browser.UpstreamSessionBinding{
		Issuer:   "https://upstream.example.test",
		ClientID: "goauthy-client",
	})
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("failed binding status=%d location=%q cookies=%q", response.Code, response.Header().Get("Location"), response.Header().Get("Set-Cookie"))
	}
}

func TestCompleteUpstreamAuthenticationMFAPassedSatisfiesForceMFA(t *testing.T) {
	h, db := testHandlerWithDB(t, true) // ForceMFA=true
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
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusSeeOther || location.Query().Get("code") == "" {
		t.Fatalf("mfa-passed forceMFA completion status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == init.Value {
		t.Fatalf("mfa-passed cookies=%#v", cookies)
	}
	replacement, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil || replacement.AuthenticationMethod != "mfa" {
		t.Fatalf("mfa-passed replacement=%#v err=%v", replacement, err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         "SELECT session_digest, issuer, client_id, upstream_subject, upstream_sid FROM browser_upstream_session_bindings",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 5 || rows.Rows[0][0] != replacement.ID || rows.Rows[0][1] != binding.Issuer || rows.Rows[0][2] != binding.ClientID || rows.Rows[0][3] != binding.Subject || rows.Rows[0][4] != binding.SessionID {
		t.Fatalf("mfa-passed binding rows=%#v err=%v", rows.Rows, err)
	}
}

func TestCompleteUpstreamAuthenticationMFAPassedFalseRejectsForceMFA(t *testing.T) {
	h := testHandlerWithForceMFA(t)
	init, _, interactionDigest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", &browser.UpstreamSessionBinding{
		Issuer:    "https://upstream.example.test",
		ClientID:  "goauthy-client",
		Subject:   "upstream-user",
		SessionID: "upstream-sid",
		MFAPassed: false,
	})
	if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("mfa-false forceMFA status=%d location=%q cookies=%q", response.Code, response.Header().Get("Location"), response.Header().Get("Set-Cookie"))
	}
}

func TestCompleteUpstreamAuthenticationNilBindingRejectsForceMFA(t *testing.T) {
	h := testHandlerWithForceMFA(t)
	init, _, interactionDigest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, interactionDigest, "user-1", nil)
	if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("nil-binding forceMFA status=%d location=%q cookies=%q", response.Code, response.Header().Get("Location"), response.Header().Get("Set-Cookie"))
	}
}
