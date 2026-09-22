package login

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func approvalInteraction(t *testing.T, h *Handler, saved approvalLoginInteraction) (*http.Cookie, string) {
	t.Helper()
	payload, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/account/connection-login", nil)
	peer, ok := h.resolvePeerIP(r)
	if !ok {
		t.Fatal("peer")
	}
	interaction, _, cookie, err := h.createLoginInteraction(r, peer, payload)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, interaction.Token
}

func TestApprovalAuthenticationReturnsToReview(t *testing.T) {
	t.Parallel()
	code := "AB12CD34"
	for _, tc := range []struct {
		name  string
		saved approvalLoginInteraction
		path  string
	}{
		{"device", approvalLoginInteraction{Purpose: approvalLoginPayload, DeviceCode: &code}, "/oidc/device/verify?user_code=AB12CD34"},
		{"handoff", approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID}, "/account/connection-handoffs/" + testHandoffID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t)
			cookie, token := approvalInteraction(t, h, tc.saved)
			w := httptest.NewRecorder()
			h.Login(w, postLogin(cookie, token, "alice", "correct password"))
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != h.issuer+tc.path {
				t.Fatalf("status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			session, err := h.browser.LoadSession(context.Background(), w.Result().Cookies()[0].Value)
			if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "pwd" {
				t.Fatalf("session=%+v err=%v", session, err)
			}
			replay := httptest.NewRecorder()
			h.Login(replay, postLogin(cookie, token, "alice", "correct password"))
			if replay.Code != http.StatusForbidden || replay.Header().Get("Location") != "" {
				t.Fatalf("replay=%d", replay.Code)
			}
		})
	}
}

func TestApprovalOTPReturnsToReviewAndPreservesMFA(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, false)
	service, _ := testOTPStepUp(t, h, db)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "approval-otp-profile", SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username) VALUES('user-1','alice@example.test',1,'alice')"}); err != nil {
		t.Fatal(err)
	}
	cookie, token := approvalInteraction(t, h, approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID, ForceMFA: true})
	start := httptest.NewRecorder()
	h.Login(start, postLogin(cookie, token, "alice", "correct password"))
	if start.Code != http.StatusOK || len(start.Result().Cookies()) != 0 {
		t.Fatalf("premature authentication: %d %s", start.Code, start.Body.String())
	}
	code, err := service.GenerateOTP(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	end := httptest.NewRecorder()
	h.OTPVerify(end, postOTPForm(cookie, code))
	if end.Code != http.StatusSeeOther || end.Header().Get("Location") != h.issuer+"/account/connection-handoffs/"+testHandoffID {
		t.Fatalf("completion=%d %s", end.Code, end.Body.String())
	}
	session, err := h.browser.LoadSession(ctx, end.Result().Cookies()[0].Value)
	if err != nil || session.AuthenticationMethod != "mfa" || session.Subject != "user-1" {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	replay := httptest.NewRecorder()
	h.OTPVerify(replay, postOTPForm(cookie, code))
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replay=%d", replay.Code)
	}
}

func TestApprovalExternalCompletionRechecksDeploymentMFA(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	cookie, token := approvalInteraction(t, h, approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID})
	r := httptest.NewRequest(http.MethodGet, "/upstream/start", nil)
	r.AddCookie(cookie)
	_, _, digest, err := h.PrepareExternalAuthentication(r, token)
	if err != nil {
		t.Fatal(err)
	}
	h.SetApprovalForceMFA(true)
	denied := httptest.NewRecorder()
	h.CompleteExternalAuthentication(denied, r, cookie.Value, digest, "user-1")
	if denied.Code != http.StatusForbidden || len(denied.Result().Cookies()) != 0 {
		t.Fatalf("weak proof accepted: %d", denied.Code)
	}
	approved := httptest.NewRecorder()
	h.CompleteUpstreamAuthentication(approved, r, cookie.Value, digest, "user-1", &browser.UpstreamSessionBinding{Issuer: "https://upstream.example.test", ClientID: "goauthy-client", Subject: "upstream-user", SessionID: "upstream-session", MFAPassed: true})
	if approved.Code != http.StatusSeeOther || approved.Header().Get("Location") != h.issuer+"/account/connection-handoffs/"+testHandoffID {
		t.Fatalf("MFA completion=%d %s", approved.Code, approved.Body.String())
	}
}

func TestApprovalContinuationRejectsInvalidDestinations(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	for _, payload := range []string{
		`{"Purpose":"goauthy-approval-login/v1"}`,
		`{"Purpose":"goauthy-approval-login/v1","DeviceCode":"AB12","HandoffID":"AAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"Purpose":"goauthy-approval-login/v1","DeviceCode":"https://evil.test"}`,
		`{"Purpose":"goauthy-approval-login/v1","HandoffID":"AAAA"}`,
		`{"Purpose":"goauthy-approval-login/v1","DeviceCode":"AB12","return_url":"https://evil.test"}`,
		`{"Purpose":"goauthy-fedcm-login/v1","DeviceCode":"AB12"}`,
		`{"Purpose":"goauthy-approval-login/v1","DeviceCode":"AB12"}{}`,
	} {
		if _, err := h.resolveAuthenticationRequest(r, []byte(payload)); err == nil {
			t.Errorf("accepted %s", payload)
		}
	}
}
