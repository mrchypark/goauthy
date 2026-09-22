package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oauth"
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

func TestApprovalEntryPagesCompleteOTP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, entry, action, destination string }{
		{"device", "/oidc/device/login?user_code=AB12-CD34", "/oidc/device/login", "/oidc/device/verify?user_code=AB12CD34"},
		{"handoff", "/account/connection-login?handoff_id=" + testHandoffID, "/account/connection-login", "/account/connection-handoffs/" + testHandoffID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db := testHandlerWithDB(t, false)
			configuredPasskeys := h.passkeys
			service, _ := testOTPStepUp(t, h, db)
			h.passkeys = configuredPasskeys
			ctx := context.Background()
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "entry-otp-profile", SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username) VALUES('user-1','alice@example.test',1,'alice')"}); err != nil {
				t.Fatal(err)
			}
			handler := h.DeviceLoginHandler(true)
			if tc.name == "handoff" {
				handler = h.ConnectionHandoffLoginHandler(true)
			}
			page := httptest.NewRecorder()
			handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, tc.entry, nil))
			if page.Code != http.StatusOK {
				t.Fatalf("entry=%d %s", page.Code, page.Body.String())
			}
			token := interactionToken(t, page.Body.String())
			csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
			if len(csrf) != 2 {
				t.Fatal("missing csrf")
			}
			cookie := page.Result().Cookies()[0]
			form := url.Values{"interaction": {token}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
			post := httptest.NewRequest(http.MethodPost, tc.action, strings.NewReader(form.Encode()))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", h.issuer)
			post.AddCookie(cookie)
			step := httptest.NewRecorder()
			handler.ServeHTTP(step, post)
			if step.Code != http.StatusOK || !strings.Contains(step.Body.String(), `name="code"`) || len(step.Result().Cookies()) != 0 {
				t.Fatalf("step=%d %s", step.Code, step.Body.String())
			}
			code, err := service.GenerateOTP(ctx, "user-1")
			if err != nil {
				t.Fatal(err)
			}
			result := httptest.NewRecorder()
			h.OTPVerify(result, postOTPForm(cookie, code))
			if result.Code != http.StatusSeeOther || result.Header().Get("Location") != h.issuer+tc.destination {
				t.Fatalf("finish=%d %q %s", result.Code, result.Header().Get("Location"), result.Body.String())
			}
			session, err := h.browser.LoadSession(ctx, result.Result().Cookies()[0].Value)
			if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "mfa" {
				t.Fatalf("session=%+v err=%v", session, err)
			}
		})
	}
}

func TestApprovalEntryOffersSharedPasskeyAndUpstreamMethods(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.SetUpstreamProviderCatalog(func(context.Context) ([]UpstreamProvider, error) {
		return []UpstreamProvider{{ID: "upstream", Name: "Company login", CallbackURI: "http://localhost/upstream/upstream/callback"}}, nil
	})
	for _, tc := range []struct {
		entry   string
		handler http.Handler
	}{
		{"/oidc/device/login?user_code=AB12CD34", h.DeviceLoginHandler(true)},
		{"/account/connection-login?handoff_id=" + testHandoffID, h.ConnectionHandoffLoginHandler(true)},
	} {
		page := httptest.NewRecorder()
		tc.handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, tc.entry, nil))
		body := page.Body.String()
		for _, want := range []string{`id="passkey-btn"`, `document.getElementById('login-form')`, `/auth/v1/users/webauthn_start`, `/auth/v1/users/webauthn_finish`, `/upstream/upstream/start?`} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %s", tc.entry, want)
			}
		}
		r := httptest.NewRequest(http.MethodGet, "/upstream/upstream/start", nil)
		r.AddCookie(page.Result().Cookies()[0])
		_, _, _, err := h.PrepareExternalAuthentication(r, interactionToken(t, body))
		if err != nil {
			t.Fatalf("%s external preparation: %v", tc.entry, err)
		}
	}
}

func TestApprovalOTPSelectionDoesNotMaskInvalidPasskeyState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, handle string
		status       int
	}{
		{"no eligible credential", strings.Repeat("A", 43), http.StatusOK},
		{"corrupt user handle", strings.Repeat("!", 43), http.StatusNotAcceptable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db := testHandlerWithDB(t, false)
			configuredPasskeys := h.passkeys
			_, delivered := testOTPStepUp(t, h, db)
			h.passkeys = configuredPasskeys
			ctx := context.Background()
			for i, statement := range []struct {
				SQL  string
				Args []any
			}{
				{SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username) VALUES('user-1','alice@example.test',1,'alice')"},
				{SQL: "INSERT INTO identity_webauthn_users(subject,user_handle,created_at_unix_ms) VALUES('user-1',?,0)", Args: []any{tc.handle}},
			} {
				_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("selection-%d", i), SQL: statement.SQL, Args: statement.Args})
				if err != nil {
					t.Fatal(err)
				}
			}
			cookie, token := approvalInteraction(t, h, approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID, ForceMFA: true})
			result := httptest.NewRecorder()
			h.Login(result, postLogin(cookie, token, "alice", "correct password"))
			if result.Code != tc.status || len(result.Result().Cookies()) != 0 {
				t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
			}
			select {
			case <-delivered:
				if tc.status != http.StatusOK {
					t.Fatal("invalid passkey state fell back to OTP")
				}
			default:
				if tc.status == http.StatusOK {
					t.Fatal("missing OTP delivery")
				}
			}
		})
	}
}

func TestApprovalPolicyRejectionDoesNotConsumeInteraction(t *testing.T) {
	t.Parallel()
	for _, byDigest := range []bool{false, true} {
		t.Run(fmt.Sprintf("digest=%t", byDigest), func(t *testing.T) {
			h := testHandler(t)
			cookie, token := approvalInteraction(t, h, approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID})
			h.SetApprovalForceMFA(true)
			r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
			r.AddCookie(cookie)
			finish := func(w http.ResponseWriter, method string) {
				if byDigest {
					digest, err := browser.CanonicalTokenDigest(token)
					if err != nil {
						t.Fatal(err)
					}
					h.completeAuthenticationByDigest(w, r, cookie.Value, digest, "user-1", method, nil)
				} else {
					h.completeAuthentication(w, r, cookie.Value, token, "user-1", method, nil)
				}
			}
			weak := httptest.NewRecorder()
			finish(weak, "pwd")
			if weak.Code != http.StatusForbidden || len(weak.Result().Cookies()) != 0 {
				t.Fatalf("weak=%d", weak.Code)
			}
			if _, err := h.browser.LoadAuthorizationInteractionReadOnly(r.Context(), cookie.Value, token); err != nil {
				t.Fatalf("policy rejection consumed continuation: %v", err)
			}
			strong := httptest.NewRecorder()
			finish(strong, "mfa")
			if strong.Code != http.StatusSeeOther || strong.Header().Get("Location") != h.issuer+"/account/connection-handoffs/"+testHandoffID {
				t.Fatalf("strong=%d %s", strong.Code, strong.Body.String())
			}
			replay := httptest.NewRecorder()
			finish(replay, "mfa")
			if replay.Code != http.StatusForbidden {
				t.Fatalf("replay=%d", replay.Code)
			}
		})
	}
}

func TestDeviceReauthenticationBindsOriginalSubjectAndSession(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "other subject", "revoked parent", "upstream parent"} {
		t.Run(mode, func(t *testing.T) {
			h, db := testHandlerWithDB(t, false)
			service, delivered := testOTPStepUp(t, h, db)
			ctx := context.Background()
			hash, err := testHash(ctx, []byte("correct password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.identity.BootstrapUser(ctx, "user-2", "bob", hash); err != nil {
				t.Fatal(err)
			}
			if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "reauth-profiles", SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username) VALUES('user-1','alice@example.test',1,'alice'),('user-2','bob@example.test',1,'bob')"}); err != nil {
				t.Fatal(err)
			}
			entry := httptest.NewRequest(http.MethodGet, "/oidc/device/verify?user_code=AB12CD34", nil)
			peer, _ := h.resolvePeerIP(entry)
			parent, err := h.browser.CreateSession(ctx, "user-1", "pwd", h.now().Add(time.Hour), peer)
			if mode == "upstream parent" {
				parent, err = h.browser.CreateUpstreamSession(ctx, "user-1", browser.UpstreamSessionBinding{Issuer: "https://upstream.example.test", ClientID: "client-1", Subject: "external-alice", SessionID: "sid-1"}, "external", h.now().Add(time.Hour), peer)
			}
			if err != nil {
				t.Fatal(err)
			}
			parentCookie, err := browser.SessionCookie(h.issuer, parent.Token, parent.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			entry.AddCookie(parentCookie)
			page := httptest.NewRecorder()
			h.DeviceReviewReauthentication(page, entry, "AB12-CD34")
			if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
				t.Fatalf("entry=%d %s", page.Code, page.Body.String())
			}
			cookie := page.Result().Cookies()[0]
			if cookie.Value == parent.Token {
				t.Fatal("reauthentication reused authenticated session")
			}
			token := interactionToken(t, page.Body.String())
			csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
			if len(csrf) != 2 {
				t.Fatal("missing csrf")
			}
			username := "alice"
			if mode == "other subject" {
				username = "bob"
			}
			form := url.Values{"interaction": {token}, "csrf_token": {csrf[1]}, "username": {username}, "password": {"correct password"}}
			post := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.AddCookie(cookie)
			step := httptest.NewRecorder()
			h.DeviceLoginHandler(false).ServeHTTP(step, post)
			if mode == "other subject" {
				if step.Code != http.StatusForbidden || len(step.Result().Cookies()) != 0 {
					t.Fatalf("subject swap=%d", step.Code)
				}
				select {
				case <-delivered:
					t.Fatal("sent second factor for wrong subject")
				default:
				}
				return
			}
			if step.Code != http.StatusOK || len(step.Result().Cookies()) != 0 {
				t.Fatalf("step=%d %s", step.Code, step.Body.String())
			}
			code, err := service.GenerateOTP(ctx, "user-1")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "revoked parent" {
				if err = h.browser.RevokeSessionID(ctx, parent.ID); err != nil {
					t.Fatal(err)
				}
			}
			end := httptest.NewRecorder()
			h.OTPVerify(end, postOTPForm(cookie, code))
			if mode == "revoked parent" {
				if end.Code != http.StatusForbidden || len(end.Result().Cookies()) != 0 {
					t.Fatalf("revoked parent completed=%d %s", end.Code, end.Body.String())
				}
				return
			}
			if end.Code != http.StatusSeeOther || end.Header().Get("Location") != h.issuer+"/oidc/device/verify?user_code=AB12CD34" {
				t.Fatalf("end=%d %s", end.Code, end.Body.String())
			}
			session, err := h.browser.LoadSession(ctx, end.Result().Cookies()[0].Value)
			if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "mfa" {
				t.Fatalf("session=%+v err=%v", session, err)
			}
			if _, err = h.browser.LoadSession(ctx, parent.Token); !errors.Is(err, browser.ErrRevoked) {
				t.Fatalf("old parent remained active: %v", err)
			}
			if mode == "upstream parent" {
				if err := h.oauth.RevokeUpstreamSessions(ctx, oauth.UpstreamLogout{Issuer: "https://upstream.example.test", ClientID: "client-1", Subject: "external-alice", SessionID: "sid-1", JTI: "reauth-logout", TokenDigest: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
					t.Fatal(err)
				}
				if _, err := h.browser.LoadSession(ctx, end.Result().Cookies()[0].Value); !errors.Is(err, browser.ErrRevoked) {
					t.Fatalf("upstream logout missed replacement: %v", err)
				}
			}
		})
	}
}
