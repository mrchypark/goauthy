package device

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
)

// The originating session does not own the grant decision. Another live,
// authenticated approver session may decide it. headerSubject models those
// independent approver identities for the handler contract tests.
func headerSubject(r *http.Request) (AuthenticatedSubject, bool) {
	subject := "user-1"
	if subject := r.Header.Get("X-Test-Subject"); subject != "" {
		return testApprover(subject, false), true
	}
	return testApprover(subject, false), true
}

func testApprover(subject string, mfa bool) AuthenticatedSubject {
	authMethod := "pwd"
	if mfa {
		authMethod = "mfa"
	}
	return AuthenticatedSubject{
		Session:      browser.Session{ID: "test-session-" + subject, Subject: subject, AuthenticationMethod: authMethod},
		SessionGuard: func() (string, []any) { return "1=1", nil },
	}
}

func decisionForm(grant Grant, cookie *http.Cookie, csrf, action, subject, peer string) *http.Request {
	r := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {action}})
	r.AddCookie(cookie)
	r.Header.Set("X-Test-Subject", subject)
	r.RemoteAddr = peer
	return r
}

// A second authenticated subject holding the reviewed-device cookie and the
// user code decides a grant started elsewhere, and becomes the grant subject.
func TestDeviceDecisionContractSecondSubjectBecomesGrantSubject(t *testing.T) {
	ctx, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, headerSubject)
	grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	// user-1 reviews the code and holds the cookie; user-2 decides with it.
	cookie, csrf := verificationCSRF(t, h, grant.UserCode)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, decisionForm(grant, cookie, csrf, "approve", "user-2", "192.0.2.80:4000"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Device approved") {
		t.Fatalf("cross-subject approve=%d %s", w.Code, w.Body.String())
	}
	poll, err := store.Poll(ctx, grant.DeviceCode, "client-1", deviceHTTPTestNow)
	if err != nil || poll.Status != StatusClaimed || poll.Subject != "user-2" {
		t.Fatalf("poll=%+v err=%v", poll, err)
	}
	row, found, err := store.load(ctx, digest(grant.DeviceCode), "client-1")
	if err != nil || !found || row.state != "approved" || row.subject != "user-2" {
		t.Fatalf("row=%+v found=%v err=%v", row, found, err)
	}
}

// The verification quota is charged to the authenticated approver subject, so
// exhausting one subject's budget from a peer does not block another subject
// from the same peer.
func TestDeviceDecisionContractRateLimitChargedToApproverSubject(t *testing.T) {
	ctx, store, _ := testStore(t)
	h, err := NewHandlerWithLimits(store, "https://id.example.test", func(*http.Request, string, []string) error { return nil }, headerSubject, Limits{Window: time.Minute, VerificationLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return deviceHTTPTestNow }
	const peer = "192.0.2.70:4000"
	first, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	firstCookie, firstCSRF := verificationCSRF(t, h, first.UserCode, peer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, decisionForm(first, firstCookie, firstCSRF, "approve", "user-1", peer))
	if w.Code != http.StatusOK {
		t.Fatalf("first approve=%d", w.Code)
	}
	// The review lookup shares the same quota value but its own key, so read the
	// second code from another peer to reach the decision limit under test.
	secondCookie, secondCSRF := verificationCSRF(t, h, second.UserCode, "192.0.2.71:4000")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, decisionForm(second, secondCookie, secondCSRF, "approve", "user-1", peer))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted subject=%d", w.Code)
	}
	row, found, err := store.load(ctx, digest(second.DeviceCode), "client-1")
	if err != nil || !found || row.state != "pending" {
		t.Fatalf("blocked decision changed the grant: row=%+v found=%v err=%v", row, found, err)
	}
	// Same peer and the same reviewed cookie, different authenticated subject.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, decisionForm(second, secondCookie, secondCSRF, "approve", "user-2", peer))
	if w.Code != http.StatusOK {
		t.Fatalf("second subject approve=%d", w.Code)
	}
	poll, err := store.Poll(ctx, second.DeviceCode, "client-1", deviceHTTPTestNow)
	if err != nil || poll.Status != StatusClaimed || poll.Subject != "user-2" {
		t.Fatalf("poll=%+v err=%v", poll, err)
	}
}

// A denial records no subject even though the approver is authenticated.
func TestDeviceDecisionContractDenyRecordsNoSubject(t *testing.T) {
	ctx, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, headerSubject)
	grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := verificationCSRF(t, h, grant.UserCode)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, decisionForm(grant, cookie, csrf, "deny", "user-2", "192.0.2.90:4000"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Device denied") {
		t.Fatalf("deny=%d %s", w.Code, w.Body.String())
	}
	poll, err := store.Poll(ctx, grant.DeviceCode, "client-1", deviceHTTPTestNow)
	if err != nil || poll.Status != StatusDenied || poll.Subject != "" {
		t.Fatalf("poll=%+v err=%v", poll, err)
	}
	row, found, err := store.load(ctx, digest(grant.DeviceCode), "client-1")
	if err != nil || !found || row.state != "denied" || row.subject != "" {
		t.Fatalf("row=%+v found=%v err=%v", row, found, err)
	}
}

// Revocation after authentication but before persistence fences both decision
// kinds. The grant starter is not the approver, so this guard binds only the
// session that authenticated the current decision request.
func TestDeviceDecisionRejectsSessionRevokedBeforePersistence(t *testing.T) {
	ctx, store, db := testStore(t)
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	const testPHC = "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY"
	if _, err := identities.BootstrapUser(ctx, "device-session-actor", "device-session-actor", testPHC); err != nil {
		t.Fatal(err)
	}
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	cookieName, err := browser.CookieName("https://id.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			session, err := browserStore.CreateSession(ctx, "device-session-actor", "pwd", time.Now().UTC().Add(time.Hour), "192.0.2.80")
			if err != nil {
				t.Fatal(err)
			}
			authenticated := make(chan struct{})
			continueDecision := make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(continueDecision) })
			subject := func(r *http.Request) (AuthenticatedSubject, bool) {
				cookie, err := r.Cookie(cookieName)
				if err != nil {
					return AuthenticatedSubject{}, false
				}
				peerIP := browser.PeerIPFromContext(r.Context())
				loaded, err := browserStore.LoadSessionReadOnlyForPeer(r.Context(), cookie.Value, peerIP)
				if err != nil || loaded.Subject == "" {
					return AuthenticatedSubject{}, false
				}
				if r.Method == http.MethodPost {
					close(authenticated)
					<-continueDecision
				}
				return AuthenticatedSubject{
					Session: loaded,
					SessionGuard: func() (string, []any) {
						return browserStore.SessionAuthorizationGuard(loaded, peerIP)
					},
				}, true
			}
			h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, subject)
			grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			csrfCookie, err := csrfToken()
			if err != nil {
				t.Fatal(err)
			}
			request := decisionForm(grant, &http.Cookie{Name: h.csrfCookieName(), Value: csrfCookie}, reviewedDeviceCSRF(csrfCookie, grant.UserCode), action, "", "192.0.2.80:4000")
			request.AddCookie(&http.Cookie{Name: cookieName, Value: session.Token})
			request = request.WithContext(browser.ContextWithPeerIP(request.Context(), "192.0.2.80"))
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request)
				response <- w
			}()
			select {
			case <-authenticated:
			case <-time.After(5 * time.Second):
				t.Fatal("browser-session authentication did not reach the interposition point")
			}
			if err := browserStore.RevokeSession(ctx, session.Token); err != nil {
				t.Fatal(err)
			}
			if _, err := browserStore.LoadSessionReadOnlyForPeer(ctx, session.Token, "192.0.2.80"); !errors.Is(err, browser.ErrRevoked) {
				t.Fatalf("session after revoke=%v", err)
			}
			release.Do(func() { close(continueDecision) })
			w := <-response
			if w.Code != http.StatusBadRequest {
				t.Fatalf("decision after session revoke=%d %s", w.Code, w.Body.String())
			}
			row, found, err := store.load(ctx, digest(grant.DeviceCode), "client-1")
			if err != nil || !found || row.state != "pending" || row.subject != "" {
				t.Fatalf("revoked session changed grant: row=%+v found=%v err=%v", row, found, err)
			}
		})
	}
}
