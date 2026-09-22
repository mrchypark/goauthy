package device

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The device decision contract is fenced by grant state and grant expiry, not
// by the browser session that started the flow, so these tests drive one
// handler with more than one authenticated approver identity. headerSubject
// takes the approver from a test header and defaults to the identity that the
// shared verificationCSRF helper reviews with.
func headerSubject(r *http.Request) (string, bool, bool) {
	if subject := r.Header.Get("X-Test-Subject"); subject != "" {
		return subject, false, true
	}
	return "user-1", false, true
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
