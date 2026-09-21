package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

const testHandoffID = "AAAAAAAAAAAAAAAAAAAAAAAA"

func handoffLoginPage(t *testing.T, h *Handler, rawQuery string) (*httptest.ResponseRecorder, *http.Cookie, string, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/account/connection-login?"+rawQuery, nil)
	r.RemoteAddr = "203.0.113.8:1234"
	w := httptest.NewRecorder()
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body.String())
	}
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("missing handoff form fields body=%s cookies=%#v", w.Body.String(), w.Result().Cookies())
	}
	return w, w.Result().Cookies()[0], interaction[1], csrf[1]
}

func TestConnectionHandoffLoginAuthenticatesAndRedirectsWithoutApproval(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page, cookie, interaction, csrf := handoffLoginPage(t, h, "handoff_id="+testHandoffID)
	if page.Header().Get("Cache-Control") != "no-store" || page.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers=%#v", page.Header())
	}
	if strings.Contains(page.Body.String(), "Device sign in") || strings.Contains(page.Body.String(), "code from your device") {
		t.Fatalf("connection handoff used device-login copy: %s", page.Body.String())
	}
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {"alice"}, "password": {"correct password"}}
	r := httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
	want := "http://localhost/account/connection-handoffs/" + testHandoffID
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
		t.Fatalf("POST status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 || w.Result().Cookies()[0].Value == cookie.Value {
		t.Fatal("session was not rotated")
	}
	// The login boundary only redirects to review; it cannot approve the ticket.
	if strings.Contains(w.Body.String(), "approved") {
		t.Fatal("login response approved handoff")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost")
	r.AddCookie(cookie)
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("replay status=%d", w.Code)
	}
}

func TestConnectionHandoffLoginRejectsBadQueriesCSRFAndForcedMFA(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	for _, raw := range []string{"handoff_id=" + testHandoffID + "&handoff_id=" + testHandoffID, "handoff_id=" + testHandoffID + "&extra=1", "handoff_id=AAAA", "handoff_id=" + testHandoffID + "="} {
		r := httptest.NewRequest(http.MethodGet, "/account/connection-login?"+raw, nil)
		r.RemoteAddr = "203.0.113.8:1234"
		w := httptest.NewRecorder()
		h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q status=%d", raw, w.Code)
		}
	}
	for _, name := range []string{"authorization", "raw path"} {
		r := httptest.NewRequest(http.MethodGet, "/account/connection-login?handoff_id="+testHandoffID, nil)
		r.RemoteAddr = "203.0.113.8:1234"
		if name == "authorization" {
			r.Header.Set("Authorization", "Bearer token")
		} else {
			r.URL.RawPath = r.URL.Path
		}
		w := httptest.NewRecorder()
		h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s status=%d", name, w.Code)
		}
	}
	forceQuery := httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(""))
	forceQuery.URL.ForceQuery = true
	w := httptest.NewRecorder()
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, forceQuery)
	if w.Code != http.StatusForbidden {
		t.Fatalf("force-query status=%d", w.Code)
	}
	_, cookie, interaction, _ := handoffLoginPage(t, h, "handoff_id="+testHandoffID)
	form := url.Values{"interaction": {interaction}, "csrf_token": {"wrong"}, "username": {"alice"}, "password": {"correct password"}}
	r := httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("csrf status=%d", w.Code)
	}

	force := testHandlerWithForceMFA(t)
	_, cookie, interaction, csrf := handoffLoginPage(t, force, "handoff_id="+testHandoffID)
	form.Set("interaction", interaction)
	form.Set("csrf_token", csrf)
	r = httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	force.ConnectionHandoffLoginHandler(true).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forced MFA status=%d", w.Code)
	}
}

func TestConnectionHandoffLoginRejectsDeviceInteractionPurpose(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	w := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, get)
	cookie := w.Result().Cookies()[0]
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/account/connection-login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://localhost")
	post.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ConnectionHandoffLoginHandler(false).ServeHTTP(w, post)
	if w.Code != http.StatusForbidden {
		t.Fatalf("purpose mix-up status=%d", w.Code)
	}
}
