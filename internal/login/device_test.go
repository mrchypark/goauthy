package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestDeviceLoginHandoffRotatesSessionAndRedirects(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=ab12-cd34", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	response := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(response, get)
	if response.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing init cookie")
	}
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 {
		t.Fatal("missing handoff fields")
	}
	form := url.Values{"interaction": {interaction[1]}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://localhost")
	post.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(response, post)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "http://localhost/oidc/device/verify?user_code=AB12CD34" {
		t.Fatalf("POST status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if len(response.Result().Cookies()) == 0 || response.Result().Cookies()[0].Value == cookies[0].Value {
		t.Fatal("session was not rotated")
	}
	post = httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(response, post)
	if response.Code != http.StatusForbidden {
		t.Fatalf("replay status=%d", response.Code)
	}
}

func TestDeviceLoginRejectsCSRFAndForcedPasswordDowngrade(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	response := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(response, get)
	cookie := response.Result().Cookies()[0]
	match := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 || len(csrf) != 2 {
		t.Fatal("missing fields")
	}
	form := url.Values{"interaction": {match[1]}, "csrf_token": {"wrong"}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	response = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(response, post)
	if response.Code != http.StatusForbidden {
		t.Fatalf("csrf status=%d", response.Code)
	}
	force := testHandlerWithForceMFA(t)
	get = httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	response = httptest.NewRecorder()
	force.DeviceLoginHandler(true).ServeHTTP(response, get)
	if response.Code != http.StatusOK {
		t.Fatalf("force GET status=%d", response.Code)
	}
	forceCookie := response.Result().Cookies()[0]
	forceMatch := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	forceCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(forceMatch) != 2 || len(forceCSRF) != 2 {
		t.Fatal("missing force-MFA form fields")
	}
	forceForm := url.Values{"interaction": {forceMatch[1]}, "csrf_token": {forceCSRF[1]}, "username": {"alice"}, "password": {"correct password"}}
	forcePost := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(forceForm.Encode()))
	forcePost.RemoteAddr = get.RemoteAddr
	forcePost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forcePost.AddCookie(forceCookie)
	response = httptest.NewRecorder()
	force.DeviceLoginHandler(true).ServeHTTP(response, forcePost)
	if response.Code != http.StatusNotAcceptable || len(response.Result().Cookies()) != 0 {
		t.Fatalf("unenrolled forced-MFA password POST status=%d", response.Code)
	}
}

func TestDeviceLoginRejectsMalformedOrDuplicateQueries(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	for _, raw := range []string{"user_code=AB12&user_code=CD34", "user_code=AB12&extra=1", "user_code=%ZZ", "user_code=AB%2F12"} {
		r := httptest.NewRequest(http.MethodGet, "/oidc/device/login?"+raw, nil)
		r.RemoteAddr = "203.0.113.8:1234"
		w := httptest.NewRecorder()
		h.DeviceLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q status=%d body=%s", raw, w.Code, w.Body.String())
		}
	}
}

func TestDeviceLoginFormActionDropsGETQueryAndBlankCodeRedirectsWithoutApproval(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, "/oidc/device/login", nil)
	get.RemoteAddr = "203.0.113.8:1234"
	w := httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/oidc/device/login"`) || strings.Contains(w.Body.String(), "user_code=") {
		t.Fatalf("blank-code form status=%d body=%s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 {
		t.Fatal("missing form interaction")
	}
	form := url.Values{"interaction": {interaction[1]}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/oidc/device/login?user_code=evil", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, post)
	if w.Code != http.StatusForbidden {
		t.Fatalf("post query status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	// A clean POST for a blank-code interaction redirects without inventing a code.
	post = httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, post)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "http://localhost/oidc/device/verify" {
		t.Fatalf("blank redirect status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}
