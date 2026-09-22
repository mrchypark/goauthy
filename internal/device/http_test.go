package device

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var deviceHTTPTestNow = time.Unix(1_700_000_000, 0).UTC()

func TestDeviceAuthorizationHTTP(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(_ *http.Request, client string, scopes []string) error {
		if client != "client-1" || strings.Join(scopes, " ") != "openid goauthy.read" {
			return errors.New("no")
		}
		return nil
	}, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, formRequest(http.MethodPost, deviceAuthorizationPath, url.Values{"client_id": {"client-1"}, "scope": {"openid goauthy.read"}}))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	var got struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.DeviceCode == "" || got.UserCode == "" || got.VerificationURI != "https://id.example.test/oidc/device/verify" || got.ExpiresIn < 1 || got.Interval != 5 {
		t.Fatalf("response=%+v", got)
	}
	u, err := url.Parse(got.VerificationURIComplete)
	if err != nil || u.Query().Get("user_code") != got.UserCode {
		t.Fatalf("complete=%q err=%v", got.VerificationURIComplete, err)
	}
}

func TestDeviceAuthorizationRejectsUntrustedInputAndPaths(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, nil)
	valid := url.Values{"client_id": {"client-1"}, "scope": {"openid"}}
	for _, tt := range []struct {
		name, method, path, typ string
		form                    url.Values
		want                    int
	}{
		{"wrong method", http.MethodGet, deviceAuthorizationPath, "", valid, 404},
		{"wrong subtree", http.MethodPost, deviceAuthorizationPath + "/x", "application/x-www-form-urlencoded", valid, 404},
		{"query", http.MethodPost, deviceAuthorizationPath + "?x=1", "application/x-www-form-urlencoded", valid, 400},
		{"content type", http.MethodPost, deviceAuthorizationPath, "text/plain", valid, 400},
		{"missing scope", http.MethodPost, deviceAuthorizationPath, "application/x-www-form-urlencoded", url.Values{"client_id": {"client-1"}}, 400},
		{"duplicate client", http.MethodPost, deviceAuthorizationPath, "application/x-www-form-urlencoded", url.Values{"client_id": {"client-1", "two"}, "scope": {"openid"}}, 400},
		{"unknown field", http.MethodPost, deviceAuthorizationPath, "application/x-www-form-urlencoded", url.Values{"client_id": {"client-1"}, "scope": {"openid"}, "x": {"x"}}, 400},
		{"duplicate scope", http.MethodPost, deviceAuthorizationPath, "application/x-www-form-urlencoded", url.Values{"client_id": {"client-1"}, "scope": {"openid openid"}}, 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := formRequest(tt.method, tt.path, tt.form)
			if tt.typ != "" {
				r.Header.Set("Content-Type", tt.typ)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
	denied := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return errors.New("secret error") }, nil)
	w := httptest.NewRecorder()
	denied.ServeHTTP(w, formRequest(http.MethodPost, deviceAuthorizationPath, valid))
	if w.Code != 400 || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("auth status=%d body=%s", w.Code, w.Body.String())
	}
	over := httptest.NewRequest(http.MethodPost, deviceAuthorizationPath, strings.NewReader(strings.Repeat("x", deviceFormLimit+1)))
	over.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, over)
	if w.Code != 400 {
		t.Fatalf("oversize=%d", w.Code)
	}
}

func TestDeviceVerificationCSRFSubjectApproveAndDeny(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	noSubject := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, nil)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool) { return "user-1", true })
	cookie, csrf := verificationCSRF(t, h, grant.UserCode)
	w := httptest.NewRecorder()
	r := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}})
	r.AddCookie(cookie)
	noSubject.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("nil subject=%d", w.Code)
	}
	cookie, csrf = verificationCSRF(t, h, grant.UserCode)
	for _, tt := range []struct {
		name  string
		form  url.Values
		setup func(*http.Request)
	}{
		{"missing csrf", url.Values{"user_code": {grant.UserCode}, "action": {"approve"}}, nil},
		{"wrong csrf", url.Values{"user_code": {grant.UserCode}, "csrf_token": {"wrong"}, "action": {"approve"}}, nil},
		{"cross site", url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"wrong origin", url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := formRequest(http.MethodPost, verificationPath, tt.form)
			r.AddCookie(cookie)
			if tt.setup != nil {
				tt.setup(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if (tt.name == "missing csrf" || tt.name == "wrong csrf") && w.Code != http.StatusBadRequest || (tt.name != "missing csrf" && tt.name != "wrong csrf") && w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
	w = httptest.NewRecorder()
	r = formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {strings.ToLower(grant.UserCode)}, "csrf_token": {csrf}, "action": {"approve"}})
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://id.example.test")
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Device approved") {
		t.Fatalf("approve=%d %s", w.Code, w.Body.String())
	}
	poll, err := store.Poll(ctx, grant.DeviceCode, "client-1", deviceHTTPTestNow)
	if err != nil || poll.Status != StatusClaimed || poll.Subject != "user-1" {
		t.Fatalf("poll=%+v err=%v", poll, err)
	}

	deniedGrant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf = verificationCSRF(t, h, deniedGrant.UserCode)
	w = httptest.NewRecorder()
	r = formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {deniedGrant.UserCode}, "csrf_token": {csrf}, "action": {"deny"}})
	r.AddCookie(cookie)
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Device denied") {
		t.Fatalf("deny=%d %s", w.Code, w.Body.String())
	}
	poll, err = store.Poll(ctx, deniedGrant.DeviceCode, "client-1", deviceHTTPTestNow)
	if err != nil || poll.Status != StatusDenied {
		t.Fatalf("deny poll=%+v err=%v", poll, err)
	}
}

func TestDeviceVerificationGETBoundary(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, nil)
	for path, want := range map[string]int{
		verificationPath + "/x":                          http.StatusNotFound,
		verificationPath + "?extra=x":                    http.StatusBadRequest,
		verificationPath + "?user_code=bad%3Cscript%3E":  http.StatusBadRequest,
		verificationPath + "?user_code=%ZZ":              http.StatusBadRequest,
		verificationPath + "?user_code=ABCD;extra=value": http.StatusBadRequest,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Fatalf("path=%q status=%d want=%d", path, w.Code, want)
		}
		if strings.Contains(w.Body.String(), "<script>") {
			t.Fatalf("unsafe reflection: %s", w.Body.String())
		}
	}
}

func TestDeviceVerificationGETUnauthenticatedHandsOffToLogin(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, verificationPath+"?user_code=ABCD-2345-6789", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://id.example.test/oidc/device/login?user_code=ABCD-2345-6789" {
		t.Fatalf("handoff status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, verificationPath+"?user_code=", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://id.example.test/oidc/device/login?user_code=" {
		t.Fatalf("manual handoff status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestDeviceHTTPDistributedRateLimitsUseDirectRemoteIP(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	limits := Limits{Window: time.Minute, CreationLimit: 1, VerificationLimit: 1}
	h, err := NewHandlerWithLimits(store, "https://id.example.test", func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool) { return "user-1", true }, limits)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return deviceHTTPTestNow }
	form := url.Values{"client_id": {"client-1"}, "scope": {"openid"}}
	first := formRequest(http.MethodPost, deviceAuthorizationPath, form)
	first.RemoteAddr = "192.0.2.40:4000"
	first.Header.Set("X-Forwarded-For", "198.51.100.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, first)
	if w.Code != 200 {
		t.Fatalf("first=%d", w.Code)
	}
	second := formRequest(http.MethodPost, deviceAuthorizationPath, form)
	second.RemoteAddr = "192.0.2.40:4001"
	second.Header.Set("X-Forwarded-For", "203.0.113.2")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, second)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("creation limit=%d headers=%v", w.Code, w.Header())
	}

	grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := verificationCSRF(t, h, grant.UserCode)
	verify := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}})
	verify.RemoteAddr = "192.0.2.50:4000"
	verify.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, verify)
	if w.Code != 200 {
		t.Fatalf("first verification=%d", w.Code)
	}
	secondGrant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	// Fetch the second review from another peer so this tests the POST limit,
	// independently of the new GET review limit.
	cookie, csrf = verificationCSRF(t, h, secondGrant.UserCode, "192.0.2.60:4000")
	verify = formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {secondGrant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}})
	verify.RemoteAddr = "192.0.2.50:4999"
	verify.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, verify)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("verification limit=%d headers=%v", w.Code, w.Header())
	}
}

func TestDeviceHTTPFailedAuthenticationIsRateLimitedBeforeAuthorizer(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	calls := 0
	h, err := NewHandlerWithLimits(store, "https://id.example.test", func(*http.Request, string, []string) error {
		calls++
		return ErrClientAuthentication
	}, nil, Limits{CreationLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return deviceHTTPTestNow }
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
		r := formRequest(http.MethodPost, deviceAuthorizationPath, url.Values{"client_id": {"client-1"}, "scope": {"goauthy.read"}})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("status=%d want=%d", w.Code, status)
		}
	}
	if calls != 1 {
		t.Fatalf("authentication calls=%d want=1", calls)
	}
}

func testDeviceHandler(t *testing.T, store *Store, authorize ClientAuthorizer, subject Subject) *Handler {
	t.Helper()
	h, err := NewHandler(store, "https://id.example.test", authorize, subject)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return deviceHTTPTestNow }
	return h
}
func formRequest(method, target string, form url.Values) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}
func verificationCSRF(t *testing.T, h *Handler, code string, peer ...string) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, verificationPath+"?user_code="+url.QueryEscape(code), nil)
	if len(peer) != 0 {
		r.RemoteAddr = peer[0]
	}
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("GET=%d headers=%v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || !c[0].HttpOnly || !c[0].Secure || c[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookies=%+v", c)
	}
	m := regexp.MustCompile(`name="csrf_token" value="([A-Za-z0-9_-]+)"`).FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatalf("csrf missing: %s", w.Body.String())
	}
	return c[0], m[1]
}
