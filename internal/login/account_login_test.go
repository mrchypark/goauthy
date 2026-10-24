package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/rhiza"
)

func TestAccountLoginFreshGETSingleMutation(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	readSlot := func() uint64 {
		t.Helper()
		result, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		return result.AppliedSlot
	}
	before := readSlot()
	started := time.Now()
	cookie, interactionToken, csrf := accountLoginPage(t, h)
	after := readSlot()
	if got := after - before; got != 1 {
		t.Fatalf("fresh account GET committed mutations=%d want=1", got)
	}
	session, err := h.browser.LoadSessionReadOnlyForPeer(t.Context(), cookie.Value, "203.0.113.8")
	if err != nil || session.Authenticated() {
		t.Fatalf("init session invalid: %v", err)
	}
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnly(t.Context(), cookie.Value, interactionToken)
	if err != nil {
		t.Fatal(err)
	}
	if browser.ValidateCSRFToken(cookie.Value, csrf) != nil || !interaction.ExpiresAt.Equal(session.ExpiresAt) || session.ExpiresAt.Before(started.Add(interactionLifetime-time.Second)) || session.ExpiresAt.After(time.Now().Add(interactionLifetime)) {
		t.Fatal("CSRF binding or session/interaction TTL changed")
	}
	if _, err := h.browser.LoadSessionReadOnlyForPeer(t.Context(), cookie.Value, "203.0.113.9"); err == nil {
		t.Fatal("wrong peer accepted")
	}
	t.Logf("fresh account GET committed mutations=%d; peer/CSRF/TTL verified", after-before)
}

func accountLoginPage(t *testing.T, h *Handler) (*http.Cookie, string, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/account/login", nil)
	r.RemoteAddr = "203.0.113.8:1234"
	h.AccountLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign in to manage your account.") {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `name="username" value=""`) {
		t.Fatalf("fresh account login username should default empty: %s", w.Body.String())
	}
	interaction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("missing account form fields body=%s cookies=%#v", w.Body.String(), w.Result().Cookies())
	}
	return w.Result().Cookies()[0], interaction[1], csrf[1]
}

func accountLoginPost(cookie *http.Cookie, interaction, csrf, password string) *http.Request {
	return accountLoginPostUser(cookie, interaction, csrf, "alice", password)
}

func accountLoginPostUser(cookie *http.Cookie, interaction, csrf, username, password string) *http.Request {
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {username}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(cookie)
	return r
}

func TestAccountLoginAuthenticatesAndRedirects(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	cookie, interaction, csrf := accountLoginPage(t, h)
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, accountLoginPost(cookie, interaction, csrf, "correct password"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != h.issuer+"/" {
		t.Fatalf("POST status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 || w.Result().Cookies()[0].Value == cookie.Value {
		t.Fatal("session was not rotated")
	}
	replay := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(replay, accountLoginPost(cookie, interaction, csrf, "correct password"))
	if replay.Code != http.StatusForbidden || replay.Header().Get("Location") != "" {
		t.Fatalf("replay=%d location=%q", replay.Code, replay.Header().Get("Location"))
	}
}

func TestAccountLoginWrongPasswordKeepsInteraction(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.issuer = "http://localhost/prefix"
	cookie, interaction, csrf := accountLoginPage(t, h)

	wrong := httptest.NewRecorder()
	wrongRequest := accountLoginPost(cookie, interaction, csrf, "wrong password")
	wrongRequest.Header.Set("Accept", "text/html")
	h.AccountLoginHandler(false).ServeHTTP(wrong, wrongRequest)
	body := wrong.Body.String()
	for _, want := range []string{`id="login-error" class="auth-error" role="alert"`, `data-i18n="Login failed">Login failed`, "Check your username or password", `action="/prefix/account/login"`, `name="interaction" value="` + interaction + `"`, `name="csrf_token" value="` + csrf + `"`, `name="username" value="alice"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("wrong-password page missing %q: %s", want, body)
		}
	}
	if wrong.Code != http.StatusUnauthorized || wrong.Header().Get("Location") != "" || strings.Contains(body, "wrong password") || strings.Contains(body, `action="/auth/login"`) {
		t.Fatalf("wrong password status=%d location=%q body=%q", wrong.Code, wrong.Header().Get("Location"), wrong.Body.String())
	}
	if browser.ValidateCSRFToken(cookie.Value, csrf) != nil {
		t.Fatal("failed login did not retain the valid CSRF binding")
	}

	invalidCSRF := httptest.NewRecorder()
	invalidRequest := accountLoginPost(cookie, interaction, "invalid-csrf", "wrong password")
	invalidRequest.Header.Set("Accept", "text/html")
	h.AccountLoginHandler(false).ServeHTTP(invalidCSRF, invalidRequest)
	if invalidCSRF.Code != http.StatusForbidden || strings.Contains(invalidCSRF.Body.String(), `id="login-form"`) || strings.Contains(invalidCSRF.Body.String(), `name="csrf_token"`) {
		t.Fatalf("invalid CSRF produced a retry form: status=%d body=%q", invalidCSRF.Code, invalidCSRF.Body.String())
	}

	unknown := httptest.NewRecorder()
	unknownRequest := accountLoginPostUser(cookie, interaction, csrf, `nobody"<script>`, "wrong password")
	unknownRequest.Header.Set("Accept", "text/html")
	h.AccountLoginHandler(false).ServeHTTP(unknown, unknownRequest)
	unknownBody := unknown.Body.String()
	for _, want := range []string{`role="alert"`, "Check your username or password", `action="/prefix/account/login"`, `name="interaction" value="` + interaction + `"`, `name="csrf_token" value="` + csrf + `"`, `name="username" value="nobody&#34;&lt;script&gt;"`} {
		if !strings.Contains(unknownBody, want) {
			t.Fatalf("unknown-user page missing %q: %s", want, unknownBody)
		}
	}
	if unknown.Code != wrong.Code || strings.Contains(unknownBody, `nobody"<script>`) || strings.Contains(unknownBody, "wrong password") {
		t.Fatalf("known/unknown failure mismatch: known=%d unknown=%d body=%q", wrong.Code, unknown.Code, unknownBody)
	}

	correct := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(correct, accountLoginPost(cookie, interaction, csrf, "correct password"))
	if correct.Code != http.StatusSeeOther || correct.Header().Get("Location") != h.issuer+"/" {
		t.Fatalf("correct password after rejection status=%d location=%q body=%q", correct.Code, correct.Header().Get("Location"), correct.Body.String())
	}
}

func TestAccountLoginSharedInitSessionAndExpiredPassword(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.onPasswordExpired = func(context.Context, string) error { return nil }
	cookie, firstInteraction, csrf := accountLoginPage(t, h)
	secondPage := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodGet, "/account/login", nil)
	secondRequest.RemoteAddr = "203.0.113.8:1234"
	secondRequest.AddCookie(cookie)
	h.AccountLoginHandler(false).ServeHTTP(secondPage, secondRequest)
	secondInteraction := regexp.MustCompile(`name="interaction" value="([^"]+)"`).FindStringSubmatch(secondPage.Body.String())
	if secondPage.Code != http.StatusOK || len(secondInteraction) != 2 || len(secondPage.Result().Cookies()) != 1 || secondPage.Result().Cookies()[0].Value != cookie.Value {
		t.Fatalf("second tab status=%d cookies=%#v", secondPage.Code, secondPage.Result().Cookies())
	}
	first := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(first, accountLoginPost(cookie, firstInteraction, csrf, "correct password"))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first tab=%d", first.Code)
	}
	second := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(second, accountLoginPost(cookie, secondInteraction[1], csrf, "correct password"))
	if second.Code != http.StatusForbidden {
		t.Fatalf("second tab=%d", second.Code)
	}

	cookie, interaction, csrf := accountLoginPage(t, h)
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {"expired"}, "password": {"correct password"}}
	request := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader(form.Encode()))
	request.RemoteAddr = "203.0.113.8:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://localhost")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(cookie)
	expired := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(expired, request)
	if expired.Code != http.StatusForbidden || expired.Body.String() != "Password reset required\n" {
		t.Fatalf("expired status=%d body=%q", expired.Code, expired.Body.String())
	}
}

func TestAccountLoginExistingSessionAndForceMFA(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	peer := "203.0.113.8"
	session, err := h.browser.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), peer)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/account/login", nil)
	r.RemoteAddr = peer + ":1234"
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != h.issuer+"/" {
		t.Fatalf("existing session=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	h.AccountLoginHandler(true).ServeHTTP(w, r)
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Value == cookie.Value {
		t.Fatalf("force MFA=%d cookies=%#v", w.Code, w.Result().Cookies())
	}
}

func TestAccountLoginRejectsUntrustedRequestsAndWrongDestination(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	for _, raw := range []string{"?return_url=/account", "?extra=1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/account/login"+raw, nil)
		r.RemoteAddr = "203.0.113.8:1234"
		h.AccountLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q status=%d", raw, w.Code)
		}
	}
	for _, name := range []string{"authorization", "raw path"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/account/login", nil)
		r.RemoteAddr = "203.0.113.8:1234"
		if name == "authorization" {
			r.Header.Set("Authorization", "Bearer token")
		} else {
			r.URL.RawPath = r.URL.Path
		}
		h.AccountLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s status=%d", name, w.Code)
		}
	}
	cookie, interaction, csrf := accountLoginPage(t, h)
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		r := accountLoginPost(cookie, interaction, csrf, "correct password")
		mutate(r)
		w := httptest.NewRecorder()
		h.AccountLoginHandler(false).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("mutation status=%d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, accountLoginPost(cookie, interaction, "wrong", "correct password"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("CSRF status=%d", w.Code)
	}
	r := accountLoginPost(cookie, interaction, csrf, "correct password")
	r.URL.Path = "/oidc/device/login"
	w = httptest.NewRecorder()
	h.DeviceLoginHandler(false).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross destination status=%d", w.Code)
	}
}

func TestAccountLoginUsesIssuerPrefixForFixedDestination(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.issuer = "http://localhost/prefix"
	cookie, interaction, csrf := accountLoginPage(t, h)
	w := httptest.NewRecorder()
	h.AccountLoginHandler(false).ServeHTTP(w, accountLoginPost(cookie, interaction, csrf, "correct password"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "http://localhost/prefix/" {
		t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}
