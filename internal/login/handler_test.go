package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoginCompletesAuthorizationAndRotatesSession(t *testing.T) {
	h := testHandler(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if got := page.Header().Get("Content-Security-Policy"); got != authorizationFormCSP(authorizeValues().Get("redirect_uri")) {
		t.Fatalf("authorization form policy=%q", got)
	}
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" || !strings.Contains(page.Body.String(), `name="interaction"`) {
		t.Fatalf("authorize status=%d headers=%#v body=%s", page.Code, page.Header(), page.Body.String())
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	bad := postLogin(init, interaction, "alice", "wrong password")
	badResponse := httptest.NewRecorder()
	h.Login(badResponse, bad)
	if badResponse.Code != http.StatusUnauthorized || badResponse.Body.String() != "Invalid user credentials\n" {
		t.Fatalf("bad login status=%d body=%q", badResponse.Code, badResponse.Body.String())
	}
	unknown := postLogin(init, interaction, "nobody", "wrong password")
	unknownResponse := httptest.NewRecorder()
	h.Login(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusUnauthorized || unknownResponse.Body.String() != badResponse.Body.String() {
		t.Fatalf("unknown login status=%d body=%q", unknownResponse.Code, unknownResponse.Body.String())
	}

	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	location, err := url.Parse(completed.Header().Get("Location"))
	if err != nil || completed.Code != http.StatusSeeOther || location.Query().Get("code") == "" || location.Query().Get("state") != strings.Repeat("s", 32) {
		t.Fatalf("login status=%d location=%q err=%v", completed.Code, completed.Header().Get("Location"), err)
	}
	rotated := completed.Result().Cookies()[0]
	if rotated.Value == init.Value || !rotated.HttpOnly || rotated.Secure {
		t.Fatalf("rotated cookie=%#v init=%#v", rotated, init)
	}
	replay := httptest.NewRecorder()
	h.Login(replay, postLogin(init, interaction, "alice", "correct password"))
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replay status=%d body=%q", replay.Code, replay.Body.String())
	}
}

func TestAuthorizeRendersSelectedLanguageAndMalformedFallback(t *testing.T) {
	for _, test := range []struct {
		name, language, want string
	}{
		{"korean", "ko-KR, en;q=0.8", `<html lang="ko">`},
		{"malformed fallback", "ko;q=bogus", `<html lang="en">`},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testHandler(t)
			request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
			request.Header.Set("Accept-Language", test.language)
			response := httptest.NewRecorder()
			h.Authorize(response, request)
			wantLanguage := "en"
			if test.name == "korean" {
				wantLanguage = "ko"
			}
			if response.Code != http.StatusOK || response.Header().Get("Content-Language") != wantLanguage || !strings.Contains(response.Header().Get("Vary"), "Accept-Language") || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if test.name == "korean" && !strings.Contains(response.Body.String(), "로그인") {
				t.Fatalf("Korean page=%q", response.Body.String())
			}
		})
	}
}

func TestEnableFedCMIsHTTPSOnlyAndUsesSeparateCookie(t *testing.T) {
	h := testHandler(t)
	if err := h.EnableFedCM(true); err == nil {
		t.Fatal("HTTP issuer enabled FedCM")
	}
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	cookie, err := h.fedCMSessionCookie(otherBrowserToken(), time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if cookie == nil || cookie.Name != browser.FedCMSessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" {
		t.Fatalf("FedCM cookie=%#v", cookie)
	}
	if err := h.EnableFedCM(false); err != nil {
		t.Fatal(err)
	}
	if cookie, err := h.fedCMSessionCookie(otherBrowserToken(), time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)); err != nil || cookie != nil {
		t.Fatalf("disabled cookie=%#v err=%v", cookie, err)
	}
}

func TestCompleteExternalAuthenticationCompletesAndRejectsOldInit(t *testing.T) {
	h := testHandler(t)
	init, _, digest := externalAuthorization(t, h)
	response := httptest.NewRecorder()
	h.CompleteExternalAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusSeeOther || location.Query().Get("code") == "" {
		t.Fatalf("completion status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == init.Value {
		t.Fatalf("rotated cookies=%#v", cookies)
	}
	session, err := h.browser.LoadSession(context.Background(), cookies[0].Value)
	if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "external" {
		t.Fatalf("external session=%#v err=%v", session, err)
	}

	old := httptest.NewRecorder()
	h.CompleteExternalAuthentication(old, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
	if old.Code != http.StatusForbidden || old.Header().Get("Location") != "" {
		t.Fatalf("old init status=%d location=%q", old.Code, old.Header().Get("Location"))
	}
}

func TestPrepareExternalAuthenticationBindsCurrentInitSession(t *testing.T) {
	h := testHandler(t)
	init, interaction, wantInteractionDigest := externalAuthorization(t, h)
	req := httptest.NewRequest(http.MethodGet, "/upstream/start", nil)
	req.AddCookie(init)
	sessionToken, sessionDigest, interactionDigest, err := h.PrepareExternalAuthentication(req, interaction)
	if err != nil || sessionToken != init.Value || interactionDigest != wantInteractionDigest || sessionDigest == sessionToken || len(sessionDigest) != 43 {
		t.Fatalf("session=%q digest=%q interaction=%q err=%v", sessionToken, sessionDigest, interactionDigest, err)
	}
	if _, err := h.browser.LoadAuthorizationInteractionReadOnly(context.Background(), init.Value, interaction); err != nil {
		t.Fatalf("prepare consumed interaction: %v", err)
	}
}

func TestPrepareExternalAuthenticationRejectsInvalidBindings(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request, *http.Cookie, string) string
	}{
		{name: "missing cookie", mutate: func(_ *http.Request, _ *http.Cookie, interaction string) string { return interaction }},
		{name: "wrong cookie", mutate: func(r *http.Request, cookie *http.Cookie, interaction string) string {
			r.AddCookie(&http.Cookie{Name: cookie.Name, Value: otherBrowserToken()})
			return interaction
		}},
		{name: "wrong peer", mutate: func(r *http.Request, cookie *http.Cookie, interaction string) string {
			r.AddCookie(cookie)
			r.RemoteAddr = "198.51.100.9:1234"
			return interaction
		}},
		{name: "wrong interaction", mutate: func(r *http.Request, cookie *http.Cookie, _ string) string {
			r.AddCookie(cookie)
			return otherBrowserToken()
		}},
		{name: "noncanonical interaction", mutate: func(r *http.Request, cookie *http.Cookie, interaction string) string {
			r.AddCookie(cookie)
			return interaction + "="
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			init, interaction, _ := externalAuthorization(t, h)
			req := httptest.NewRequest(http.MethodGet, "/upstream/start", nil)
			_, _, _, err := h.PrepareExternalAuthentication(req, tc.mutate(req, init, interaction))
			if !errors.Is(err, ErrExternalAuthentication) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	init, interaction, _ := externalAuthorization(t, h)
	if _, err := h.browser.ConsumeAuthorizationInteraction(context.Background(), init.Value, interaction); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/upstream/start", nil)
	req.AddCookie(init)
	if _, _, _, err := h.PrepareExternalAuthentication(req, interaction); !errors.Is(err, ErrExternalAuthentication) {
		t.Fatalf("consumed interaction err=%v", err)
	}
	authenticated := authenticatedCookie(t, h)
	req = httptest.NewRequest(http.MethodGet, "/upstream/start", nil)
	req.AddCookie(authenticated)
	if _, _, err := h.CurrentExternalInitSession(req); !errors.Is(err, ErrExternalAuthentication) {
		t.Fatalf("authenticated session err=%v", err)
	}
}

func TestCompleteExternalAuthenticationRejectsPreflightFailuresWithoutConsuming(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		name    string
		subject string
		mutate  func(*http.Request, string, string) (string, string)
	}{
		{name: "wrong digest", subject: "user-1", mutate: func(_ *http.Request, token, _ string) (string, string) { return token, otherBrowserToken() }},
		{name: "wrong session", subject: "user-1", mutate: func(_ *http.Request, _ string, digest string) (string, string) {
			return otherBrowserToken(), digest
		}},
		{name: "wrong peer", subject: "user-1", mutate: func(r *http.Request, token, digest string) (string, string) {
			r.RemoteAddr = "198.51.100.9:1234"
			return token, digest
		}},
		{name: "disabled subject", subject: "user-disabled", mutate: func(_ *http.Request, token, digest string) (string, string) { return token, digest }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			init, _, digest := externalAuthorization(t, h)
			req := httptest.NewRequest(http.MethodGet, "/upstream/callback", nil)
			sessionToken, suppliedDigest := tc.mutate(req, init.Value, digest)
			failed := httptest.NewRecorder()
			h.CompleteExternalAuthentication(failed, req, sessionToken, suppliedDigest, tc.subject)
			if failed.Code != http.StatusForbidden && failed.Code != http.StatusUnauthorized {
				t.Fatalf("failure status=%d body=%q", failed.Code, failed.Body.String())
			}
			completed := httptest.NewRecorder()
			h.CompleteExternalAuthentication(completed, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
			if completed.Code != http.StatusSeeOther {
				t.Fatalf("preflight consumed interaction: status=%d body=%q", completed.Code, completed.Body.String())
			}
		})
	}
}

func TestCompleteExternalAuthenticationForceMFAAndReplay(t *testing.T) {
	force := testHandlerWithForceMFA(t)
	init, _, digest := externalAuthorization(t, force)
	blocked := httptest.NewRecorder()
	force.CompleteExternalAuthentication(blocked, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
	if blocked.Code != http.StatusForbidden || blocked.Header().Get("Location") != "" || blocked.Header().Get("Set-Cookie") != "" {
		t.Fatalf("force MFA status=%d headers=%v", blocked.Code, blocked.Header())
	}
	if _, err := force.browser.LoadAuthorizationInteractionReadOnlyByDigest(context.Background(), init.Value, digest); err != nil {
		t.Fatalf("force MFA consumed interaction: %v", err)
	}

	h := testHandler(t)
	init, _, digest = externalAuthorization(t, h)
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := httptest.NewRecorder()
			h.CompleteExternalAuthentication(response, httptest.NewRequest(http.MethodGet, "/upstream/callback", nil), init.Value, digest, "user-1")
			responses <- response
		}()
	}
	close(start)
	wait.Wait()
	close(responses)
	winners := 0
	for response := range responses {
		if response.Code == http.StatusSeeOther && response.Header().Get("Location") != "" {
			winners++
			continue
		}
		if response.Code != http.StatusForbidden {
			t.Fatalf("replay status=%d body=%q", response.Code, response.Body.String())
		}
	}
	if winners != 1 {
		t.Fatalf("completion winners=%d", winners)
	}
}

func TestAuthorizeResourceFailureRedirectsOnlyToRegisteredCallback(t *testing.T) {
	h := testHandler(t)

	registered := authorizeValues()
	registered.Set("resource", "https://unknown.example.test")
	registeredResponse := httptest.NewRecorder()
	h.Authorize(registeredResponse, httptest.NewRequest(http.MethodGet, authorizePath+"?"+registered.Encode(), nil))
	registeredLocation, err := url.Parse(registeredResponse.Header().Get("Location"))
	if err != nil || registeredResponse.Code != http.StatusSeeOther || registeredLocation.String() == "" || registeredLocation.Query().Get("error") != "invalid_target" || registeredLocation.Query().Get("state") != registered.Get("state") {
		t.Fatalf("registered callback response: status=%d location=%q err=%v", registeredResponse.Code, registeredResponse.Header().Get("Location"), err)
	}

	unregistered := authorizeValues()
	unregistered.Set("redirect_uri", "http://attacker.example.test/callback")
	unregistered.Set("resource", "https://unknown.example.test")
	unregisteredResponse := httptest.NewRecorder()
	h.Authorize(unregisteredResponse, httptest.NewRequest(http.MethodGet, authorizePath+"?"+unregistered.Encode(), nil))
	if unregisteredResponse.Code != http.StatusBadRequest || unregisteredResponse.Header().Get("Location") != "" {
		t.Fatalf("unregistered callback response: status=%d location=%q", unregisteredResponse.Code, unregisteredResponse.Header().Get("Location"))
	}

	missingPKCE := authorizeValues()
	missingPKCE.Del("code_challenge")
	missingPKCE.Del("code_challenge_method")
	missingPKCEResponse := httptest.NewRecorder()
	h.Authorize(missingPKCEResponse, httptest.NewRequest(http.MethodGet, authorizePath+"?"+missingPKCE.Encode(), nil))
	if missingPKCEResponse.Code != http.StatusBadRequest || missingPKCEResponse.Header().Get("Location") != "" {
		t.Fatalf("missing PKCE response: status=%d location=%q", missingPKCEResponse.Code, missingPKCEResponse.Header().Get("Location"))
	}
}

func TestLoginFailureDoesNotRevealOrConsumeInteraction(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		name, username, password string
	}{
		{name: "wrong password", username: "alice", password: "wrong password"},
		{name: "unknown user", username: "nobody", password: "wrong password"},
		{name: "disabled user", username: "disabled", password: "correct password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := httptest.NewRecorder()
			h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			if page.Code != http.StatusOK {
				t.Fatalf("authorize status=%d", page.Code)
			}
			init := page.Result().Cookies()[0]
			interaction := interactionToken(t, page.Body.String())

			failure := httptest.NewRecorder()
			h.Login(failure, postLogin(init, interaction, tc.username, tc.password))
			if failure.Code != http.StatusUnauthorized || failure.Body.String() != "Invalid user credentials\n" || failure.Header().Get("Set-Cookie") != "" {
				t.Fatalf("failure status=%d body=%q set-cookie=%q", failure.Code, failure.Body.String(), failure.Header().Get("Set-Cookie"))
			}

			completed := httptest.NewRecorder()
			h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
			if completed.Code != http.StatusSeeOther || completed.Header().Get("Location") == "" {
				t.Fatalf("failure consumed interaction: status=%d location=%q", completed.Code, completed.Header().Get("Location"))
			}
		})
	}
}

func TestExpiredPasswordRecoveryIsExactOnceAndDoesNotConsumeInteraction(t *testing.T) {
	var calls []string
	h := testHandler(t)
	h.onPasswordExpired = func(_ context.Context, subject string) error {
		calls = append(calls, subject)
		return nil
	}
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init, interaction := page.Result().Cookies()[0], interactionToken(t, page.Body.String())
	expired := httptest.NewRecorder()
	h.Login(expired, postLogin(init, interaction, "expired", "correct password"))
	if expired.Code != http.StatusForbidden || expired.Body.String() != "Password reset required\n" || len(calls) != 1 || calls[0] != "user-expired" {
		t.Fatalf("expired status=%d body=%q calls=%v", expired.Code, expired.Body.String(), calls)
	}
	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("interaction consumed after recovery: status=%d body=%q", completed.Code, completed.Body.String())
	}
}

func TestExpiredPasswordRecoveryUnavailableIs503(t *testing.T) {
	for _, tc := range []struct {
		name     string
		callback func(context.Context, string) error
	}{
		{name: "nil"},
		{name: "error", callback: func(context.Context, string) error { return errors.New("reset unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t)
			h.onPasswordExpired = tc.callback
			page := httptest.NewRecorder()
			h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			init, interaction := page.Result().Cookies()[0], interactionToken(t, page.Body.String())
			response := httptest.NewRecorder()
			h.Login(response, postLogin(init, interaction, "expired", "correct password"))
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "expired") || strings.Contains(response.Body.String(), "user-expired") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestExpiredRecoveryDoesNotRunForWrongPassword(t *testing.T) {
	h := testHandler(t)
	calls := 0
	h.onPasswordExpired = func(context.Context, string) error { calls++; return nil }
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	response := httptest.NewRecorder()
	h.Login(response, postLogin(page.Result().Cookies()[0], interactionToken(t, page.Body.String()), "alice", "wrong password"))
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("status=%d body=%q callback_calls=%d", response.Code, response.Body.String(), calls)
	}
}

func TestLoginPolicyBlocksWithoutConsumingInteraction(t *testing.T) {
	h := testHandler(t)
	ip := "198.51.100.40"
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return now }
	for range 7 {
		if _, err := h.policy.Failure(context.Background(), ip, now); err != nil {
			t.Fatal(err)
		}
	}
	page := httptest.NewRecorder()
	authorizeReq := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	authorizeReq.RemoteAddr = ip + ":1234"
	h.Authorize(page, authorizeReq)
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())
	blocked := postLogin(init, interaction, "alice", "correct password")
	blocked.RemoteAddr = ip + ":1234"
	response := httptest.NewRecorder()
	h.Login(response, blocked)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || strings.Contains(response.Body.String(), "alice") {
		t.Fatalf("blocked status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	// Clearing the test-only block demonstrates the rejected request did not
	// consume the authorization interaction.
	now = now.Add(time.Minute + time.Millisecond)
	completed := postLogin(init, interaction, "alice", "correct password")
	completed.RemoteAddr = ip + ":1234"
	accepted := httptest.NewRecorder()
	h.Login(accepted, completed)
	if accepted.Code != http.StatusSeeOther {
		t.Fatalf("unblocked interaction status=%d body=%q", accepted.Code, accepted.Body.String())
	}
}

func TestUnexpectedAuthenticationErrorDoesNotResetLoginPolicy(t *testing.T) {
	h := testHandler(t)
	ip := "198.51.100.41"
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return now }
	for range 3 {
		if _, err := h.policy.Failure(context.Background(), ip, now); err != nil {
			t.Fatal(err)
		}
	}
	before, err := h.policy.Check(context.Background(), ip, now)
	if err != nil {
		t.Fatal(err)
	}
	workLimit := errors.New("argon work limit")
	if err := h.recordSuccessfulAuthentication(context.Background(), ip, time.Hour, workLimit); !errors.Is(err, workLimit) {
		t.Fatalf("error=%v", err)
	}
	after, err := h.policy.Check(context.Background(), ip, now)
	if err != nil || after.Failures != before.Failures || after.Mean != before.Mean {
		t.Fatalf("before=%+v after=%+v err=%v", before, after, err)
	}
	if err := h.recordSuccessfulAuthentication(context.Background(), ip, time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	clamped, err := h.policy.Check(context.Background(), ip, now)
	if err != nil || clamped.Failures != 3 || clamped.Mean != 30*time.Second {
		t.Fatalf("clamped=%+v err=%v", clamped, err)
	}
}

func TestLoginFailureExtendsWriteDeadlineForEveryDelayTier(t *testing.T) {
	seed := time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		failures int
		advance  time.Duration
	}{
		{failures: 6},
		{failures: 9, advance: time.Minute + time.Millisecond},
		{failures: 14, advance: 10*time.Minute + time.Millisecond},
		{failures: 19, advance: 15*time.Minute + time.Millisecond},
		{failures: 24, advance: time.Hour + time.Millisecond},
	} {
		t.Run(strconv.Itoa(tc.failures), func(t *testing.T) {
			h := testHandler(t)
			ip := "198.51.100.42"
			if err := h.policy.Success(context.Background(), ip, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			for range tc.failures - 1 {
				if _, err := h.policy.Failure(context.Background(), ip, seed); err != nil {
					t.Fatal(err)
				}
			}
			now := seed.Add(tc.advance)
			var waited time.Duration
			h.wait = func(_ context.Context, delay time.Duration) error { waited = delay; return nil }
			var deadline time.Time
			h.deadline = func(_ http.ResponseWriter, value time.Time) error { deadline = value; return nil }

			page := httptest.NewRecorder()
			authorizeReq := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
			authorizeReq.RemoteAddr = ip + ":1234"
			h.Authorize(page, authorizeReq)
			request := postLogin(page.Result().Cookies()[0], interactionToken(t, page.Body.String()), "alice", "wrong password")
			h.now = func() time.Time { return now }
			request.RemoteAddr = ip + ":1234"
			response := httptest.NewRecorder()
			h.Login(response, request)

			wantDelay := loginpolicy.Delay(loginpolicy.Status{Failures: int64(tc.failures), Mean: 30 * time.Second}, 0)
			if response.Code != http.StatusUnauthorized || waited != wantDelay || !deadline.Equal(now.Add(wantDelay+failureWriteGrace)) {
				t.Fatalf("status=%d waited=%s deadline=%s want-delay=%s", response.Code, waited, deadline, wantDelay)
			}
		})
	}
}

func TestAuthorizePromptNoneAndRejectsCrossSiteOrAmbiguousForms(t *testing.T) {
	h := testHandler(t)
	values := authorizeValues()
	values.Set("prompt", "none")
	response := httptest.NewRecorder()
	h.Authorize(response, httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil))
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "login_required" {
		t.Fatalf("prompt none status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("interaction=a&interaction=b&username=alice&password=x"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response = httptest.NewRecorder()
	h.Login(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous form status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("interaction=a&username=alice&password=x"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response = httptest.NewRecorder()
	h.Login(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-site status=%d", response.Code)
	}
}

func TestParseLoginFormPasswordBoundary(t *testing.T) {
	valid := strings.Repeat("🙂", 256)
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{name: "256 unicode code points", body: url.Values{"interaction": {"a"}, "username": {"alice"}, "password": {valid}}.Encode(), want: true},
		{name: "257 unicode code points", body: url.Values{"interaction": {"a"}, "username": {"alice"}, "password": {strings.Repeat("🙂", 257)}}.Encode()},
		{name: "invalid utf8", body: "interaction=a&username=alice&password=%FF"},
		{name: "empty", body: "interaction=a&username=alice&password="},
		{name: "duplicate password", body: "interaction=a&username=alice&password=x&password=y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			form, err := parseLoginForm(httptest.NewRecorder(), request)
			if (err == nil) != tc.want {
				t.Fatalf("parse err=%v form=%+v", err, form)
			}
		})
	}
}

func TestAuthorizeAuthenticatedSessionPromptAndMaxAgePolicy(t *testing.T) {
	h := testHandler(t)
	cookie := authenticatedCookie(t, h)
	for _, tc := range []struct {
		name         string
		prompt       string
		maxAge       string
		wantLogin    bool
		wantRequired bool
	}{
		{name: "reuses authenticated session"},
		{name: "prompt login", prompt: "login", wantLogin: true},
		{name: "prompt consent", prompt: "consent", wantLogin: true},
		{name: "max age zero", maxAge: "0", wantLogin: true},
		{name: "prompt none authenticated", prompt: "none"},
		{name: "prompt none expired max age", prompt: "none", maxAge: "0", wantRequired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := authorizeValues()
			if tc.prompt != "" {
				values.Set("prompt", tc.prompt)
			}
			if tc.maxAge != "" {
				values.Set("max_age", tc.maxAge)
			}
			request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			h.Authorize(response, request)
			if tc.wantLogin {
				if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || interactionPattern.FindStringSubmatch(response.Body.String()) == nil {
					t.Fatalf("forced login status=%d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
				}
				return
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil || response.Code != http.StatusSeeOther {
				t.Fatalf("authorize status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
			}
			if tc.wantRequired {
				if location.Query().Get("error") != "login_required" {
					t.Fatalf("login required location=%q", location)
				}
				return
			}
			if location.Query().Get("code") == "" || location.Query().Get("error") != "" {
				t.Fatalf("authorization did not reuse session: %q", location)
			}
		})
	}
}

func TestAuthorizeLegacySessionDoesNotIssueFedCMSessionCookie(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	cookie := authenticatedCookie(t, h)
	request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	h.Authorize(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	for _, issued := range response.Result().Cookies() {
		if issued.Name == browser.FedCMSessionCookieName {
			t.Fatalf("legacy session received FedCM cookie: %#v", issued)
		}
	}
}

func TestForceMFARejectsPasswordSessionAndPromptNoneButAllowsMFASession(t *testing.T) {
	h, db := testHandlerWithDB(t, true)
	for _, tc := range []struct {
		name, subject, method, prompt string
		wantCode                      bool
		wantRequired                  bool
	}{
		{name: "password session", subject: "user-1", method: "pwd"},
		{name: "password session prompt none", subject: "user-1", method: "pwd", prompt: "none", wantRequired: true},
		{name: "MFA session", subject: "user-1", method: "mfa", wantCode: true},
		{name: "disabled MFA session", subject: "user-disabled", method: "mfa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "disabled MFA session" {
				if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "enable-before-force-mfa-session", SQL: `UPDATE identity_users SET disabled=0 WHERE subject=?`, Args: []any{tc.subject}}); err != nil {
					t.Fatal(err)
				}
			}
			session, err := h.browser.CreateSession(context.Background(), tc.subject, tc.method, time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "disabled MFA session" {
				if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "disable-force-mfa-user", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"user-disabled"}}); err != nil {
					t.Fatal(err)
				}
			}
			cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			values := authorizeValues()
			if tc.prompt != "" {
				values.Set("prompt", tc.prompt)
			}
			request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			h.Authorize(response, request)
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantRequired {
				if response.Code != http.StatusSeeOther || location.Query().Get("error") != "login_required" {
					t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
				}
				return
			}
			if tc.wantCode {
				if response.Code != http.StatusSeeOther || location.Query().Get("code") == "" {
					t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
				}
				return
			}
			if response.Code != http.StatusOK || interactionPattern.FindStringSubmatch(response.Body.String()) == nil || location.Query().Get("code") != "" {
				t.Fatalf("status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
			}
		})
	}
}

func TestForceMFANoCredentialDoesNotConsumeInteraction(t *testing.T) {
	h := testHandlerWithForceMFA(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init, interaction := page.Result().Cookies()[0], interactionToken(t, page.Body.String())
	for attempt := range 2 {
		response := httptest.NewRecorder()
		h.Login(response, postLogin(init, interaction, "alice", "correct password"))
		if response.Code != http.StatusNotAcceptable || response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" {
			t.Fatalf("attempt=%d status=%d headers=%v body=%q", attempt, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestWebAuthnStartRejectsInvalidBrowserAndPasswordlessCookies(t *testing.T) {
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())
	valid, err := h.passkeys.PasswordlessCookie("user-1")
	if err != nil {
		t.Fatal(err)
	}
	request := func(cookie *http.Cookie) *http.Request {
		body, err := json.Marshal(passkeyStartRequest{Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.AddCookie(init)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
	}{
		{name: "missing"},
		{name: "tampered", cookie: &http.Cookie{Name: h.passkeyCookieName(), Value: valid + "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.WebAuthnStart(response, request(tc.cookie))
			if response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
		})
	}

	crossSite := request(&http.Cookie{Name: h.passkeyCookieName(), Value: valid})
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	crossResponse := httptest.NewRecorder()
	h.WebAuthnStart(crossResponse, crossSite)
	if crossResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-site status=%d", crossResponse.Code)
	}

	if err := h.browser.RevokeSession(context.Background(), init.Value); err != nil {
		t.Fatal(err)
	}
	staleResponse := httptest.NewRecorder()
	h.WebAuthnStart(staleResponse, request(&http.Cookie{Name: h.passkeyCookieName(), Value: valid}))
	if staleResponse.Code != http.StatusForbidden {
		t.Fatalf("stale init status=%d", staleResponse.Code)
	}
}

func TestWebAuthnFinishStrictInputAndFailurePreservesInteraction(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		name, contentType, body string
		want                    int
	}{
		{name: "wrong content type", contentType: "text/plain", body: `{}`, want: http.StatusBadRequest},
		{name: "unknown field", contentType: "application/json", body: `{"code":"x","data":"{}","extra":true}`, want: http.StatusBadRequest},
		{name: "trailing JSON", contentType: "application/json", body: `{"code":"x","data":"{}"}{}`, want: http.StatusBadRequest},
		{name: "missing data", contentType: "application/json", body: `{"code":"x"}`, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_finish", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()
			h.WebAuthnFinish(response, request)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}

	page := httptest.NewRecorder()
	authorizeReq := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	authorizeReq.RemoteAddr = "198.51.100.88:1234"
	h.Authorize(page, authorizeReq)
	init, interaction := page.Result().Cookies()[0], interactionToken(t, page.Body.String())
	failure := httptest.NewRecorder()
	finish := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_finish", strings.NewReader(`{"code":"not-a-ceremony","data":"{}"}`))
	finish.Header.Set("Content-Type", "application/json")
	finish.Header.Set("Sec-Fetch-Site", "same-origin")
	finish.RemoteAddr = "198.51.100.88:1234"
	finish.AddCookie(init)
	h.WebAuthnFinish(failure, finish)
	if failure.Code != http.StatusUnauthorized || failure.Header().Get("Set-Cookie") != "" {
		t.Fatalf("failure status=%d headers=%v body=%q", failure.Code, failure.Header(), failure.Body.String())
	}
	completed := httptest.NewRecorder()
	password := postLogin(init, interaction, "alice", "correct password")
	password.RemoteAddr = "198.51.100.88:1234"
	h.Login(completed, password)
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("passkey failure consumed interaction: status=%d body=%q", completed.Code, completed.Body.String())
	}
}

func TestPasswordlessCookieUsesHostPrefixOnlyForHTTPS(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		issuer, wantName string
		secure           bool
	}{
		{issuer: "http://localhost", wantName: "goauthy-passkey"},
		{issuer: "https://issuer.example.test", wantName: "__Host-goauthy-passkey", secure: true},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			h.issuer = tc.issuer
			cookie, err := h.passwordlessCookie("opaque")
			if err != nil || cookie.Name != tc.wantName || cookie.Path != "/" || !cookie.HttpOnly || cookie.Secure != tc.secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("cookie=%#v err=%v", cookie, err)
			}
		})
	}
}

func TestConstructorStoresNormalizedIssuerForCookies(t *testing.T) {
	base := testHandler(t)
	h, err := NewWithRecovery("HTTPS://ISSUER.EXAMPLE.TEST/", base.browser, base.identity, base.oauth, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := h.passwordlessCookie("opaque")
	if err != nil || h.issuer != "https://issuer.example.test" || cookie.Name != "__Host-goauthy-passkey" || !cookie.Secure {
		t.Fatalf("issuer=%q cookie=%#v err=%v", h.issuer, cookie, err)
	}
}

func testHandler(t *testing.T) *Handler {
	return testHandlerWithForce(t, false)
}

func testHandlerWithForceMFA(t *testing.T) *Handler {
	return testHandlerWithForce(t, true)
}

func testHandlerWithForce(t *testing.T, forceMFA bool) *Handler {
	h, _ := testHandlerWithDB(t, forceMFA)
	return h
}

func testHandlerWithDB(t *testing.T, forceMFA bool) (*Handler, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "login-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.BootstrapUser(ctx, "user-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.BootstrapUser(ctx, "user-disabled", "disabled", password); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-fixture-disabled-user", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='user-disabled'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.BootstrapUser(ctx, "user-expired", "expired", password); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-expire-user",
		SQL:       `UPDATE identity_users SET password_changed_at_unix_ms = ? WHERE subject = ?`,
		Args:      []any{1, "user-expired"},
	}); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	secret[0] = 1
	var oauthServer *oauth.Server
	if forceMFA {
		oauthServer, err = oauth.NewServerWithOIDC(ctx, db, secret, "browser-client", "0123456789abcdef", "http://localhost/callback", nil, oauth.OIDCConfig{Issuer: "http://localhost", BootstrapForceMFA: true, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidc.SigningKey{}, nil }})
	} else {
		oauthServer, err = oauth.NewServer(ctx, db, secret, "browser-client", "0123456789abcdef", "http://localhost/callback")
	}
	if err != nil {
		t.Fatal(err)
	}
	passkeys, err := passkey.New(db, passkey.Config{
		RPID:          "localhost",
		RPDisplayName: "GoAuthy test",
		Origins:       []string{"http://localhost"},
		CookieKey:     secret,
		Keyring:       testOIDCKeyring(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewWithPolicyRecoveryAndPasskeys("http://localhost", browserStore, identityStore, oauthServer, loginpolicy.NewStore(db), nil, passkeys)
	if err != nil {
		t.Fatal(err)
	}
	// Existing login behavior tests exercise policy state but do not sleep.
	h.wait = func(context.Context, time.Duration) error { return nil }
	h.deadline = func(http.ResponseWriter, time.Time) error { return nil }
	return h, db
}

func testOIDCKeyring(t *testing.T) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	key[0] = 0x11
	if err := os.WriteFile(filepath.Join(dir, "test-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "test-1")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func authorizeValues() url.Values {
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{
		"response_type": {"code"}, "client_id": {"browser-client"}, "redirect_uri": {"http://localhost/callback"},
		"scope": {"goauthy.read offline_access"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
}

var interactionPattern = regexp.MustCompile(`name="interaction" value="([A-Za-z0-9_-]{43})"`)

var fedCMCSRFPattern = regexp.MustCompile(`name="csrf_token" value="([A-Za-z0-9_-]{43})"`)

func TestFedCMLandingUsesSharedPasswordTransitionAndOneTimeClaim(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	peer := "198.51.100.42:1234"
	get := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	get.RemoteAddr = peer
	get.Header.Set("Accept-Language", "ko")
	page := httptest.NewRecorder()
	h.FedCMLanding(page, get)
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" || !strings.Contains(page.Body.String(), `name="fedcm"`) {
		t.Fatalf("landing status=%d headers=%#v body=%s", page.Code, page.Header(), page.Body.String())
	}
	cookies := page.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-goauthy_session" || !cookies[0].Secure {
		t.Fatalf("landing cookies=%#v", cookies)
	}
	interaction := interactionPattern.FindStringSubmatch(page.Body.String())
	csrf := fedCMCSRFPattern.FindStringSubmatch(page.Body.String())
	if len(interaction) != 2 || len(csrf) != 2 {
		t.Fatalf("landing tokens interaction=%v csrf=%v", interaction, csrf)
	}

	values := url.Values{"fedcm": {"1"}, "interaction": {interaction[1]}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(values.Encode()))
	post.RemoteAddr = peer
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://issuer.example.test")
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	post.Header.Set("Accept-Language", "ko")
	post.AddCookie(cookies[0])
	completed := httptest.NewRecorder()
	h.FedCMLanding(completed, post)
	if completed.Code != http.StatusOK || completed.Header().Get("Content-Language") != "ko" || !strings.Contains(completed.Header().Get("Vary"), "Accept-Language") || !strings.Contains(completed.Body.String(), "로그인되었습니다.") || len(completed.Result().Cookies()) != 2 {
		t.Fatalf("completion status=%d cookies=%#v body=%q", completed.Code, completed.Result().Cookies(), completed.Body.String())
	}
	rotated := completed.Result().Cookies()[0]
	session, err := h.browser.LoadSession(context.Background(), rotated.Value)
	if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "pwd" || session.PeerIP != "198.51.100.42" {
		t.Fatalf("rotated session=%#v err=%v", session, err)
	}

	replay := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(values.Encode()))
	replayReq.RemoteAddr = peer
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayReq.Header.Set("Origin", "https://issuer.example.test")
	replayReq.Header.Set("Sec-Fetch-Site", "same-origin")
	replayReq.AddCookie(cookies[0])
	h.FedCMLanding(replay, replayReq)
	if replay.Code != http.StatusForbidden || replay.Header().Get("Set-Cookie") != "" {
		t.Fatalf("replay status=%d headers=%v body=%q", replay.Code, replay.Header(), replay.Body.String())
	}
}

func TestFedCMExistingSessionRendersLocalizedSuccess(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	issued, err := h.browser.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	request.RemoteAddr = "203.0.113.8:1234"
	request.Header.Set("Accept-Language", "ko")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	h.FedCMLanding(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Language") != "ko" || !strings.Contains(response.Header().Get("Vary"), "Accept-Language") || !strings.Contains(response.Body.String(), "로그인되었습니다.") {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestFedCMLandingConcurrentPostsHaveOneWinner(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	get.RemoteAddr = "198.51.100.45:1234"
	page := httptest.NewRecorder()
	h.FedCMLanding(page, get)
	init := page.Result().Cookies()[0]
	interaction := interactionPattern.FindStringSubmatch(page.Body.String())[1]
	csrf := fedCMCSRFPattern.FindStringSubmatch(page.Body.String())[1]
	values := url.Values{"fedcm": {"1"}, "interaction": {interaction}, "csrf_token": {csrf}, "username": {"alice"}, "password": {"correct password"}}
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(values.Encode()))
			req.RemoteAddr = get.RemoteAddr
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://issuer.example.test")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.AddCookie(init)
			response := httptest.NewRecorder()
			h.FedCMLanding(response, req)
			responses <- response
		}()
	}
	close(start)
	wait.Wait()
	close(responses)
	winners := 0
	for response := range responses {
		if response.Code == http.StatusOK {
			winners++
		} else if response.Code != http.StatusForbidden {
			t.Fatalf("concurrent status=%d body=%q", response.Code, response.Body.String())
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners=%d", winners)
	}
}

func TestFedCMLandingRejectsCrossSiteAndCSRFWithoutConsuming(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	get.RemoteAddr = "198.51.100.43:1234"
	page := httptest.NewRecorder()
	h.FedCMLanding(page, get)
	init := page.Result().Cookies()[0]
	interaction := interactionPattern.FindStringSubmatch(page.Body.String())[1]
	csrf := fedCMCSRFPattern.FindStringSubmatch(page.Body.String())[1]
	values := url.Values{"fedcm": {"1"}, "interaction": {interaction}, "csrf_token": {csrf + "x"}, "username": {"alice"}, "password": {"correct password"}}
	for _, tc := range []struct {
		name, site, origin string
	}{
		{name: "cross-site", site: "cross-site", origin: "https://issuer.example.test"},
		{name: "wrong-origin", site: "same-origin", origin: "https://attacker.example.test"},
		{name: "csrf", site: "same-origin", origin: "https://issuer.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(values.Encode()))
			req.RemoteAddr = "198.51.100.43:1234"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			req.AddCookie(init)
			response := httptest.NewRecorder()
			h.FedCMLanding(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if _, err := h.browser.LoadAuthorizationInteractionReadOnly(context.Background(), init.Value, interaction); err != nil {
				t.Fatalf("interaction consumed on %s: %v", tc.name, err)
			}
		})
	}
}

func TestFedCMLandingNeverDowngradesForcedMFAToPassword(t *testing.T) {
	h := testHandlerWithForceMFA(t)
	h.issuer = "https://issuer.example.test"
	h.SetFedCMForceMFA(true)
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	get.RemoteAddr = "198.51.100.44:1234"
	page := httptest.NewRecorder()
	h.FedCMLanding(page, get)
	init := page.Result().Cookies()[0]
	interaction := interactionPattern.FindStringSubmatch(page.Body.String())[1]
	csrf := fedCMCSRFPattern.FindStringSubmatch(page.Body.String())[1]
	values := url.Values{"fedcm": {"1"}, "interaction": {interaction}, "csrf_token": {csrf}, "username": {"alice"}, "password": {"correct password"}}
	post := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(values.Encode()))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://issuer.example.test")
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	post.AddCookie(init)
	response := httptest.NewRecorder()
	h.FedCMLanding(response, post)
	if response.Code != http.StatusForbidden || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	if _, err := h.browser.LoadAuthorizationInteractionReadOnly(context.Background(), init.Value, interaction); err != nil {
		t.Fatalf("forced MFA consumed interaction: %v", err)
	}
}

func interactionToken(t *testing.T, page string) string {
	t.Helper()
	match := interactionPattern.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("interaction missing from page: %s", page)
	}
	return match[1]
}

func externalAuthorization(t *testing.T, h *Handler) (*http.Cookie, string, string) {
	t.Helper()
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%q", page.Code, page.Body.String())
	}
	init := page.Result().Cookies()
	if len(init) != 1 {
		t.Fatalf("init cookies=%#v", init)
	}
	interaction := interactionToken(t, page.Body.String())
	return init[0], interaction, interactionDigest(interaction)
}

func interactionDigest(token string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(decoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func otherBrowserToken() string { return strings.Repeat("A", 43) }

func postLogin(cookie *http.Cookie, interaction, username, password string) *http.Request {
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(cookie)
	return request
}

func authenticatedCookie(t *testing.T, h *Handler) *http.Cookie {
	t.Helper()
	session, err := h.browser.CreateSession(context.Background(), "user-1", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func testHandlerWithTrustedProxies(t *testing.T) *Handler {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "login-proxy-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	password, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.BootstrapUser(ctx, "user-1", "alice", password); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	secret[0] = 1
	oauthServer, err := oauth.NewServer(ctx, db, secret, "browser-client", "0123456789abcdef", "http://localhost/callback")
	if err != nil {
		t.Fatal(err)
	}
	trustedProxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h, err := NewWithPolicyAndTrustedProxies("http://localhost", browserStore, identityStore, oauthServer, loginpolicy.NewStore(db), nil, trustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	h.wait = func(context.Context, time.Duration) error { return nil }
	h.deadline = func(http.ResponseWriter, time.Time) error { return nil }
	return h
}

func TestAuthorizeRejectsMalformedForwardedHeaderFromTrustedProxy(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "10.0.0.1:443"
	get.Header.Set("Forwarded", "for=unknown")
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", page.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeRejectsAmbiguousForwardedHeaderFromTrustedProxy(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "10.0.0.1:443"
	get.Header.Set("Forwarded", "for=203.0.113.8, for=198.51.100.9")
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", page.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeAcceptsValidForwardedFromTrustedProxy(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "10.0.0.1:443"
	get.Header.Set("Forwarded", "for=203.0.113.8;proto=https")
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", page.Code, http.StatusOK)
	}
}

func TestAuthorizeIgnoresForwardedFromUntrustedPeer(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "198.51.100.1:443"
	get.Header.Set("Forwarded", "for=203.0.113.8")
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", page.Code, http.StatusOK)
	}
}

func TestSessionIPBindingRejectsMismatchedPeer(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	// Create session bound to 203.0.113.8
	issued, err := h.browser.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// Request from a different IP — should fail
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "10.0.0.1:443"
	get.Header.Set("Forwarded", "for=198.51.100.9")
	get.AddCookie(cookie)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("status=%d want %d (mismatched IP should be treated as no session)", page.Code, http.StatusOK)
	}
	// Verify it created a new init session rather than using the mismatched one
	newCookies := page.Result().Cookies()
	if len(newCookies) == 0 {
		t.Fatal("expected new session cookie")
	}
}

func TestSessionIPBindingAcceptsMatchingPeer(t *testing.T) {
	h := testHandlerWithTrustedProxies(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	// Create unauthenticated session bound to 203.0.113.8
	issued, err := h.browser.CreateInitSession(ctx, now.Add(time.Minute), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// Request from matching IP via trusted proxy — should reuse session
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "10.0.0.1:443"
	get.Header.Set("Forwarded", "for=203.0.113.8")
	get.AddCookie(cookie)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", page.Code, http.StatusOK)
	}
	// When session is reused, the cookie is re-set with the same token.
	for _, c := range page.Result().Cookies() {
		if c.Name == "goauthy_session" && c.Value != issued.Token {
			t.Fatalf("new session cookie (value=%s) differs from original (value=%s)", c.Value, issued.Token)
		}
	}
}

func TestSessionIPBindingDirectModeRejectsMismatchedPeer(t *testing.T) {
	h := testHandler(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	// Create session bound to 203.0.113.8 (no trusted proxies — direct mode).
	issued, err := h.browser.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// Request from a different raw TCP peer — should reject the bound session.
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.RemoteAddr = "198.51.100.9:12345"
	get.AddCookie(cookie)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("status=%d want %d (direct-mode mismatch should fall through to new init session)", page.Code, http.StatusOK)
	}
	newCookies := page.Result().Cookies()
	if len(newCookies) == 0 {
		t.Fatal("expected new session cookie")
	}
	for _, c := range newCookies {
		if c.Name == "goauthy_session" && c.Value == issued.Token {
			t.Fatalf("mismatched direct-mode peer should not reuse bound session (value=%s)", c.Value)
		}
	}
}
