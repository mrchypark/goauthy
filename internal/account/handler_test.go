package account

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestPasswordHandlerChangesOnlyAuthenticatedSubject(t *testing.T) {
	t.Parallel()
	h, sessions, identities, cookie, csrf := testPasswordHandler(t)

	get := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	get.AddCookie(cookie)
	getResponse := httptest.NewRecorder()
	h.GetPassword(getResponse, get)
	var document passwordResponse
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("Cache-Control") != "no-store" || getResponse.Header().Get("Referrer-Policy") != "no-referrer" || getResponse.Header().Get("X-Content-Type-Options") != "nosniff" || json.Unmarshal(getResponse.Body.Bytes(), &document) != nil || document.CSRFToken != csrf || document.PasswordPolicy != policyResponse(testRules()) {
		t.Fatalf("password form status=%d body=%s policy=%+v", getResponse.Code, getResponse.Body.String(), document.PasswordPolicy)
	}

	change := passwordChangeRequest{Current: stringPtr("CurrentPassword1"), Next: stringPtr("UpdatedPassword2")}
	changeResponse := passwordRequest(t, h, cookie, csrf, "subject-1", change)
	if changeResponse.Code != http.StatusOK || changeResponse.Header().Get("Cache-Control") != "no-store" || changeResponse.Header().Get("Referrer-Policy") != "no-referrer" || changeResponse.Header().Get("X-Content-Type-Options") != "nosniff" || changeResponse.Body.Len() != 0 {
		t.Fatalf("password change status=%d headers=%#v body=%q", changeResponse.Code, changeResponse.Header(), changeResponse.Body.String())
	}
	if _, err := identities.Authenticate(context.Background(), "alice", []byte(*change.Current)); err != identity.ErrInvalidCredentials {
		t.Fatalf("old password remains valid: %v", err)
	}
	if got, err := identities.Authenticate(context.Background(), "alice", []byte(*change.Next)); err != nil || got.Subject != "subject-1" {
		t.Fatalf("new password authentication=%+v err=%v", got, err)
	}
	if _, err := sessions.LoadSession(context.Background(), cookie.Value); err != nil {
		t.Fatalf("self password change unexpectedly invalidated session: %v", err)
	}
}

func TestPasswordlessCookieMatchesLoginContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		issuer, name string
		secure       bool
	}{
		{"http://localhost", "goauthy-passkey", false},
		{"https://issuer.example.test", "__Host-goauthy-passkey", true},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			h := &Handler{issuer: tc.issuer}
			cookie := h.passwordlessCookie("opaque")
			if cookie.Name != tc.name || cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure != tc.secure {
				t.Fatalf("cookie=%#v", cookie)
			}
		})
	}
}

func TestRegistrationCookieMatchesHostCookieContract(t *testing.T) {
	t.Parallel()
	h := &Handler{issuer: "https://issuer.example.test"}
	cookie := h.registrationCookie("subject", "code", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	cleared := h.clearRegistrationCookie()

	for _, got := range []*http.Cookie{cookie, cleared} {
		if got.Name != "__Host-goauthy_passkey_registration" || got.Domain != "" || got.Path != "/" || !got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie=%#v", got)
		}
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("clearing cookie MaxAge=%d", cleared.MaxAge)
	}
}

func TestMFAWebAuthnStartExpiryUsesRauthyEpochSeconds(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(mfaWebAuthnStartResponse{Exp: 123})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"exp":123`)) || bytes.Contains(raw, []byte(`"exp":"`)) {
		t.Fatalf("MFA start response=%s", raw)
	}
}

func TestPasswordHandlerRejectsUntrustedOrMalformedChanges(t *testing.T) {
	t.Parallel()
	h, _, identities, cookie, csrf := testPasswordHandler(t)
	valid := passwordChangeRequest{Current: stringPtr("CurrentPassword1"), Next: stringPtr("UpdatedPassword2")}

	for _, tc := range []struct {
		name    string
		cookie  *http.Cookie
		csrf    string
		subject string
		mutate  func(*http.Request)
		want    int
	}{
		{name: "missing cookie", csrf: csrf, subject: "subject-1", want: http.StatusUnauthorized},
		{name: "wrong subject", cookie: cookie, csrf: csrf, subject: "subject-2", want: http.StatusForbidden},
		{name: "wrong csrf", cookie: cookie, csrf: "wrong", subject: "subject-1", want: http.StatusForbidden},
		{name: "cross site", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, want: http.StatusForbidden},
		{name: "wrong current", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) {
			r.Body = ioNopCloser(`{"password_current":"wrong","password_new":"UpdatedPassword2"}`)
		}, want: http.StatusUnauthorized},
		{name: "wrong content type", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, want: http.StatusBadRequest},
		{name: "unknown field", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) {
			r.Body = ioNopCloser(`{"password_current":"CurrentPassword1","password_new":"UpdatedPassword2","other":true}`)
		}, want: http.StatusBadRequest},
		{name: "trailing JSON", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) {
			r.Body = ioNopCloser(`{"password_current":"CurrentPassword1","password_new":"UpdatedPassword2"}{}`)
		}, want: http.StatusBadRequest},
		{name: "oversized password", cookie: cookie, csrf: csrf, subject: "subject-1", mutate: func(r *http.Request) {
			r.Body = ioNopCloser(`{"password_current":"CurrentPassword1","password_new":"` + string(bytes.Repeat([]byte("a"), maxPasswordLength+1)) + `"}`)
		}, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := passwordHTTP(t, tc.subject, valid)
			if tc.cookie != nil {
				request.AddCookie(tc.cookie)
			}
			request.Header.Set("X-CSRF-Token", tc.csrf)
			if tc.mutate != nil {
				tc.mutate(request)
			}
			response := httptest.NewRecorder()
			h.PutSelfPassword(response, request)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%q want=%d", response.Code, response.Body.String(), tc.want)
			}
			if got, err := identities.Authenticate(context.Background(), "alice", []byte("CurrentPassword1")); err != nil || got.Subject != "subject-1" {
				t.Fatalf("rejected request changed password: auth=%+v err=%v", got, err)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		request *http.Request
		get     bool
		want    int
	}{
		{name: "get unauthenticated", request: httptest.NewRequest(http.MethodGet, "/account/password", nil), get: true, want: http.StatusUnauthorized},
		{name: "get cross site", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/account/password", nil)
			r.AddCookie(cookie)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		}(), get: true, want: http.StatusForbidden},
		{name: "put wrong method", request: httptest.NewRequest(http.MethodPost, "/auth/v1/users/subject-1/self", nil), want: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			if tc.get {
				h.GetPassword(response, tc.request)
			} else {
				h.PutSelfPassword(response, tc.request)
			}
			if response.Code != tc.want || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("status=%d headers=%#v want=%d", response.Code, response.Header(), tc.want)
			}
		})
	}
}

func TestConvertSelfPasskey(t *testing.T) {
	t.Parallel()
	h, identities, cookie, csrf, addCredential := testConversionHandler(t)
	addCredential(t, true)

	response := conversionRequest(t, h, cookie, csrf, "subject-1", http.MethodPost, nil)
	if response.Code != http.StatusOK || response.Body.Len() != 0 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("status=%d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
	}
	if passkeyOnly, err := identities.IsPasskeyOnly(context.Background(), "subject-1"); err != nil || !passkeyOnly {
		t.Fatalf("passkey-only=%t err=%v", passkeyOnly, err)
	}
	if _, err := identities.Authenticate(context.Background(), "alice", []byte("CurrentPassword1")); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("password authentication after conversion: %v", err)
	}

	// Conversion is irreversible and the repeat has the same generic client
	// failure as any account that cannot satisfy the conversion preconditions.
	if replay := conversionRequest(t, h, cookie, csrf, "subject-1", http.MethodPost, nil); replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d body=%q", replay.Code, replay.Body.String())
	}
}

func TestConvertSelfPasskeyRequiresCurrentMFAPeerBoundSession(t *testing.T) {
	t.Parallel()
	h, _, _, _, addCredential := testConversionHandler(t)
	addCredential(t, true)
	ctx := context.Background()
	now := time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name, method, peer, requestPeer string
	}{
		{name: "password session", method: "pwd", peer: "203.0.113.8", requestPeer: "203.0.113.8"},
		{name: "legacy empty peer", method: "mfa", peer: "", requestPeer: "203.0.113.8"},
		{name: "mismatched peer", method: "mfa", peer: "203.0.113.8", requestPeer: "198.51.100.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued, err := h.browser.CreateSession(ctx, "subject-1", tc.method, now, tc.peer)
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			csrf, err := browser.DeriveCSRFToken(issued.Token)
			if err != nil {
				t.Fatal(err)
			}
			response := conversionRequestWithPeer(t, h, cookie, csrf, "subject-1", tc.requestPeer)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			passkeyOnly, err := h.identity.IsPasskeyOnly(ctx, "subject-1")
			if err != nil || passkeyOnly {
				t.Fatalf("conversion occurred: passkey-only=%t err=%v", passkeyOnly, err)
			}
		})
	}
}

func TestConvertSelfPasskeyRejectsUntrustedOrInvalidRequests(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		subject      string
		csrf         string
		method       string
		body         []byte
		crossSite    bool
		credentialUV *bool
		want         int
	}{
		{name: "different subject", subject: "subject-2", method: http.MethodPost, want: http.StatusForbidden},
		{name: "missing csrf", subject: "subject-1", method: http.MethodPost, want: http.StatusUnauthorized},
		{name: "cross site", subject: "subject-1", method: http.MethodPost, crossSite: true, want: http.StatusForbidden},
		{name: "wrong method", subject: "subject-1", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "body rejected", subject: "subject-1", method: http.MethodPost, body: []byte(`{}`), want: http.StatusBadRequest},
		{name: "trailing body rejected", subject: "subject-1", method: http.MethodPost, body: []byte(" \n"), want: http.StatusBadRequest},
		{name: "no passkey", subject: "subject-1", method: http.MethodPost, credentialUV: nil, want: http.StatusBadRequest},
		{name: "no user verification", subject: "subject-1", method: http.MethodPost, credentialUV: boolPtr(false), want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, identities, cookie, csrf, addCredential := testConversionHandler(t)
			if tc.credentialUV != nil {
				addCredential(t, *tc.credentialUV)
			}
			if tc.csrf == "" && tc.name != "missing csrf" {
				tc.csrf = csrf
			}
			fetchSite := "same-origin"
			if tc.crossSite {
				// The production SameSite cookie is defense in depth; Fetch Metadata
				// rejects a cross-site request before the mutation boundary.
				fetchSite = "cross-site"
			}
			response := conversionRequestWithFetchSite(t, h, cookie, tc.csrf, tc.subject, tc.method, tc.body, fetchSite)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%q want=%d", response.Code, response.Body.String(), tc.want)
			}
			if passkeyOnly, err := identities.IsPasskeyOnly(context.Background(), "subject-1"); err != nil || passkeyOnly {
				t.Fatalf("rejected request converted account: passkey-only=%t err=%v", passkeyOnly, err)
			}
		})
	}
}

func TestExternalLinkAccountBoundary(t *testing.T) {
	t.Parallel()
	h, sessions, identities, cookie, csrf := testPasswordHandler(t)
	ctx := context.Background()

	request := func(method, provider string, body []byte, sessionCookie *http.Cookie, token string) *http.Request {
		r := httptest.NewRequest(method, "/auth/v1/providers/"+provider+"/link", bytes.NewReader(body))
		if sessionCookie != nil {
			r.AddCookie(sessionCookie)
		}
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.SetPathValue("providerID", provider)
		return r
	}
	call := func(method, provider string, body []byte, sessionCookie *http.Cookie, token string, unlink bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		if unlink {
			h.UnlinkExternal(w, request(method, provider, body, sessionCookie, token))
		} else {
			h.StartExternalLink(w, request(method, provider, body, sessionCookie, token))
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security headers=%#v", w.Header())
		}
		return w
	}

	if got := call(http.MethodPost, "google", nil, cookie, csrf, false).Code; got != http.StatusNotFound {
		t.Fatalf("unconfigured status=%d", got)
	}
	delegated := false
	if err := h.ConfigureExternalLinks(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delegated = r.Method == http.MethodPost && r.PathValue("providerID") == "google"
		w.WriteHeader(http.StatusAccepted)
	}), []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if err := h.ConfigureExternalLinks(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), []string{" Google"}); err == nil {
		t.Fatal("non-canonical provider accepted")
	}
	fixedNow := time.Date(2099, time.January, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return fixedNow }
	h.random = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i + 1)
		}
		return len(p), nil
	}

	for _, tc := range []struct {
		name, method, provider, token string
		cookie                        *http.Cookie
		body                          []byte
		crossSite                     bool
		want                          int
	}{
		{name: "wrong method", method: http.MethodGet, provider: "google", cookie: cookie, token: csrf, want: http.StatusMethodNotAllowed},
		{name: "cross site", method: http.MethodPost, provider: "google", cookie: cookie, token: csrf, crossSite: true, want: http.StatusForbidden},
		{name: "missing cookie", method: http.MethodPost, provider: "google", token: csrf, want: http.StatusUnauthorized},
		{name: "wrong issuer cookie", method: http.MethodPost, provider: "google", cookie: &http.Cookie{Name: "other-session", Value: cookie.Value}, token: csrf, want: http.StatusUnauthorized},
		{name: "wrong cookie", method: http.MethodPost, provider: "google", cookie: &http.Cookie{Name: cookie.Name, Value: "wrong"}, token: csrf, want: http.StatusUnauthorized},
		{name: "wrong csrf", method: http.MethodPost, provider: "google", cookie: cookie, token: "wrong", want: http.StatusForbidden},
		{name: "unknown provider", method: http.MethodPost, provider: "github", cookie: cookie, token: csrf, want: http.StatusNotFound},
		{name: "body", method: http.MethodPost, provider: "google", cookie: cookie, token: csrf, body: []byte(`{}`), want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(tc.method, tc.provider, tc.body, tc.cookie, tc.token)
			if tc.crossSite {
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			w := httptest.NewRecorder()
			h.StartExternalLink(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
	if got := call(http.MethodPost, "google", nil, cookie, csrf, false).Code; got != http.StatusAccepted || !delegated {
		t.Fatalf("delegated status=%d called=%t", got, delegated)
	}

	peerIssued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	peerCookie, err := browser.SessionCookie("https://issuer.example.test", peerIssued.Token, peerIssued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	peerCSRF, err := browser.DeriveCSRFToken(peerIssued.Token)
	if err != nil {
		t.Fatal(err)
	}
	peerRequest := request(http.MethodPost, "google", nil, peerCookie, peerCSRF).WithContext(browser.ContextWithPeerIP(ctx, "192.0.2.2"))
	peerResponse := httptest.NewRecorder()
	h.StartExternalLink(peerResponse, peerRequest)
	if peerResponse.Code != http.StatusUnauthorized {
		t.Fatalf("peer mismatch status=%d", peerResponse.Code)
	}

	if _, err := identities.LinkExternal(ctx, "subject-1", upstreamprovider.SubjectResult{ProviderID: "google", Subject: "external-1"}, fixedNow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"present", "absent"} {
		t.Run("unlink "+name, func(t *testing.T) {
			if got := call(http.MethodDelete, "google", nil, cookie, csrf, true).Code; got != http.StatusNoContent {
				t.Fatalf("unlink status=%d", got)
			}
		})
	}
	if _, found, err := identities.FindExternalLink(ctx, upstreamprovider.SubjectResult{ProviderID: "google", Subject: "external-1"}); err != nil || found {
		t.Fatalf("external link found=%t err=%v", found, err)
	}
	for _, tc := range []struct {
		name   string
		random func([]byte) (int, error)
	}{
		{name: "short entropy", random: func([]byte) (int, error) { return 15, nil }},
		{name: "entropy error", random: func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: tc.name}
			if _, err := identities.LinkExternal(ctx, "subject-1", external, fixedNow); err != nil {
				t.Fatal(err)
			}
			h.random = tc.random
			if got := call(http.MethodDelete, "google", nil, cookie, csrf, true).Code; got != http.StatusServiceUnavailable {
				t.Fatalf("unlink status=%d", got)
			}
			if _, found, err := identities.FindExternalLink(ctx, external); err != nil || !found {
				t.Fatalf("external link found=%t err=%v", found, err)
			}
			h.random = func(p []byte) (int, error) { return len(p), nil }
			if got := call(http.MethodDelete, "google", nil, cookie, csrf, true).Code; got != http.StatusNoContent {
				t.Fatalf("cleanup unlink status=%d", got)
			}
		})
	}
	if _, err := sessions.LoadSession(ctx, cookie.Value); err != nil {
		t.Fatalf("unlink invalidated session: %v", err)
	}
}

func TestExternalLinkUnlinkAllowsPasskeyOnlyAccount(t *testing.T) {
	t.Parallel()
	h, identities, cookie, csrf, addCredential := testConversionHandler(t)
	ctx := context.Background()
	addCredential(t, true)
	if err := identities.ConvertToPasskeyOnly(ctx, "subject-1"); err != nil {
		t.Fatal(err)
	}
	if passkeyOnly, err := identities.IsPasskeyOnly(ctx, "subject-1"); err != nil || !passkeyOnly {
		t.Fatalf("passkey-only=%t err=%v", passkeyOnly, err)
	}
	if err := h.ConfigureExternalLinks(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), []string{"google"}); err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return time.Date(2099, time.January, 2, 3, 4, 5, 0, time.UTC) }
	h.random = func(p []byte) (int, error) { return len(p), nil }
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "passkey-only"}
	if _, err := identities.LinkExternal(ctx, "subject-1", external, h.now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/google/link", nil)
	request = request.WithContext(browser.ContextWithPeerIP(request.Context(), "203.0.113.8"))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.SetPathValue("providerID", "google")
	response := httptest.NewRecorder()
	h.UnlinkExternal(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("unlink status=%d", response.Code)
	}
	if _, found, err := identities.FindExternalLink(ctx, external); err != nil || found {
		t.Fatalf("external link found=%t err=%v", found, err)
	}
	sessionResponse := httptest.NewRecorder()
	sessionRequest := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	sessionRequest = sessionRequest.WithContext(browser.ContextWithPeerIP(sessionRequest.Context(), "203.0.113.8"))
	sessionRequest.AddCookie(cookie)
	h.GetPassword(sessionResponse, sessionRequest)
	if sessionResponse.Code != http.StatusOK {
		t.Fatalf("session status=%d", sessionResponse.Code)
	}
}

func TestCurrentExternalLinkSession(t *testing.T) {
	t.Parallel()
	h, db, _, cookie, _, passwordSession := testPasskeyAccountHandler(t)
	ctx := context.Background()
	request := func(cookie *http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/upstream/google/callback", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}
	assertSession := func(t *testing.T, cookie *http.Cookie, want browser.Session) {
		t.Helper()
		subject, token, digest, err := h.CurrentExternalLinkSession(request(cookie))
		if err != nil || subject != want.Subject || token != cookie.Value || digest != want.ID {
			t.Fatalf("subject=%q token=%q digest=%q err=%v", subject, token, digest, err)
		}
	}

	t.Run("password", func(t *testing.T) { assertSession(t, cookie, passwordSession) })
	passkeySession, err := h.browser.CreateSession(ctx, "subject-1", "webauthn", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	passkeyCookie, err := browser.SessionCookie("https://issuer.example.test", passkeySession.Token, passkeySession.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("passkey", func(t *testing.T) { assertSession(t, passkeyCookie, passkeySession.Session) })

	for _, tc := range []struct {
		name    string
		request *http.Request
	}{
		{name: "missing cookie", request: request(nil)},
		{name: "init session", request: func() *http.Request {
			init, err := h.browser.CreateInitSession(ctx, time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
			if err != nil {
				t.Fatal(err)
			}
			initCookie, err := browser.SessionCookie("https://issuer.example.test", init.Token, init.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			return request(initCookie)
		}()},
		{name: "peer mismatch", request: func() *http.Request {
			issued, err := h.browser.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			peerCookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			return request(peerCookie).WithContext(browser.ContextWithPeerIP(ctx, "192.0.2.2"))
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := h.CurrentExternalLinkSession(tc.request); !errors.Is(err, ErrExternalLinkSession) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	if err := h.browser.RevokeSession(ctx, cookie.Value); err != nil {
		t.Fatal(err)
	}
	t.Run("revoked", func(t *testing.T) {
		if _, _, _, err := h.CurrentExternalLinkSession(request(cookie)); !errors.Is(err, ErrExternalLinkSession) {
			t.Fatalf("err=%v", err)
		}
	})
	expiredToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiredDigest, err := browser.CanonicalTokenDigest(expiredToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-external-link-expired-session", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES (?,?,?,?,?,?,?)`, Args: []any{expiredDigest, "subject-1", "pwd", int64(0), int64(1), int64(0), ""}}); err != nil {
		t.Fatal(err)
	}
	t.Run("expired", func(t *testing.T) {
		expiredCookie := &http.Cookie{Name: cookie.Name, Value: expiredToken}
		if _, _, _, err := h.CurrentExternalLinkSession(request(expiredCookie)); !errors.Is(err, ErrExternalLinkSession) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestExternalLinkUnlinkRejectsDisabledSessionSubject(t *testing.T) {
	t.Parallel()
	h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
	ctx := context.Background()
	if err := h.ConfigureExternalLinks(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), []string{"google"}); err != nil {
		t.Fatal(err)
	}
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "disabled-session"}
	if _, err := h.identity.LinkExternal(ctx, "subject-1", external, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-disable-before-unlink", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/google/link", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	request.SetPathValue("providerID", "google")
	response := httptest.NewRecorder()
	h.UnlinkExternal(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unlink status=%d", response.Code)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_external_links WHERE provider_id = ? AND local_subject = ?`, Args: []any{"google", "subject-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("link rows=%#v err=%v", result.Rows, err)
	}
}

func TestPasskeyCrossSiteRequestsDoNotMutateState(t *testing.T) {
	t.Parallel()
	h, db, service, cookie, csrf, session := testPasskeyAccountHandler(t)
	ctx := context.Background()

	t.Run("modification token", func(t *testing.T) {
		response := httptest.NewRecorder()
		h.IssueModificationToken(response, passkeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/mfa_token", "subject-1", cookie, csrf, []byte(`{"password":"CurrentPassword1"}`)))
		if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`) != 0 {
			t.Fatalf("status=%d tokens=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`))
		}
	})

	t.Run("registration start", func(t *testing.T) {
		token, _, err := service.IssueModificationToken(ctx, "subject-1", session.ID)
		if err != nil {
			t.Fatal(err)
		}
		beforeTokens := tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`)
		beforeCeremonies := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies`)
		body, _ := json.Marshal(registrationStartRequest{Name: "platform", Token: token})
		response := httptest.NewRecorder()
		h.BeginPasskeyRegistration(response, passkeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/webauthn/register/start", "subject-1", cookie, csrf, body))
		if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`) != beforeTokens || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies`) != beforeCeremonies {
			t.Fatalf("status=%d tokens=%d ceremonies=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`), tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies`))
		}
	})

	t.Run("registration finish", func(t *testing.T) {
		_, code, _, err := service.BeginRegistration(ctx, "subject-1", "alice", "finish", session.ID)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(registrationFinishRequest{Name: "finish", Data: json.RawMessage(`{}`)})
		request := passkeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/webauthn/register/finish", "subject-1", cookie, csrf, body)
		request.AddCookie(h.registrationCookie("subject-1", code, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)))
		response := httptest.NewRecorder()
		h.FinishPasskeyRegistration(response, request)
		if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials`) != 0 || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies WHERE passkey_name = 'finish' AND consumed_attempt IS NOT NULL`) != 0 {
			t.Fatalf("status=%d credentials=%d consumed=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials`), tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies WHERE passkey_name = 'finish' AND consumed_attempt IS NOT NULL`))
		}
	})

	t.Run("delete", func(t *testing.T) {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-cross-site-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"delete-credential", "subject-1", "delete", "opaque", int64(0), int64(1), int64(0), int64(0)}}); err != nil {
			t.Fatal(err)
		}
		beforeTokens := tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`)
		body, _ := json.Marshal(modificationRequest{Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
		request := passkeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1/webauthn/delete/delete", "subject-1", cookie, csrf, body)
		request.SetPathValue("name", "delete")
		response := httptest.NewRecorder()
		h.DeletePasskey(response, request)
		if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id = 'delete-credential'`) != 1 || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`) != beforeTokens {
			t.Fatalf("status=%d credentials=%d tokens=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id = 'delete-credential'`), tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`))
		}
	})
}

func TestIssueModificationTokenEnforcesRauthyFactorSelection(t *testing.T) {
	t.Parallel()
	validProof := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name            string
		credential      bool
		body            string
		want            int
		wantTokenChange bool
	}{
		{name: "password only account accepts password", body: `{"password":"CurrentPassword1"}`, want: http.StatusOK, wantTokenChange: true},
		{name: "password only rejects mfa proof", body: `{"mfa_code":"` + validProof + `"}`, want: http.StatusBadRequest},
		{name: "password only rejects both factors", body: `{"password":"CurrentPassword1","mfa_code":"` + validProof + `"}`, want: http.StatusBadRequest},
		{name: "password only rejects neither factor", body: `{}`, want: http.StatusBadRequest},
		{name: "password only rejects malformed payload", body: `{"password":"CurrentPassword1","other":true}`, want: http.StatusBadRequest},
		{name: "passkey account rejects password downgrade", credential: true, body: `{"password":"CurrentPassword1"}`, want: http.StatusBadRequest},
		{name: "passkey account rejects unissued proof", credential: true, body: `{"mfa_code":"` + validProof + `"}`, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
			if tc.credential {
				seedAccountCredential(t, db, "factor-credential", "factor")
			}
			before := tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`)
			response := httptest.NewRecorder()
			h.IssueModificationToken(response, sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/mfa_token", "subject-1", cookie, csrf, []byte(tc.body)))
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%q want=%d", response.Code, response.Body.String(), tc.want)
			}
			after := tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`)
			if tc.wantTokenChange && after != before+1 {
				t.Fatalf("token count=%d want=%d", after, before+1)
			}
			if !tc.wantTokenChange && after != before {
				t.Fatalf("rejected factor mutated tokens: before=%d after=%d", before, after)
			}
		})
	}
}

func TestMFAWebAuthnHandlersRejectUntrustedAndMalformedRequestsWithoutState(t *testing.T) {
	t.Parallel()
	validCode := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name    string
		finish  bool
		subject string
		csrf    string
		cookie  bool
		cross   bool
		body    string
		want    int
	}{
		{name: "start wrong purpose", subject: "subject-1", body: `{"purpose":"Login"}`, want: http.StatusBadRequest},
		{name: "start strict unknown field", subject: "subject-1", body: `{"purpose":"MfaModToken","other":true}`, want: http.StatusBadRequest},
		{name: "start no credential", subject: "subject-1", body: `{"purpose":"MfaModToken"}`, want: http.StatusBadRequest},
		{name: "start wrong account", subject: "subject-2", body: `{"purpose":"MfaModToken"}`, want: http.StatusForbidden},
		{name: "start missing session", subject: "subject-1", body: `{"purpose":"MfaModToken"}`, want: http.StatusUnauthorized},
		{name: "start invalid csrf", subject: "subject-1", csrf: "wrong", body: `{"purpose":"MfaModToken"}`, want: http.StatusForbidden},
		{name: "start cross site", subject: "subject-1", cross: true, body: `{"purpose":"MfaModToken"}`, want: http.StatusForbidden},
		{name: "finish malformed code", finish: true, subject: "subject-1", body: `{"code":"short","data":{}}`, want: http.StatusBadRequest},
		{name: "finish trailing JSON", finish: true, subject: "subject-1", body: `{"code":"` + validCode + `","data":{}}{}`, want: http.StatusBadRequest},
		{name: "finish cross site", finish: true, subject: "subject-1", cross: true, body: `{"code":"` + validCode + `","data":{}}`, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
			if tc.csrf != "" {
				csrf = tc.csrf
			}
			if !tc.cookie && tc.name == "start missing session" {
				cookie = nil
			}
			beforeCeremonies := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_ceremonies`)
			beforeProofs := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs`)
			request := sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/"+tc.subject+"/webauthn/auth", tc.subject, cookie, csrf, []byte(tc.body))
			if tc.cross {
				request.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			response := httptest.NewRecorder()
			if tc.finish {
				h.FinishMFAWebAuthn(response, request)
			} else {
				h.BeginMFAWebAuthn(response, request)
			}
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%q want=%d", response.Code, response.Body.String(), tc.want)
			}
			if got := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_ceremonies`); got != beforeCeremonies {
				t.Fatalf("ceremonies mutated: before=%d after=%d", beforeCeremonies, got)
			}
			if got := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs`); got != beforeProofs {
				t.Fatalf("proofs mutated: before=%d after=%d", beforeProofs, got)
			}
		})
	}
}

func TestPutSelfPasswordPasskeyOnlyRequiresPasswordNewProof(t *testing.T) {
	t.Parallel()
	h, db, _, cookie, csrf, session := testPasskeyAccountHandler(t)
	seedAccountCredential(t, db, "reverse-credential", "reverse")
	if err := h.identity.ConvertToPasskeyOnly(context.Background(), "subject-1"); err != nil {
		t.Fatal(err)
	}

	proof := strings.Repeat("a", 48)
	seedServiceProof(t, db, proof, "MfaModToken", session.ID)
	response := passwordRawRequest(t, h, cookie, csrf, "subject-1", `{"mfa_code":"`+proof+`","password_new":"UpdatedPassword2"}`)
	if response.Code != http.StatusBadRequest || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs WHERE code_digest = '`+codeDigest(proof)+`' AND consumed_attempt IS NULL`) != 1 {
		t.Fatalf("cross-purpose status=%d body=%q", response.Code, response.Body.String())
	}

	proof = strings.Repeat("b", 48)
	seedServiceProof(t, db, proof, "PasswordNew", session.ID)
	response = passwordRawRequest(t, h, cookie, csrf, "subject-1", `{"mfa_code":"`+proof+`","password_new":"UpdatedPassword2"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("reverse status=%d body=%q", response.Code, response.Body.String())
	}
	if got, err := h.identity.Authenticate(context.Background(), "alice", []byte("UpdatedPassword2")); err != nil || got.Subject != "subject-1" {
		t.Fatalf("new password authentication=%+v err=%v", got, err)
	}
	if _, err := h.browser.LoadSession(context.Background(), cookie.Value); err != nil {
		t.Fatalf("reverse conversion invalidated established session: %v", err)
	}
}

func TestPutSelfPasswordPasskeyOnlyRejectsInvalidFormsWithoutProofMutation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		subject string
		csrf    string
		cross   bool
		content []string
		body    string
		want    int
	}{
		{name: "password factor", subject: "subject-1", body: `{"password_current":"CurrentPassword1","password_new":"UpdatedPassword2"}`, want: http.StatusBadRequest},
		{name: "both factors", subject: "subject-1", body: `{"password_current":"CurrentPassword1","mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2"}`, want: http.StatusBadRequest},
		{name: "neither factor", subject: "subject-1", body: `{"password_new":"UpdatedPassword2"}`, want: http.StatusBadRequest},
		{name: "empty proof", subject: "subject-1", body: `{"mfa_code":"","password_new":"UpdatedPassword2"}`, want: http.StatusBadRequest},
		{name: "empty new password", subject: "subject-1", body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":""}`, want: http.StatusBadRequest},
		{name: "unknown field", subject: "subject-1", body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2","other":true}`, want: http.StatusBadRequest},
		{name: "duplicate content type", subject: "subject-1", content: []string{"application/json", "application/json"}, body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2"}`, want: http.StatusBadRequest},
		{name: "cross site", subject: "subject-1", cross: true, body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2"}`, want: http.StatusForbidden},
		{name: "wrong subject", subject: "subject-2", body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2"}`, want: http.StatusForbidden},
		{name: "wrong csrf", subject: "subject-1", csrf: "wrong", body: `{"mfa_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password_new":"UpdatedPassword2"}`, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _, cookie, csrf, session := testPasskeyAccountHandler(t)
			seedAccountCredential(t, db, "invalid-"+tc.name, "invalid")
			if err := h.identity.ConvertToPasskeyOnly(context.Background(), "subject-1"); err != nil {
				t.Fatal(err)
			}
			proof := strings.Repeat("c", 48)
			seedServiceProof(t, db, proof, "PasswordNew", session.ID)
			if tc.csrf != "" {
				csrf = tc.csrf
			}
			request := passwordRawHTTP(t, tc.subject, tc.body)
			request.AddCookie(cookie)
			request.Header.Set("X-CSRF-Token", csrf)
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			if tc.cross {
				request.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			if tc.content != nil {
				request.Header.Del("Content-Type")
				for _, contentType := range tc.content {
					request.Header.Add("Content-Type", contentType)
				}
			}
			response := httptest.NewRecorder()
			h.PutSelfPassword(response, request)
			if response.Code != tc.want || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs WHERE code_digest = '`+codeDigest(proof)+`' AND consumed_attempt IS NULL`) != 1 {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestModificationProofCannotCrossBrowserSessions(t *testing.T) {
	t.Parallel()
	h, db, _, _, _, original := testPasskeyAccountHandler(t)
	seedAccountCredential(t, db, "proof-credential", "proof")
	proof := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest := codeDigest(proof)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-session-bound-proof", SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digest, "subject-1", original.ID, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	otherStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	other, err := otherStore.CreateSession(context.Background(), "subject-1", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", other.Token, other.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(other.Token)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.IssueModificationToken(response, sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/mfa_token", "subject-1", cookie, csrf, []byte(`{"mfa_code":"`+proof+`"}`)))
	if response.Code != http.StatusBadRequest || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`) != 0 || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs WHERE consumed_attempt IS NOT NULL`) != 0 {
		t.Fatalf("status=%d tokens=%d consumed=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`), tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_mfa_proofs WHERE consumed_attempt IS NOT NULL`))
	}
}

func TestMFAModificationRejectsAmbiguousContentTypeWithoutMutation(t *testing.T) {
	t.Parallel()
	h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
	request := sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/mfa_token", "subject-1", cookie, csrf, []byte(`{"password":"CurrentPassword1"}`))
	request.Header.Add("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.IssueModificationToken(response, request)
	if response.Code != http.StatusBadRequest || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`) != 0 {
		t.Fatalf("status=%d tokens=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens`))
	}
}

func TestPasskeyMutationsRejectDuplicateJSONKeysWithoutStateChange(t *testing.T) {
	t.Parallel()
	t.Run("delete modification token", func(t *testing.T) {
		h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		seedAccountCredential(t, db, "duplicate-delete", "duplicate-delete")
		request := sameOriginPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1/webauthn/delete/duplicate-delete", "subject-1", cookie, csrf, []byte(`{"mfa_mod_token_id":"first","mfa_mod_token_id":"second"}`))
		request.SetPathValue("name", "duplicate-delete")
		response := httptest.NewRecorder()
		h.DeletePasskey(response, request)
		if response.Code != http.StatusUnauthorized || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id = 'duplicate-delete'`) != 1 {
			t.Fatalf("status=%d credentials=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id = 'duplicate-delete'`))
		}
	})

	t.Run("registration passkey name", func(t *testing.T) {
		h, db, service, cookie, csrf, session := testPasskeyAccountHandler(t)
		token, _, err := service.IssueModificationToken(context.Background(), "subject-1", session.ID)
		if err != nil {
			t.Fatal(err)
		}
		request := sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/webauthn/register/start", "subject-1", cookie, csrf, []byte(`{"passkey_name":"first","passkey_name":"second","mfa_mod_token_id":"`+token+`"}`))
		response := httptest.NewRecorder()
		h.BeginPasskeyRegistration(response, request)
		if response.Code != http.StatusUnauthorized || tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`) != 1 || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies`) != 0 {
			t.Fatalf("status=%d tokens=%d ceremonies=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE consumed_attempt IS NULL`), tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies`))
		}
	})

	t.Run("registration assertion data", func(t *testing.T) {
		h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		request := sameOriginPasskeyRequest(t, http.MethodPost, "/auth/v1/users/subject-1/webauthn/register/finish", "subject-1", cookie, csrf, []byte(`{"passkey_name":"finish","data":{"credential":{"id":"first","id":"second"}}}`))
		response := httptest.NewRecorder()
		h.FinishPasskeyRegistration(response, request)
		if response.Code != http.StatusUnauthorized || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials`) != 0 || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies WHERE consumed_attempt IS NOT NULL`) != 0 {
			t.Fatalf("status=%d credentials=%d consumed=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials`), tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_ceremonies WHERE consumed_attempt IS NOT NULL`))
		}
	})
}

func TestValidPasskeyNameMatchesRauthyPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ascii", value: "Laptop-2026", want: true},
		{name: "latin extended whitespace apostrophe", value: "Àɏ ' key\u00a0", want: true},
		{name: "32 runes", value: "éééééééééééééééééééééééééééééééé", want: true},
		{name: "33 runes", value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", want: false},
		{name: "combining mark", value: "e\u0301", want: false},
		{name: "outside latin range", value: "\u0250", want: false},
		{name: "legacy underscore", value: "old_name", want: false},
		{name: "invalid utf8", value: string([]byte{0xff}), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validPasskeyName(tc.value); got != tc.want {
				t.Fatalf("validPasskeyName(%q)=%t want=%t", tc.value, got, tc.want)
			}
		})
	}
}

func TestPasskeyAdminAndAPIKeyBoundaries(t *testing.T) {
	t.Parallel()
	h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
	seedAccountCredential(t, db, "credential-api", "api-key")
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "users-reader", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	rbacStore := rbac.NewStore(db)
	if _, err := rbacStore.EnsureBootstrapPrincipal(context.Background(), "subject-1", []string{rbac.AdminRole}, nil); err != nil {
		t.Fatal(err)
	}
	h.ConfigurePasskeyAdministrators(keys, rbacStore.IsAdmin)

	apiGet := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/webauthn", nil)
	apiGet.SetPathValue("subject", "subject-1")
	apiGet.Header.Set("Authorization", "API-Key "+token)
	apiResponse := httptest.NewRecorder()
	h.ListPasskeys(apiResponse, apiGet)
	if apiResponse.Code != http.StatusOK || !strings.Contains(apiResponse.Body.String(), `"name":"api-key"`) {
		t.Fatalf("API read status=%d body=%s", apiResponse.Code, apiResponse.Body.String())
	}

	for _, tc := range []struct {
		name    string
		request *http.Request
		want    int
	}{
		{name: "malformed authorization cannot use cookie", request: func() *http.Request {
			r := passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodGet, nil)
			r.Header.Set("Authorization", "Bearer nope")
			return r
		}(), want: http.StatusUnauthorized},
		{name: "multiple authorization cannot use cookie", request: func() *http.Request {
			r := passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodGet, nil)
			r.Header.Add("Authorization", "API-Key "+token)
			r.Header.Add("Authorization", "API-Key "+token)
			return r
		}(), want: http.StatusUnauthorized},
		{name: "query rejected", request: func() *http.Request {
			r := passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodGet, nil)
			r.URL.RawQuery = "x=1"
			return r
		}(), want: http.StatusForbidden},
		{name: "cross site rejected", request: func() *http.Request {
			r := passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodGet, nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		}(), want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ListPasskeys(response, tc.request)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	apiDelete := httptest.NewRequest(http.MethodDelete, "/auth/v1/users/subject-1/webauthn/delete/api-key", nil)
	apiDelete.SetPathValue("subject", "subject-1")
	apiDelete.Header.Set("Authorization", "API-Key "+token)
	response := httptest.NewRecorder()
	h.DeletePasskey(response, apiDelete)
	if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-api'`) != 1 {
		t.Fatalf("API delete status=%d credentials=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-api'`))
	}
	selfAdminDelete := passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodDelete, nil)
	selfAdminDelete.SetPathValue("name", "api-key")
	response = httptest.NewRecorder()
	h.DeletePasskey(response, selfAdminDelete)
	if response.Code != http.StatusUnauthorized || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-api'`) != 1 {
		t.Fatalf("self admin reset status=%d credentials=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-api'`))
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-admin-reset-target", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"credential-target", "subject-2", "final-uv", "opaque", int64(0), int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	missingCSRF := passkeyBrowserRequest(cookie, "", "subject-2", http.MethodDelete, nil)
	missingCSRF.SetPathValue("name", "final-uv")
	response = httptest.NewRecorder()
	h.DeletePasskey(response, missingCSRF)
	if response.Code != http.StatusForbidden || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-target'`) != 1 {
		t.Fatalf("admin reset without CSRF status=%d credentials=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-target'`))
	}

	// Rauthy's admin reset intentionally deletes even the final UV passkey.
	// The target may therefore need administrator recovery before passkey-only login works again.
	adminDelete := passkeyBrowserRequest(cookie, csrf, "subject-2", http.MethodDelete, nil)
	adminDelete.SetPathValue("name", "final-uv")
	response = httptest.NewRecorder()
	h.DeletePasskey(response, adminDelete)
	if response.Code != http.StatusOK || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-target'`) != 0 {
		t.Fatalf("admin reset status=%d credentials=%d", response.Code, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-target'`))
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-admin-reset-revoked-target", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"credential-revoked", "subject-2", "revoked-final", "opaque", int64(0), int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
	// This completed replicated mutation is the deterministic revocation barrier:
	// the following reset must evaluate the revoked role in its own DELETE CAS.
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-admin-reset-revoke-role", SQL: `DELETE FROM rbac_user_roles WHERE subject=?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.passkeys.DeleteForAdministrator(context.Background(), "subject-1", "subject-2", "revoked-final"); err == nil || tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-revoked'`) != 1 {
		t.Fatalf("revoked admin reset err=%v credentials=%d", err, tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE credential_id='credential-revoked'`))
	}
}

func TestUserDeletionHTTPBoundaries(t *testing.T) {
	t.Parallel()
	t.Run("DELETE rejects browser boundary violations without mutation", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			admin       bool
			auth        []string
			csrf        string
			missingCSRF bool
			crossSite   bool
			query       bool
			body        []byte
			want        int
		}{
			{name: "admin malformed authorization", admin: true, auth: []string{"Bearer nope"}, want: http.StatusUnauthorized},
			{name: "admin multiple authorization", admin: true, auth: []string{"Bearer nope", "Bearer nope"}, want: http.StatusUnauthorized},
			{name: "admin missing csrf", admin: true, missingCSRF: true, want: http.StatusForbidden},
			{name: "admin wrong csrf", admin: true, csrf: "wrong", want: http.StatusForbidden},
			{name: "admin cross site", admin: true, crossSite: true, want: http.StatusForbidden},
			{name: "admin query", admin: true, query: true, want: http.StatusForbidden},
			{name: "admin non-empty body", admin: true, body: []byte(`{}`), want: http.StatusBadRequest},
			{name: "self missing csrf", missingCSRF: true, want: http.StatusForbidden},
			{name: "self wrong csrf", csrf: "wrong", want: http.StatusForbidden},
			{name: "self cross site", crossSite: true, want: http.StatusForbidden},
			{name: "self query", query: true, want: http.StatusForbidden},
			{name: "self non-empty body", body: []byte(`{}`), want: http.StatusBadRequest},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
				if tc.admin {
					rbacStore := rbac.NewStore(db)
					if _, err := rbacStore.EnsureBootstrapPrincipal(context.Background(), "subject-1", []string{rbac.AdminRole}, nil); err != nil {
						t.Fatal(err)
					}
					h.ConfigurePasskeyAdministrators(nil, rbacStore.IsAdmin)
				} else {
					h.ConfigurePasskeyAdministrators(nil, func(context.Context, string) (bool, error) { return false, nil })
					h.ConfigureSelfDelete(true)
				}
				if tc.missingCSRF {
					csrf = ""
				} else if tc.csrf != "" {
					csrf = tc.csrf
				}
				path := "/auth/v1/users/subject-1"
				if !tc.admin {
					path += "/self/delete"
				}
				r := accountPasskeyRequest(t, http.MethodDelete, path, "subject-1", cookie, csrf, tc.body, "same-origin")
				if tc.crossSite {
					r.Header.Set("Sec-Fetch-Site", "cross-site")
				}
				if tc.query {
					r.URL.RawQuery = "x=1"
				}
				for _, value := range tc.auth {
					r.Header.Add("Authorization", value)
				}
				response := httptest.NewRecorder()
				if tc.admin {
					h.DeleteUser(response, r)
				} else {
					h.SelfDelete(response, r)
				}
				if response.Code != tc.want || tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`) != 1 || response.Header().Get("Set-Cookie") != "" {
					t.Fatalf("status=%d want=%d users=%d set-cookie=%q", response.Code, tc.want, tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`), response.Header().Get("Set-Cookie"))
				}
			})
		}
	})

	t.Run("admin deleting self with another admin clears cookie", func(t *testing.T) {
		h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-second-admin", SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES ('subject-2','bob','phc')`, Args: nil}); err != nil {
			t.Fatal(err)
		}
		rbacStore := rbac.NewStore(db)
		if _, err := rbacStore.EnsureBootstrapPrincipal(context.Background(), "subject-1", []string{rbac.AdminRole}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := rbacStore.EnsureBootstrapPrincipal(context.Background(), "subject-2", []string{rbac.AdminRole}, nil); err != nil {
			t.Fatal(err)
		}
		h.ConfigurePasskeyAdministrators(nil, rbacStore.IsAdmin)
		r := accountPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1", "subject-1", cookie, csrf, nil, "same-origin")
		response := httptest.NewRecorder()
		h.DeleteUser(response, r)
		if response.Code != http.StatusNoContent || !strings.Contains(response.Header().Get("Set-Cookie"), "Max-Age=0") || tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`) != 0 {
			t.Fatalf("status=%d set-cookie=%q users=%d", response.Code, response.Header().Get("Set-Cookie"), tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`))
		}
	})

	t.Run("self is default off", func(t *testing.T) {
		h, _, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		r := accountPasskeyRequest(t, http.MethodGet, "/auth/v1/users/subject-1/self/delete", "subject-1", cookie, csrf, nil, "same-origin")
		response := httptest.NewRecorder()
		h.SelfDelete(response, r)
		if response.Code != http.StatusNotAcceptable || response.Body.Len() != 0 {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("self capability and delete", func(t *testing.T) {
		h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		h.ConfigurePasskeyAdministrators(nil, func(context.Context, string) (bool, error) { return false, nil })
		h.ConfigureSelfDelete(true)
		get := accountPasskeyRequest(t, http.MethodGet, "/auth/v1/users/subject-1/self/delete", "subject-1", cookie, csrf, nil, "same-origin")
		response := httptest.NewRecorder()
		h.SelfDelete(response, get)
		if response.Code != http.StatusAccepted || response.Body.Len() != 0 {
			t.Fatalf("capability status=%d body=%q", response.Code, response.Body.String())
		}
		deleteRequest := accountPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1/self/delete", "subject-1", cookie, csrf, nil, "same-origin")
		response = httptest.NewRecorder()
		h.SelfDelete(response, deleteRequest)
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 || tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`) != 0 {
			t.Fatalf("delete status=%d body=%q users=%d", response.Code, response.Body.String(), tableCount(t, db, `SELECT COUNT(*) FROM identity_users WHERE subject='subject-1'`))
		}
		deletedCookie := response.Header().Get("Set-Cookie")
		if !strings.Contains(deletedCookie, "Max-Age=0") || !strings.Contains(deletedCookie, "__Host-goauthy_session=") {
			t.Fatalf("session cookie was not cleared: %q", deletedCookie)
		}
	})

	t.Run("authorization never falls back to cookie", func(t *testing.T) {
		h, _, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
		h.ConfigurePasskeyAdministrators(nil, func(context.Context, string) (bool, error) { return false, nil })
		h.ConfigureSelfDelete(true)
		for _, values := range [][]string{{"Bearer nope"}, {"API-Key nope", "API-Key nope"}} {
			r := accountPasskeyRequest(t, http.MethodGet, "/auth/v1/users/subject-1/self/delete", "subject-1", cookie, csrf, nil, "same-origin")
			for _, value := range values {
				r.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			h.SelfDelete(response, r)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("authorization=%v status=%d", values, response.Code)
			}
		}
		query := accountPasskeyRequest(t, http.MethodGet, "/auth/v1/users/subject-1/self/delete?x=1", "subject-1", cookie, csrf, nil, "same-origin")
		query.URL.RawQuery = "x=1"
		response := httptest.NewRecorder()
		h.SelfDelete(response, query)
		if response.Code != http.StatusForbidden {
			t.Fatalf("query status=%d", response.Code)
		}
	})

	t.Run("admin route is not a self-delete bypass", func(t *testing.T) {
		ordinary, _, _, ordinaryCookie, ordinaryCSRF, _ := testPasskeyAccountHandler(t)
		ordinary.ConfigurePasskeyAdministrators(nil, func(context.Context, string) (bool, error) { return false, nil })
		ordinaryRequest := accountPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1", "subject-1", ordinaryCookie, ordinaryCSRF, nil, "same-origin")
		ordinaryResponse := httptest.NewRecorder()
		ordinary.DeleteUser(ordinaryResponse, ordinaryRequest)
		if ordinaryResponse.Code != http.StatusForbidden {
			t.Fatalf("ordinary self-delete through admin route status=%d", ordinaryResponse.Code)
		}

		h, db, _, cookie, csrf, session := testPasskeyAccountHandler(t)
		rbacStore := rbac.NewStore(db)
		if _, err := rbacStore.EnsureBootstrapPrincipal(context.Background(), "subject-1", []string{rbac.AdminRole}, nil); err != nil {
			t.Fatal(err)
		}
		h.ConfigurePasskeyAdministrators(nil, rbacStore.IsAdmin)
		h.ConfigureSelfDelete(true)
		normal := func() *http.Request {
			return accountPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/subject-1", "subject-1", cookie, csrf, nil, "same-origin")
		}
		h.ConfigureAdminForceMFA(true)
		response := httptest.NewRecorder()
		h.DeleteUser(response, normal())
		if response.Code != http.StatusNotAcceptable {
			t.Fatalf("forced MFA status=%d", response.Code)
		}
		if session.AuthenticationMethod != "pwd" {
			t.Fatalf("test session method=%q", session.AuthenticationMethod)
		}
	})

	t.Run("api key delete and missing subject", func(t *testing.T) {
		h, db, _, _, _, _ := testPasskeyAccountHandler(t)
		keys, err := apikey.NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "users-delete", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Delete}}}})
		if err != nil {
			t.Fatal(err)
		}
		h.ConfigurePasskeyAdministrators(keys, nil)
		for _, subject := range []string{"missing", "subject-1"} {
			r := accountPasskeyRequest(t, http.MethodDelete, "/auth/v1/users/"+subject, subject, nil, "", nil, "same-origin")
			r.Header.Set("Authorization", "API-Key "+token)
			response := httptest.NewRecorder()
			h.DeleteUser(response, r)
			want := http.StatusNotFound
			if subject == "subject-1" {
				want = http.StatusNoContent
			}
			if response.Code != want {
				t.Fatalf("subject=%s status=%d want=%d", subject, response.Code, want)
			}
		}
	})

}

func passkeyBrowserRequest(cookie *http.Cookie, csrf, subject, method string, body []byte) *http.Request {
	r := httptest.NewRequest(method, "/auth/v1/users/"+subject+"/webauthn", bytes.NewReader(body))
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.SetPathValue("subject", subject)
	return r
}

func testPasskeyAccountHandler(t *testing.T) (*Handler, *rhiza.DB, *passkey.Service, *http.Cookie, string, browser.Session) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-passkey-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	rules := testRules()
	hasher := testHasher(t)
	identities, err := identity.NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.Hash(ctx, []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "alice", phc); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	service, err := passkey.New(db, passkey.Config{RPID: "issuer.example.test", RPDisplayName: "GoAuthy", Origins: []string{"https://issuer.example.test"}, CookieKey: bytes.Repeat([]byte{'k'}, 32), Keyring: testOIDCKeyring(t)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewWithPasskeys("https://issuer.example.test", sessions, identities, rules, service)
	if err != nil {
		t.Fatal(err)
	}
	return h, db, service, cookie, csrf, issued.Session
}

func testOIDCKeyring(t *testing.T) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x11}, 32)
	if err := os.WriteFile(filepath.Join(dir, "test-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "test-1")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func passkeyRequest(t *testing.T, method, path, subject string, cookie *http.Cookie, csrf string, body []byte) *http.Request {
	t.Helper()
	return accountPasskeyRequest(t, method, path, subject, cookie, csrf, body, "cross-site")
}

func sameOriginPasskeyRequest(t *testing.T, method, path, subject string, cookie *http.Cookie, csrf string, body []byte) *http.Request {
	t.Helper()
	return accountPasskeyRequest(t, method, path, subject, cookie, csrf, body, "same-origin")
}

func accountPasskeyRequest(t *testing.T, method, path, subject string, cookie *http.Cookie, csrf string, body []byte, fetchSite string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Sec-Fetch-Site", fetchSite)
	r.SetPathValue("subject", subject)
	return r
}

func seedAccountCredential(t *testing.T, db *rhiza.DB, id, name string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-seed-credential-" + id, SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{id, "subject-1", name, "opaque", int64(0), int64(1), int64(0), int64(0)}}); err != nil {
		t.Fatal(err)
	}
}

func codeDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func tableCount(t *testing.T, db *rhiza.DB, query string) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("query=%q result=%#v err=%v", query, result, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("query=%q count=%#v", query, result.Rows[0][0])
	}
	return count
}

func testConversionHandler(t *testing.T) (*Handler, *identity.Store, *http.Cookie, string, func(*testing.T, bool)) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-conversion-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	rules := testRules()
	hasher := testHasher(t)
	identities, err := identity.NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	currentPHC, err := hasher.Hash(ctx, []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "alice", currentPHC); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "mfa", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("https://issuer.example.test", sessions, identities, rules)
	if err != nil {
		t.Fatal(err)
	}
	addCredential := func(t *testing.T, verified bool) {
		t.Helper()
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-conversion-credential", SQL: `INSERT INTO identity_webauthn_credentials (credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{"credential-1", "subject-1", "platform", "{}", int64(0), boolInt(verified), int64(0), int64(0)}}); err != nil {
			t.Fatal(err)
		}
	}
	return h, identities, cookie, csrf, addCredential
}

func conversionRequest(t *testing.T, h *Handler, cookie *http.Cookie, csrf, subject, method string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return conversionRequestWithFetchSite(t, h, cookie, csrf, subject, method, body, "same-origin")
}

func conversionRequestWithFetchSite(t *testing.T, h *Handler, cookie *http.Cookie, csrf, subject, method string, body []byte, fetchSite string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "/auth/v1/users/"+subject+"/self/convert_passkey", bytes.NewReader(body))
	request.AddCookie(cookie)
	request = request.WithContext(browser.ContextWithPeerIP(request.Context(), "203.0.113.8"))
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("Sec-Fetch-Site", fetchSite)
	request.SetPathValue("subject", subject)
	response := httptest.NewRecorder()
	h.ConvertSelfPasskey(response, request)
	return response
}

func conversionRequestWithPeer(t *testing.T, h *Handler, cookie *http.Cookie, csrf, subject, peer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/"+subject+"/self/convert_passkey", nil)
	request.AddCookie(cookie)
	request = request.WithContext(browser.ContextWithPeerIP(request.Context(), peer))
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.SetPathValue("subject", subject)
	response := httptest.NewRecorder()
	h.ConvertSelfPasskey(response, request)
	return response
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }
func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func testPasswordHandler(t *testing.T) (*Handler, *browser.Store, *identity.Store, *http.Cookie, string) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statements := append(browser.SchemaStatements(), identity.SchemaStatements()...)
	statements = append(statements, rhiza.SQLStatement{SQL: `CREATE TABLE IF NOT EXISTS identity_external_links (
		provider_id TEXT NOT NULL,
		external_key TEXT NOT NULL,
		local_subject TEXT NOT NULL,
		linked_at_unix_ms INTEGER NOT NULL,
		PRIMARY KEY (provider_id, external_key),
		UNIQUE (local_subject, provider_id)
	) STRICT`})
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-test-schema", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	rules := testRules()
	hasher := testHasher(t)
	identities, err := identity.NewStoreWithPolicies(db, hasher, rules)
	if err != nil {
		t.Fatal(err)
	}
	currentPHC, err := hasher.Hash(ctx, []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "alice", currentPHC); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("https://issuer.example.test", sessions, identities, rules)
	if err != nil {
		t.Fatal(err)
	}
	return h, sessions, identities, cookie, csrf
}

func testRules() credential.Rules {
	return credential.Rules{LengthMin: 8, LengthMax: 64, LowerCase: 1, UpperCase: 1, Digits: 1, History: 2, ValidDays: 90}
}

func testHasher(t *testing.T) *credential.Hasher {
	t.Helper()
	policy := credential.DefaultPolicy()
	policy.MaxConcurrency = 1
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	return hasher
}

func passwordRequest(t *testing.T, h *Handler, cookie *http.Cookie, csrf, subject string, payload passwordChangeRequest) *httptest.ResponseRecorder {
	t.Helper()
	request := passwordHTTP(t, subject, payload)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	h.PutSelfPassword(response, request)
	return response
}

func passwordHTTP(t *testing.T, subject string, payload passwordChangeRequest) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/auth/v1/users/"+subject+"/self", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("subject", subject)
	return request
}

func passwordRawRequest(t *testing.T, h *Handler, cookie *http.Cookie, csrf, subject, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := passwordRawHTTP(t, subject, body)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	h.PutSelfPassword(response, request)
	return response
}

func passwordRawHTTP(t *testing.T, subject, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/auth/v1/users/"+subject+"/self", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("subject", subject)
	return request
}

func seedServiceProof(t *testing.T, db *rhiza.DB, proof, purpose, sessionDigest string) {
	t.Helper()
	digest := codeDigest(proof)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-proof-" + digest[:32], Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{digest, "subject-1", sessionDigest, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, purpose}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func ioNopCloser(value string) io.ReadCloser { return io.NopCloser(bytes.NewBufferString(value)) }
