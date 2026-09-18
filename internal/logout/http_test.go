package logout

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const logoutRedirect = "https://rp.example.test/logout?from=goauthy"

func TestEnableFedCMIsHTTPSOnlyAndDeletesSeparateCookie(t *testing.T) {
	h, _, _ := testLogoutHandler(t)
	h.issuer = "http://localhost"
	if err := h.EnableFedCM(true); err == nil {
		t.Fatal("HTTP issuer enabled FedCM")
	}
	h.issuer = testIssuer
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := h.deleteSessionCookies(recorder); err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name == cookies[1].Name || cookies[1].Name != browser.FedCMSessionCookieName || cookies[1].MaxAge != -1 || !cookies[1].Secure || cookies[1].SameSite != http.SameSiteNoneMode {
		t.Fatalf("deletion cookies=%#v", cookies)
	}
}

func TestHandlerMatchingHintLogsOutAndDeletesCookie(t *testing.T) {
	h, sessions, key := testLogoutHandler(t)
	issued, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	hint := httpHint(t, key, "user-1", issued.ID)
	req := httptest.NewRequest(http.MethodGet, "/oidc/logout?"+url.Values{"id_token_hint": {hint}, "client_id": {"client-1"}, "post_logout_redirect_uri": {logoutRedirect}, "state": {"opaque state"}}.Encode(), nil)
	setSessionCookie(t, req, issued.Token)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != logoutRedirect+"&state=opaque+state" {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || cookies[0].Value != "" {
		t.Fatalf("deletion cookies=%#v", cookies)
	}
	if _, err := sessions.LoadSession(context.Background(), issued.Token); !errors.Is(err, browser.ErrRevoked) {
		t.Fatalf("session after logout: %v", err)
	}
}

func TestHandlerConfirmationIsSessionBoundSingleUseAndSameOrigin(t *testing.T) {
	h, sessions, _ := testLogoutHandler(t)
	first, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/oidc/logout?"+url.Values{"client_id": {"client-1"}, "post_logout_redirect_uri": {logoutRedirect}, "state": {"state"}}.Encode(), nil)
	get.Header.Set("Accept-Language", "ko-KR, en;q=0.5")
	setSessionCookie(t, get, first.Token)
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	confirmation := confirmationFromPage(t, page.Body.String())
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" || strings.Count(page.Body.String(), `name="confirmation"`) != 1 {
		t.Fatalf("page status=%d headers=%v body=%s", page.Code, page.Header(), page.Body.String())
	}
	if page.Header().Get("Content-Language") != "ko" || !strings.Contains(page.Header().Get("Vary"), "Accept-Language") || !strings.Contains(page.Body.String(), `<html lang="ko">`) || !strings.Contains(page.Body.String(), "로그아웃") {
		t.Fatalf("localized confirmation=%s", page.Body.String())
	}

	wrongSession := confirmationRequest(confirmation, second.Token)
	wrongSession.Header.Set("Sec-Fetch-Site", "same-origin")
	wrongResult := httptest.NewRecorder()
	h.ServeHTTP(wrongResult, wrongSession)
	if wrongResult.Code != http.StatusForbidden {
		t.Fatalf("cross-session status=%d", wrongResult.Code)
	}
	for _, site := range []string{"cross-site", "same-site"} {
		crossSite := confirmationRequest(confirmation, first.Token)
		crossSite.Header.Set("Sec-Fetch-Site", site)
		cross := httptest.NewRecorder()
		h.ServeHTTP(cross, crossSite)
		if cross.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d", site, cross.Code)
		}
	}
	valid := confirmationRequest(confirmation, first.Token)
	valid.Header.Set("Sec-Fetch-Site", "same-origin")
	ok := httptest.NewRecorder()
	h.ServeHTTP(ok, valid)
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != logoutRedirect+"&state=state" || len(ok.Result().Cookies()) != 1 {
		t.Fatalf("confirmation status=%d location=%q cookies=%#v", ok.Code, ok.Header().Get("Location"), ok.Result().Cookies())
	}
	if _, err := sessions.LoadSession(context.Background(), first.Token); !errors.Is(err, browser.ErrRevoked) {
		t.Fatalf("confirmed session: %v", err)
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, valid)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replay status=%d", replay.Code)
	}
}

func TestHandlerMismatchedHintConfirmationUsesHintClient(t *testing.T) {
	h, sessions, key := testLogoutHandler(t)
	current, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	hint := httpHint(t, key, "other-user", testSessionID(9))
	get := httptest.NewRequest(http.MethodGet, "/oidc/logout?"+url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {logoutRedirect}, "state": {"state"}}.Encode(), nil)
	setSessionCookie(t, get, current.Token)
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("mismatched hint status=%d body=%s", page.Code, page.Body.String())
	}
	post := confirmationRequest(confirmationFromPage(t, page.Body.String()), current.Token)
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, post)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != logoutRedirect+"&state=state" {
		t.Fatalf("confirmation status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestHandlerRejectsMalformedAndSupportsBackendHintPost(t *testing.T) {
	h, sessions, key := testLogoutHandler(t)
	issued, err := sessions.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	hint := httpHint(t, key, "user-1", issued.ID)
	malformedHint := httpHint(t, key, "user-1", "not-a-session-id")
	malformed := httptest.NewRequest(http.MethodGet, "/oidc/logout?"+url.Values{"id_token_hint": {malformedHint}}.Encode(), nil)
	setSessionCookie(t, malformed, issued.Token)
	malformedResponse := httptest.NewRecorder()
	h.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("malformed sid status=%d", malformedResponse.Code)
	}
	if _, err := sessions.LoadSession(context.Background(), issued.Token); err != nil {
		t.Fatalf("malformed sid changed session: %v", err)
	}
	backend := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(url.Values{"id_token_hint": {hint}}.Encode()))
	backend.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, backend)
	if response.Code != http.StatusNoContent {
		t.Fatalf("backend status=%d body=%s", response.Code, response.Body.String())
	}
	for _, raw := range []string{
		"/oidc/logout?unexpected=x",
		"/oidc/logout?id_token_hint=x&id_token_hint=y",
		"/oidc/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2F",
		"/oidc/logout?state=" + strings.Repeat("s", maxStateLength+1),
		"/oidc/logout?id_token_hint=" + strings.Repeat("x", maxHintLength+1),
	} {
		r := httptest.NewRequest(http.MethodGet, raw, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q status=%d", raw[:min(len(raw), 32)], w.Code)
		}
	}
	postQuery := httptest.NewRequest(http.MethodPost, "/oidc/logout?id_token_hint=x", strings.NewReader("id_token_hint=x"))
	postQuery.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postQuery)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST query status=%d", w.Code)
	}
	duplicateType := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader("id_token_hint=x"))
	duplicateType.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	duplicateType.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, duplicateType)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate Content-Type status=%d", w.Code)
	}
}

func testLogoutHandler(t *testing.T) (*Handler, *browser.Store, oidc.SigningKey) {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "logout-http-key", Algorithm: "EdDSA", Use: "sig"}}
	encoded, err := json.Marshal(key.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "logout-http-key", SQL: `INSERT INTO oidc_signing_keys (kid, public_jwk, private_envelope, state, created_at_unix_ms) VALUES (?, ?, ?, 'active', ?)`, Args: []any{key.PublicJWK.KeyID, string(encoded), "unused", time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("test password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(context.Background(), "user-1", "user-1@example.test", phc); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	oauthServer, err := oauth.NewServerWithOIDC(context.Background(), db, secret, "client-1", "0123456789abcdef", "https://rp.example.test/callback", nil, oauth.OIDCConfig{Issuer: testIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(testIssuer, db, sessions, oauthServer, []Client{{ID: "client-1", PostLogoutRedirectURIs: []string{logoutRedirect}}})
	if err != nil {
		t.Fatal(err)
	}
	return h, sessions, key
}

func httpHint(t *testing.T, key oidc.SigningKey, subject, sid string) string {
	t.Helper()
	hint, err := oidc.SignIDToken(key, oidc.IDTokenClaims{Issuer: testIssuer, Subject: subject, Audience: []string{"client-1"}, AuthorizedParty: "client-1", SessionID: sid, IssuedAt: time.Now().Add(-time.Minute), NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return hint
}

func setSessionCookie(t *testing.T, r *http.Request, token string) {
	t.Helper()
	name, err := browser.CookieName(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: name, Value: token})
}

func confirmationFromPage(t *testing.T, page string) string {
	t.Helper()
	match := regexp.MustCompile(`name="confirmation" value="([^"]+)"`).FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("confirmation missing from %s", page)
	}
	return match[1]
}

func confirmationRequest(token, sessionToken string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(url.Values{logoutConfirmationKey: {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	name, _ := browser.CookieName(testIssuer)
	r.AddCookie(&http.Cookie{Name: name, Value: sessionToken})
	return r
}
