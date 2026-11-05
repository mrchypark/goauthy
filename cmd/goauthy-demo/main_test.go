package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"golang.org/x/oauth2"
)

func signingKey(t *testing.T) oidc.SigningKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "demo-test-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
}

func testDemo(id string) *demo {
	listen := "127.0.0.1:18081"
	if strings.HasSuffix(id, "-b") {
		listen = "127.0.0.1:18082"
	}
	return newDemo(config{Name: "GoAuthy Demo", Listen: listen, Issuer: "http://localhost:18080", ClientID: id}, "synthetic-client-secret")
}

func TestIdentityValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := signingKey(t)
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}
	app := testDemo("goauthy-demo-a")
	for _, tc := range []struct {
		name string
		edit func(*oidc.IDTokenClaims)
	}{
		{"valid", nil},
		{"wrong issuer", func(c *oidc.IDTokenClaims) { c.Issuer = "http://localhost:18090" }},
		{"wrong receiving client", func(c *oidc.IDTokenClaims) { c.Audience = []string{"goauthy-demo-b"} }},
		{"expired", func(c *oidc.IDTokenClaims) { c.IssuedAt = now.Add(-time.Hour); c.ExpiresAt = now.Add(-time.Minute) }},
		{"wrong nonce", func(c *oidc.IDTokenClaims) { c.Nonce = "other-nonce" }},
		{"access token mismatch", func(c *oidc.IDTokenClaims) { c.AccessTokenHash = oidc.AccessTokenHash("other-token") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := oidc.IDTokenClaims{Issuer: app.cfg.Issuer, Subject: "synthetic-user", Audience: []string{app.cfg.ClientID}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Nonce: "test-nonce", AccessTokenHash: oidc.AccessTokenHash("synthetic-access-token")}
			if tc.edit != nil {
				tc.edit(&claims)
			}
			token, err := oidc.SignIDToken(key, claims)
			if err != nil {
				t.Fatal(err)
			}
			got, err := app.verify(token, "synthetic-access-token", "test-nonce", keys, now)
			if tc.edit == nil {
				if err != nil || got.Subject != "synthetic-user" {
					t.Fatal("valid identity rejected")
				}
			} else if err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
	claims := oidc.IDTokenClaims{Issuer: app.cfg.Issuer, Subject: "synthetic-user", Audience: []string{app.cfg.ClientID}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: "test-nonce"}
	token, err := oidc.SignIDToken(signingKey(t), claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.verify(token, "", "test-nonce", keys, now); err == nil {
		t.Fatal("signature from an untrusted key accepted")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("a", 32))}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"synthetic-user"}`))
	if err != nil {
		t.Fatal(err)
	}
	token, err = object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.verify(token, "", "test-nonce", keys, now); err == nil {
		t.Fatal("non-EdDSA signing algorithm accepted")
	}
}

func beginLogin(t *testing.T, app *demo) (string, pendingLogin, *http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	app.handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, app.origin+"/login", nil))
	if recorder.Code != http.StatusSeeOther {
		t.Fatal("login did not redirect")
	}
	authorize, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorize.Query().Get("state")
	pending := app.pending[state]
	if state == "" || pending.Nonce == "" || pending.Binding == "" || pending.Verifier == "" || authorize.Query().Get("nonce") != pending.Nonce || authorize.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(pending.Verifier) || authorize.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("missing random state, nonce, binding or PKCE challenge")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("transaction cookie is not protected")
	}
	return state, pending, cookies[0]
}

func TestLoginPromptConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, clientID, prompt string
		forceLogin             bool
	}{
		{"A interactive", "goauthy-demo-a", "login", true},
		{"B normal SSO", "goauthy-demo-b", "", false},
		{"A default remains SSO", "goauthy-demo-a", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := testDemo(tc.clientID)
			app.cfg.ForceLogin = tc.forceLogin
			response := httptest.NewRecorder()
			app.handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, app.origin+"/login?prompt=none", nil))
			redirect, err := url.Parse(response.Header().Get("Location"))
			if err != nil || response.Code != http.StatusSeeOther {
				t.Fatal("login did not redirect to GoAuthy")
			}
			query := redirect.Query()
			if query.Get("prompt") != tc.prompt || (tc.prompt == "" && query.Has("prompt")) {
				t.Fatal("login prompt does not match explicit fixture configuration")
			}
			pending, ok := app.pending[query.Get("state")]
			if !ok || pending.Nonce == "" || query.Get("nonce") != pending.Nonce ||
				query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(pending.Verifier) || query.Get("code_challenge_method") != "S256" {
				t.Fatal("prompt configuration lost state, nonce or S256 PKCE")
			}
		})
	}
}

func callbackRequest(app *demo, state string, cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, app.origin+"/callback?"+url.Values{"code": {"synthetic-code"}, "state": {state}}.Encode(), nil)
	req.AddCookie(cookie)
	return req
}

func TestTransactionsAreBoundOneUseAndExpire(t *testing.T) {
	a, b := testDemo("goauthy-demo-a"), testDemo("goauthy-demo-b")
	state, pending, cookie := beginLogin(t, a)
	otherState, otherPending, otherCookie := beginLogin(t, b)
	if cookie.Name == otherCookie.Name || a.cookieName("session") == b.cookieName("session") || state == otherState || pending.Nonce == otherPending.Nonce || pending.Verifier == otherPending.Verifier {
		t.Fatal("apps share cookies or login randomness")
	}
	if _, ok := a.takePending(callbackRequest(a, "wrong-state", cookie)); ok {
		t.Fatal("wrong state accepted")
	}
	wrongBinding := *cookie
	wrongBinding.Value = otherCookie.Value
	if _, ok := a.takePending(callbackRequest(a, state, &wrongBinding)); ok {
		t.Fatal("another browser binding accepted")
	}
	if _, ok := a.takePending(callbackRequest(a, state, cookie)); !ok {
		t.Fatal("valid callback rejected")
	}
	if _, ok := a.takePending(callbackRequest(a, state, cookie)); ok {
		t.Fatal("callback replay accepted")
	}
	otherPending.Expires = time.Now().Add(-time.Minute)
	b.pending[otherState] = otherPending
	if _, ok := b.takePending(callbackRequest(b, otherState, otherCookie)); ok {
		t.Fatal("expired pending login accepted")
	}
}

func TestCallbackCreatesPrivateAppSession(t *testing.T) {
	key := signingKey(t)
	var app *demo
	var pending pendingLogin
	var token string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oidc/token":
			if r.ParseForm() != nil || r.Form.Get("code_verifier") != pending.Verifier || r.Form.Get("grant_type") != "authorization_code" {
				t.Error("code exchange omitted PKCE verifier")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != app.cfg.ClientID || secret != "synthetic-client-secret" {
				t.Error("code exchange has incorrect client authentication")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access-token", "token_type": "Bearer", "id_token": token})
		case "/oidc/jwks.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	app = newDemo(config{Name: "GoAuthy Demo A", Listen: "127.0.0.1:18081", Issuer: issuer.URL, ClientID: "goauthy-demo-a"}, "synthetic-client-secret")
	var state string
	var cookie *http.Cookie
	state, pending, cookie = beginLogin(t, app)
	email, verified := "demo@goauthy.local", true
	now := time.Now().UTC()
	var err error
	token, err = oidc.SignIDToken(key, oidc.IDTokenClaims{Issuer: issuer.URL, Subject: "synthetic-shared-subject", Audience: []string{app.cfg.ClientID}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: pending.Nonce, AccessTokenHash: oidc.AccessTokenHash("synthetic-access-token"), Profile: oidc.ProfileClaims{Email: &email, EmailVerified: &verified}})
	if err != nil {
		t.Fatal(err)
	}
	result := httptest.NewRecorder()
	app.handler().ServeHTTP(result, callbackRequest(app, state, cookie))
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/" {
		t.Fatalf("callback status=%d", result.Code)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == app.cookieName("session") {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode || strings.Contains(sessionCookie.Value, "synthetic") {
		t.Fatal("app session cookie is not private and opaque")
	}
	home := httptest.NewRequest(http.MethodGet, app.origin+"/", nil)
	home.AddCookie(sessionCookie)
	page := httptest.NewRecorder()
	app.handler().ServeHTTP(page, home)
	if !strings.Contains(page.Body.String(), "synthetic-shared-subject") || !strings.Contains(page.Body.String(), email) {
		t.Fatal("verified account not displayed")
	}
	// For a native form POST, no-referrer makes the browser send Origin: null.
	// Keep referrers limited to the origin without disabling the logout Origin check.
	if page.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Error("page referrer policy prevents browser form logout")
	}
	for _, sensitive := range []string{token, "synthetic-access-token", "synthetic-client-secret", pending.Verifier} {
		if strings.Contains(page.Body.String(), sensitive) {
			t.Fatal("credential appeared in app page")
		}
	}
	otherApp := testDemo("goauthy-demo-b")
	otherHome := httptest.NewRequest(http.MethodGet, otherApp.origin+"/", nil)
	otherHome.AddCookie(sessionCookie)
	otherPage := httptest.NewRecorder()
	otherApp.handler().ServeHTTP(otherPage, otherHome)
	if strings.Contains(otherPage.Body.String(), "synthetic-shared-subject") || !strings.Contains(otherPage.Body.String(), "Signed out") {
		t.Fatal("app A session authenticated app B")
	}
	logout := httptest.NewRequest(http.MethodPost, app.origin+"/logout", nil)
	logout.AddCookie(sessionCookie)
	for _, origin := range []string{"", "null", otherApp.origin} {
		logout.Header.Set("Origin", origin)
		rejected := httptest.NewRecorder()
		app.handler().ServeHTTP(rejected, logout)
		if rejected.Code != http.StatusForbidden || len(app.sessions) != 1 {
			t.Fatal("invalid-origin logout changed app session")
		}
	}
	logout.Header.Set("Origin", app.origin)
	result = httptest.NewRecorder()
	app.handler().ServeHTTP(result, logout)
	if result.Code != http.StatusSeeOther || len(app.sessions) != 0 {
		t.Fatal("local app logout failed")
	}
	cleared := false
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == app.cookieName("session") && cookie.Value == "" && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear its session cookie")
	}
	page = httptest.NewRecorder()
	app.handler().ServeHTTP(page, home)
	if !strings.Contains(page.Body.String(), "Signed out") || strings.Contains(page.Body.String(), "synthetic-shared-subject") {
		t.Fatal("logout did not revoke the session on reload")
	}
}
