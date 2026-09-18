package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func testHandler(t *testing.T, now *time.Time) *handler {
	t.Helper()
	seed := make([]byte, 4096)
	for i := range seed {
		seed[i] = byte(i)
	}
	h, err := newHandler(config{issuer: "https://issuer.test", clientID: "fixture-client", clientSecret: "0123456789abcdef", callbackURI: "https://client.test/callback", subject: "subject"}, func() time.Time { return *now }, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testHandlerManaged(t *testing.T, now *time.Time) *handler {
	t.Helper()
	seed := make([]byte, 4096)
	for i := range seed {
		seed[i] = byte(i)
	}
	h, err := newHandler(config{issuer: "https://issuer.test", clientID: "fixture-client", clientSecret: "0123456789abcdef", callbackURI: "https://client.test/callback", subject: "subject", allowManagedCallbacks: true}, func() time.Time { return *now }, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

const managedID = "ABCDEFGHIJKLMNOPQRSTUVWX" // 24 ASCII alphanumeric

func managedCallbackURI() string {
	return "https://client.test/upstream/" + managedID + "/callback"
}

func authorize(t *testing.T, h *handler, mutate func(url.Values)) string {
	t.Helper()
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.cfg.callbackURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	if mutate != nil {
		mutate(q)
	}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%q", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Query().Get("state") != "state" || u.Query().Get("code") == "" {
		t.Fatalf("redirect=%q err=%v", w.Header().Get("Location"), err)
	}
	return u.Query().Get("code")
}

func tokenRequest(h *handler, code, verifier string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.callbackURI}, "code_verifier": {verifier}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w := httptest.NewRecorder()
	h.serveHTTP(w, r)
	return w
}

func githubAuthorize(t *testing.T, h *handler) string {
	t.Helper()
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.githubCallbackURI()}, "response_type": {"code"}, "scope": {"read:user"}, "state": {"github-state"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/login/oauth/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("github authorize status=%d body=%q", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Query().Get("state") != "github-state" || u.Query().Get("code") == "" || u.Path != "/github/callback" {
		t.Fatalf("github redirect=%q err=%v", w.Header().Get("Location"), err)
	}
	return u.Query().Get("code")
}

func githubTokenRequest(h *handler, code, verifier string) *httptest.ResponseRecorder {
	form := url.Values{"client_id": {h.cfg.clientID}, "client_secret": {h.cfg.clientSecret}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.githubCallbackURI()}, "code_verifier": {verifier}}
	r := httptest.NewRequest(http.MethodPost, "/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serveHTTP(w, r)
	return w
}

func TestAuthorizationValidationAndOneUsePKCE(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	for _, change := range []func(url.Values){
		func(q url.Values) { q.Set("redirect_uri", "https://client.test/other") },
		func(q url.Values) { q.Set("scope", "profile") },
		func(q url.Values) { q.Set("code_challenge_method", "plain") },
		func(q url.Values) { q.Set("state", "") },
	} {
		q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.cfg.callbackURI}, "response_type": {"code"}, "scope": {"openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
		change(q)
		w := httptest.NewRecorder()
		h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid authorization status=%d", w.Code)
		}
	}
	code := authorize(t, h, nil)
	if got := tokenRequest(h, code, strings.Repeat("a", 43)); got.Code != http.StatusBadRequest {
		t.Fatalf("wrong pkce=%d", got.Code)
	}
	if got := tokenRequest(h, code, verifier); got.Code != http.StatusBadRequest {
		t.Fatalf("consumed code replay=%d", got.Code)
	}
	code = authorize(t, h, nil)
	if got := tokenRequest(h, code, "short"); got.Code != http.StatusBadRequest {
		t.Fatalf("short verifier=%d", got.Code)
	}
	if got := tokenRequest(h, code, strings.Repeat("a", 42)+"!"); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid verifier=%d", got.Code)
	}
	if got := tokenRequest(h, code, verifier); got.Code != http.StatusOK {
		t.Fatalf("token=%d body=%q", got.Code, got.Body.String())
	}
}

func TestTokenClaimsSignatureAndConcurrency(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	jwks := httptest.NewRecorder()
	h.serveHTTP(jwks, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(jwks.Body.Bytes(), &keys); jwks.Code != http.StatusOK || err != nil || len(keys.Keys) != 1 || keys.Keys[0].KeyID != h.public.KeyID {
		t.Fatalf("jwks status=%d keys=%+v err=%v", jwks.Code, keys, err)
	}
	code := authorize(t, h, nil)
	response := tokenRequest(h, code, verifier)
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.IDToken == "" {
		t.Fatalf("token body=%q err=%v", response.Body.String(), err)
	}
	parsed, err := jose.ParseSigned(body.IDToken, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsed.Verify(h.public.Key)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil || claims["iss"] != h.cfg.issuer || claims["sub"] != h.cfg.subject || claims["nonce"] != "nonce" {
		t.Fatalf("claims=%v err=%v", claims, err)
	}

	code = authorize(t, h, nil)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tokenRequest(h, code, verifier).Code == http.StatusOK {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
}

func TestGitHubOAuthAppFixture(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	code := githubAuthorize(t, h)
	response := githubTokenRequest(h, code, verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("github token status=%d body=%q", response.Code, response.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.AccessToken == "" || body.TokenType != "bearer" || body.Scope != "read:user" || body.IDToken != "" {
		t.Fatalf("github token body=%q err=%v", response.Body.String(), err)
	}
	user := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user", nil)
	r.Header.Set("Authorization", "Bearer "+body.AccessToken)
	h.serveHTTP(user, r)
	var profile struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(user.Body.Bytes(), &profile); user.Code != http.StatusOK || err != nil || profile.ID <= 0 {
		t.Fatalf("github user status=%d body=%q err=%v", user.Code, user.Body.String(), err)
	}
	if replay := githubTokenRequest(h, code, verifier); replay.Code != http.StatusBadRequest {
		t.Fatalf("github code replay status=%d", replay.Code)
	}
	if invalid := func() *httptest.ResponseRecorder {
		q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.githubCallbackURI()}, "response_type": {"code"}, "scope": {"read:user"}, "state": {"github-state"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "nonce": {"must-be-rejected"}}
		w := httptest.NewRecorder()
		h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/login/oauth/authorize?"+q.Encode(), nil))
		return w
	}(); invalid.Code != http.StatusBadRequest {
		t.Fatalf("github nonce accepted status=%d", invalid.Code)
	}
}

func TestBoundedCodeCleanupAndConfig(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	code := authorize(t, h, nil)
	if len(h.codes) != 1 {
		t.Fatalf("codes=%d", len(h.codes))
	}
	now = now.Add(codeLifetime)
	_ = authorize(t, h, nil)
	if _, exists := h.codes[code]; exists || len(h.codes) != 1 {
		t.Fatalf("expired code was retained: %d", len(h.codes))
	}
	env := map[string]string{"TLS_CERT_FILE": "cert", "TLS_KEY_FILE": "key", "ISSUER": "https://issuer.test", "CLIENT_ID": "id", "CLIENT_SECRET": "0123456789abcdef", "CALLBACK_URI": "https://client.test/callback"}
	c, err := configFromEnv(func(key string) string { return env[key] })
	if err != nil || c.addr != ":8443" || c.subject != "fixture-subject" {
		t.Fatalf("config=%+v err=%v", c, err)
	}
	if c.allowTestClaims {
		t.Fatal("allowTestClaims should be false by default")
	}
	env["ALLOW_TEST_CLAIMS"] = "1"
	c, err = configFromEnv(func(key string) string { return env[key] })
	if err != nil || !c.allowTestClaims {
		t.Fatalf("allowTestClaims not set: config=%+v err=%v", c, err)
	}
	if c.githubCallbackURI != "https://client.test/github/callback" {
		t.Fatalf("github callback=%q", c.githubCallbackURI)
	}
	env["CLIENT_SECRET"] = "short"
	if _, err := configFromEnv(func(key string) string { return env[key] }); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestManagedCallbackAccepted(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerManaged(t, &now)
	managedURI := managedCallbackURI()
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {managedURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%q", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, managedURI+"?") {
		t.Fatalf("redirect not to managed URI: %q", loc)
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {managedURI}, "code_verifier": {verifier}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w2 := httptest.NewRecorder()
	h.serveHTTP(w2, r)
	if w2.Code != http.StatusOK {
		t.Fatalf("managed token=%d body=%q", w2.Code, w2.Body.String())
	}
}

func TestManagedCallbackDefaultDenial(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {managedCallbackURI()}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("managed URI accepted without flag: %d", w.Code)
	}
}

func TestManagedCallbackWrongOrigin(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerManaged(t, &now)
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {"https://evil.test/upstream/" + managedID + "/callback"}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong origin accepted: %d", w.Code)
	}
}

func TestManagedCallbackWrongPath(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerManaged(t, &now)
	for _, badURI := range []string{
		"https://client.test/upstream/SHORT/callback",
		"https://client.test/upstream/" + managedID + "/callback/extra",
		"https://client.test/upstream/abcdefghijklmnopqrstuv!/callback",
		"https://client.test/not-upstream/" + managedID + "/callback",
	} {
		q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {badURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
		w := httptest.NewRecorder()
		h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("bad managed URI %q accepted: %d", badURI, w.Code)
		}
	}
}

func TestManagedCrossCallbackRedemption(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerManaged(t, &now)
	uriA := managedCallbackURI()
	uriB := "https://client.test/upstream/BCDEFGHIJKLMNOPQRSTUVWX0/callback"
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {uriA}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status=%d", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	code := u.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {uriB}, "code_verifier": {verifier}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w2 := httptest.NewRecorder()
	h.serveHTTP(w2, r)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("cross-callback redemption accepted: %d", w2.Code)
	}
}

func TestTokenOptionalClientID(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerManaged(t, &now)
	code := authorize(t, h, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.callbackURI}, "code_verifier": {verifier}, "client_id": {h.cfg.clientID}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w := httptest.NewRecorder()
	h.serveHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("correct client_id in body rejected: %d body=%q", w.Code, w.Body.String())
	}

	code = authorize(t, h, nil)
	form = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.callbackURI}, "code_verifier": {verifier}, "client_id": {"wrong"}}
	r = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w = httptest.NewRecorder()
	h.serveHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong client_id in body accepted: %d", w.Code)
	}

	code = authorize(t, h, nil)
	form = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.callbackURI}, "code_verifier": {verifier}, "unknown": {"value"}}
	r = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w = httptest.NewRecorder()
	h.serveHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown param accepted: %d", w.Code)
	}

	code = authorize(t, h, nil)
	form = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.callbackURI}, "code_verifier": {verifier}, "client_id": {h.cfg.clientID, "extra"}}
	r = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(h.cfg.clientID, h.cfg.clientSecret)
	w = httptest.NewRecorder()
	h.serveHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate client_id accepted: %d", w.Code)
	}
}
