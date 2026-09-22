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
	"testing"
	"time"
)

const testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func testHandler(t *testing.T) *handler {
	t.Helper()
	seed := make([]byte, 4096)
	for i := range seed {
		seed[i] = byte(i)
	}
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	return newHandler(config{redirectURI: "https://client.test/auth/v1/saas/callback/provider"}, func() time.Time { return now }, bytes.NewReader(seed))
}
func testChallenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
func testAuthorize(t *testing.T, h *handler) string {
	t.Helper()
	q := url.Values{"client_id": {fixtureClientID}, "redirect_uri": {h.cfg.redirectURI}, "response_type": {"code"}, "scope": {"openid profile"}, "state": {"state"}, "code_challenge": {testChallenge(testVerifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize=%d", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	return u.Query().Get("code")
}
func testToken(t *testing.T, h *handler, form url.Values, secret string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(fixtureClientID, secret)
	w := httptest.NewRecorder()
	h.serveHTTP(w, r)
	return w
}

func TestAuthorizationCodePKCEAndSingleUse(t *testing.T) {
	h := testHandler(t)
	code := testAuthorize(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.redirectURI}, "code_verifier": {testVerifier}}
	wrong := testToken(t, h, func() url.Values {
		x := url.Values{}
		for k, v := range form {
			x[k] = v
		}
		x.Set("code_verifier", strings.Repeat("a", 43))
		return x
	}(), fixtureSecret)
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier=%d", wrong.Code)
	}
	if replay := testToken(t, h, form, fixtureSecret); replay.Code != http.StatusBadRequest {
		t.Fatalf("replay=%d", replay.Code)
	}
	code = testAuthorize(t, h)
	form.Set("code", code)
	ok := testToken(t, h, form, fixtureSecret)
	if ok.Code != http.StatusOK {
		t.Fatalf("token=%d body=%s", ok.Code, ok.Body.String())
	}
	if replay := testToken(t, h, form, fixtureSecret); replay.Code != http.StatusBadRequest {
		t.Fatalf("successful code reused: status=%d", replay.Code)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("token body=%s", ok.Body.String())
	}
	user := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	h.serveHTTP(user, req)
	var profile struct {
		Subject string `json:"sub"`
	}
	if user.Code != http.StatusOK || json.Unmarshal(user.Body.Bytes(), &profile) != nil || profile.Subject != "fixture-subject" {
		t.Fatalf("userinfo=%d body=%s", user.Code, user.Body.String())
	}
	refresh := testToken(t, h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}, fixtureSecret)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh=%d", refresh.Code)
	}
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refresh.Body.Bytes(), &rotated); err != nil || rotated.RefreshToken == tok.RefreshToken || rotated.AccessToken == tok.AccessToken {
		t.Fatalf("refresh did not rotate: %s", refresh.Body.String())
	}
	if again := testToken(t, h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotated.RefreshToken}}, fixtureSecret); again.Code != http.StatusOK {
		t.Fatalf("rotated refresh=%d", again.Code)
	}
	if replay := testToken(t, h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}, fixtureSecret); replay.Code != http.StatusBadRequest {
		t.Fatalf("refresh replay=%d", replay.Code)
	}
}

func TestConfigRequiresExactRegisteredRedirect(t *testing.T) {
	env := map[string]string{"SAAS_OAUTH_FIXTURE_TLS_CERT_FILE": "cert", "SAAS_OAUTH_FIXTURE_TLS_KEY_FILE": "key", "SAAS_OAUTH_FIXTURE_REDIRECT_URI": "https://localhost:1/auth/v1/saas/callback/provider"}
	if _, err := configFromEnv(func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "http://localhost/cb", "https://user@localhost/cb", "https://localhost/cb?x=1", "https://localhost/cb?", "https://localhost/cb#fragment"} {
		env["SAAS_OAUTH_FIXTURE_REDIRECT_URI"] = invalid
		if _, err := configFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Fatal("invalid redirect accepted")
		}
	}
}

func TestTokenRejectsWrongRedirectAndDuplicateFields(t *testing.T) {
	for _, mode := range []string{"wrong-redirect", "duplicate-code", "invalid-verifier"} {
		t.Run(mode, func(t *testing.T) {
			h := testHandler(t)
			code := testAuthorize(t, h)
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.redirectURI}, "code_verifier": {testVerifier}}
			switch mode {
			case "wrong-redirect":
				form.Set("redirect_uri", "https://other.test/callback")
			case "duplicate-code":
				form.Add("code", code)
			case "invalid-verifier":
				form.Set("code_verifier", "short")
			}
			if got := testToken(t, h, form, fixtureSecret); got.Code != http.StatusBadRequest {
				t.Fatalf("malformed exchange accepted: %d", got.Code)
			}
		})
	}
}

func TestOAuthFixtureRejectsClientAndServesUserinfoStats(t *testing.T) {
	h := testHandler(t)
	code := testAuthorize(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.redirectURI}, "code_verifier": {testVerifier}}
	if got := testToken(t, h, form, "wrong-secret"); got.Code != http.StatusUnauthorized {
		t.Fatalf("bad auth=%d", got.Code)
	}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/userinfo", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("healthz=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var s stats
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil || s.Authorize != 1 || s.Token != 1 || s.UserInfo != 1 || s.Healthz != 1 || s.TokenFailures != 1 || s.UserInfoFailures != 1 {
		t.Fatalf("stats=%s err=%v", w.Body.String(), err)
	}
}

func TestModelRequiresIssuedAccessToken(t *testing.T) {
	h := testHandler(t)
	code := testAuthorize(t, h)
	token := testToken(t, h, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.cfg.redirectURI}, "code_verifier": {testVerifier}}, fixtureSecret)
	var issued struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if token.Code != 200 || json.Unmarshal(token.Body.Bytes(), &issued) != nil || issued.Access == "" {
		t.Fatal("issue token")
	}
	for _, tc := range []struct {
		name, credential, body string
		want                   int
	}{
		{"issued", issued.Access, `{"messages":[{"role":"user","content":"hello"}]}`, 200},
		{"unknown", "unknown", `{"messages":[{}]}`, 401},
		{"refresh", issued.Refresh, `{"messages":[{}]}`, 401},
		{"empty", issued.Access, `{"messages":[]}`, 400},
		{"stream", issued.Access, `{"messages":[{}],"stream":true}`, 400},
		{"trailing", issued.Access, `{"messages":[{}]}{}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+tc.credential)
			w := httptest.NewRecorder()
			h.serveHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			if tc.want == 200 && !strings.Contains(w.Body.String(), "fixture-model-ok") {
				t.Fatal("missing completion")
			}
			if strings.Contains(w.Body.String(), issued.Access) || strings.Contains(w.Body.String(), issued.Refresh) {
				t.Fatal("credential echoed")
			}
		})
	}
	if h.stats.Model != 6 || h.stats.ModelFailures != 5 {
		t.Fatalf("unexpected counters: %+v", h.stats)
	}
}
