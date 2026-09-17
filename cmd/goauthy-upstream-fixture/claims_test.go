package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func testHandlerWithClaims(t *testing.T, now *time.Time) *handler {
	t.Helper()
	seed := make([]byte, 4096)
	for i := range seed {
		seed[i] = byte(i)
	}
	h, err := newHandler(config{issuer: "https://issuer.test", clientID: "fixture-client", clientSecret: "0123456789abcdef", callbackURI: "https://client.test/callback", subject: "subject", allowTestClaims: true}, func() time.Time { return *now }, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func authorizeWithClaims(t *testing.T, h *handler, mutate func(url.Values)) string {
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

func TestTestClaimsInIDToken(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerWithClaims(t, &now)
	code := authorizeWithClaims(t, h, func(q url.Values) {
		q.Set("fixture_email", "alice@test.example")
		q.Set("fixture_email_verified", "1")
		q.Set("fixture_given_name", "Alice")
		q.Set("fixture_family_name", "Test")
		q.Set("fixture_mfa", "1")
	})
	response := tokenRequest(h, code, verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%q", response.Code, response.Body.String())
	}
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
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != h.cfg.issuer || claims["sub"] != h.cfg.subject || claims["nonce"] != "nonce" {
		t.Fatalf("protected claims wrong: %v", claims)
	}
	if claims["email"] != "alice@test.example" {
		t.Fatalf("email=%v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Fatalf("email_verified=%v", claims["email_verified"])
	}
	if claims["given_name"] != "Alice" || claims["family_name"] != "Test" {
		t.Fatalf("profile=%v %v", claims["given_name"], claims["family_name"])
	}
	amr, ok := claims["amr"].([]any)
	if !ok || len(amr) != 1 || amr[0] != "mfa" {
		t.Fatalf("amr=%v", claims["amr"])
	}
}

func TestTestClaimsRejectedWhenDisabled(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandler(t, &now)
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.cfg.callbackURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "fixture_email": {"x"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("fixture_ param accepted without allowTestClaims: %d", w.Code)
	}
}

func TestTestClaimsFrozenPerCode(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerWithClaims(t, &now)
	code := authorizeWithClaims(t, h, func(q url.Values) {
		q.Set("fixture_email", "frozen@test.example")
	})
	response := tokenRequest(h, code, verifier)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal(response.Body.Bytes(), &tok)
	parsed, _ := jose.ParseSigned(tok.IDToken, []jose.SignatureAlgorithm{jose.EdDSA})
	sum := sha256.Sum256([]byte(verifier))
	_ = base64.RawURLEncoding.EncodeToString(sum[:])
	payload, _ := parsed.Verify(h.public.Key)
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	if claims["email"] != "frozen@test.example" {
		t.Fatalf("frozen email=%v", claims["email"])
	}
	response2 := tokenRequest(h, code, verifier)
	if response2.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d", response2.Code)
	}
}

func TestExtractTestClaimsEmpty(t *testing.T) {
	q := url.Values{}
	m := extractTestClaims(q)
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %v", m)
	}
}

func TestExtractTestClaimsPartial(t *testing.T) {
	q := url.Values{"fixture_email": {"bob@test.example"}}
	m := extractTestClaims(q)
	if m["email"] != "bob@test.example" {
		t.Fatalf("email=%v", m["email"])
	}
	if _, ok := m["email_verified"]; ok {
		t.Fatal("email_verified should not be set")
	}
}

func TestTestClaimsEmptyValuesIgnored(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerWithClaims(t, &now)
	code := authorizeWithClaims(t, h, func(q url.Values) {
		q.Set("fixture_email", "")
		q.Set("fixture_mfa", "0")
	})
	response := tokenRequest(h, code, verifier)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal(response.Body.Bytes(), &tok)
	parsed, _ := jose.ParseSigned(tok.IDToken, []jose.SignatureAlgorithm{jose.EdDSA})
	payload, _ := parsed.Verify(h.public.Key)
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	if _, ok := claims["email"]; ok {
		t.Fatal("empty fixture_email should not appear")
	}
	if _, ok := claims["amr"]; ok {
		t.Fatal("fixture_mfa=0 should not produce amr")
	}
}
func TestTestClaimsReservedOverrideRejected(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerWithClaims(t, &now)
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.cfg.callbackURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "fixture_sub": {"injected"}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reserved claim accepted at authorize: %d", w.Code)
	}
}

func TestExtractTestClaimsMaxValueLength(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	h := testHandlerWithClaims(t, &now)
	q := url.Values{"client_id": {h.cfg.clientID}, "redirect_uri": {h.cfg.callbackURI}, "response_type": {"code"}, "scope": {"profile openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "fixture_email": {string(make([]byte, 257))}}
	w := httptest.NewRecorder()
	h.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("overlong value accepted at authorize: %d", w.Code)
	}
}
