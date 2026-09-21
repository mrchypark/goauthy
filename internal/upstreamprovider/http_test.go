package upstreamprovider

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
)

// testCanonicalTestToken is a valid 32-byte base64url browser token for test
// fixtures. DigestSHA256 must NOT be used for session token digests.
var testCanonicalTestToken = func() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}()

var testCanonicalTestDigest = func() string {
	d, _ := browser.CanonicalTokenDigest(testCanonicalTestToken)
	return d
}()

// --- test doubles ---

type fakeTokenExchanger struct {
	idToken   string
	subject   *SubjectResult
	err       error
	nilResult bool
	calls     int
}

type advancingTokenExchanger struct {
	now     *time.Time
	advance time.Duration
}

func (e *advancingTokenExchanger) ExchangeCode(_ context.Context, _, _, _, _ string) (*TokenExchangeResult, error) {
	*e.now = e.now.Add(e.advance)
	return &TokenExchangeResult{IDToken: "token"}, nil
}

func (f *fakeTokenExchanger) ExchangeCode(_ context.Context, _, _, _, _ string) (*TokenExchangeResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.nilResult {
		return nil, nil
	}
	return &TokenExchangeResult{IDToken: f.idToken, Subject: f.subject}, nil
}

// recordingExchanger captures the arguments passed to ExchangeCode so
// tests can verify the exchanger receives trusted stored context.
type recordingExchanger struct {
	providerID   string
	callbackURI  string
	code         string
	pkceVerifier string
	idToken      string
}

func (r *recordingExchanger) ExchangeCode(_ context.Context, providerID, callbackURI, code, pkceVerifier string) (*TokenExchangeResult, error) {
	r.providerID = providerID
	r.callbackURI = callbackURI
	r.code = code
	r.pkceVerifier = pkceVerifier
	return &TokenExchangeResult{IDToken: r.idToken}, nil
}

type fakeTokenVerifierHTTP struct {
	claims *IDTokenClaims
	err    error
}

func (f *fakeTokenVerifierHTTP) VerifyIDToken(_ context.Context, _ string, _, _ string) (*IDTokenClaims, error) {
	return f.claims, f.err
}

type countingTokenVerifier struct {
	calls int
}

func (v *countingTokenVerifier) VerifyIDToken(context.Context, string, string, string) (*IDTokenClaims, error) {
	v.calls++
	return nil, errors.New("unexpected id-token verification")
}

// deterministicVerifier returns a verifier that looks up the nonce from
// the most recently created transaction in the given store and injects
// it into the claims before returning. This avoids needing to predict
// the crypto provider's nonce output.
type deterministicVerifier struct {
	claims *IDTokenClaims
	err    error
	store  Store
}

func (d *deterministicVerifier) VerifyIDToken(_ context.Context, _ string, issuer, _ string) (*IDTokenClaims, error) {
	if d.err != nil {
		return nil, d.err
	}
	c := *d.claims
	s := d.store.(*testInMemoryStore)
	s.mu.Lock()
	for _, tx := range s.transactions {
		if tx.Issuer == issuer {
			c.Nonce = tx.Nonce
			break
		}
	}
	s.mu.Unlock()
	return &c, nil
}

func testHandler(t *testing.T, exchanger TokenExchanger, verifier TokenVerifier, entropy []byte) (*Handler, *testInMemoryStore) {
	t.Helper()
	store := newTestStore()
	configs := map[string]Config{
		"google": {
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/auth",
			TokenEndpoint:         "https://issuer.example.com/token",
			ClientID:              "test-client",
			Scopes:                []string{"openid", "profile"},
			Audience:              "test-audience",
		},
	}
	allowed := map[string]bool{
		"https://app.example.com/callback": true,
	}
	v := verifier
	if fv, ok := verifier.(*fakeTokenVerifierHTTP); ok {
		v = &deterministicVerifier{claims: fv.claims, err: fv.err, store: store}
	}
	h, err := NewHandler(configs, store, exchanger, v, newCryptoProvider(newFixedRandom(entropy)), allowed)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store
}

func makeCallbackRequest(providerID, state, code string, stateCookie, browserCookie *http.Cookie) *http.Request {
	u := "/upstream/" + providerID + "/callback?state=" + url.QueryEscape(state) +
		"&code=" + url.QueryEscape(code)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	if stateCookie != nil {
		req.AddCookie(stateCookie)
	}
	if browserCookie != nil {
		req.AddCookie(browserCookie)
	}
	return req
}

func TestCallbacksUseTimeAfterTokenExchange(t *testing.T) {
	t.Parallel()
	setupClock := func(h *Handler, clock *time.Time) {
		h.now = func() time.Time { return *clock }
		h.exchanger = &advancingTokenExchanger{now: clock, advance: 2 * time.Second}
		h.verifier.(*deterministicVerifier).claims.ExpiresAt = fixedNow.Add(time.Second).Unix()
	}

	t.Run("legacy", func(t *testing.T) {
		clock := fixedNow
		h, _ := testHandler(t, &fakeTokenExchanger{}, &fakeTokenVerifierHTTP{claims: &IDTokenClaims{
			Issuer: "https://issuer.example.com", Subject: "external-user", Audience: []string{"test-client"},
			ExpiresAt: fixedNow.Add(time.Hour).Unix(), IssuedAt: fixedNow.Add(-time.Minute).Unix(),
		}}, make([]byte, 256))
		setupClock(h, &clock)
		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)
		u, _ := url.Parse(start.Header().Get("Location"))
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", u.Query().Get("state"), "code", stateCookie, browserCookie))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want expired token rejection", rec.Code)
		}
	})

	t.Run("local login", func(t *testing.T) {
		clock := fixedNow
		hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
		h, _ := testLocalHandler(t, hooks.hooks())
		setupClock(h, &clock)
		stateCookie, state := localStart(t, h)
		rec := httptest.NewRecorder()
		h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want expired token rejection", rec.Code)
		}
	})

	t.Run("link", func(t *testing.T) {
		clock := fixedNow
		hooks := &linkHookRecorder{subject: "local-user", token: testCanonicalTestToken, digest: testCanonicalTestDigest, decision: LinkDecisionLinked}
		h, _ := testLinkHandler(t, hooks.hooks())
		setupClock(h, &clock)
		start := httptest.NewRecorder()
		h.LinkStartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/upstream/google/link", nil))
		stateCookie := start.Result().Cookies()[0]
		var body map[string]string
		if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(body["authorization_url"])
		rec := httptest.NewRecorder()
		h.LinkCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", u.Query().Get("state"), "code", stateCookie, nil))
		if rec.Code != http.StatusBadRequest || hooks.linkCalls != 0 {
			t.Fatalf("status=%d link calls=%d, want expired token rejection", rec.Code, hooks.linkCalls)
		}
	})
}

func getCookies(t *testing.T, rec *httptest.ResponseRecorder) (stateCookie, browserCookie *http.Cookie) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case stateCookieName:
			stateCookie = c
		case browserCookieName:
			browserCookie = c
		}
	}
	return
}

// getClearCookies returns cookies that clear (MaxAge=-1) after a callback.
func getClearCookies(t *testing.T, rec *httptest.ResponseRecorder) (stateClear, browserClear bool) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case stateCookieName:
			stateClear = c.MaxAge < 0 && c.Value == ""
		case browserCookieName:
			browserClear = c.MaxAge < 0 && c.Value == ""
		}
	}
	return
}

// --- tests ---

// TestTwoUserStartBarrier proves no cross-talk between two simultaneous
// users through start + callback flows with a genuine start barrier.
func TestTwoUserStartBarrier(t *testing.T) {
	t.Parallel()
	const clientID = "test-client"

	entropy1 := make([]byte, 256)
	entropy2 := make([]byte, 256)
	for i := range entropy1 {
		entropy1[i] = byte(i)
		entropy2[i] = byte(i + 128)
	}

	now := fixedNow
	claims1 := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "user1-subject",
		Audience:  []string{clientID},
		Nonce:     "expected-nonce",
		ExpiresAt: now.Add(time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
	}
	claims2 := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "user2-subject",
		Audience:  []string{clientID},
		Nonce:     "expected-nonce",
		ExpiresAt: now.Add(time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
	}

	h1, _ := testHandler(t, &fakeTokenExchanger{idToken: "tok1"}, &fakeTokenVerifierHTTP{claims: claims1}, entropy1)
	h2, _ := testHandler(t, &fakeTokenExchanger{idToken: "tok2"}, &fakeTokenVerifierHTTP{claims: claims2}, entropy2)

	var wg sync.WaitGroup
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	wg.Add(2)

	var rec1, rec2 *httptest.ResponseRecorder
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		r := httptest.NewRecorder()
		h1.StartHandler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		rec1 = r
	}()
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		r := httptest.NewRecorder()
		h2.StartHandler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		rec2 = r
	}()

	<-ready
	<-ready
	close(start)
	wg.Wait()

	if rec1.Code != http.StatusFound {
		t.Fatalf("start1 status = %d", rec1.Code)
	}
	if rec2.Code != http.StatusFound {
		t.Fatalf("start2 status = %d", rec2.Code)
	}

	stateCookie1, browserCookie1 := getCookies(t, rec1)
	stateCookie2, browserCookie2 := getCookies(t, rec2)
	if stateCookie1 == nil || browserCookie1 == nil {
		t.Fatal("missing cookies in start1 response")
	}
	if stateCookie2 == nil || browserCookie2 == nil {
		t.Fatal("missing cookies in start2 response")
	}
	if stateCookie1.Value == stateCookie2.Value {
		t.Error("state cookies cross-talk between users")
	}
	if browserCookie1.Value == browserCookie2.Value {
		t.Error("browser cookies cross-talk between users")
	}

	parsed1, _ := url.Parse(rec1.Header().Get("Location"))
	parsed2, _ := url.Parse(rec2.Header().Get("Location"))
	state1 := parsed1.Query().Get("state")
	state2 := parsed2.Query().Get("state")
	if state1 == state2 {
		t.Error("authorization URL states cross-talk between users")
	}

	nonce1 := parsed1.Query().Get("nonce")
	nonce2 := parsed2.Query().Get("nonce")
	if nonce1 == nonce2 {
		t.Error("authorization URL nonces cross-talk between users")
	}

	challenge1 := parsed1.Query().Get("code_challenge")
	challenge2 := parsed2.Query().Get("code_challenge")
	if challenge1 == challenge2 {
		t.Error("authorization URL PKCE challenges cross-talk between users")
	}

	// Concurrent callbacks with barrier.
	cbReq1 := makeCallbackRequest("google", state1, "code-user1", stateCookie1, browserCookie1)
	cbReq2 := makeCallbackRequest("google", state2, "code-user2", stateCookie2, browserCookie2)

	var cbRec1, cbRec2 *httptest.ResponseRecorder
	wg.Add(2)
	ready2 := make(chan struct{}, 2)
	start2Ch := make(chan struct{})

	go func() {
		defer wg.Done()
		ready2 <- struct{}{}
		<-start2Ch
		r := httptest.NewRecorder()
		h1.CallbackHandler().ServeHTTP(r, cbReq1)
		cbRec1 = r
	}()
	go func() {
		defer wg.Done()
		ready2 <- struct{}{}
		<-start2Ch
		r := httptest.NewRecorder()
		h2.CallbackHandler().ServeHTTP(r, cbReq2)
		cbRec2 = r
	}()

	<-ready2
	<-ready2
	close(start2Ch)
	wg.Wait()

	if cbRec1.Code != http.StatusOK {
		t.Fatalf("callback1 status = %d body = %q", cbRec1.Code, cbRec1.Body.String())
	}
	if cbRec2.Code != http.StatusOK {
		t.Fatalf("callback2 status = %d body = %q", cbRec2.Code, cbRec2.Body.String())
	}

	body1 := cbRec1.Body.String()
	body2 := cbRec2.Body.String()
	if body1 == body2 {
		t.Error("callback responses cross-talk between users")
	}
	if !strings.Contains(body1, "user1-subject") {
		t.Errorf("callback1 body = %q, want subject", body1)
	}
	if !strings.Contains(body2, "user2-subject") {
		t.Errorf("callback2 body = %q, want subject", body2)
	}
}

// TestStartRejectsRedirectURIOutsideAllowlist verifies that start
// rejects redirect_uri values not in the allowlist before saving any
// transaction (fix 1).
func TestStartRejectsRedirectURIOutsideAllowlist(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, store := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://evil.example.com/callback", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("disallowed redirect status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if len(store.transactions) != 0 {
		t.Error("transaction should not be saved for disallowed redirect_uri")
	}
}

// TestBrowserCookieContainsRawNotDigest verifies that the browser cookie
// stores the raw secret while the transaction stores only its SHA-256
// digest (fix 2).
func TestBrowserCookieContainsRawNotDigest(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, store := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))

	_, browserCookie := getCookies(t, rec)
	if browserCookie == nil {
		t.Fatal("missing browser cookie")
	}
	rawValue := browserCookie.Value

	// The raw cookie value must NOT appear anywhere in the stored transaction.
	for _, tx := range store.transactions {
		if tx.BrowserBindingDigest == rawValue {
			t.Error("raw browser cookie value appears in stored transaction BrowserBindingDigest")
		}
	}

	// The stored digest must be DigestSHA256 of the raw value.
	expectedDigest := DigestSHA256(rawValue)
	for _, tx := range store.transactions {
		if tx.BrowserBindingDigest != expectedDigest {
			t.Errorf("BrowserBindingDigest = %q, want %q", tx.BrowserBindingDigest, expectedDigest)
		}
	}
}

// TestTamperedSameLengthStateRejected verifies that a same-length state
// query parameter differing from the cookie is rejected. The source
// code review confirms this goes through crypto/subtle.ConstantTimeCompare.
func TestTamperedSameLengthStateRejected(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)

	parsed, _ := url.Parse(start.Header().Get("Location"))
	origState := parsed.Query().Get("state")

	// Unconditional same-length tampering: copy bytes, flip the first
	// byte to a different valid base64url character. This always
	// produces a different same-length string regardless of content.
	tampered := []byte(origState)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}

	cb := makeCallbackRequest("google", string(tampered), "code", stateCookie, browserCookie)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, cb)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tampered same-length state status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestCollapsedCallbackErrors verifies that all callback validation
// failures produce the same status/body/content-type (fix 4).
func TestCollapsedCallbackErrors(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	type testCase struct {
		name string
		req  *http.Request
	}
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)
	parsed, _ := url.Parse(start.Header().Get("Location"))
	state := parsed.Query().Get("state")

	cases := []testCase{
		{"unknown state", makeCallbackRequest("google", "unknown", "code", stateCookie, browserCookie)},
		{"tampered state", makeCallbackRequest("google", "tampered", "code", stateCookie, browserCookie)},
		{"empty browser cookie", makeCallbackRequest("google", state, "code", stateCookie, nil)},
		{"wrong browser cookie", makeCallbackRequest("google", state, "code", stateCookie, &http.Cookie{Name: browserCookieName, Value: "wrong"})},
		{"missing state cookie", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/upstream/google/callback?state="+url.QueryEscape(state)+"&code=code", nil)
			r.AddCookie(browserCookie)
			return r
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.CallbackHandler().ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if body := rec.Body.String(); body != "State mismatch\n" {
				t.Errorf("body = %q, want %q", body, "State mismatch\n")
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("content-type = %q", ct)
			}
		})
	}
}

// TestCollapsedCallbackErrorsIncludesVerifierAndExchangeFailures
// verifies that verifier failures and exchange failures also produce
// the collapsed response (fix 4).
func TestCollapsedCallbackErrorsIncludesVerifierAndExchangeFailures(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	t.Run("verifier failure", func(t *testing.T) {
		verifierErr := errors.New("signature verification failed")
		h, _ := testHandler(t, &fakeTokenExchanger{idToken: "bad"}, &fakeTokenVerifierHTTP{err: verifierErr}, entropy)

		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)
		parsed, _ := url.Parse(start.Header().Get("Location"))
		state := parsed.Query().Get("state")

		cb := makeCallbackRequest("google", state, "code", stateCookie, browserCookie)
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, cb)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("verifier failure status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if body := rec.Body.String(); body != "State mismatch\n" {
			t.Errorf("body = %q, want %q", body, "State mismatch\n")
		}
	})

	t.Run("exchange failure", func(t *testing.T) {
		h, _ := testHandler(t, &fakeTokenExchanger{err: errors.New("upstream 400")}, &fakeTokenVerifierHTTP{claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "s",
			Audience:  []string{"test-client"},
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		}}, entropy)

		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)
		parsed, _ := url.Parse(start.Header().Get("Location"))
		state := parsed.Query().Get("state")

		cb := makeCallbackRequest("google", state, "code", stateCookie, browserCookie)
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, cb)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("exchange failure status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if body := rec.Body.String(); body != "State mismatch\n" {
			t.Errorf("body = %q, want %q", body, "State mismatch\n")
		}
	})

	t.Run("nil exchange result", func(t *testing.T) {
		h, _ := testHandler(t, &fakeTokenExchanger{nilResult: true}, &fakeTokenVerifierHTTP{claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "s",
			Audience:  []string{"test-client"},
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		}}, entropy)

		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)
		parsed, _ := url.Parse(start.Header().Get("Location"))
		state := parsed.Query().Get("state")

		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, browserCookie))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("nil exchange result status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if body := rec.Body.String(); body != "State mismatch\n" {
			t.Errorf("body = %q, want %q", body, "State mismatch\n")
		}
	})
}

// TestCookiesClearedAfterCallback verifies that both cookies are cleared
// after every callback attempt (fix 5).
func TestCookiesClearedAfterCallback(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}

	t.Run("cleared on success", func(t *testing.T) {
		h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)
		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)
		parsed, _ := url.Parse(start.Header().Get("Location"))
		state := parsed.Query().Get("state")

		cb := makeCallbackRequest("google", state, "code", stateCookie, browserCookie)
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, cb)

		stateClear, browserClear := getClearCookies(t, rec)
		if !stateClear {
			t.Error("state cookie not cleared after successful callback")
		}
		if !browserClear {
			t.Error("browser cookie not cleared after successful callback")
		}
	})

	t.Run("cleared on failure", func(t *testing.T) {
		h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)
		start := httptest.NewRecorder()
		h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
		stateCookie, browserCookie := getCookies(t, start)

		cb := makeCallbackRequest("google", "bad-state", "code", stateCookie, browserCookie)
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, cb)

		stateClear, browserClear := getClearCookies(t, rec)
		if !stateClear {
			t.Error("state cookie not cleared after failed callback")
		}
		if !browserClear {
			t.Error("browser cookie not cleared after failed callback")
		}
	})
}

// TestReplayedStateRejected verifies that replaying a consumed
// transaction is rejected with the collapsed error response.
func TestReplayedStateRejected(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)

	parsed, _ := url.Parse(start.Header().Get("Location"))
	state := parsed.Query().Get("state")

	cb1 := makeCallbackRequest("google", state, "code1", stateCookie, browserCookie)
	rec1 := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec1, cb1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first callback status = %d", rec1.Code)
	}

	cb2 := makeCallbackRequest("google", state, "code2", stateCookie, browserCookie)
	rec2 := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec2, cb2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("replay status = %d, want %d", rec2.Code, http.StatusBadRequest)
	}
	if body := rec2.Body.String(); body != "State mismatch\n" {
		t.Errorf("replay body = %q, want %q", body, "StateMismatch\n")
	}
}

// TestConstructorClonesConfigs verifies that mutating the original
// configs map after construction does not affect the handler (fix 7).
func TestConstructorClonesConfigs(t *testing.T) {
	t.Parallel()
	store := newTestStore()
	ex := &fakeTokenExchanger{idToken: "t"}
	ver := &fakeTokenVerifierHTTP{claims: &IDTokenClaims{}}
	cfgs := map[string]Config{
		"g": {
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/auth",
			TokenEndpoint:         "https://issuer.example.com/token",
			ClientID:              "c",
			Scopes:                []string{"openid"},
		},
	}
	allowed := map[string]bool{"https://ok.example.com/cb": true}

	h, err := NewHandler(cfgs, store, ex, ver, nil, allowed)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate original maps.
	cfgs["g"] = Config{
		Issuer:                cfgs["g"].Issuer,
		AuthorizationEndpoint: cfgs["g"].AuthorizationEndpoint,
		TokenEndpoint:         cfgs["g"].TokenEndpoint,
		ClientID:              "mutated",
	}
	cfgs["evil"] = Config{ClientID: "evil"}
	allowed["https://evil.example.com/cb"] = true

	if h.configs["g"].ClientID == "mutated" {
		t.Error("handler configs were mutated")
	}
	if _, ok := h.configs["evil"]; ok {
		t.Error("handler configs contain injected key")
	}
	if h.allowedRedirects["https://evil.example.com/cb"] {
		t.Error("handler allowedRedirects were mutated")
	}
}

// TestStartMethodNotAllowed verifies 405 on non-GET start.
func TestStartMethodNotAllowed(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST start status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if rec.Header().Get("Allow") != http.MethodGet {
		t.Errorf("Allow header = %q, want GET", rec.Header().Get("Allow"))
	}
}

// TestCallbackMethodNotAllowed verifies 405 on non-GET callback.
func TestCallbackMethodNotAllowed(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upstream/google/callback?state=s&code=c", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST callback status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// TestInvalidProviderRejected verifies 404 for unknown provider.
func TestInvalidProviderRejected(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/nonexistent/start?redirect_uri=https://app.example.com/callback", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown provider status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestMissingStartParams verifies 400 for missing redirect_uri.
func TestMissingStartParams(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing redirect_uri status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestMissingCallbackParams verifies 400 for missing state or code.
func TestMissingCallbackParams(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	req := httptest.NewRequest(http.MethodGet, "/upstream/google/callback?code=c", nil)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing state status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if body := rec.Body.String(); body != "State mismatch\n" {
		t.Errorf("missing state body = %q, want %q", body, "State mismatch\n")
	}

	req = httptest.NewRequest(http.MethodGet, "/upstream/google/callback?state=s", nil)
	rec = httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing code status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if body := rec.Body.String(); body != "State mismatch\n" {
		t.Errorf("missing code body = %q, want %q", body, "State mismatch\n")
	}
}

// TestLargeQueryRejected verifies 400 for oversized query string.
func TestLargeQueryRejected(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	bigQuery := strings.Repeat("x", maxQueryLen+1)
	req := httptest.NewRequest(http.MethodGet, "/upstream/google/callback?"+bigQuery, nil)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("large query status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if body := rec.Body.String(); body != "State mismatch\n" {
		t.Errorf("large query body = %q, want %q", body, "State mismatch\n")
	}
}

// TestNewHandlerValidation verifies constructor rejects nil/empty inputs.
func TestNewHandlerValidation(t *testing.T) {
	t.Parallel()
	store := newTestStore()
	ex := &fakeTokenExchanger{idToken: "t"}
	ver := &fakeTokenVerifierHTTP{claims: &IDTokenClaims{}}
	cfgs := map[string]Config{"g": {Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "c"}}

	if _, err := NewHandler(nil, store, ex, ver, nil, nil); err == nil {
		t.Error("expected error for empty configs")
	}
	if _, err := NewHandler(cfgs, nil, ex, ver, nil, nil); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := NewHandler(cfgs, store, nil, ver, nil, nil); err == nil {
		t.Error("expected error for nil exchanger")
	}
	if _, err := NewHandler(cfgs, store, ex, nil, nil, nil); err == nil {
		t.Error("expected error for nil verifier")
	}
	invalidKey := map[string]Config{"Google": cfgs["g"]}
	if _, err := NewHandler(invalidKey, store, ex, ver, nil, nil); err == nil {
		t.Error("expected error for noncanonical provider key")
	}
	if _, err := NewHandler(map[string]Config{"g": {}}, store, ex, ver, nil, nil); err == nil {
		t.Error("expected error for invalid provider config")
	}
	h, err := NewHandler(cfgs, store, ex, ver, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if h == nil {
		t.Error("handler is nil")
	}
}

// TestExtractProviderID verifies URL path parsing.
func TestExtractProviderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path, want string
	}{
		{"/upstream/google/start", "google"},
		{"/upstream/github/callback", "github"},
		{"/upstream/", ""},
		{"/other/path", ""},
		{"upstream/google/start", "google"},
	}
	for _, tt := range tests {
		got := extractProviderID(tt.path)
		if got != tt.want {
			t.Errorf("extractProviderID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// TestStartHandlerSetsSecureCookies verifies cookie security attributes.
func TestStartHandlerSetsSecureCookies(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if !c.Secure {
			t.Errorf("cookie %q not Secure", c.Name)
		}
		if !c.HttpOnly {
			t.Errorf("cookie %q not HttpOnly", c.Name)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %q SameSite = %v, want Lax", c.Name, c.SameSite)
		}
	}
}

// TestCallbackResponseContentType verifies successful callback returns JSON.
func TestCallbackResponseContentType(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "sub-123",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "tok"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)

	parsed, _ := url.Parse(start.Header().Get("Location"))
	state := parsed.Query().Get("state")
	cb := makeCallbackRequest("google", state, "code", stateCookie, browserCookie)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, cb)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestStateMismatchBetweenCookieAndQuery verifies that a state query
// parameter differing from the cookie is rejected.
func TestStateMismatchBetweenCookieAndQuery(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)

	cb := makeCallbackRequest("google", "different-state", "code", stateCookie, browserCookie)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, cb)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("state mismatch status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestStartHandlerRedirectLocation verifies the redirect URL is correct.
func TestStartHandlerRedirectLocation(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	h, _ := testHandler(t, &fakeTokenExchanger{idToken: "t"}, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	rec := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("empty Location header")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location parse error: %v", err)
	}
	if parsed.Scheme != "https" {
		t.Errorf("Location scheme = %q, want https", parsed.Scheme)
	}
	if parsed.Host != "issuer.example.com" {
		t.Errorf("Location host = %q, want issuer.example.com", parsed.Host)
	}
	if parsed.Query().Get("client_id") != "test-client" {
		t.Error("Location missing client_id")
	}
	if parsed.Query().Get("response_type") != "code" {
		t.Error("Location missing response_type")
	}
}

type localHookRecorder struct {
	prepareErr                           error
	currentErr                           error
	resolveErr                           error
	session                              string
	prepareToken                         string
	currentToken                         string
	digest                               string
	interaction                          string
	mu                                   sync.Mutex
	completed                            int
	resolved                             int
	gotToken, gotInteraction, gotSubject string
	gotUpstream                          SubjectResult
	gotOIDC                              *OIDCSession
}

func (h *localHookRecorder) hooks() LocalLoginHooks {
	return LocalLoginHooks{
		Prepare: func(_ *http.Request, interaction string) (string, string, string, error) {
			if h.prepareErr != nil {
				return "", "", "", h.prepareErr
			}
			token := h.session
			if h.prepareToken != "" {
				token = h.prepareToken
			}
			return token, h.digest, h.interaction, nil
		},
		Current: func(_ *http.Request) (string, string, error) {
			if h.currentErr != nil {
				return "", "", h.currentErr
			}
			token := h.session
			if h.currentToken != "" {
				token = h.currentToken
			}
			return token, h.digest, nil
		},
		Resolve: func(_ context.Context, upstream SubjectResult) (string, error) {
			h.mu.Lock()
			h.resolved++
			h.gotUpstream = upstream
			h.mu.Unlock()
			if h.resolveErr != nil {
				return "", h.resolveErr
			}
			return "local-user", nil
		},
		Complete: func(w http.ResponseWriter, _ *http.Request, token, interaction, subject string, upstream *OIDCSession) {
			h.mu.Lock()
			h.completed++
			h.gotOIDC = upstream
			h.gotToken, h.gotInteraction, h.gotSubject = token, interaction, subject
			h.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		},
	}
}

func testLocalHandler(t *testing.T, hooks LocalLoginHooks) (*Handler, *testInMemoryStore) {
	t.Helper()
	store := newTestStore()
	claims := &fakeTokenVerifierHTTP{claims: &IDTokenClaims{Issuer: "https://issuer.example.com", Subject: "external-user", Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(), IssuedAt: fixedNow.Add(-time.Minute).Unix()}}
	h, err := NewLocalLoginHandler(map[string]Config{"google": {Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "test-client", Scopes: []string{"openid", "profile"}}}, store, &fakeTokenExchanger{idToken: "token"}, &deterministicVerifier{claims: claims.claims, store: store}, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store
}

func localStart(t *testing.T, h *Handler) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start status=%d body=%q", rec.Code, rec.Body.String())
	}
	state, browser := getCookies(t, rec)
	if state == nil || browser != nil {
		t.Fatalf("cookies state=%#v browser=%#v", state, browser)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return state, u.Query().Get("state")
}

func TestLocalLoginHooksRequired(t *testing.T) {
	t.Parallel()
	_, err := NewLocalLoginHandler(map[string]Config{"g": {}}, newTestStore(), &fakeTokenExchanger{}, &fakeTokenVerifierHTTP{}, nil, nil, LocalLoginHooks{})
	if !errors.Is(err, errHandlerLocalHooks) {
		t.Fatalf("err=%v", err)
	}
}

func TestGitHubCallbacksPassImmutableSubjectWithoutIDTokenVerification(t *testing.T) {
	t.Parallel()
	github := Config{
		Kind: ProviderKindGitHub, Issuer: "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user", ClientID: "client", Scopes: []string{"read:user"},
	}
	upstream := SubjectResult{ProviderID: "github", Subject: "123456789"}

	t.Run("local login", func(t *testing.T) {
		hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
		verifier := &countingTokenVerifier{}
		store := newTestStore()
		h, err := NewLocalLoginHandler(map[string]Config{"github": github}, store, &fakeTokenExchanger{subject: &upstream}, verifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true}, hooks.hooks())
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }
		start := httptest.NewRecorder()
		h.LocalStartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/github/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
		stateCookie, _ := getCookies(t, start)
		u, _ := url.Parse(start.Header().Get("Location"))
		state := u.Query().Get("state")
		rec := httptest.NewRecorder()
		h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("github", state, "code", stateCookie, nil))
		if rec.Code != http.StatusNoContent || verifier.calls != 0 {
			t.Fatalf("status=%d verifier calls=%d", rec.Code, verifier.calls)
		}
		hooks.mu.Lock()
		got := hooks.gotUpstream
		if hooks.gotOIDC != nil {
			t.Fatal("GitHub login created OIDC session binding")
		}
		hooks.mu.Unlock()
		if got != upstream {
			t.Fatalf("upstream subject = %#v, want %#v", got, upstream)
		}
	})

	t.Run("link", func(t *testing.T) {
		hooks := &linkHookRecorder{subject: "local-user", token: testCanonicalTestToken, digest: testCanonicalTestDigest, decision: LinkDecisionLinked}
		verifier := &countingTokenVerifier{}
		store := newTestStore()
		h, err := NewLinkHandler(map[string]Config{"github": github}, store, &fakeTokenExchanger{subject: &upstream}, verifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]string{"github": "https://app.example.com/link/callback"}, hooks.hooks())
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }
		start := httptest.NewRecorder()
		h.LinkStartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/upstream/github/link", nil))
		var body map[string]string
		if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(body["authorization_url"])
		rec := httptest.NewRecorder()
		h.LinkCallbackHandler().ServeHTTP(rec, makeCallbackRequest("github", u.Query().Get("state"), "code", &http.Cookie{Name: stateCookieName, Value: u.Query().Get("state")}, nil))
		if rec.Code != http.StatusNoContent || verifier.calls != 0 {
			t.Fatalf("status=%d verifier calls=%d", rec.Code, verifier.calls)
		}
		if hooks.gotUpstream != upstream {
			t.Fatalf("upstream subject = %#v, want %#v", hooks.gotUpstream, upstream)
		}
	})
}

func TestLocalStartPrepareFailureDoesNotPersist(t *testing.T) {
	t.Parallel()
	hooks := &localHookRecorder{prepareErr: errors.New("no")}
	h, store := testLocalHandler(t, hooks.hooks())
	rec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if rec.Code != http.StatusBadRequest || len(store.transactions) != 0 {
		t.Fatalf("status=%d transactions=%d", rec.Code, len(store.transactions))
	}
}

func TestLocalStartRejectsMismatchedRawSessionToken(t *testing.T) {
	t.Parallel()
	hooks := &localHookRecorder{session: testCanonicalTestToken, prepareToken: "other-token", digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	h, store := testLocalHandler(t, hooks.hooks())
	rec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if rec.Code != http.StatusBadRequest || len(store.transactions) != 0 {
		t.Fatalf("status=%d transactions=%d", rec.Code, len(store.transactions))
	}
}

func TestLocalFlowBindsAndCompletesWithoutBrowserCookie(t *testing.T) {
	t.Parallel()
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	h, store := testLocalHandler(t, hooks.hooks())
	stateCookie, state := localStart(t, h)
	for _, tx := range store.transactions {
		if tx.BrowserBindingDigest != hooks.digest || tx.SessionDigest != hooks.digest || tx.InteractionDigest != hooks.interaction {
			t.Fatalf("binding=%#v", tx)
		}
	}
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusNoContent || strings.Contains(rec.Body.String(), "external-user") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.completed != 1 || hooks.gotToken != hooks.session || hooks.gotInteraction != hooks.interaction || hooks.gotSubject != "local-user" {
		t.Fatalf("complete=%d token=%q interaction=%q subject=%q", hooks.completed, hooks.gotToken, hooks.gotInteraction, hooks.gotSubject)
	}
}

func TestLocalCallbackRejectsCurrentResolveAndSessionFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		current, resolve error
		mismatch         bool
	}{
		{"current", errors.New("no"), nil, false}, {"missing link", nil, errors.New("no link"), false}, {"disabled link", nil, errors.New("disabled"), false}, {"session mismatch", nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction"), currentErr: tc.current, resolveErr: tc.resolve}
			h, store := testLocalHandler(t, hooks.hooks())
			stateCookie, state := localStart(t, h)
			if tc.mismatch {
				for key, tx := range store.transactions {
					tx.SessionDigest = DigestSHA256("other-session")
					store.transactions[key] = tx
				}
			}
			rec := httptest.NewRecorder()
			h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
			if rec.Code != http.StatusBadRequest || rec.Body.String() != "State mismatch\n" {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
			hooks.mu.Lock()
			completed := hooks.completed
			hooks.mu.Unlock()
			if completed != 0 {
				t.Fatalf("completed=%d", completed)
			}
		})
	}
}

func TestLocalCallbackRejectsMismatchedRawSessionTokenWithoutConsume(t *testing.T) {
	t.Parallel()
	hooks := &localHookRecorder{session: testCanonicalTestToken, currentToken: "other-token", digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	h, store := testLocalHandler(t, hooks.hooks())
	stateCookie, state := localStart(t, h)
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest || rec.Body.String() != "State mismatch\n" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	for key := range store.transactions {
		if store.consumed[key] {
			t.Fatal("mismatched raw token consumed transaction")
		}
	}
	hooks.mu.Lock()
	completed := hooks.completed
	hooks.mu.Unlock()
	if completed != 0 {
		t.Fatalf("completed=%d", completed)
	}
}

func TestLoginCallbacksRejectLinkPurpose(t *testing.T) {
	t.Parallel()
	t.Run("legacy", func(t *testing.T) {
		exchanger := &recordingExchanger{idToken: "token"}
		h, store := testHandler(t, exchanger, &fakeTokenVerifierHTTP{claims: &IDTokenClaims{Issuer: "https://issuer.example.com", Subject: "external-user", Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(), IssuedAt: fixedNow.Add(-time.Minute).Unix()}}, make([]byte, 256))
		rawBrowser := "browser-token"
		result, err := GenerateAuthorizationURL(context.Background(), h.provider, h.configs["google"], store, AuthorizationParams{Purpose: PurposeLink, CallbackURI: "https://app.example.com/callback", LinkSubject: "local-user", LinkSessionDigest: DigestSHA256(rawBrowser)}, DigestSHA256(rawBrowser), "google", h.now())
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(result.URL)
		state := u.Query().Get("state")
		rec := httptest.NewRecorder()
		h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", &http.Cookie{Name: stateCookieName, Value: state}, &http.Cookie{Name: browserCookieName, Value: rawBrowser}))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != "State mismatch\n" || exchanger.code != "" {
			t.Fatalf("status=%d body=%q exchange-code=%q", rec.Code, rec.Body.String(), exchanger.code)
		}
		if !store.consumed[result.Transaction.StateDigest] {
			t.Fatal("purpose rejection did not preserve one-use consume")
		}
	})

	t.Run("local", func(t *testing.T) {
		hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
		h, store := testLocalHandler(t, hooks.hooks())
		result, err := GenerateAuthorizationURL(context.Background(), h.provider, h.configs["google"], store, AuthorizationParams{Purpose: PurposeLink, CallbackURI: "https://app.example.com/callback", LinkSubject: "local-user", LinkSessionDigest: hooks.digest}, hooks.digest, "google", h.now())
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(result.URL)
		state := u.Query().Get("state")
		rec := httptest.NewRecorder()
		h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", &http.Cookie{Name: stateCookieName, Value: state}, nil))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != "State mismatch\n" {
			t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
		}
		if exchanger := h.exchanger.(*fakeTokenExchanger); exchanger.calls != 0 {
			t.Fatalf("exchange calls=%d", exchanger.calls)
		}
		hooks.mu.Lock()
		resolved, completed := hooks.resolved, hooks.completed
		hooks.mu.Unlock()
		if resolved != 0 || completed != 0 || !store.consumed[result.Transaction.StateDigest] {
			t.Fatalf("resolved=%d completed=%d consumed=%v", resolved, completed, store.consumed[result.Transaction.StateDigest])
		}
	})
}

type linkHookRecorder struct {
	subject, token, digest string
	currentErr             error
	decision               LinkDecision
	linkErr                error
	linkCalls              int
	linkNow                time.Time
	gotUpstream            SubjectResult
}

func (h *linkHookRecorder) hooks() LinkHooks {
	return LinkHooks{
		Current: func(*http.Request) (string, string, string, error) { return h.subject, h.token, h.digest, h.currentErr },
		Link: func(_ context.Context, _ string, upstream SubjectResult, now time.Time) (LinkDecision, error) {
			h.linkCalls++
			h.linkNow = now
			h.gotUpstream = upstream
			return h.decision, h.linkErr
		},
	}
}

func testLinkHandler(t *testing.T, hooks LinkHooks) (*Handler, *testInMemoryStore) {
	t.Helper()
	store := newTestStore()
	claims := &IDTokenClaims{Issuer: "https://issuer.example.com", Subject: "external-user", Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(), IssuedAt: fixedNow.Add(-time.Minute).Unix()}
	h, err := NewLinkHandler(map[string]Config{"google": {Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "test-client", Scopes: []string{"openid"}}}, store, &fakeTokenExchanger{idToken: "token"}, &deterministicVerifier{claims: claims, store: store}, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]string{"google": "https://app.example.com/link/callback"}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store
}

func TestLinkFlowFixedCallbackAndOutcomes(t *testing.T) {
	t.Parallel()
	newFlow := func(t *testing.T, decision LinkDecision) (*Handler, *testInMemoryStore, *linkHookRecorder, *http.Cookie, string) {
		hooks := &linkHookRecorder{subject: "local-user", token: testCanonicalTestToken, digest: testCanonicalTestDigest, decision: decision}
		h, store := testLinkHandler(t, hooks.hooks())
		rec := httptest.NewRecorder()
		h.LinkStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upstream/google/link", nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("start=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		state, browser := getCookies(t, rec)
		if state == nil || browser != nil {
			t.Fatalf("cookies state=%#v browser=%#v", state, browser)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(body["authorization_url"])
		for _, tx := range store.transactions {
			if tx.Purpose != PurposeLink || tx.CallbackURI != "https://app.example.com/link/callback" {
				t.Fatalf("tx=%#v", tx)
			}
		}
		return h, store, hooks, state, u.Query().Get("state")
	}
	t.Run("linked then replay", func(t *testing.T) {
		h, _, hooks, stateCookie, state := newFlow(t, LinkDecisionLinked)
		rec := httptest.NewRecorder()
		req := makeCallbackRequest("google", state, "code", stateCookie, &http.Cookie{Name: browserCookieName, Value: "legacy-browser"})
		h.LinkCallbackHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || hooks.linkCalls != 1 || !hooks.linkNow.Equal(fixedNow) {
			t.Fatalf("status=%d calls=%d", rec.Code, hooks.linkCalls)
		}
		_, browserClear := getClearCookies(t, rec)
		if browserClear {
			t.Fatal("link success cleared legacy browser cookie")
		}
		replay := httptest.NewRecorder()
		h.LinkCallbackHandler().ServeHTTP(replay, makeCallbackRequest("google", state, "code", stateCookie, nil))
		if replay.Code != http.StatusBadRequest || hooks.linkCalls != 1 {
			t.Fatalf("replay=%d calls=%d", replay.Code, hooks.linkCalls)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		h, _, hooks, stateCookie, state := newFlow(t, LinkDecisionConflict)
		rec := httptest.NewRecorder()
		h.LinkCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, &http.Cookie{Name: browserCookieName, Value: "legacy-browser"}))
		if rec.Code != http.StatusConflict || hooks.linkCalls != 1 {
			t.Fatalf("status=%d calls=%d", rec.Code, hooks.linkCalls)
		}
		_, browserClear := getClearCookies(t, rec)
		if browserClear {
			t.Fatal("link conflict cleared legacy browser cookie")
		}
	})
	t.Run("wrong subject", func(t *testing.T) {
		h, _, hooks, stateCookie, state := newFlow(t, LinkDecisionLinked)
		hooks.subject = "other-user"
		rec := httptest.NewRecorder()
		h.LinkCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, &http.Cookie{Name: browserCookieName, Value: "legacy-browser"}))
		if rec.Code != http.StatusBadRequest || hooks.linkCalls != 0 {
			t.Fatalf("subject status=%d calls=%d", rec.Code, hooks.linkCalls)
		}
		_, browserClear := getClearCookies(t, rec)
		if browserClear {
			t.Fatal("link failure cleared legacy browser cookie")
		}
	})
}

func TestCombinedCallbackSelectsOnlyOneSessionMode(t *testing.T) {
	t.Parallel()
	newCombined := func(t *testing.T, local *localHookRecorder, link *linkHookRecorder) (*Handler, *testInMemoryStore) {
		store := newTestStore()
		claims := &IDTokenClaims{Issuer: "https://issuer.example.com", Subject: "external-user", Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(), IssuedAt: fixedNow.Add(-time.Minute).Unix()}
		h, err := NewLocalLoginAndLinkHandler(map[string]Config{"google": {Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "test-client", Scopes: []string{"openid"}}}, store, &fakeTokenExchanger{idToken: "token"}, &deterministicVerifier{claims: claims, store: store}, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true}, local.hooks(), map[string]string{"google": "https://app.example.com/link/callback"}, link.hooks())
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }
		return h, store
	}
	t.Run("init selects login", func(t *testing.T) {
		local := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
		link := &linkHookRecorder{currentErr: errors.New("not authenticated")}
		h, _ := newCombined(t, local, link)
		stateCookie, state := localStart(t, h)
		rec := httptest.NewRecorder()
		h.CombinedCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
		if rec.Code != http.StatusNoContent || local.completed != 1 || link.linkCalls != 0 {
			t.Fatalf("status=%d complete=%d links=%d", rec.Code, local.completed, link.linkCalls)
		}
	})
	t.Run("neither and both do not consume", func(t *testing.T) {
		for _, both := range []bool{false, true} {
			local := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
			link := &linkHookRecorder{currentErr: errors.New("not authenticated")}
			if !both {
				local.currentErr = errors.New("not init")
			} else {
				link.currentErr = nil
				link.subject, link.token, link.digest = "local-user", testCanonicalTestToken, testCanonicalTestDigest
			}
			h, store := newCombined(t, local, link)
			stateCookie, state := localStart(t, h)
			rec := httptest.NewRecorder()
			h.CombinedCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
			if rec.Code != http.StatusBadRequest || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("both=%v status=%d cookies=%d", both, rec.Code, len(rec.Result().Cookies()))
			}
			for key := range store.transactions {
				if store.consumed[key] {
					t.Fatalf("both=%v consumed", both)
				}
			}
		}
	})
}

func TestLocalCallbackConcurrentReplayCompletesOnce(t *testing.T) {
	t.Parallel()
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	h, _ := testLocalHandler(t, hooks.hooks())
	stateCookie, state := localStart(t, h)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
			results <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins, rejects := 0, 0
	for status := range results {
		if status == http.StatusNoContent {
			wins++
		}
		if status == http.StatusBadRequest {
			rejects++
		}
	}
	hooks.mu.Lock()
	completed := hooks.completed
	hooks.mu.Unlock()
	if wins != 1 || rejects != 1 || completed != 1 {
		t.Fatalf("wins=%d rejects=%d completed=%d", wins, rejects, completed)
	}
}

// TestExchangerReceivesTrustedStoredContext proves the exchanger receives
// the providerID and the exact transaction CallbackURI (stored, trusted
// context) rather than any query-controlled data.
func TestExchangerReceivesTrustedStoredContext(t *testing.T) {
	t.Parallel()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "s",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}

	ex := &recordingExchanger{idToken: "tok"}
	h, store := testHandler(t, ex, &fakeTokenVerifierHTTP{claims: claims}, entropy)

	// Start the flow.
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet,
		"/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	stateCookie, browserCookie := getCookies(t, start)
	parsed, _ := url.Parse(start.Header().Get("Location"))
	state := parsed.Query().Get("state")

	// Verify the stored transaction has the expected CallbackURI.
	var storedTx Transaction
	store.mu.Lock()
	for _, tx := range store.transactions {
		storedTx = tx
		break
	}
	store.mu.Unlock()
	if storedTx.CallbackURI != "https://app.example.com/callback" {
		t.Fatalf("stored CallbackURI = %q, want %q", storedTx.CallbackURI, "https://app.example.com/callback")
	}
	if storedTx.ProviderID != "google" {
		t.Fatalf("stored ProviderID = %q, want %q", storedTx.ProviderID, "google")
	}

	// Complete the callback.
	cb := makeCallbackRequest("google", state, "auth-code", stateCookie, browserCookie)
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, cb)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body = %q", rec.Code, rec.Body.String())
	}

	// The exchanger must have received the stored providerID and CallbackURI.
	if ex.providerID != "google" {
		t.Errorf("exchanger received providerID = %q, want %q", ex.providerID, "google")
	}
	if ex.callbackURI != "https://app.example.com/callback" {
		t.Errorf("exchanger received callbackURI = %q, want %q", ex.callbackURI, "https://app.example.com/callback")
	}
	if ex.code != "auth-code" {
		t.Errorf("exchanger received code = %q, want %q", ex.code, "auth-code")
	}
}

func TestLocalCallbackCarriesVerifiedOIDCSession(t *testing.T) {
	t.Parallel()
	for _, sid := range []string{"", "upstream-session"} {
		t.Run("sid="+sid, func(t *testing.T) {
			hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
			h, _ := testLocalHandler(t, hooks.hooks())
			h.verifier.(*deterministicVerifier).claims.SessionID = sid
			cookie, state := localStart(t, h)
			rec := httptest.NewRecorder()
			h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", cookie, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("callback status=%d", rec.Code)
			}
			want := OIDCSession{Issuer: "https://issuer.example.com", ClientID: "test-client", Subject: "external-user", SessionID: sid}
			if hooks.gotOIDC == nil || *hooks.gotOIDC != want {
				t.Fatalf("verified session = %#v, want %#v", hooks.gotOIDC, want)
			}
		})
	}
}


// rawClaimsVerifier returns claims with rawClaims set, enabling MFA
// claim mapping evaluation in the callback handler. It copies the
// nonce from the stored transaction to pass ValidateIDToken checks.
type rawClaimsVerifier struct {
	claims *IDTokenClaims
	raw    json.RawMessage
	store  Store
}

func (v *rawClaimsVerifier) VerifyIDToken(_ context.Context, _ string, issuer, _ string) (*IDTokenClaims, error) {
	c := *v.claims
	c.rawClaims = make(json.RawMessage, len(v.raw))
	copy(c.rawClaims, v.raw)
	s := v.store.(*testInMemoryStore)
	s.mu.Lock()
	for _, tx := range s.transactions {
		if tx.Issuer == issuer {
			c.Nonce = tx.Nonce
			break
		}
	}
	s.mu.Unlock()
	return &c, nil
}

// testLocalHandlerWithMFA creates a handler with MFAClaimPath/MFAClaimValue
// in the google config and a verifier that returns claims with rawClaims.
func testLocalHandlerWithMFA(t *testing.T, hooks LocalLoginHooks, mfaPath string, mfaValue *string, raw json.RawMessage) (*Handler, *testInMemoryStore) {
	t.Helper()
	store := newTestStore()
	claims := &IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "external-user",
		Audience:  []string{"test-client"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
	}
	verifier := &rawClaimsVerifier{claims: claims, raw: raw, store: store}
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		MFAClaimPath:          &mfaPath,
		MFAClaimValue:         mfaValue,
	}
	h, err := NewLocalLoginHandler(map[string]Config{"google": cfg}, store, &fakeTokenExchanger{idToken: "token"}, verifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store
}

func TestLocalCallbackMFAEvalErrorRejectsBeforeResolve(t *testing.T) {
	t.Parallel()
	// MFAClaimPath present but MFAClaimValue nil triggers evalErr
	// and the callback must reject before reaching ResolveVerified.
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	mfaPath := "$.amr"
	h, _ := testLocalHandlerWithMFA(t, hooks.hooks(), mfaPath, nil, json.RawMessage(`{"amr":"mfa"}`))
	cookie, state := localStart(t, h)
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", cookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want BadRequest for eval error", rec.Code)
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.resolved != 0 {
		t.Fatalf("resolved=%d, want 0 (must not reach ResolveVerified)", hooks.resolved)
	}
	if hooks.completed != 0 {
		t.Fatalf("completed=%d, want 0", hooks.completed)
	}
}

func TestLocalCallbackMFAMalformedPathContinuesWithoutMFA(t *testing.T) {
	t.Parallel()
	// Malformed JSONPath returns nil matched (no error), callback proceeds
	// without setting MFAPassed.
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	barVal := "bar"
	h, _ := testLocalHandlerWithMFA(t, hooks.hooks(), "$[invalid", &barVal, json.RawMessage(`{"foo":"bar"}`))
	cookie, state := localStart(t, h)
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", cookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want NoContent", rec.Code)
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.resolved != 1 {
		t.Fatalf("resolved=%d, want 1", hooks.resolved)
	}
	if hooks.completed != 1 {
		t.Fatalf("completed=%d, want 1", hooks.completed)
	}
	if hooks.gotOIDC == nil {
		t.Fatal("gotOIDC is nil")
	}
	if hooks.gotOIDC.MFAPassed {
		t.Fatal("MFAPassed=true, want false for malformed path")
	}
}

func TestLocalCallbackMFATrueClaimSetsMFAPassed(t *testing.T) {
	t.Parallel()
	// Matching claim sets MFAPassed=true on the OIDCSession passed to Complete.
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	mfaVal := "mfa"
	h, _ := testLocalHandlerWithMFA(t, hooks.hooks(), "$.amr", &mfaVal, json.RawMessage(`{"amr":"mfa"}`))
	cookie, state := localStart(t, h)
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", cookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want NoContent", rec.Code)
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.completed != 1 {
		t.Fatalf("completed=%d, want 1", hooks.completed)
	}
	if hooks.gotOIDC == nil {
		t.Fatal("gotOIDC is nil")
	}
	if !hooks.gotOIDC.MFAPassed {
		t.Fatal("MFAPassed=false, want true for matching amr claim")
	}
}
