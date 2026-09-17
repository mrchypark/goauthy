package upstreamprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// managedID is the fixed 24-char alphanumeric provider ID used for
// managed (registry source) test configs. "google" is only 6 chars
// and fails isPinned24ManagedID.
const managedID = "AbCdEfGhIjKlMnOpQrStUvWx"

// bindingTestVerifier returns fixed claims; wraps deterministic nonce lookup.
type bindingTestVerifier struct {
	claims *IDTokenClaims
	err    error
	store  Store
}

func (v *bindingTestVerifier) VerifyIDToken(_ context.Context, _ string, issuer, _ string) (*IDTokenClaims, error) {
	if v.err != nil {
		return nil, v.err
	}
	c := *v.claims
	if s, ok := v.store.(*testInMemoryStore); ok {
		s.mu.Lock()
		for _, tx := range s.transactions {
			if tx.Issuer == issuer {
				c.Nonce = tx.Nonce
				break
			}
		}
		s.mu.Unlock()
	}
	return &c, nil
}
// --- helpers for runtime-binding HTTP tests ---

// managedConfig returns an OIDC config with registry source/version.
func managedConfig(version string) Config {
	return Config{
		Kind:                  ProviderKindOIDC,
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		Audience:              "test-audience",
		ProviderSource:        "registry",
		RuntimeVersion:        version,
	}
}

// managedTestHandler builds a legacy (empty source/version) handler.
func managedTestHandler(t *testing.T, exchanger TokenExchanger) (*Handler, *testInMemoryStore, *bindingTestVerifier) {
	t.Helper()
	store := newTestStore()
	verifier := &bindingTestVerifier{store: store}
	configs := map[string]Config{"google": {
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		Audience:              "test-audience",
	}}
	allowed := map[string]bool{"https://app.example.com/callback": true}
	h, err := NewHandler(configs, store, exchanger, verifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store, verifier
}

// managedHandlerWithVersion builds a handler whose config carries the given
// source/version. Used to test that the callback compares handler config
// against the consumed transaction.
func managedHandlerWithVersion(t *testing.T, exchanger TokenExchanger, version string) (*Handler, *testInMemoryStore, *bindingTestVerifier) {
	t.Helper()
	store := newTestStore()
	verifier := &bindingTestVerifier{store: store}
	cfg := managedConfig(version)
	configs := map[string]Config{managedID: cfg}
	allowed := map[string]bool{"https://app.example.com/callback": true}
	h, err := NewHandler(configs, store, exchanger, verifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store, verifier
}

// --- legacy: zero source/version stays identical ---

func TestRuntimeBindingLegacyCallbackProceeds(t *testing.T) {
	ex := &fakeTokenExchanger{idToken: "tok"}
	h, _, verifier := managedTestHandler(t, ex)
	verifier.claims = &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	// Start
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/google/start?redirect_uri=https://app.example.com/callback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status=%d", start.Code)
	}
	stateCookie, browserCookie := getCookies(t, start)
	u, _ := url.Parse(start.Header().Get("Location"))
	// Callback
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", u.Query().Get("state"), "code", stateCookie, browserCookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy callback status=%d, want 200", rec.Code)
	}
	if ex.calls != 1 {
		t.Fatalf("exchange calls=%d, want 1", ex.calls)
	}
}

// --- managed: matching version proceeds ---

func TestRuntimeBindingManagedMatchProceeds(t *testing.T) {
	ex := &fakeTokenExchanger{idToken: "tok"}
	h, _, verifier := managedHandlerWithVersion(t, ex, "v1.0")
	verifier.claims = &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/AbCdEfGhIjKlMnOpQrStUvWx/start?redirect_uri=https://app.example.com/callback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status=%d", start.Code)
	}
	stateCookie, browserCookie := getCookies(t, start)
	u, _ := url.Parse(start.Header().Get("Location"))
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest(managedID, u.Query().Get("state"), "code", stateCookie, browserCookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("managed match callback status=%d, want 200", rec.Code)
	}
	if ex.calls != 1 {
		t.Fatalf("exchange calls=%d, want 1", ex.calls)
	}
}

// --- managed: changed version rejected with zero exchange ---

func TestRuntimeBindingChangedVersionRejected(t *testing.T) {
	// Handler is v1.0 but we simulate a version change by starting a
	// transaction with v1.0, then swapping the handler config to v2.0
	// before callback.
	ex := &fakeTokenExchanger{idToken: "tok"}
	h, store, verifier := managedHandlerWithVersion(t, ex, "v1.0")
	verifier.claims = &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/AbCdEfGhIjKlMnOpQrStUvWx/start?redirect_uri=https://app.example.com/callback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status=%d", start.Code)
	}
	stateCookie, browserCookie := getCookies(t, start)
	u, _ := url.Parse(start.Header().Get("Location"))
	// Swap handler config to v2.0 (simulates runtime upgrade between start and callback).
	h.configs[managedID] = managedConfig("v2.0")
	// Callback should reject: tx has v1.0 but handler now has v2.0.
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest(managedID, u.Query().Get("state"), "code", stateCookie, browserCookie))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("changed version status=%d, want 400", rec.Code)
	}
	if ex.calls != 0 {
		t.Fatalf("exchange calls=%d, want 0 (fail closed)", ex.calls)
	}
	_ = store // transaction consumed but exchange never called
}

// --- managed: legacy handler vs managed transaction rejected ---

func TestRuntimeBindingLegacyHandlerVsManagedTxRejected(t *testing.T) {
	// Start a transaction with managed binding (v1.0), then try to
	// callback against a legacy handler (empty source/version).
	ex := &fakeTokenExchanger{idToken: "tok"}
	// Step 1: build a managed handler with lowercase 24-char ID
	// (works for both managed and legacy validation).
	store := newTestStore()
	mgrVerifier := &bindingTestVerifier{store: store}
	mgrCfg := managedConfig("v1.0")
	mgrConfigs := map[string]Config{"abcdefghijklmnopqrstuvwx": mgrCfg}
	managedH, err := NewHandler(mgrConfigs, store, ex, mgrVerifier, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true})
	if err != nil {
		t.Fatal(err)
	}
	managedH.now = func() time.Time { return fixedNow }
	start := httptest.NewRecorder()
	managedH.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/abcdefghijklmnopqrstuvwx/start?redirect_uri=https://app.example.com/callback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status=%d", start.Code)
	}
	stateCookie, browserCookie := getCookies(t, start)
	u, _ := url.Parse(start.Header().Get("Location"))
	stateVal := u.Query().Get("state")
	// Step 2: build a legacy handler with the same store.
	legacyEx := &fakeTokenExchanger{idToken: "tok"}
	legacyV := &bindingTestVerifier{claims: &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}}
	legacyCfgs := map[string]Config{"abcdefghijklmnopqrstuvwx": {
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		Audience:              "test-audience",
	}}
	legacyH, err := NewHandler(legacyCfgs, store, legacyEx, legacyV, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true})
	if err != nil {
		t.Fatal(err)
	}
	legacyH.now = func() time.Time { return fixedNow }
	// Callback: tx has source="registry", handler has empty → rejected.
	rec := httptest.NewRecorder()
	legacyH.CallbackHandler().ServeHTTP(rec, makeCallbackRequest("abcdefghijklmnopqrstuvwx", stateVal, "code", stateCookie, browserCookie))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("legacy-vs-managed status=%d, want 400", rec.Code)
	}
	if legacyEx.calls != 0 {
		t.Fatalf("exchange calls=%d, want 0 (fail closed)", legacyEx.calls)
	}
}

// --- local callback: changed version rejected with zero exchange ---

func TestRuntimeBindingLocalCallbackChangedVersionRejected(t *testing.T) {
	ex := &fakeTokenExchanger{idToken: "tok"}
	hooks := &localHookRecorder{session: testCanonicalTestToken, digest: testCanonicalTestDigest, interaction: DigestSHA256("interaction")}
	// Build a managed local handler.
	store := newTestStore()
	claims := &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	cfg := managedConfig("v1.0")
	h, err := NewLocalLoginHandler(map[string]Config{managedID: cfg}, store, ex, &deterministicVerifier{claims: claims, store: store}, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]bool{"https://app.example.com/callback": true}, hooks.hooks())
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	// Start (inline localStart with managedID path)
	startRec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(startRec, httptest.NewRequest(http.MethodGet, "/upstream/AbCdEfGhIjKlMnOpQrStUvWx/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if startRec.Code != http.StatusFound {
		t.Fatalf("start status=%d body=%q", startRec.Code, startRec.Body.String())
	}
	stateCookie, _ := getCookies(t, startRec)
	startURL, _ := url.Parse(startRec.Header().Get("Location"))
	state := startURL.Query().Get("state")
	// Swap config to v2.0.
	h.configs[managedID] = managedConfig("v2.0")
	// Callback should reject.
	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest(managedID, state, "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("local changed version status=%d, want 400", rec.Code)
	}
	if ex.calls != 0 {
		t.Fatalf("exchange calls=%d, want 0", ex.calls)
	}
}

// --- link callback: changed version rejected with zero exchange ---

func TestRuntimeBindingLinkCallbackChangedVersionRejected(t *testing.T) {
	ex := &fakeTokenExchanger{idToken: "tok"}
	linkHooks := &linkHookRecorder{subject: "local-user", token: testCanonicalTestToken, digest: testCanonicalTestDigest, decision: LinkDecisionLinked}
	store := newTestStore()
	claims := &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	cfg := managedConfig("v1.0")
	h, err := NewLinkHandler(map[string]Config{managedID: cfg}, store, ex, &deterministicVerifier{claims: claims, store: store}, newCryptoProvider(newFixedRandom(make([]byte, 256))), map[string]string{managedID: "https://app.example.com/link/callback"}, linkHooks.hooks())
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	// Start link flow.
	startRec := httptest.NewRecorder()
	h.LinkStartHandler().ServeHTTP(startRec, httptest.NewRequest(http.MethodPost, "/upstream/AbCdEfGhIjKlMnOpQrStUvWx/link", nil))
	if startRec.Code != http.StatusOK {
		t.Fatalf("link start status=%d", startRec.Code)
	}
	stateCookie := startRec.Result().Cookies()[0]
	var body map[string]string
	if err := json.Unmarshal(startRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(body["authorization_url"])
	// Swap config to v2.0.
	h.configs[managedID] = managedConfig("v2.0")
	// Callback should reject.
	rec := httptest.NewRecorder()
	h.LinkCallbackHandler().ServeHTTP(rec, makeCallbackRequest(managedID, u.Query().Get("state"), "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("link changed version status=%d, want 400", rec.Code)
	}
	if ex.calls != 0 {
		t.Fatalf("exchange calls=%d, want 0", ex.calls)
	}
}

// --- managed: issuer mismatch rejected with zero exchange ---

func TestRuntimeBindingIssuerMismatchRejected(t *testing.T) {
	ex := &fakeTokenExchanger{idToken: "tok"}
	h, _, verifier := managedHandlerWithVersion(t, ex, "v1.0")
	verifier.claims = &IDTokenClaims{
		Issuer: "https://issuer.example.com", Subject: "u1",
		Audience: []string{"test-client"}, ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		IssuedAt: fixedNow.Add(-time.Minute).Unix(),
	}
	start := httptest.NewRecorder()
	h.StartHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/upstream/AbCdEfGhIjKlMnOpQrStUvWx/start?redirect_uri=https://app.example.com/callback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status=%d", start.Code)
	}
	stateCookie, browserCookie := getCookies(t, start)
	u, _ := url.Parse(start.Header().Get("Location"))
	// Swap issuer in handler config (simulates config drift).
	cfg := managedConfig("v1.0")
	cfg.Issuer = "https://other.example.com"
	h.configs[managedID] = cfg
	rec := httptest.NewRecorder()
	h.CallbackHandler().ServeHTTP(rec, makeCallbackRequest(managedID, u.Query().Get("state"), "code", stateCookie, browserCookie))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("issuer mismatch status=%d, want 400", rec.Code)
	}
	if ex.calls != 0 {
		t.Fatalf("exchange calls=%d, want 0", ex.calls)
	}
}
