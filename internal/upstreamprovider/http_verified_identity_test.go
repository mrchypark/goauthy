package upstreamprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// --- helpers for VerifiedIdentity tests ---

// signedIdentityToken creates a real RS256-signed JWT with the given extra
// claims merged into the standard iss/sub/aud/exp/iat/nbf/nonce set.
func signedIdentityToken(t *testing.T, key *rsa.PrivateKey, kid string, nonce string, extra map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	now := fixedNow
	claims := map[string]any{
		"iss":   "https://issuer.example.com",
		"aud":   "test-client",
		"sub":   "oidc-subject",
		"nonce": nonce,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// identityTestLocalHandler creates a handler with a JWKS-backed verifier
// for the "google" OIDC provider. The verifier performs real signature
// verification against the generated RSA key.
func identityTestLocalHandler(t *testing.T, key *rsa.PrivateKey, hooks LocalLoginHooks) (*Handler, *testInMemoryStore) {
	t.Helper()
	store := newTestStore()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}},
		})
	}))
	t.Cleanup(server.Close)

	configs := map[string]Config{
		"google": {
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/auth",
			TokenEndpoint:         "https://issuer.example.com/token",
			ClientID:              "test-client",
			Scopes:                []string{"openid", "profile"},
		},
	}
	allowed := map[string]bool{"https://app.example.com/callback": true}

	// Build a JWKSVerifier manually to avoid NewJWKSVerifier's Validate()
	// which requires HTTPS JWKS URIs (test servers use HTTP).
	verifier := &JWKSVerifier{
		jwksByIssuer: map[string]string{"https://issuer.example.com": server.URL},
		client:       server.Client(),
		now:          func() time.Time { return fixedNow },
		entries:      make(map[string]jwksCacheEntry),
		fetching:     make(map[string]*jwksFetch),
	}

	h, err := NewLocalLoginHandler(configs, store, &fakeTokenExchanger{}, verifier,
		newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed, hooks)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }
	return h, store
}

// --- identityHookRecorder captures ResolveVerified calls ---

type identityHookRecorder struct {
	mu              sync.Mutex
	session         string
	digest          string
	interaction     string
	resolveErr      error
	resolveVerifiedErr error
	verifiedCalls   int
	gotIdentity     VerifiedIdentity
	completed       int
	gotToken        string
	gotInteraction  string
	gotSubject      string
	gotOIDC         *OIDCSession
}

func (h *identityHookRecorder) hooks() LocalLoginHooks {
	return LocalLoginHooks{
		Prepare: func(_ *http.Request, interaction string) (string, string, string, error) {
			return h.session, h.digest, h.interaction, nil
		},
		Current: func(_ *http.Request) (string, string, error) {
			return h.session, h.digest, nil
		},
		Resolve: func(_ context.Context, _ SubjectResult) (string, error) {
			return "", errors.New("Resolve should not be called when ResolveVerified is set")
		},
		ResolveVerified: func(_ context.Context, identity VerifiedIdentity) (string, error) {
			h.mu.Lock()
			h.verifiedCalls++
			h.gotIdentity = identity
			h.mu.Unlock()
			if h.resolveVerifiedErr != nil {
				return "", h.resolveVerifiedErr
			}
			return "local-user", nil
		},
		Complete: func(w http.ResponseWriter, _ *http.Request, token, interaction, subject string, upstream *OIDCSession) {
			h.mu.Lock()
			h.completed++
			h.gotToken, h.gotInteraction, h.gotSubject = token, interaction, subject
			h.gotOIDC = upstream
			h.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		},
	}
}

// --- tests ---

// TestVerifiedIdentityOIDCSuccessProfileRawAndRuntimeSnapshot proves that a
// signed OIDC token with profile claims and custom raw claims produces a
// VerifiedIdentity carrying: the typed profile claims (Email, EmailVerified,
// GivenName, FamilyName), the full raw JSON payload, a deep-cloned Config
// snapshot with runtime version, and the validated SubjectResult.
func TestVerifiedIdentityOIDCSuccessProfileRawAndRuntimeSnapshot(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, store := identityTestLocalHandler(t, key, hooks.hooks())

	// Set runtime binding fields on the stored config.
	rtCfg := h.configs["google"]
	rtCfg.ProviderSource = "registry"
	rtCfg.RuntimeVersion = "v1.2.3"
	h.configs["google"] = rtCfg

	// Create a transaction with matching runtime binding.
	rawToken := signedIdentityToken(t, key, "k1", "", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"given_name":     "Alice",
		"family_name":    "Lovelace",
		"custom": map[string]any{
			"nested": map[string]any{
				"roles": []string{"admin", "user"},
			},
		},
	})

	// We need the nonce from the transaction for the token.
	// Start the flow, then extract the nonce and re-sign with it.
	stateCookie, state, nonce := localStartWithNonce(t, h)

	// Re-sign with the actual nonce.
	rawToken = signedIdentityToken(t, key, "k1", nonce, map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"given_name":     "Alice",
		"family_name":    "Lovelace",
		"custom": map[string]any{
			"nested": map[string]any{
				"roles": []string{"admin", "user"},
			},
		},
	})

	// Replace the exchanger to return our real signed token.
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("callback status=%d body=%q", rec.Code, rec.Body.String())
	}

	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.verifiedCalls != 1 {
		t.Fatalf("ResolveVerified calls=%d, want 1", hooks.verifiedCalls)
	}

	vi := hooks.gotIdentity

	// SubjectResult
	if vi.Subject.Subject != "oidc-subject" {
		t.Errorf("Subject = %q, want oidc-subject", vi.Subject.Subject)
	}

	// Typed profile claims
	if vi.IDTokenClaims == nil {
		t.Fatal("IDTokenClaims is nil")
	}
	if vi.IDTokenClaims.Email == nil || *vi.IDTokenClaims.Email != "alice@example.com" {
		t.Errorf("Email = %v, want alice@example.com", vi.IDTokenClaims.Email)
	}
	if vi.IDTokenClaims.EmailVerified == nil || !*vi.IDTokenClaims.EmailVerified {
		t.Errorf("EmailVerified = %v, want true", vi.IDTokenClaims.EmailVerified)
	}
	if vi.IDTokenClaims.GivenName == nil || *vi.IDTokenClaims.GivenName != "Alice" {
		t.Errorf("GivenName = %v, want Alice", vi.IDTokenClaims.GivenName)
	}
	if vi.IDTokenClaims.FamilyName == nil || *vi.IDTokenClaims.FamilyName != "Lovelace" {
		t.Errorf("FamilyName = %v, want Lovelace", vi.IDTokenClaims.FamilyName)
	}

	// Raw claims
	raw := vi.IDTokenClaims.RawClaims()
	if raw == nil {
		t.Fatal("RawClaims() returned nil")
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("RawClaims unmarshal: %v", err)
	}
	custom, ok := parsed["custom"].(map[string]any)
	if !ok {
		t.Fatalf("custom claim missing from RawClaims, keys: %v", keysOf(parsed))
	}
	nested, ok := custom["nested"].(map[string]any)
	if !ok {
		t.Fatal("custom.nested missing")
	}
	roles, ok := nested["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "admin" || roles[1] != "user" {
		t.Fatalf("custom.nested.roles = %v, want [admin user]", nested["roles"])
	}

	// Config snapshot carries runtime version
	if vi.Config.RuntimeVersion != "v1.2.3" {
		t.Errorf("Config.RuntimeVersion = %q, want v1.2.3", vi.Config.RuntimeVersion)
	}
	if vi.Config.ProviderSource != "registry" {
		t.Errorf("Config.ProviderSource = %q, want registry", vi.Config.ProviderSource)
	}
	if vi.Config.ClientID != "test-client" {
		t.Errorf("Config.ClientID = %q, want test-client", vi.Config.ClientID)
	}

	// OIDCSession is passed to Complete
	want := OIDCSession{Issuer: "https://issuer.example.com", ClientID: "test-client", Subject: "oidc-subject"}
	if hooks.gotOIDC == nil || hooks.gotOIDC.Issuer != want.Issuer || hooks.gotOIDC.ClientID != want.ClientID || hooks.gotOIDC.Subject != want.Subject {
		t.Fatalf("OIDCSession = %#v, want %#v", hooks.gotOIDC, want)
	}

	// Clean up the store to avoid interfering with nonce extraction.
	_ = store
}

// TestVerifiedIdentityInvalidSignatureNeverInvokesHook proves that an OIDC
// token signed with a different key never reaches the ResolveVerified hook.
func TestVerifiedIdentityInvalidSignatureNeverInvokesHook(t *testing.T) {
	correctKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, _ := identityTestLocalHandler(t, correctKey, hooks.hooks())

	stateCookie, state, nonce := localStartWithNonce(t, h)

	// Sign with wrong key.
	rawToken := signedIdentityToken(t, wrongKey, "k1", nonce, nil)
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want BadRequest for invalid signature", rec.Code)
	}
	hooks.mu.Lock()
	calls := hooks.verifiedCalls
	hooks.mu.Unlock()
	if calls != 0 {
		t.Fatalf("ResolveVerified calls=%d, want 0", calls)
	}
}

// TestVerifiedIdentityNonceMismatchNeverInvokesHook proves that an OIDC
// token with a wrong nonce never reaches the ResolveVerified hook.
func TestVerifiedIdentityNonceMismatchNeverInvokesHook(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, _ := identityTestLocalHandler(t, key, hooks.hooks())

	stateCookie, state, _ := localStartWithNonce(t, h)

	// Sign with a nonce that doesn't match the transaction.
	rawToken := signedIdentityToken(t, key, "k1", "wrong-nonce", nil)
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want BadRequest for nonce mismatch", rec.Code)
	}
	hooks.mu.Lock()
	calls := hooks.verifiedCalls
	hooks.mu.Unlock()
	if calls != 0 {
		t.Fatalf("ResolveVerified calls=%d, want 0", calls)
	}
}

// TestVerifiedIdentityRuntimeVersionMismatchNeverInvokesHook proves that
// when runtime binding mismatches, the hook is never called.
func TestVerifiedIdentityRuntimeVersionMismatchNeverInvokesHook(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, _ := identityTestLocalHandler(t, key, hooks.hooks())

	// Set runtime binding on the handler config.
	rtCfg := h.configs["google"]
	rtCfg.ProviderSource = "registry"
	rtCfg.RuntimeVersion = "v1.0.0"
	h.configs["google"] = rtCfg

	stateCookie, state, nonce := localStartWithNonce(t, h)

	// Modify the stored transaction to have a different runtime version.
	h.store.(*testInMemoryStore).mu.Lock()
	for k, tx := range h.store.(*testInMemoryStore).transactions {
		tx.RuntimeVersion = "v2.0.0"
		h.store.(*testInMemoryStore).transactions[k] = tx
	}
	h.store.(*testInMemoryStore).mu.Unlock()

	rawToken := signedIdentityToken(t, key, "k1", nonce, nil)
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want BadRequest for runtime mismatch", rec.Code)
	}
	hooks.mu.Lock()
	calls := hooks.verifiedCalls
	hooks.mu.Unlock()
	if calls != 0 {
		t.Fatalf("ResolveVerified calls=%d, want 0", calls)
	}
}

// TestVerifiedIdentityResolveFallback proves that when ResolveVerified is
// nil, the existing Resolve hook is used and the flow completes normally.
func TestVerifiedIdentityResolveFallback(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	hooks := &localHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, _ := identityTestLocalHandler(t, key, hooks.hooks())

	stateCookie, state, nonce := localStartWithNonce(t, h)

	rawToken := signedIdentityToken(t, key, "k1", nonce, nil)
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want NoContent for Resolve fallback", rec.Code)
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.resolved != 1 {
		t.Fatalf("Resolve calls=%d, want 1", hooks.resolved)
	}
	if hooks.gotUpstream.Subject != "oidc-subject" {
		t.Errorf("Resolve got subject %q, want oidc-subject", hooks.gotUpstream.Subject)
	}
}

// TestVerifiedIdentityDeepCopyIsolation proves that mutating the
// VerifiedIdentity.Config after construction does not affect the handler's
// internal config, and vice versa.
func TestVerifiedIdentityDeepCopyIsolation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	h, _ := identityTestLocalHandler(t, key, hooks.hooks())

	// Set a pointer field on the handler config.
	path := ".claims.admin"
	cfg := h.configs["google"]
	cfg.AdminClaimPath = &path
	h.configs["google"] = cfg

	stateCookie, state, nonce := localStartWithNonce(t, h)
	rawToken := signedIdentityToken(t, key, "k1", nonce, map[string]any{
		"email": "bob@example.com",
	})
	h.exchanger = &fakeTokenExchanger{idToken: rawToken}

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("google", state, "code", stateCookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}

	hooks.mu.Lock()
	vi := hooks.gotIdentity
	hooks.mu.Unlock()

	// Mutate the handler's config after the flow.
	path2 := ".claims.mfa"
	cfg2 := h.configs["google"]
	cfg2.AdminClaimPath = &path2
	h.configs["google"] = cfg2

	// The VerifiedIdentity.Config must retain the original value.
	if vi.Config.AdminClaimPath == nil || *vi.Config.AdminClaimPath != ".claims.admin" {
		t.Errorf("VerifiedIdentity.Config.AdminClaimPath = %v, want .claims.admin (leaked mutation)", vi.Config.AdminClaimPath)
	}

	// Mutate the VerifiedIdentity config and verify the handler is unaffected.
	*vi.Config.AdminClaimPath = "MUTATED"
	if h.configs["google"].AdminClaimPath == nil || *h.configs["google"].AdminClaimPath != ".claims.mfa" {
		t.Errorf("handler config leaked mutation from VerifiedIdentity")
	}

	// Verify rawClaims are independently copied.
	if vi.IDTokenClaims == nil {
		t.Fatal("IDTokenClaims nil")
	}
	raw := vi.IDTokenClaims.RawClaims()
	for i := range raw {
		raw[i] = 'X'
	}
	raw2 := vi.IDTokenClaims.RawClaims()
	var parsed map[string]any
	if err := json.Unmarshal(raw2, &parsed); err != nil {
		t.Fatalf("second RawClaims unmarshal: %v", err)
	}
	if parsed["email"] != "bob@example.com" {
		t.Errorf("raw claims corrupted: email = %v", parsed["email"])
	}
}

// TestVerifiedIdentityGitHubNoIDTokenClaims proves that GitHub flow produces
// a VerifiedIdentity with nil IDTokenClaims.
func TestVerifiedIdentityGitHubNoIDTokenClaims(t *testing.T) {
	upstream := SubjectResult{ProviderID: "github", Subject: "gh-12345"}
	hooks := &identityHookRecorder{
		session:     testCanonicalTestToken,
		digest:      testCanonicalTestDigest,
		interaction: DigestSHA256("interaction"),
	}
	store := newTestStore()
	githubCfg := Config{
		Kind:                  ProviderKindGitHub,
		Issuer:                "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user",
		ClientID:              "github-client",
		Scopes:                []string{"read:user"},
	}
	configs := map[string]Config{"github": githubCfg}
	h, err := NewLocalLoginHandler(configs, store, &fakeTokenExchanger{subject: &upstream},
		&countingTokenVerifier{}, newCryptoProvider(newFixedRandom(make([]byte, 256))),
		map[string]bool{"https://app.example.com/callback": true}, hooks.hooks())
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return fixedNow }

	// Start the flow for GitHub.
	stateCookie, state := localStartGitHub(t, h)

	rec := httptest.NewRecorder()
	h.LocalCallbackHandler().ServeHTTP(rec, makeCallbackRequest("github", state, "code", stateCookie, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}

	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.verifiedCalls != 1 {
		t.Fatalf("ResolveVerified calls=%d, want 1", hooks.verifiedCalls)
	}
	vi := hooks.gotIdentity
	if vi.IDTokenClaims != nil {
		t.Errorf("GitHub IDTokenClaims = %+v, want nil", vi.IDTokenClaims)
	}
	if vi.Subject.Subject != "gh-12345" {
		t.Errorf("Subject = %q, want gh-12345", vi.Subject.Subject)
	}
	// Config snapshot must be present for GitHub too.
	if vi.Config.ClientID != "github-client" {
		t.Errorf("Config.ClientID = %q, want github-client", vi.Config.ClientID)
	}
}

// --- helpers ---

// localStartWithNonce performs the local start flow and returns the state
// cookie, state value, and the nonce that was used in the transaction.
func localStartWithNonce(t *testing.T, h *Handler) (*http.Cookie, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/upstream/google/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start status=%d body=%q", rec.Code, rec.Body.String())
	}
	stateCookie := rec.Result().Cookies()[0]
	if stateCookie.Name != stateCookieName {
		t.Fatalf("unexpected cookie: %s", stateCookie.Name)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	state := u.Query().Get("state")

	// Extract the nonce from the stored transaction for test token signing.
	h.store.(*testInMemoryStore).mu.Lock()
	stateDigest := DigestSHA256(state)
	tx, ok := h.store.(*testInMemoryStore).transactions[stateDigest]
	h.store.(*testInMemoryStore).mu.Unlock()
	if !ok {
		t.Fatal("transaction not found for state")
	}

	return stateCookie, state, tx.Nonce
}

// localStartGitHub performs a local start flow for the GitHub provider.
func localStartGitHub(t *testing.T, h *Handler) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.LocalStartHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/upstream/github/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start status=%d body=%q", rec.Code, rec.Body.String())
	}
	stateCookie := rec.Result().Cookies()[0]
	if stateCookie.Name != stateCookieName {
		t.Fatalf("unexpected cookie: %s", stateCookie.Name)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return stateCookie, u.Query().Get("state")
}


// TestLocalLoginHandlerAcceptsResolveVerifiedOnly proves that NewLocalLoginHandler
// accepts ResolveVerified without Resolve being set.
func TestLocalLoginHandlerAcceptsResolveVerifiedOnly(t *testing.T) {
	store := newTestStore()
	configs := map[string]Config{"google": {
		Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint: "https://issuer.example.com/token", ClientID: "c",
	}}
	allowed := map[string]bool{"https://app.example.com/callback": true}
	hooks := LocalLoginHooks{
		Prepare:  func(*http.Request, string) (string, string, string, error) { return "", "", "", nil },
		Current:  func(*http.Request) (string, string, error) { return "", "", nil },
		Resolve:  nil, // explicitly nil
		ResolveVerified: func(_ context.Context, _ VerifiedIdentity) (string, error) { return "u", nil },
		Complete: func(w http.ResponseWriter, _ *http.Request, _, _, _ string, _ *OIDCSession) { w.WriteHeader(204) },
	}
	_, err := NewLocalLoginHandler(configs, store, &fakeTokenExchanger{}, &fakeVerifier{claims: &IDTokenClaims{}},
		newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed, hooks)
	if err != nil {
		t.Fatalf("NewLocalLoginHandler with ResolveVerified only: %v", err)
	}
}

// TestLocalLoginHandlerRejectsMissingBothResolveAndResolveVerified proves
// that NewLocalLoginHandler rejects hooks when both Resolve and ResolveVerified
// are nil.
func TestLocalLoginHandlerRejectsMissingBothResolveAndResolveVerified(t *testing.T) {
	store := newTestStore()
	configs := map[string]Config{"google": {
		Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint: "https://issuer.example.com/token", ClientID: "c",
	}}
	allowed := map[string]bool{"https://app.example.com/callback": true}
	hooks := LocalLoginHooks{
		Prepare: func(*http.Request, string) (string, string, string, error) { return "", "", "", nil },
		Current: func(*http.Request) (string, string, error) { return "", "", nil },
		Resolve: nil, ResolveVerified: nil, // both nil
		Complete: func(w http.ResponseWriter, _ *http.Request, _, _, _ string, _ *OIDCSession) { w.WriteHeader(204) },
	}
	_, err := NewLocalLoginHandler(configs, store, &fakeTokenExchanger{}, &fakeVerifier{claims: &IDTokenClaims{}},
		newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed, hooks)
	if !errors.Is(err, errHandlerLocalHooks) {
		t.Fatalf("err=%v, want errHandlerLocalHooks", err)
	}
}
