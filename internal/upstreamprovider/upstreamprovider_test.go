package upstreamprovider

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test helpers (test-only code lives here, not in production files) ---

// fixedRandom is a deterministic io.Reader for testing.
type fixedRandom struct {
	data []byte
	pos  int
	mu   sync.Mutex
}

func newFixedRandom(data []byte) *fixedRandom {
	return &fixedRandom{data: data}
}

func (r *fixedRandom) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *fixedRandom) reset() {
	r.mu.Lock()
	r.pos = 0
	r.mu.Unlock()
}

// shortEntropyReader returns at most n bytes total then errors.
type shortEntropyReader struct {
	remaining int
}

func (r *shortEntropyReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return n, nil
}

// fakeVerifier is a test TokenVerifier that returns pre-configured claims.
// It records the issuer and audience arguments passed to VerifyIDToken.
type fakeVerifier struct {
	claims      *IDTokenClaims
	err         error
	gotIssuer   string
	gotAudience string
}

func (f *fakeVerifier) VerifyIDToken(_ context.Context, _ string, issuer, audience string) (*IDTokenClaims, error) {
	f.gotIssuer = issuer
	f.gotAudience = audience
	return f.claims, f.err
}

// testInMemoryStore is a mutex-safe in-memory Store for tests.
type testInMemoryStore struct {
	mu           sync.Mutex
	transactions map[string]Transaction
	consumed     map[string]bool
}

func newTestStore() *testInMemoryStore {
	return &testInMemoryStore{
		transactions: make(map[string]Transaction),
		consumed:     make(map[string]bool),
	}
}

func (s *testInMemoryStore) Save(_ context.Context, tx Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.transactions[tx.StateDigest]; exists {
		return errors.New("transaction already exists")
	}
	s.transactions[tx.StateDigest] = tx
	return nil
}

func (s *testInMemoryStore) Consume(_ context.Context, stateDigest, browserBindingDigest, providerID string, now time.Time) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, exists := s.transactions[stateDigest]
	if !exists {
		return Transaction{}, ErrTransactionNotFound
	}
	if s.consumed[stateDigest] {
		return Transaction{}, ErrTransactionAlreadyConsumed
	}
	// Strict expiry: now >= ExpiresAt means expired.
	if !now.Before(tx.ExpiresAt) {
		return Transaction{}, ErrTransactionExpired
	}
	// Binding enforcement before consume.
	if subtleConstantTimeCompare(tx.BrowserBindingDigest, browserBindingDigest) != 1 {
		return Transaction{}, ErrBindingMismatch
	}
	if subtleConstantTimeCompare(tx.ProviderID, providerID) != 1 {
		return Transaction{}, ErrBindingMismatch
	}
	s.consumed[stateDigest] = true
	return tx, nil
}

func subtleConstantTimeCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return 0
		}
	}
	return 1
}

// newTestProvider creates a cryptoProvider with deterministic randomness.
func newTestProvider(data []byte) *cryptoProvider {
	return newCryptoProvider(newFixedRandom(data))
}

func testNow() time.Time {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}

// --- tests ---

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty issuer",
			cfg:     Config{AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "empty auth endpoint",
			cfg:     Config{Issuer: "https://example.com", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "empty token endpoint",
			cfg:     Config{Issuer: "https://example.com", AuthorizationEndpoint: "https://example.com/auth", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "empty client ID",
			cfg:     Config{Issuer: "https://example.com", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token"},
			wantErr: true,
		},
		{
			name:    "http issuer rejected",
			cfg:     Config{Issuer: "http://example.com", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "http auth endpoint rejected",
			cfg:     Config{Issuer: "https://example.com", AuthorizationEndpoint: "http://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "http token endpoint rejected",
			cfg:     Config{Issuer: "https://example.com", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "http://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "relative issuer rejected",
			cfg:     Config{Issuer: "/relative", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "hostless issuer rejected",
			cfg:     Config{Issuer: "https://", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "userinfo in issuer rejected",
			cfg:     Config{Issuer: "https://user@example.com", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "fragment in issuer rejected",
			cfg:     Config{Issuer: "https://example.com#frag", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "query in issuer rejected",
			cfg:     Config{Issuer: "https://example.com?foo=bar", AuthorizationEndpoint: "https://example.com/auth", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name:    "fragment in auth endpoint rejected",
			cfg:     Config{Issuer: "https://example.com", AuthorizationEndpoint: "https://example.com/auth#frag", TokenEndpoint: "https://example.com/token", ClientID: "c"},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: Config{
				Issuer:                "https://issuer.example.com",
				AuthorizationEndpoint: "https://issuer.example.com/auth",
				TokenEndpoint:         "https://issuer.example.com/token",
				ClientID:              "c",
			},
			wantErr: false,
		},
		{
			name: "valid with userinfo endpoint",
			cfg: Config{
				Issuer:                "https://issuer.example.com",
				AuthorizationEndpoint: "https://issuer.example.com/auth",
				TokenEndpoint:         "https://issuer.example.com/token",
				UserInfoEndpoint:      "https://issuer.example.com/userinfo",
				ClientID:              "c",
			},
			wantErr: false,
		},
		{
			name: "valid with jwks",
			cfg: Config{
				Issuer:                "https://issuer.example.com",
				AuthorizationEndpoint: "https://issuer.example.com/auth",
				TokenEndpoint:         "https://issuer.example.com/token",
				JWKSURI:               "https://issuer.example.com/jwks",
				ClientID:              "c",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateState(t *testing.T) {
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	p := newTestProvider(entropy)
	state, err := p.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	if state == "" {
		t.Fatal("GenerateState() returned empty string")
	}
	state2, err := p.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() second call error = %v", err)
	}
	if state == state2 {
		t.Error("GenerateState() returned same value twice")
	}
}

func TestGenerateNonce(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	nonce, err := p.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	if nonce == "" {
		t.Fatal("GenerateNonce() returned empty string")
	}
}

func TestGeneratePKCEVerifier(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	verifier, challenge, err := p.GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier() error = %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatal("GeneratePKCEVerifier() returned empty strings")
	}
	expected := DigestSHA256(verifier)
	if challenge != expected {
		t.Errorf("challenge = %q, want %q", challenge, expected)
	}
}

func TestShortEntropyReader(t *testing.T) {
	r := &shortEntropyReader{remaining: 4}
	p := newCryptoProvider(r)
	_, err := p.GenerateState()
	if err == nil {
		t.Error("expected error from short entropy reader")
	}
}

func TestDigestSHA256(t *testing.T) {
	d1 := DigestSHA256("hello")
	d2 := DigestSHA256("hello")
	d3 := DigestSHA256("world")
	if d1 != d2 {
		t.Error("same input produced different digests")
	}
	if d1 == d3 {
		t.Error("different inputs produced same digest")
	}
}

func TestTestStoreOneUse(t *testing.T) {
	store := newTestStore()
	now := testNow()
	tx := Transaction{
		StateDigest:          "test-state-digest",
		BrowserBindingDigest: "binding-1",
		ProviderID:           "google",
		Nonce:                "test-nonce",
		Issuer:               "https://issuer.example.com",
		Audience:             "client-id",
		ExpiresAt:            now.Add(time.Hour),
	}

	if err := store.Save(context.Background(), tx); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Consume(context.Background(), "test-state-digest", "binding-1", "google", now)
	if err != nil {
		t.Fatalf("Consume() first call error = %v", err)
	}
	if got.StateDigest != tx.StateDigest {
		t.Errorf("Consume() state = %q, want %q", got.StateDigest, tx.StateDigest)
	}

	_, err = store.Consume(context.Background(), "test-state-digest", "binding-1", "google", now)
	if !errors.Is(err, ErrTransactionAlreadyConsumed) {
		t.Errorf("Consume() second call = %v, want %v", err, ErrTransactionAlreadyConsumed)
	}
}

func TestTestStoreNotFound(t *testing.T) {
	store := newTestStore()
	_, err := store.Consume(context.Background(), "nonexistent", "b", "p", testNow())
	if !errors.Is(err, ErrTransactionNotFound) {
		t.Errorf("Consume() = %v, want %v", err, ErrTransactionNotFound)
	}
}

func TestTestStoreBindingMismatch(t *testing.T) {
	store := newTestStore()
	now := testNow()
	tx := Transaction{
		StateDigest:          "sd",
		BrowserBindingDigest: "correct-binding",
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	_, err := store.Consume(context.Background(), "sd", "wrong-binding", "google", now)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("Consume() wrong binding = %v, want %v", err, ErrBindingMismatch)
	}
}

func TestTestStoreProviderMismatch(t *testing.T) {
	store := newTestStore()
	now := testNow()
	tx := Transaction{
		StateDigest:          "sd",
		BrowserBindingDigest: "binding",
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	_, err := store.Consume(context.Background(), "sd", "binding", "github", now)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("Consume() wrong provider = %v, want %v", err, ErrBindingMismatch)
	}
}

func TestTestStoreExpiryEquality(t *testing.T) {
	store := newTestStore()
	now := testNow()
	tx := Transaction{
		StateDigest:          "sd",
		BrowserBindingDigest: "binding",
		ProviderID:           "google",
		ExpiresAt:            now, // now == ExpiresAt => expired
	}
	_ = store.Save(context.Background(), tx)

	_, err := store.Consume(context.Background(), "sd", "binding", "google", now)
	if !errors.Is(err, ErrTransactionExpired) {
		t.Errorf("Consume() at expiry = %v, want %v", err, ErrTransactionExpired)
	}
}

func TestGenerateAuthorizationURL(t *testing.T) {
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	p := newTestProvider(entropy)

	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		Audience:              "test-audience",
	}

	store := newTestStore()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	binding := DigestSHA256("browser-session-token")

	result, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store,
		AuthorizationParams{
			CallbackURI: "https://app.example.com/callback",
			Scopes:      []string{"openid", "profile"},
		},
		binding, "google", now,
	)
	if err != nil {
		t.Fatalf("GenerateAuthorizationURL() error = %v", err)
	}
	if result.URL == "" {
		t.Fatal("URL is empty")
	}
	if result.Transaction.StateDigest == "" {
		t.Error("StateDigest is empty")
	}
	if result.Transaction.BrowserBindingDigest != binding {
		t.Errorf("BrowserBindingDigest = %q, want %q", result.Transaction.BrowserBindingDigest, binding)
	}
	if result.Transaction.ProviderID != "google" {
		t.Errorf("ProviderID = %q, want %q", result.Transaction.ProviderID, "google")
	}
	if result.Transaction.SessionDigest != "" || result.Transaction.InteractionDigest != "" {
		t.Errorf("legacy binding = (%q, %q), want empty", result.Transaction.SessionDigest, result.Transaction.InteractionDigest)
	}

	// Verify URL was built via net/url: parse it back.
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatalf("URL parse error = %v", err)
	}
	if parsed.Scheme != "https" {
		t.Errorf("scheme = %q, want https", parsed.Scheme)
	}
	if parsed.Host != "issuer.example.com" {
		t.Errorf("host = %q, want issuer.example.com", parsed.Host)
	}
	if parsed.Path != "/auth" {
		t.Errorf("path = %q, want /auth", parsed.Path)
	}
	q := parsed.Query()
	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
}

func TestGenerateGitHubAuthorizationURLOmitsNonce(t *testing.T) {
	cfg := Config{
		Kind:                  ProviderKindGitHub,
		Issuer:                "https://github.com",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint:         "https://github.com/login/oauth/access_token",
		UserInfoEndpoint:      "https://api.github.com/user",
		ClientID:              "client",
		Scopes:                []string{"read:user"},
	}
	result, err := GenerateAuthorizationURL(context.Background(), newTestProvider(make([]byte, 256)), cfg, newTestStore(), AuthorizationParams{
		CallbackURI: "https://app.example.test/callback", Scopes: []string{"read:user"},
	}, DigestSHA256("browser"), "github", time.Unix(100, 0))
	if err != nil {
		t.Fatalf("GenerateAuthorizationURL: %v", err)
	}
	if result.Transaction.Nonce != "" {
		t.Fatalf("transaction nonce = %q, want empty", result.Transaction.Nonce)
	}
	if nonce := mustParseURL(t, result.URL).Query().Get("nonce"); nonce != "" {
		t.Fatalf("authorization nonce = %q, want empty", nonce)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return u
}

func TestGenerateAuthorizationURLInvalidCallbackURI(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "c",
	}
	store := newTestStore()
	_, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store,
		AuthorizationParams{CallbackURI: "http://insecure.example.com/cb", Scopes: []string{}},
		"binding", "google", testNow(),
	)
	if err == nil {
		t.Error("expected error for non-HTTPS callback URI")
	}
}

func TestGenerateAuthorizationURLScopeViolation(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "c",
		Scopes:                []string{"openid"},
	}
	store := newTestStore()
	_, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store,
		AuthorizationParams{CallbackURI: "https://app.example.com/cb", Scopes: []string{"openid", "admin"}},
		"binding", "google", testNow(),
	)
	if err == nil {
		t.Error("expected error for out-of-scope request")
	}
}

func TestGenerateAuthorizationURLInvalidConfig(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	store := newTestStore()
	_, err := GenerateAuthorizationURL(
		context.Background(), p, Config{}, store,
		AuthorizationParams{}, "", "", testNow(),
	)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestGenerateAuthorizationURLMissingBinding(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "c",
	}
	store := newTestStore()
	_, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store,
		AuthorizationParams{CallbackURI: "https://app.example.com/cb"},
		"", "google", testNow(),
	)
	if err == nil {
		t.Error("expected error for empty browser binding")
	}
}

func TestGenerateAuthorizationURLPersistsLocalOAuthBinding(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "c"}
	params := AuthorizationParams{CallbackURI: "https://app.example.com/cb", SessionDigest: DigestSHA256("session"), InteractionDigest: DigestSHA256("interaction")}
	result, err := GenerateAuthorizationURL(context.Background(), p, cfg, newTestStore(), params, DigestSHA256("browser"), "google", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction.SessionDigest != params.SessionDigest || result.Transaction.InteractionDigest != params.InteractionDigest {
		t.Fatalf("binding = (%q, %q), want (%q, %q)", result.Transaction.SessionDigest, result.Transaction.InteractionDigest, params.SessionDigest, params.InteractionDigest)
	}
}

func TestGenerateAuthorizationURLRejectsMalformedLocalOAuthBinding(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "c"}
	_, err := GenerateAuthorizationURL(context.Background(), p, cfg, newTestStore(), AuthorizationParams{CallbackURI: "https://app.example.com/cb", SessionDigest: DigestSHA256("session")}, DigestSHA256("browser"), "google", testNow())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("GenerateAuthorizationURL() error=%v, want invalid config", err)
	}
}

func TestGenerateAuthorizationURLPersistsLinkBinding(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "c"}
	binding := DigestSHA256("session")
	params := AuthorizationParams{Purpose: PurposeLink, CallbackURI: "https://app.example.com/cb", LinkSubject: "subject-1", LinkSessionDigest: binding}
	result, err := GenerateAuthorizationURL(context.Background(), p, cfg, newTestStore(), params, binding, "google", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction.Purpose != PurposeLink || result.Transaction.LinkSubject != params.LinkSubject || result.Transaction.LinkSessionDigest != binding {
		t.Fatalf("link transaction = %#v", result.Transaction)
	}
}

func TestGenerateAuthorizationURLRejectsMalformedLinkBinding(t *testing.T) {
	p := newTestProvider(make([]byte, 128))
	cfg := Config{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: "https://issuer.example.com/token", ClientID: "c"}
	binding := DigestSHA256("session")
	_, err := GenerateAuthorizationURL(context.Background(), p, cfg, newTestStore(), AuthorizationParams{Purpose: PurposeLink, CallbackURI: "https://app.example.com/cb", LinkSubject: "subject-1", LinkSessionDigest: binding, SessionDigest: DigestSHA256("unexpected")}, binding, "google", testNow())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("GenerateAuthorizationURL() error=%v, want invalid config", err)
	}
}

func TestValidateCallbackSuccess(t *testing.T) {
	store := newTestStore()
	now := testNow()
	binding := DigestSHA256("browser-session")
	state := "my-state"
	tx := Transaction{
		StateDigest:          DigestSHA256(state),
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		Nonce:                "my-nonce",
		Issuer:               "https://issuer.example.com",
		Audience:             "test-client",
		ExpiresAt:            now.Add(time.Hour),
		CreatedAt:            now,
	}
	if err := store.Save(context.Background(), tx); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	result, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "auth-code-123"},
		binding, "google", now,
	)
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	if result.Code != "auth-code-123" {
		t.Errorf("Code = %q, want %q", result.Code, "auth-code-123")
	}
	if result.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q", result.Issuer)
	}
}

func TestValidateCallbackStateMismatch(t *testing.T) {
	store := newTestStore()
	now := testNow()
	binding := DigestSHA256("b")
	// Store a transaction with one state digest.
	tx := Transaction{
		StateDigest:          DigestSHA256("correct-state"),
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	// Callback with different state: digest derived internally won't match.
	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: "wrong-state", Code: "c"},
		binding, "google", now,
	)
	if err == nil {
		t.Error("expected error for wrong state")
	}
}

// TestValidateCallbackInternalStateDigest verifies that the state digest
// is derived internally from params.State via DigestSHA256.
func TestValidateCallbackInternalStateDigest(t *testing.T) {
	store := newTestStore()
	now := testNow()
	binding := DigestSHA256("b")
	state := "my-secret-state"
	expectedDigest := DigestSHA256(state)
	tx := Transaction{
		StateDigest:          expectedDigest,
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		Nonce:                "n",
		Issuer:               "https://issuer.example.com",
		Audience:             "c",
		ExpiresAt:            now.Add(time.Hour),
		CreatedAt:            now,
	}
	if err := store.Save(context.Background(), tx); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Calling with matching state should succeed — digest is derived internally.
	result, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "code"},
		binding, "google", now,
	)
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	if result.Transaction.StateDigest != expectedDigest {
		t.Errorf("StateDigest = %q, want %q", result.Transaction.StateDigest, expectedDigest)
	}
}

func TestValidateCallbackReplay(t *testing.T) {
	store := newTestStore()
	now := testNow()
	state := "my-state"
	stateDigest := DigestSHA256(state)
	binding := DigestSHA256("b")
	tx := Transaction{
		StateDigest:          stateDigest,
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
		CreatedAt:            now,
	}
	_ = store.Save(context.Background(), tx)

	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "code"},
		binding, "google", now,
	)
	if err != nil {
		t.Fatalf("first ValidateCallback() error = %v", err)
	}

	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "code"},
		binding, "google", now,
	)
	if !errors.Is(err, ErrTransactionAlreadyConsumed) {
		t.Errorf("replay ValidateCallback() = %v, want %v", err, ErrTransactionAlreadyConsumed)
	}
}

func TestValidateCallbackExpired(t *testing.T) {
	store := newTestStore()
	now := testNow()
	state := "my-state"
	stateDigest := DigestSHA256(state)
	binding := DigestSHA256("b")
	tx := Transaction{
		StateDigest:          stateDigest,
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		ExpiresAt:            now.Add(-time.Hour),
		CreatedAt:            now.Add(-2 * time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "code"},
		binding, "google", now,
	)
	if !errors.Is(err, ErrTransactionExpired) {
		t.Errorf("ValidateCallback() = %v, want %v", err, ErrTransactionExpired)
	}
}

func TestValidateCallbackMissingParams(t *testing.T) {
	store := newTestStore()
	now := testNow()

	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: "s", Code: "c"},
		"", "p", now,
	)
	if err == nil {
		t.Error("should fail with empty browser binding")
	}

	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{Code: "c"},
		"b", "p", now,
	)
	if err == nil {
		t.Error("should fail with empty state")
	}

	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{State: "s"},
		"b", "p", now,
	)
	if err == nil {
		t.Error("should fail with empty code")
	}

	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{State: "s", Code: "c"},
		"b", "", now,
	)
	if err == nil {
		t.Error("should fail with empty provider ID")
	}
}

func TestValidateIDTokenNilClaims(t *testing.T) {
	v := &fakeVerifier{claims: nil}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "c",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, testNow())
	if err == nil {
		t.Error("expected error for nil claims")
	}
}

func TestValidateIDTokenNonceMismatch(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Nonce:     "wrong-nonce",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "expected-nonce",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("ValidateIDToken() = %v, want %v", err, ErrNonceMismatch)
	}
}

func TestValidateIDTokenIssuerMismatch(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://wrong-issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Nonce:     "expected-nonce",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "expected-nonce",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if err == nil {
		t.Error("should fail with issuer mismatch")
	}
}

func TestValidateIDTokenEmptySubject(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "",
			Audience:  []string{"test-client"},
			Nonce:     "n",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if err == nil {
		t.Error("should fail with empty subject")
	}
}

func TestValidateIDTokenAudienceMismatch(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"other-client"},
			Nonce:     "n",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if err == nil {
		t.Error("should fail with audience mismatch")
	}
}

func TestValidateIDTokenAzpMismatch(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Azp:       "wrong-client",
			Nonce:     "n",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if err == nil {
		t.Error("should fail with azp mismatch")
	}
}

func TestValidateIDTokenExpired(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Nonce:     "n",
			ExpiresAt: testNow().Add(-time.Hour).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, testNow())
	if err == nil {
		t.Error("should fail with expired token")
	}
}

func TestValidateIDTokenNotYetValid(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Nonce:     "n",
			ExpiresAt: testNow().Add(time.Hour).Unix(),
			NotBefore: testNow().Add(time.Hour).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "test-client",
	}
	_, err := ValidateIDToken(context.Background(), v, "token", tx, testNow())
	if err == nil {
		t.Error("should fail with not-yet-valid token")
	}
}

func TestValidateIDTokenSuccess(t *testing.T) {
	now := testNow()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-123",
			Audience:  []string{"test-client"},
			Nonce:     "expected-nonce",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "expected-nonce",
		ClientID: "test-client",
	}
	claims, err := ValidateIDToken(context.Background(), v, "token", tx, now)
	if err != nil {
		t.Fatalf("ValidateIDToken() error = %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
	}
}

func TestValidateIDTokenNilVerifier(t *testing.T) {
	_, err := ValidateIDToken(context.Background(), nil, "token", Transaction{}, testNow())
	if err == nil {
		t.Error("should fail with nil verifier")
	}
}

func TestValidateIDTokenVerifierError(t *testing.T) {
	v := &fakeVerifier{err: errors.New("verification failed")}
	_, err := ValidateIDToken(context.Background(), v, "token", Transaction{Issuer: "iss"}, testNow())
	if err == nil {
		t.Error("should fail when verifier returns error")
	}
}

func TestSubjectResultValidation(t *testing.T) {
	tests := []struct {
		name    string
		sr      SubjectResult
		wantErr bool
	}{
		{"valid", SubjectResult{ProviderID: "google", Subject: "123"}, false},
		{"empty provider", SubjectResult{Subject: "123"}, true},
		{"empty subject", SubjectResult{ProviderID: "google"}, true},
		{"both empty", SubjectResult{}, true},
		{"provider too long", SubjectResult{ProviderID: strings.Repeat("a", maxProviderIDLen+1), Subject: "123"}, true},
		{"subject too long", SubjectResult{ProviderID: "google", Subject: strings.Repeat("a", maxSubjectLen+1)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sr.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSubjectResultExternalKey(t *testing.T) {
	sr := SubjectResult{ProviderID: "google", Subject: "12345"}
	key := sr.ExternalKey()
	// Must be deterministic
	key2 := sr.ExternalKey()
	if key != key2 {
		t.Errorf("ExternalKey() not deterministic: %q != %q", key, key2)
	}
	// Must be 43 chars (base64url of 32 bytes)
	if len(key) != 43 {
		t.Errorf("ExternalKey() len = %d, want 43", len(key))
	}
	// Different inputs produce different keys
	sr2 := SubjectResult{ProviderID: "github", Subject: "12345"}
	if sr2.ExternalKey() == key {
		t.Error("different providers produced same key")
	}
}

func TestNormalizeProviderID(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Google", "google"},
		{"  GitHub  ", "github"},
		{"", ""},
		{"OIDC:accounts.google.com", "oidc:accounts.google.com"},
		{strings.Repeat("a", maxProviderIDLen+1), ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeProviderID(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeProviderID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLinkDecisionString(t *testing.T) {
	tests := []struct {
		d    LinkDecision
		want string
	}{
		{LinkDecisionNone, "none"},
		{LinkDecisionLinked, "linked"},
		{LinkDecisionConflict, "conflict"},
		{LinkDecision(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

// TestDeterministicTwoUserBarrier proves no verifier/token/PKCE cross-talk
// between two simultaneous callbacks by using deterministic randomness
// and barriers.
func TestDeterministicTwoUserBarrier(t *testing.T) {
	// Each user gets distinct 256-byte entropy blocks.
	entropy1 := make([]byte, 256)
	entropy2 := make([]byte, 256)
	for i := range entropy1 {
		entropy1[i] = byte(i)
		entropy2[i] = byte(i + 128)
	}
	p1 := newTestProvider(entropy1)
	p2 := newTestProvider(entropy2)

	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid"},
		Audience:              "test-audience",
	}

	store := newTestStore()
	now := testNow()
	binding1 := DigestSHA256("browser-session-1")
	binding2 := DigestSHA256("browser-session-2")

	// Generate auth URLs for both users.
	r1, err := GenerateAuthorizationURL(
		context.Background(), p1, cfg, store,
		AuthorizationParams{CallbackURI: "https://app.example.com/cb", Scopes: []string{"openid"}},
		binding1, "google", now,
	)
	if err != nil {
		t.Fatalf("user1 GenerateAuthorizationURL() error = %v", err)
	}
	r2, err := GenerateAuthorizationURL(
		context.Background(), p2, cfg, store,
		AuthorizationParams{CallbackURI: "https://app.example.com/cb", Scopes: []string{"openid"}},
		binding2, "google", now,
	)
	if err != nil {
		t.Fatalf("user2 GenerateAuthorizationURL() error = %v", err)
	}

	// The PKCE verifiers must be different.
	if r1.Transaction.PKCEVerifier == r2.Transaction.PKCEVerifier {
		t.Error("PKCE verifiers cross-talk between users")
	}
	// The nonces must be different.
	if r1.Transaction.Nonce == r2.Transaction.Nonce {
		t.Error("nonces cross-talk between users")
	}
	// The state digests must be different.
	if r1.Transaction.StateDigest == r2.Transaction.StateDigest {
		t.Error("state digests cross-talk between users")
	}

	// Simulate two users completing callbacks with a deterministic start barrier.
	// Each goroutine signals ready, then blocks on start; main collects both
	// ready signals and closes start so both proceed concurrently.
	var wg sync.WaitGroup
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	type callbackResult struct {
		user int
		res  *CallbackResult
		err  error
	}
	results := make(chan callbackResult, 2)
	wg.Add(2)

	// User 1 callback.
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		res, err := ValidateCallback(
			context.Background(), store,
			CallbackParams{
				State: r1.URL[strings.Index(r1.URL, "state=")+6 : strings.Index(r1.URL, "state=")+6+43],
				Code:  "code-user1",
			},
			binding1, "google", now,
		)
		results <- callbackResult{user: 1, res: res, err: err}
	}()

	// User 2 callback.
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		res, err := ValidateCallback(
			context.Background(), store,
			CallbackParams{
				State: r2.URL[strings.Index(r2.URL, "state=")+6 : strings.Index(r2.URL, "state=")+6+43],
				Code:  "code-user2",
			},
			binding2, "google", now,
		)
		results <- callbackResult{user: 2, res: res, err: err}
	}()

	// Wait for both goroutines to be ready, then release them.
	<-ready
	<-ready
	close(start)

	wg.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			t.Errorf("user%d ValidateCallback() error = %v", result.user, result.err)
			continue
		}
		want := r1.Transaction.PKCEVerifier
		if result.user == 2 {
			want = r2.Transaction.PKCEVerifier
		}
		if result.res.Transaction.PKCEVerifier != want {
			t.Errorf("user%d got the wrong PKCE verifier", result.user)
		}
	}
}

// TestWrongBrowserRejectionWithoutConsume verifies that a wrong browser
// binding is rejected and the transaction is NOT consumed.
func TestWrongBrowserRejectionWithoutConsume(t *testing.T) {
	store := newTestStore()
	now := testNow()
	state := "s"
	stateDigest := DigestSHA256(state)
	correctBinding := DigestSHA256("browser-correct")
	wrongBinding := DigestSHA256("browser-wrong")

	tx := Transaction{
		StateDigest:          stateDigest,
		BrowserBindingDigest: correctBinding,
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	// Wrong binding should fail.
	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "c"},
		wrongBinding, "google", now,
	)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("wrong binding = %v, want %v", err, ErrBindingMismatch)
	}

	// Correct binding should succeed (transaction not consumed).
	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "c"},
		correctBinding, "google", now,
	)
	if err != nil {
		t.Errorf("correct binding after wrong = %v", err)
	}
}

// TestWrongProviderRejectionWithoutConsume verifies wrong provider doesn't
// consume the transaction.
func TestWrongProviderRejectionWithoutConsume(t *testing.T) {
	store := newTestStore()
	now := testNow()
	state := "s"
	stateDigest := DigestSHA256(state)
	binding := DigestSHA256("b")

	tx := Transaction{
		StateDigest:          stateDigest,
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		ExpiresAt:            now.Add(time.Hour),
	}
	_ = store.Save(context.Background(), tx)

	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "c"},
		binding, "github", now,
	)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("wrong provider = %v, want %v", err, ErrBindingMismatch)
	}

	// Correct provider should still succeed.
	_, err = ValidateCallback(
		context.Background(), store,
		CallbackParams{State: state, Code: "c"},
		binding, "google", now,
	)
	if err != nil {
		t.Errorf("correct provider after wrong = %v", err)
	}
}

// TestURLBuildViaNetURL verifies the authorization URL is built with net/url
// and survives round-trip parsing.
func TestURLBuildViaNetURL(t *testing.T) {
	p := newTestProvider(make([]byte, 256))
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/auth?existing=param",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "c",
	}
	store := newTestStore()
	now := testNow()

	result, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store,
		AuthorizationParams{
			CallbackURI: "https://app.example.com/callback",
			Scopes:      []string{"openid"},
		},
		DigestSHA256("b"), "google", now,
	)
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatalf("URL parse error = %v", err)
	}
	if parsed.Query().Get("existing") != "param" {
		t.Error("existing query param lost")
	}
	if parsed.Query().Get("client_id") != "c" {
		t.Error("client_id missing")
	}
}

func TestCallbackURIRelativeRejected(t *testing.T) {
	err := validateCallbackURI("/relative/path")
	if err == nil {
		t.Error("expected error for relative callback URI")
	}
}

func TestCallbackURIHTTPRejected(t *testing.T) {
	err := validateCallbackURI("http://insecure.example.com/cb")
	if err == nil {
		t.Error("expected error for HTTP callback URI")
	}
}

func TestCallbackURIUserinfoRejected(t *testing.T) {
	err := validateCallbackURI("https://user@example.com/cb")
	if err == nil {
		t.Error("expected error for userinfo in callback URI")
	}
}

func TestCallbackURIFragmentRejected(t *testing.T) {
	err := validateCallbackURI("https://example.com/cb#frag")
	if err == nil {
		t.Error("expected error for fragment in callback URI")
	}
}

func TestValidateScopesEmptyConfig(t *testing.T) {
	err := validateScopes(nil, []string{"any"})
	if err != nil {
		t.Errorf("empty config should accept any scope, got %v", err)
	}
}

func TestValidateScopesViolation(t *testing.T) {
	err := validateScopes([]string{"openid", "profile"}, []string{"openid", "admin"})
	if err == nil {
		t.Error("expected error for out-of-scope request")
	}
}

func TestValidateScopesSubset(t *testing.T) {
	err := validateScopes([]string{"openid", "profile"}, []string{"openid"})
	if err != nil {
		t.Errorf("subset should be valid, got %v", err)
	}
}

// --- Deterministic fixed-time tests for new validation paths ---

var fixedNow = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

// TestValidateIDTokenMissingExp verifies that zero exp is rejected.
func TestValidateIDTokenMissingExp(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Nonce:     "n",
			ExpiresAt: 0,
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "missing exp") {
		t.Errorf("got %v, want missing exp error", err)
	}
}

// TestValidateIDTokenMissingIat verifies that zero iat is rejected.
func TestValidateIDTokenMissingIat(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  0,
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "missing iat") {
		t.Errorf("got %v, want missing iat error", err)
	}
}

// TestValidateIDTokenExpiryEquality verifies that now == exp is expired.
func TestValidateIDTokenExpiryEquality(t *testing.T) {
	exp := fixedNow.Unix()
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Nonce:     "n",
			ExpiresAt: exp,
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("got %v, want expired error", err)
	}
}

// TestValidateIDTokenMultiAudienceMissingAzp verifies multi-aud requires azp.
func TestValidateIDTokenMultiAudienceMissingAzp(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c", "other"},
			Azp:       "",
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "missing azp in multi-audience") {
		t.Errorf("got %v, want missing azp in multi-audience error", err)
	}
}

// TestValidateIDTokenMultiAudienceAzpMismatch verifies multi-aud azp must match client ID.
func TestValidateIDTokenMultiAudienceAzpMismatch(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c", "other"},
			Azp:       "wrong",
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "azp mismatch in multi-audience") {
		t.Errorf("got %v, want azp mismatch in multi-audience error", err)
	}
}

// TestValidateIDTokenEmptyNonceTransaction verifies empty tx nonce is rejected.
func TestValidateIDTokenEmptyNonceTransaction(t *testing.T) {
	v := &fakeVerifier{claims: &IDTokenClaims{Issuer: "i", Subject: "s", Audience: []string{"c"}, ExpiresAt: 1, IssuedAt: 1}}
	tx := Transaction{Issuer: "i", Nonce: "", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "empty transaction nonce") {
		t.Errorf("got %v, want empty transaction nonce error", err)
	}
}

// TestValidateIDTokenEmptyClientIDTransaction verifies empty tx clientID is rejected.
func TestValidateIDTokenEmptyClientIDTransaction(t *testing.T) {
	v := &fakeVerifier{claims: &IDTokenClaims{Issuer: "i", Subject: "s", Audience: []string{"c"}, ExpiresAt: 1, IssuedAt: 1}}
	tx := Transaction{Issuer: "i", Nonce: "n", ClientID: ""}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "empty transaction client ID") {
		t.Errorf("got %v, want empty transaction client ID error", err)
	}
}

// TestValidateIDTokenEmptyIssuerTransaction verifies empty tx issuer is rejected.
func TestValidateIDTokenEmptyIssuerTransaction(t *testing.T) {
	v := &fakeVerifier{claims: &IDTokenClaims{Issuer: "i", Subject: "s", Audience: []string{"c"}, ExpiresAt: 1, IssuedAt: 1}}
	tx := Transaction{Issuer: "", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "empty transaction issuer") {
		t.Errorf("got %v, want empty transaction issuer error", err)
	}
}

// TestValidateIDTokenFutureIat verifies future iat is rejected.
func TestValidateIDTokenFutureIat(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(time.Hour).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Errorf("got %v, want future iat error", err)
	}
}

// TestValidateIDTokenAzpPresentExactMatch verifies azp present and matching is accepted.
func TestValidateIDTokenAzpPresentExactMatch(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Azp:       "c",
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	claims, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
}

// TestValidateIDTokenSingleAudienceNoAzp verifies single-aud with no azp is accepted.
func TestValidateIDTokenSingleAudienceNoAzp(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"c"},
			Azp:       "",
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{Issuer: "https://issuer.example.com", Nonce: "n", ClientID: "c"}
	claims, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
}

// TestValidateIDTokenVerifierReceivesClientID verifies that the token
// verifier receives tx.ClientID (not tx.Audience) as the audience arg.
func TestValidateIDTokenVerifierReceivesClientID(t *testing.T) {
	v := &fakeVerifier{
		claims: &IDTokenClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-1",
			Audience:  []string{"my-client"},
			Azp:       "my-client",
			Nonce:     "n",
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
	}
	tx := Transaction{
		Issuer:   "https://issuer.example.com",
		Nonce:    "n",
		ClientID: "my-client",
		Audience: "different-audience-value",
	}
	_, err := ValidateIDToken(context.Background(), v, "tok", tx, fixedNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.gotIssuer != "https://issuer.example.com" {
		t.Errorf("verifier got issuer %q, want https://issuer.example.com", v.gotIssuer)
	}
	if v.gotAudience != "my-client" {
		t.Errorf("verifier got audience %q, want my-client (ClientID), not %q", v.gotAudience, tx.Audience)
	}
}

// TestValidateCallbackUnknownState returns ErrStateMismatch and does not
// consume anything when the derived state digest doesn't match.
func TestValidateCallbackUnknownState(t *testing.T) {
	store := newTestStore()
	binding := DigestSHA256("binding")
	// Save a transaction with a known state.
	knownState := "known-state"
	tx := Transaction{
		StateDigest:          DigestSHA256(knownState),
		BrowserBindingDigest: binding,
		ProviderID:           "google",
		ExpiresAt:            fixedNow.Add(time.Hour),
		CreatedAt:            fixedNow,
	}
	_ = store.Save(context.Background(), tx)

	// Callback with unknown state: derived digest won't match.
	_, err := ValidateCallback(
		context.Background(), store,
		CallbackParams{State: "unknown-state", Code: "c"},
		binding, "google", fixedNow,
	)
	if !errors.Is(err, ErrStateMismatch) {
		t.Errorf("got %v, want ErrStateMismatch", err)
	}
	// Verify original transaction was NOT consumed.
	if store.consumed[tx.StateDigest] {
		t.Error("transaction should not be consumed for unknown state")
	}
}
