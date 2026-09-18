package upstreamprovider

import (
	"context"
	"net/url"
	"testing"
	"time"
)

// authProtocolFixture returns the standard OIDC config, provider, store,
// and shared parameters used by protocol-param tests.
func authProtocolFixture(t *testing.T) (
	Config, *cryptoProvider, *testInMemoryStore, AuthorizationParams, string, time.Time,
) {
	t.Helper()
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	cfg := Config{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
	}
	p := newTestProvider(entropy)
	store := newTestStore()
	params := AuthorizationParams{
		CallbackURI: "https://app.example.com/cb",
		Scopes:      []string{"openid", "profile"},
	}
	binding := DigestSHA256("browser-session")
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	return cfg, p, store, params, binding, now
}

func mustGenAuthURL(t *testing.T, cfg Config, p *cryptoProvider, store *testInMemoryStore,
	params AuthorizationParams, binding string, now time.Time,
) *AuthorizationResult {
	t.Helper()
	result, err := GenerateAuthorizationURL(
		context.Background(), p, cfg, store, params, binding, "google", now,
	)
	if err != nil {
		t.Fatalf("GenerateAuthorizationURL() error = %v", err)
	}
	return result
}

func pkceParamsInURL(t *testing.T, rawURL string) (hasChallenge, hasMethod bool) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("URL parse error = %v", err)
	}
	q := u.Query()
	return q.Get("code_challenge") != "", q.Get("code_challenge_method") != ""
}

func TestProtocolPKCEOmittedDefaultsToEnabled(t *testing.T) {
	// Protocol is zero value: UsePKCE nil. EffectiveProtocol() defaults to true.
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)

	hasChallenge, hasMethod := pkceParamsInURL(t, result.URL)
	if !hasChallenge {
		t.Error("code_challenge missing for omitted (nil) UsePKCE; want present")
	}
	if !hasMethod {
		t.Error("code_challenge_method missing for omitted (nil) UsePKCE; want S256")
	}
	if result.Transaction.PKCEVerifier == "" {
		t.Error("transaction PKCEVerifier must be non-empty even when defaults")
	}
}

func TestProtocolPKCEExplicitTrue(t *testing.T) {
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	trueVal := true
	cfg.Protocol.UsePKCE = &trueVal

	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)

	hasChallenge, hasMethod := pkceParamsInURL(t, result.URL)
	if !hasChallenge {
		t.Error("code_challenge missing for explicit true; want present")
	}
	if !hasMethod {
		t.Error("code_challenge_method missing for explicit true; want S256")
	}
	if result.Transaction.PKCEVerifier == "" {
		t.Error("transaction PKCEVerifier must be non-empty")
	}
}

func TestProtocolPKCEExplicitFalseOmitsParameters(t *testing.T) {
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	falseVal := false
	cfg.Protocol.UsePKCE = &falseVal

	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)

	hasChallenge, hasMethod := pkceParamsInURL(t, result.URL)
	if hasChallenge {
		t.Error("code_challenge present for explicit false; want omitted")
	}
	if hasMethod {
		t.Error("code_challenge_method present for explicit false; want omitted")
	}

	// Transaction still stores a verifier (rhiza_store requires non-empty),
	// but the verifier is never sent upstream.
	if result.Transaction.PKCEVerifier == "" {
		t.Error("transaction PKCEVerifier must be non-empty for storage invariant")
	}
}

func TestProtocolPKCEFalsePreservesBrowserStateNonce(t *testing.T) {
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	falseVal := false
	cfg.Protocol.UsePKCE = &falseVal

	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)

	u, err := url.Parse(result.URL)
	if err != nil {
		t.Fatalf("URL parse error = %v", err)
	}
	q := u.Query()

	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q, want test-client", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/cb" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("state") == "" {
		t.Error("state param missing")
	}
	if q.Get("nonce") == "" {
		t.Error("nonce param missing for OIDC config")
	}
	if q.Get("scope") == "" {
		t.Error("scope param missing")
	}

	// Transaction invariants
	if result.Transaction.StateDigest == "" {
		t.Error("StateDigest empty")
	}
	if result.Transaction.BrowserBindingDigest != binding {
		t.Errorf("BrowserBindingDigest = %q, want %q", result.Transaction.BrowserBindingDigest, binding)
	}
	if result.Transaction.Nonce == "" {
		t.Error("Nonce empty in transaction")
	}
}

func TestProtocolPKCEFalseWithPreexistingEndpointQuery(t *testing.T) {
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	cfg.AuthorizationEndpoint = "https://issuer.example.com/authorize?existing=param&code_challenge=old&code_challenge_method=old"
	falseVal := false
	cfg.Protocol.UsePKCE = &falseVal

	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)

	u, err := url.Parse(result.URL)
	if err != nil {
		t.Fatalf("URL parse error = %v", err)
	}
	q := u.Query()

	// Preexisting param preserved.
	if q.Get("existing") != "param" {
		t.Error("preexisting query param lost")
	}
	// PKCE params still omitted.
	if q.Has("code_challenge") {
		t.Error("code_challenge still present on endpoint; want removed")
	}
	if q.Has("code_challenge_method") {
		t.Error("code_challenge_method still present on endpoint; want removed")
	}
}

func TestProtocolPKCEDefaultsToEnabledWhenNil(t *testing.T) {
	// Regression: nil UsePKCE must behave identical to explicit true.
	cfgTrue, pTrue, storeTrue, paramsTrue, binding, now := authProtocolFixture(t)
	trueVal := true
	cfgTrue.Protocol.UsePKCE = &trueVal
	resultTrue := mustGenAuthURL(t, cfgTrue, pTrue, storeTrue, paramsTrue, binding, now)

	cfgNil, pNil, storeNil, paramsNil, _, _ := authProtocolFixture(t)
	resultNil := mustGenAuthURL(t, cfgNil, pNil, storeNil, paramsNil, binding, now)

	uTrue, _ := url.Parse(resultTrue.URL)
	uNil, _ := url.Parse(resultNil.URL)

	qTrue := uTrue.Query()
	qNil := uNil.Query()

	if qTrue.Get("code_challenge") == "" {
		t.Error("explicit true: code_challenge missing")
	}
	if qNil.Get("code_challenge") == "" {
		t.Error("nil UsePKCE: code_challenge missing")
	}
	if qTrue.Get("code_challenge_method") != "S256" {
		t.Error("explicit true: code_challenge_method != S256")
	}
	if qNil.Get("code_challenge_method") != "S256" {
		t.Error("nil UsePKCE: code_challenge_method != S256")
	}
}
