package upstreamprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestJWKSVerifierVerifiesCachesAndRotates(t *testing.T) {
	t.Parallel()
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key1.PublicKey, KeyID: "one", Algorithm: "RS256", Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())
	for _, raw := range []string{signedToken(t, key1, "one", "issuer", "client"), signedToken(t, key1, "one", "issuer", "client")} {
		if _, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client"); err != nil {
			t.Fatalf("VerifyIDToken: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
	if _, err := v.VerifyIDToken(context.Background(), signedToken(t, key1, "one", "issuer", "client"+"x"), "issuer", "client"); !errors.Is(err, ErrIDTokenVerification) {
		t.Fatalf("bad audience error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("bad token refreshed JWKS: %d", got)
	}
	keys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key2.PublicKey, KeyID: "two", Algorithm: "RS256", Use: "sig"}}}
	if _, err := v.VerifyIDToken(context.Background(), signedToken(t, key2, "two", "issuer", "client"), "issuer", "client"); err != nil {
		t.Fatalf("rotated token: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("fetches after rotation = %d, want 2", got)
	}
}

func TestJWKSVerifierColdFetchIsDeduplicatedAndWaitersCancel(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())
	raw := signedToken(t, key, "key", "issuer", "client")
	secondKeys := make(chan struct{})
	var nowCalls atomic.Int32
	var signal sync.Once
	v.now = func() time.Time {
		if nowCalls.Add(1) == 2 {
			signal.Do(func() { close(secondKeys) })
		}
		return jwksTestNow()
	}
	done := make(chan error, 1)
	go func() { _, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client"); done <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() { _, err := v.VerifyIDToken(ctx, raw, "issuer", "client"); waiter <- err }()
	<-secondKeys
	cancel()
	if err := <-waiter; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestJWKSVerifierUnknownKidWaiterJoinsRefreshBeforeMissSuppression(t *testing.T) {
	t.Parallel()
	oldKeys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "old"}}}
	newKeys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "new"}}}
	active := &jwksFetch{done: make(chan struct{})}
	v := newTestJWKSVerifier("https://issuer.example.test/jwks", nil)
	v.entries["issuer"] = jwksCacheEntry{keys: oldKeys, expires: jwksTestNow().Add(jwksCacheTTL), missRefreshUntil: jwksTestNow().Add(time.Second)}
	v.fetching["issuer"] = active
	if keys, err := v.keys(context.Background(), "issuer", v.jwksByIssuer["issuer"], false); err != nil || len(keys.Key("old")) != 1 {
		t.Fatalf("known key unavailable during refresh: keys=%v err=%v", keys, err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	v.now = func() time.Time { close(entered); <-resume; return jwksTestNow() }
	t.Cleanup(func() {
		select {
		case <-active.done:
		default:
			active.keys = newKeys
			close(active.done)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type keyResult struct {
		keys jose.JSONWebKeySet
		err  error
	}
	waiter := make(chan keyResult, 1)
	go func() {
		keys, err := v.keys(ctx, "issuer", v.jwksByIssuer["issuer"], true)
		waiter <- keyResult{keys: keys, err: err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatalf("waiter did not reach keys lookup: %v", ctx.Err())
	}
	close(resume)
	var completed *keyResult
	select {
	case early := <-waiter:
		if early.err != nil {
			t.Fatal(early.err)
		}
		if got := early.keys.Key("new"); len(got) != 1 {
			t.Fatalf("in-flight waiter returned stale key set: %v", early.keys.Key("old"))
		}
		completed = &early
	case <-time.After(25 * time.Millisecond):
	}
	if completed == nil {
		select {
		case <-active.done:
		default:
			active.keys = newKeys
			close(active.done)
		}
		select {
		case earlyResult := <-waiter:
			completed = &earlyResult
		case <-ctx.Done():
			t.Fatalf("waiter did not complete after refresh: %v", ctx.Err())
		}
	}
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	if got := completed.keys.Key("new"); len(got) != 1 {
		t.Fatalf("waiter keys = %v, want refreshed new key", completed.keys)
	}
}

func TestJWKSVerifierFailedUnknownKidRefreshRetriesAfterShortInterval(t *testing.T) {
	t.Parallel()
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &oldKey.PublicKey, KeyID: "old"}}})
		case 2:
			http.Error(w, "temporary", http.StatusServiceUnavailable)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &newKey.PublicKey, KeyID: "new"}}})
		}
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())
	now := jwksTestNow()
	v.now = func() time.Time { return now }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := v.keys(ctx, "issuer", server.URL, false); err != nil {
		t.Fatal(err)
	}
	if _, err := v.keys(ctx, "issuer", server.URL, true); err == nil {
		t.Fatal("temporary refresh failure was lost")
	}
	now = now.Add(time.Second)
	keys, err := v.keys(ctx, "issuer", server.URL, true)
	if err != nil {
		t.Fatalf("retry after short interval: %v", err)
	}
	if got := keys.Key("new"); len(got) != 1 {
		t.Fatalf("retry keys = %v, want new key", got)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("fetches = %d, want initial, failed, successful", got)
	}
}

func TestNewJWKSVerifierRejectsInvalidAndConflictingIssuer(t *testing.T) {
	t.Parallel()
	valid := func(jwks string) Config {
		return Config{Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth", TokenEndpoint: "https://issuer.example.test/token", ClientID: "client", JWKSURI: jwks}
	}
	if _, err := NewJWKSVerifier(map[string]Config{"a": valid("")}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty JWKS: %v", err)
	}
	if _, err := NewJWKSVerifier(map[string]Config{"a": valid("https://issuer.example.test/a"), "b": valid("https://issuer.example.test/b")}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("conflict: %v", err)
	}
}

func TestNewJWKSVerifierSkipsGitHubAndVerifiesOIDC(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "oidc"}}})
	}))
	defer server.Close()
	configs := map[string]Config{
		"github": {Kind: ProviderKindGitHub, Issuer: "https://github.com", AuthorizationEndpoint: "https://github.com/login/oauth/authorize", TokenEndpoint: "https://github.com/login/oauth/access_token", UserInfoEndpoint: "https://api.github.com/user", ClientID: "github-client", Scopes: []string{"read:user"}},
		"oidc":   {Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/auth", TokenEndpoint: "https://issuer.example.test/token", ClientID: "oidc-client", JWKSURI: server.URL},
	}
	v, err := NewJWKSVerifier(configs, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.jwksByIssuer["https://github.com"]; ok {
		t.Fatal("GitHub unexpectedly configured for JWKS lookup")
	}
	if _, err := v.VerifyIDToken(context.Background(), signedToken(t, key, "oidc", "https://issuer.example.test", "oidc-client"), "https://issuer.example.test", "oidc-client"); err != nil {
		t.Fatalf("OIDC verification: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", got)
	}
}

func TestJWKSVerifierIsInstanceLocalAndBoundsUnknownKidRefresh(t *testing.T) {
	t.Parallel()
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := func(key *rsa.PrivateKey, calls *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "same"}}})
		}))
	}
	var firstCalls, secondCalls atomic.Int32
	first, second := server(key1, &firstCalls), server(key2, &secondCalls)
	defer first.Close()
	defer second.Close()
	v1, v2 := newTestJWKSVerifier(first.URL, first.Client()), newTestJWKSVerifier(second.URL, second.Client())
	now := jwksTestNow()
	v1.now = func() time.Time { return now }
	if _, err := v1.VerifyIDToken(context.Background(), signedToken(t, key1, "same", "issuer", "client"), "issuer", "client"); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.VerifyIDToken(context.Background(), signedToken(t, key2, "same", "issuer", "client"), "issuer", "client"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := v1.VerifyIDToken(context.Background(), signedToken(t, key1, "unknown", "issuer", "client"), "issuer", "client"); !errors.Is(err, ErrIDTokenVerification) {
			t.Fatal(err)
		}
	}
	if got := firstCalls.Load(); got != 2 {
		t.Fatalf("unknown-kid fetches = %d, want 2", got)
	}
	now = now.Add(time.Second)
	if _, err := v1.VerifyIDToken(context.Background(), signedToken(t, key1, "unknown", "issuer", "client"), "issuer", "client"); !errors.Is(err, ErrIDTokenVerification) {
		t.Fatal(err)
	}
	if got := firstCalls.Load(); got != 2 {
		t.Fatalf("successful unknown-kid refresh was retried before cache expiry: fetches = %d, want 2", got)
	}
	now = now.Add(jwksCacheTTL - time.Second)
	if _, err := v1.VerifyIDToken(context.Background(), signedToken(t, key1, "unknown", "issuer", "client"), "issuer", "client"); !errors.Is(err, ErrIDTokenVerification) {
		t.Fatal(err)
	}
	if got := firstCalls.Load(); got != 4 {
		t.Fatalf("unknown-kid fetches after cache expiry = %d, want 4", got)
	}
	if got := secondCalls.Load(); got != 1 {
		t.Fatalf("second instance fetches = %d, want 1", got)
	}
}

func TestJWKSVerifierExpiryStartsAfterFetch(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now = now.Add(time.Minute)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key"}}})
	}))
	defer server.Close()
	v := newTestJWKSVerifier(server.URL, server.Client())
	v.now = func() time.Time { return now }
	if _, err := v.VerifyIDToken(context.Background(), signedToken(t, key, "key", "issuer", "client"), "issuer", "client"); err != nil {
		t.Fatal(err)
	}
	if got, want := v.entries["issuer"].expires, now.Add(jwksCacheTTL); !got.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got, want)
	}
}

func TestJWKSVerifierLeaderCancellationDoesNotCancelFetch(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key"}}})
	}))
	defer server.Close()
	v, raw := newTestJWKSVerifier(server.URL, server.Client()), signedToken(t, key, "key", "issuer", "client")
	secondKeys := make(chan struct{})
	var nowCalls atomic.Int32
	var signal sync.Once
	v.now = func() time.Time {
		if nowCalls.Add(1) == 2 {
			signal.Do(func() { close(secondKeys) })
		}
		return jwksTestNow()
	}
	ctx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	live := make(chan error, 1)
	go func() { _, err := v.VerifyIDToken(ctx, raw, "issuer", "client"); leader <- err }()
	<-started
	go func() { _, err := v.VerifyIDToken(context.Background(), raw, "issuer", "client"); live <- err }()
	<-secondKeys
	cancel()
	close(release)
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v", err)
	}
	if err := <-live; err != nil {
		t.Fatalf("live waiter error = %v", err)
	}
}

func TestJWKSVerifierRejectsDuplicateKid(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key"}, {Key: &key.PublicKey, KeyID: "key"}}})
	}))
	defer server.Close()
	_, err = newTestJWKSVerifier(server.URL, server.Client()).VerifyIDToken(context.Background(), signedToken(t, key, "key", "issuer", "client"), "issuer", "client")
	if !errors.Is(err, ErrIDTokenVerification) {
		t.Fatalf("duplicate kid error = %v", err)
	}
}

func signedToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": "subject"})
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTestJWKSVerifier(uri string, client *http.Client) *JWKSVerifier {
	return &JWKSVerifier{jwksByIssuer: map[string]string{"issuer": uri}, client: client, now: jwksTestNow, entries: make(map[string]jwksCacheEntry), fetching: make(map[string]*jwksFetch)}
}

func jwksTestNow() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
