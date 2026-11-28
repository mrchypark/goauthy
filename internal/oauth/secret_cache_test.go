package oauth

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
)

type countingHasher struct {
	inner    fosite.Hasher
	compares atomic.Int64
}

func (c *countingHasher) Hash(ctx context.Context, data []byte) ([]byte, error) {
	return c.inner.Hash(ctx, data)
}

func (c *countingHasher) Compare(ctx context.Context, hash, data []byte) error {
	c.compares.Add(1)
	return c.inner.Compare(ctx, hash, data)
}

func TestCachedClientSecretsHasher(t *testing.T) {
	ctx := context.Background()
	counter := &countingHasher{inner: &fosite.BCrypt{Config: &fosite.Config{HashCost: 4}}}
	now := time.Unix(1700000000, 0)
	var nowMu sync.Mutex
	cache := newCachedClientSecretsHasher(counter, 5*time.Minute, 2)
	cache.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	hash1, err := cache.Hash(ctx, []byte("secret-one"))
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := cache.Hash(ctx, []byte("secret-two"))
	if err != nil {
		t.Fatal(err)
	}
	hash3, err := cache.Hash(ctx, []byte("secret-three"))
	if err != nil {
		t.Fatal(err)
	}

	// First valid compare hits inner hasher; second reuses cache.
	if err := cache.Compare(ctx, hash1, []byte("secret-one")); err != nil {
		t.Fatalf("first compare failed: %v", err)
	}
	if err := cache.Compare(ctx, hash1, []byte("secret-one")); err != nil {
		t.Fatalf("cached compare failed: %v", err)
	}
	if got := counter.compares.Load(); got != 1 {
		t.Fatalf("expected 1 inner compare, got %d", got)
	}

	// Failed comparisons must never be cached.
	for i := 0; i < 3; i++ {
		if err := cache.Compare(ctx, hash1, []byte("wrong-secret")); err == nil {
			t.Fatal("expected mismatch error")
		}
	}
	if got := counter.compares.Load(); got != 4 {
		t.Fatalf("expected 4 inner compares after failed attempts, got %d", got)
	}

	// Secret rotation (new hash) misses immediately even before TTL.
	rotatedHash1, err := cache.Hash(ctx, []byte("secret-one-rotated"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Compare(ctx, rotatedHash1, []byte("secret-one")); err == nil {
		t.Fatal("expected old secret to fail against rotated hash")
	}

	// LRU eviction when maxEntries=2: insert hash2 then hash3; hash1 was least-recent
	// (after hash2 was inserted, hash1 was not touched again, and rotated failed).
	if err := cache.Compare(ctx, hash2, []byte("secret-two")); err != nil {
		t.Fatal(err)
	}
	if err := cache.Compare(ctx, hash3, []byte("secret-three")); err != nil {
		t.Fatal(err)
	}
	beforeEvictCheck := counter.compares.Load()
	if err := cache.Compare(ctx, hash1, []byte("secret-one")); err != nil {
		t.Fatal(err)
	}
	if counter.compares.Load() != beforeEvictCheck+1 {
		t.Fatal("expected evicted hash1 entry to recompute")
	}

	// TTL expiration forces recomputation.
	nowMu.Lock()
	now = now.Add(6 * time.Minute)
	nowMu.Unlock()
	beforeTTL := counter.compares.Load()
	if err := cache.Compare(ctx, hash1, []byte("secret-one")); err != nil {
		t.Fatal(err)
	}
	if counter.compares.Load() != beforeTTL+1 {
		t.Fatal("expected expired entry to recompute")
	}
}

func TestIntrospectionCachesClientSecretVerification(t *testing.T) {
	key := oidcTestKey(t)
	server := oidcTestServer(t, oauthTestDB(t), randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })

	cfg := server.provider.(*fosite.Fosite).Config.(*fosite.Config)
	cached, ok := cfg.ClientSecretsHasher.(*cachedClientSecretsHasher)
	if !ok {
		t.Fatalf("expected *cachedClientSecretsHasher, got %T", cfg.ClientSecretsHasher)
	}
	counter := &countingHasher{inner: cached.inner}
	cached.inner = counter

	introspect := server.IntrospectionHandler()
	for i := 0; i < 5; i++ {
		rec := postOAuthForm(introspect, url.Values{"token": {"dummy-invalid-token"}}, testClientID, testClientSecret)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: status=%d want 200", i, rec.Code)
		}
	}
	if got := counter.compares.Load(); got != 1 {
		t.Fatalf("expected 1 inner bcrypt compare across 5 introspect calls, got %d", got)
	}

	rec := postOAuthForm(introspect, url.Values{"token": {"dummy-invalid-token"}}, testClientID, "wrong-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret status=%d want 401", rec.Code)
	}
	if got := counter.compares.Load(); got != 2 {
		t.Fatalf("expected failed compare not to be cached (want 2, got %d)", got)
	}
}
