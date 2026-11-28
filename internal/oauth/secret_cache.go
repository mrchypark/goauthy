package oauth

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/ory/fosite"
)

const (
	defaultClientSecretCacheTTL        = 5 * time.Minute
	defaultClientSecretCacheMaxEntries = 1024
)

type cachedSecretEntry struct {
	key       [32]byte
	expiresAt time.Time
}

// cachedClientSecretsHasher caches successful client_secret comparisons keyed
// by a process-local HMAC over both the stored hash and presented secret.
// Including the stored hash invalidates rotated secrets immediately, and failed
// comparisons are never cached.
type cachedClientSecretsHasher struct {
	inner      fosite.Hasher
	hmacKey    [32]byte
	keyReady   bool
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	order   list.List
	entries map[[32]byte]*list.Element
}

var _ fosite.Hasher = (*cachedClientSecretsHasher)(nil)

func newCachedClientSecretsHasher(inner fosite.Hasher, ttl time.Duration, maxEntries int) *cachedClientSecretsHasher {
	h := &cachedClientSecretsHasher{
		inner:      inner,
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
		entries:    make(map[[32]byte]*list.Element),
	}
	if _, err := rand.Read(h.hmacKey[:]); err == nil {
		h.keyReady = true
	}
	return h
}

func (h *cachedClientSecretsHasher) Hash(ctx context.Context, data []byte) ([]byte, error) {
	return h.inner.Hash(ctx, data)
}

func (h *cachedClientSecretsHasher) Compare(ctx context.Context, hash, data []byte) error {
	if !h.keyReady || h.ttl <= 0 || h.maxEntries <= 0 || len(hash) == 0 || len(data) == 0 {
		return h.inner.Compare(ctx, hash, data)
	}
	digest := h.cacheKey(hash, data)
	now := h.now()

	h.mu.Lock()
	if elem, ok := h.entries[digest]; ok {
		entry := elem.Value.(*cachedSecretEntry)
		if now.Before(entry.expiresAt) {
			h.order.MoveToFront(elem)
			h.mu.Unlock()
			return nil
		}
		h.order.Remove(elem)
		delete(h.entries, digest)
	}
	h.mu.Unlock()

	if err := h.inner.Compare(ctx, hash, data); err != nil {
		return err
	}

	expiresAt := h.now().Add(h.ttl)
	h.mu.Lock()
	if elem, ok := h.entries[digest]; ok {
		elem.Value.(*cachedSecretEntry).expiresAt = expiresAt
		h.order.MoveToFront(elem)
	} else {
		for len(h.entries) >= h.maxEntries {
			back := h.order.Back()
			if back == nil {
				break
			}
			evicted := back.Value.(*cachedSecretEntry)
			delete(h.entries, evicted.key)
			h.order.Remove(back)
		}
		elem := h.order.PushFront(&cachedSecretEntry{key: digest, expiresAt: expiresAt})
		h.entries[digest] = elem
	}
	h.mu.Unlock()
	return nil
}

func (h *cachedClientSecretsHasher) cacheKey(hash, data []byte) [32]byte {
	mac := hmac.New(sha256.New, h.hmacKey[:])
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(hash)))
	mac.Write(lenBuf[:])
	mac.Write(hash)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(data)))
	mac.Write(lenBuf[:])
	mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
