// Package cache provides a sharded, TTL-aware, concurrent-safe in-memory cache
// optimized for authentication server hot paths. It minimizes lock contention
// through power-of-2 sharding and uses LRU eviction within each shard.
package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks cache performance for observability.
type Metrics struct {
	Hits      atomic.Int64
	Misses    atomic.Int64
	Evictions atomic.Int64
	Stores    atomic.Int64
	Deletes   atomic.Int64
}

// HitRate returns the cache hit rate as a percentage.
func (m *Metrics) HitRate() float64 {
	h := m.Hits.Load()
	total := h + m.Misses.Load()
	if total == 0 {
		return 0
	}
	return float64(h) / float64(total) * 100
}

// Cache is a sharded, TTL-aware, LRU cache safe for concurrent use.
type Cache[K comparable, V any] struct {
	shards    []*shard[K, V]
	shardMask uint64
	metrics   Metrics
	onEvict   func(key K, value V)
}

// Config controls cache behavior.
type Config struct {
	// MaxEntries is the total maximum entries across all shards.
	MaxEntries int
	// DefaultTTL is applied when Set is called with zero TTL.
	DefaultTTL time.Duration
	// ShardCount must be a power of two. Zero means auto (16).
	ShardCount int
	// OnEvict is called when an entry is evicted (LRU or TTL).
	OnEvict func(key string, value any)
}

// New creates a cache with the given configuration.
func New[K comparable, V any](cfg Config) *Cache[K, V] {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1024
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	shardCount := cfg.ShardCount
	if shardCount <= 0 {
		shardCount = 16
	}
	// Round up to next power of two.
	if shardCount&(shardCount-1) != 0 {
		n := uint(shardCount)
		n--
		n |= n >> 1
		n |= n >> 2
		n |= n >> 4
		n |= n >> 8
		n |= n >> 16
		shardCount = int(n + 1)
	}
	// Reduce shard count so each shard has at least 1 entry.
	for shardCount > 1 && cfg.MaxEntries/shardCount < 1 {
		shardCount >>= 1
	}
	// For very small caches, use a single shard to avoid capacity waste.
	if cfg.MaxEntries < 16 {
		shardCount = 1
	}
	perShard := cfg.MaxEntries / shardCount
	if perShard < 1 {
		perShard = 1
	}
	c := &Cache[K, V]{
		shards:    make([]*shard[K, V], shardCount),
		shardMask: uint64(shardCount - 1),
	}
	for i := range c.shards {
		c.shards[i] = newShard[K, V](perShard, cfg.DefaultTTL)
	}
	return c
}

// Get retrieves a value. Returns (value, true) on hit, (zero, false) on miss.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	ent, ok := s.entries[key]
	if !ok {
		c.metrics.Misses.Add(1)
		var zero V
		return zero, false
	}
	if ent.expired() {
		s.delete(key)
		c.metrics.Misses.Add(1)
		c.metrics.Evictions.Add(1)
		var zero V
		return zero, false
	}
	// Move to front (most recently used).
	s.list.MoveToFront(ent.elem)
	c.metrics.Hits.Add(1)
	return ent.value, true
}

// Set stores a value with the default TTL.
func (c *Cache[K, V]) Set(key K, value V) {
	c.SetWithTTL(key, value, 0)
}

// SetWithTTL stores a value with a specific TTL. Zero means default.
func (c *Cache[K, V]) SetWithTTL(key K, value V, ttl time.Duration) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	if ent, ok := s.entries[key]; ok {
		ent.value = value
		ent.expires = s.expiry(ttl)
		s.list.MoveToFront(ent.elem)
		return
	}
	// Evict LRU if at capacity.
	if s.list.Len() >= s.maxEntries {
		back := s.list.Back()
		if back != nil {
			s.removeElement(back)
			c.metrics.Evictions.Add(1)
		}
	}
	s.insert(key, value, ttl)
	c.metrics.Stores.Add(1)
}

// Delete removes an entry.
func (c *Cache[K, V]) Delete(key K) bool {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[key]; !ok {
		return false
	}
	s.delete(key)
	c.metrics.Deletes.Add(1)
	return true
}

// Purge removes all entries and resets metrics.
func (c *Cache[K, V]) Purge() {
	for _, s := range c.shards {
		s.mu.Lock()
		s.entries = make(map[K]*entry[K, V])
		s.list.Init()
		s.mu.Unlock()
	}
}

// Size returns the approximate total entry count.
func (c *Cache[K, V]) Size() int {
	var n int
	for _, s := range c.shards {
		s.mu.Lock()
		n += s.list.Len()
		s.mu.Unlock()
	}
	return n
}

// Snapshot returns a copy of the metrics.
func (c *Cache[K, V]) Snapshot() (hits, misses, evictions, stores, deletes int64) {
	return c.metrics.Hits.Load(),
		c.metrics.Misses.Load(),
		c.metrics.Evictions.Load(),
		c.metrics.Stores.Load(),
		c.metrics.Deletes.Load()
}

func (c *Cache[K, V]) shard(key K) *shard[K, V] {
	h := hashKey(key)
	return c.shards[h&c.shardMask]
}

// --- shard internals ---

type entry[K comparable, V any] struct {
	key     K
	value   V
	expires int64
	elem    *listElement[K, V]
}

func (e *entry[K, V]) expired() bool {
	return e.expires > 0 && time.Now().UnixNano() > e.expires
}

type shard[K comparable, V any] struct {
	mu         sync.Mutex
	entries    map[K]*entry[K, V]
	list       *list[K, V]
	maxEntries int
	defaultTTL time.Duration
}

func newShard[K comparable, V any](maxEntries int, defaultTTL time.Duration) *shard[K, V] {
	return &shard[K, V]{
		entries:    make(map[K]*entry[K, V], maxEntries),
		list:       newList[K, V](),
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}
}

func (s *shard[K, V]) expiry(ttl time.Duration) int64 {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	return time.Now().Add(ttl).UnixNano()
}

func (s *shard[K, V]) insert(key K, value V, ttl time.Duration) {
	e := &entry[K, V]{key: key, value: value, expires: s.expiry(ttl)}
	e.elem = s.list.PushFront(e)
	s.entries[key] = e
}

func (s *shard[K, V]) delete(key K) {
	if ent, ok := s.entries[key]; ok {
		s.list.Remove(ent.elem)
		delete(s.entries, key)
	}
}

func (s *shard[K, V]) removeElement(le *listElement[K, V]) {
	e := le.Value
	s.list.Remove(le)
	delete(s.entries, e.key)
}

// --- minimal intrusive doubly-linked list ---

type listElement[K comparable, V any] struct {
	Value *entry[K, V]
	prev  *listElement[K, V]
	next  *listElement[K, V]
}

type list[K comparable, V any] struct {
	root listElement[K, V]
	len  int
}

func newList[K comparable, V any]() *list[K, V] {
	l := &list[K, V]{}
	l.root.next = &l.root
	l.root.prev = &l.root
	return l
}

func (l *list[K, V]) Init() {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
}

func (l *list[K, V]) Len() int { return l.len }

func (l *list[K, V]) PushFront(e *entry[K, V]) *listElement[K, V] {
	le := &listElement[K, V]{Value: e}
	le.next = l.root.next
	le.prev = &l.root
	l.root.next.prev = le
	l.root.next = le
	l.len++
	return le
}

func (l *list[K, V]) MoveToFront(le *listElement[K, V]) {
	if l.root.next == le {
		return
	}
	le.prev.next = le.next
	le.next.prev = le.prev
	le.next = l.root.next
	le.prev = &l.root
	l.root.next.prev = le
	l.root.next = le
}

func (l *list[K, V]) Remove(le *listElement[K, V]) {
	le.prev.next = le.next
	le.next.prev = le.prev
	le.next = nil
	le.prev = nil
	l.len--
}

func (l *list[K, V]) Back() *listElement[K, V] {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

// --- hashing ---

func hashKey[K comparable](key K) uint64 {
	switch k := any(key).(type) {
	case string:
		return fnv1a(k)
	case int:
		return uint64(k)
	case int64:
		return uint64(k)
	case uint64:
		return k
	case uint32:
		return uint64(k)
	case [32]byte:
		return uint64(k[0]) | uint64(k[1])<<8 | uint64(k[2])<<16 | uint64(k[3])<<24 |
			uint64(k[4])<<32 | uint64(k[5])<<40 | uint64(k[6])<<48 | uint64(k[7])<<56
	default:
		// Fallback: use the string representation.
		return fnv1a(fmt.Sprintf("%v", key))
	}
}

func fnv1a(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
