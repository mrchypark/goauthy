package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestBasicSetGet(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	defer func() {}()

	c.Set("a", 1)
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected (1, true), got (%v, %v)", v, ok)
	}
}

func TestMiss(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	_, ok := c.Get("missing")
	if ok {
		t.Fatal("expected miss")
	}
	hits, misses, _, _, _ := c.Snapshot()
	if hits != 0 || misses != 1 {
		t.Fatalf("expected 0 hits/1 miss, got %d/%d", hits, misses)
	}
}

func TestTTLExpiry(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: 50 * time.Millisecond})
	c.Set("k", 42)
	time.Sleep(60 * time.Millisecond)
	_, ok := c.Get("k")
	if ok {
		t.Fatal("expected expired")
	}
	_, _, evictions, _, _ := c.Snapshot()
	if evictions != 1 {
		t.Fatalf("expected 1 eviction, got %d", evictions)
	}
}

func TestCustomTTL(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Hour})
	c.SetWithTTL("k", 1, 50*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	_, ok := c.Get("k")
	if ok {
		t.Fatal("expected expired with custom TTL")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 3, DefaultTTL: time.Minute})
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)
	// Cache is full. Adding "d" should evict LRU "a".
	c.Set("d", 4)
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted")
	}
	v, ok := c.Get("d")
	if !ok || v != 4 {
		t.Fatalf("expected (4, true), got (%v, %v)", v, ok)
	}
}

func TestGetPromotesLRU(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 3, DefaultTTL: time.Minute})
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)
	// Access "a" to promote it.
	c.Get("a")
	// Now "b" is LRU. Adding "d" should evict "b".
	c.Set("d", 4)
	_, ok := c.Get("b")
	if ok {
		t.Fatal("expected 'b' to be evicted")
	}
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected 'a' to survive, got (%v, %v)", v, ok)
	}
}

func TestDelete(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	c.Set("k", 1)
	if !c.Delete("k") {
		t.Fatal("expected delete to return true")
	}
	_, ok := c.Get("k")
	if ok {
		t.Fatal("expected miss after delete")
	}
	if c.Delete("k") {
		t.Fatal("expected delete of missing key to return false")
	}
}

func TestUpdate(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	c.Set("k", 1)
	c.Set("k", 2)
	v, ok := c.Get("k")
	if !ok || v != 2 {
		t.Fatalf("expected (2, true), got (%v, %v)", v, ok)
	}
	if c.Size() != 1 {
		t.Fatalf("expected size 1, got %d", c.Size())
	}
}

func TestPurge(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	c.Set("a", 1)
	c.Set("b", 2)
	c.Purge()
	if c.Size() != 0 {
		t.Fatalf("expected size 0 after purge, got %d", c.Size())
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New[int, int](Config{MaxEntries: 1000, DefaultTTL: time.Minute})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				key := id*1000 + j
				c.Set(key, key)
				c.Get(key)
				c.Delete(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestHitRate(t *testing.T) {
	c := New[string, int](Config{MaxEntries: 1000, DefaultTTL: time.Minute})
	for i := 0; i < 100; i++ {
		c.Set(fmt.Sprintf("k%d", i), i)
	}
	// 50 hits, 50 misses
	for i := 0; i < 50; i++ {
		c.Get(fmt.Sprintf("k%d", i))
	}
	for i := 200; i < 250; i++ {
		c.Get(fmt.Sprintf("k%d", i))
	}
	rate := c.metrics.HitRate()
	if rate < 49 || rate > 51 {
		t.Fatalf("expected ~50%% hit rate, got %.1f%%", rate)
	}
}

func TestIntKeyCache(t *testing.T) {
	c := New[int, string](Config{MaxEntries: 100, DefaultTTL: time.Minute})
	c.Set(42, "answer")
	v, ok := c.Get(42)
	if !ok || v != "answer" {
		t.Fatalf("expected (answer, true), got (%v, %v)", v, ok)
	}
}

// --- Benchmarks ---

func BenchmarkCacheGetHit(b *testing.B) {
	c := New[string, int](Config{MaxEntries: 10000, DefaultTTL: time.Minute})
	for i := 0; i < 1000; i++ {
		c.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(fmt.Sprintf("key-%d", i%1000))
	}
}

func BenchmarkCacheGetMiss(b *testing.B) {
	c := New[string, int](Config{MaxEntries: 10000, DefaultTTL: time.Minute})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(fmt.Sprintf("miss-%d", i))
	}
}

func BenchmarkCacheSet(b *testing.B) {
	c := New[string, int](Config{MaxEntries: 100000, DefaultTTL: time.Minute})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(fmt.Sprintf("key-%d", i%100000), i)
	}
}

func BenchmarkCacheSetParallel(b *testing.B) {
	c := New[string, int](Config{MaxEntries: 100000, DefaultTTL: time.Minute})
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Set(fmt.Sprintf("key-%d", i%100000), i)
			i++
		}
	})
}

func BenchmarkCacheGetParallel(b *testing.B) {
	c := New[string, int](Config{MaxEntries: 100000, DefaultTTL: time.Minute})
	for i := 0; i < 10000; i++ {
		c.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get(fmt.Sprintf("key-%d", i%10000))
			i++
		}
	})
}
