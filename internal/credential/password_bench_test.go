package credential

import (
	"context"
	"testing"
	"time"
)

func BenchmarkHash(b *testing.B) {
	h, err := NewHasher(DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	password := []byte("test-password-123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.Hash(ctx, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyOrDummy(b *testing.B) {
	h, err := NewHasher(DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	password := []byte("test-password-123")
	phc, err := h.Hash(ctx, password)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := h.VerifyOrDummy(ctx, password, phc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyOrDummyMiss(b *testing.B) {
	h, err := NewHasher(DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	password := []byte("test-password-123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := h.VerifyOrDummy(ctx, password, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTryAcquireContended(b *testing.B) {
	h, err := NewHasher(Policy{
		MemoryKiB:      19 * 1024,
		Iterations:     2,
		Parallelism:    1,
		MaxConcurrency: 4,
		WaitTimeout:    100 * time.Millisecond,
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			release, err := h.tryAcquire(ctx)
			if err != nil {
				b.Fatal(err)
			}
			release()
		}
	})
}
