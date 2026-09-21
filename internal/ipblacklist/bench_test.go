package ipblacklist

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// GA-PERF-002 baseline. Check issues one linearizable SELECT of every column of
// ip_blacklist_entries and computes the longest matching prefix in Go, so the
// untimed cost grows with the table size up to DefaultMaxEntries (Add enforces
// the ceiling with a COUNT(*) precondition). Nothing here is optimized; the
// numbers are recorded in docs/PERFORMANCE.md.
const (
	benchHitIP          = "203.0.113.7" // matches only the seeded /32
	benchLongestIP      = "198.18.7.9"  // matches the seeded /16 and /24
	benchMissIP         = "172.31.0.1"  // matches nothing
	benchHitPrefix      = "203.0.113.7/32"
	benchLongestWide    = "198.18.0.0/16"
	benchLongestNarrow  = "198.18.7.0/24"
	benchSeedChunkRows  = 500
	benchSpecialEntries = 3
)

// benchStore opens a store on a migrated database. store_test.go's
// newTestStore takes *testing.T and builds a narrowed fixture schema, so it is
// not reusable here; storage.Migrate gives the production schema instead.
func benchStore(b *testing.B, maxEntries int) *Store {
	b.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "bench-ipbl", DataDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		b.Fatal(err)
	}
	return NewStore(db, maxEntries)
}

// seedEntries inserts n entries in chunks: the three queried prefixes plus
// filler /24s, none of which cover the other queries' addresses.
func seedEntries(b *testing.B, db *rhiza.DB, n int) {
	b.Helper()
	if n <= benchSpecialEntries {
		b.Fatalf("seedEntries needs more than %d entries, got %d", benchSpecialEntries, n)
	}
	prefixes := make([]string, 0, n)
	prefixes = append(prefixes, benchHitPrefix, benchLongestWide, benchLongestNarrow)
	for i := 0; i < n-benchSpecialEntries; i++ {
		prefixes = append(prefixes, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	for start := 0; start < len(prefixes); start += benchSeedChunkRows {
		end := min(start+benchSeedChunkRows, len(prefixes))
		args := make([]any, 0, end-start)
		for _, prefix := range prefixes[start:end] {
			args = append(args, prefix)
		}
		values := strings.TrimSuffix(strings.Repeat("(?, '', 1, 1),", end-start), ",")
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: fmt.Sprintf("bench-ipbl-seed-%d-%d", n, start),
			SQL:       "INSERT INTO ip_blacklist_entries(prefix, note, created_at_unix_ms, updated_at_unix_ms) VALUES " + values,
			Args:      args,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCheckAtCeiling measures Check on a store at its own ceiling.
func BenchmarkCheckAtCeiling(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("entries=%d", size), func(b *testing.B) {
			store := benchStore(b, size)
			seedEntries(b, store.db, size)

			// One correctness check per size: the fixture must answer as intended
			// before its timings are trusted.
			for _, want := range []struct {
				ip     string
				prefix string
			}{
				{benchHitIP, benchHitPrefix},
				{benchLongestIP, benchLongestNarrow},
				{benchMissIP, ""},
			} {
				got, err := store.Check(context.Background(), want.ip)
				if err != nil {
					b.Fatalf("Check(%s): %v", want.ip, err)
				}
				if got.Matched != (want.prefix != "") || got.Prefix != want.prefix {
					b.Fatalf("Check(%s) = %#v, want prefix %q", want.ip, got, want.prefix)
				}
			}

			ctx := context.Background()
			b.ResetTimer()
			b.Run("hit32", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, err := store.Check(ctx, benchHitIP); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("miss", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, err := store.Check(ctx, benchMissIP); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("longestPrefix", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, err := store.Check(ctx, benchLongestIP); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
