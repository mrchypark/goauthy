package oauth

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// GA-PERF-001 baseline. Every token issuance also runs two cleanup statements:
// DELETE FROM oauth_access_tokens WHERE expires_at_unix_ms <= ? and
// DELETE FROM oauth_token_requests WHERE NOT EXISTS (...). Both are extended
// with the transaction principal guard for the code and refresh kinds.
//
// What is measured here: the storage-layer issuance cycle, i.e. the production
// Store.CreateAccessTokenSession on a migrated database. That method is the
// only place the cleanup statements are built, and for a non-transactional
// (client-credentials) issuance it batches cleanup, the token INSERT, and the
// client last-used UPDATE into one replicated Execute. The full fosite HTTP
// token-endpoint path is NOT driven; the measured unit is the storage cycle
// that carries the cleanup.
//
// The seeded table holds live access tokens, which is the steady state: the
// expired-row DELETE probes the expires_at_unix_ms index and the orphan DELETE
// anti-joins every oauth_token_requests row, so the recurring cost of cleanup
// grows with the live token count even when it deletes nothing. Signature is
// the primary key, so each iteration issues a fresh one and the table grows by
// one access row and one request row per iteration. Nothing is optimized here;
// the numbers are recorded in docs/PERFORMANCE.md.
const (
	benchSeedChunk      = 250
	benchLiveExpiryMs   = int64(4_000_000_000_000) // year 2096
	benchSeedClientID   = "bench-client"
	benchSeedRequestArg = "'[]'"
)

// benchOAuthStore builds a migrated database and the production server/store
// pair. grant_test.go's oauthTestDB and oauthTestServer take *testing.T, so the
// benchmark opens the same things directly.
func benchOAuthStore(b *testing.B) (*Store, *rhiza.DB) {
	b.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "bench-oauth", DataDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		b.Fatal(err)
	}
	server, err := NewServer(context.Background(), db, bytes.Repeat([]byte{7}, 32), testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		b.Fatal(err)
	}
	return server.store, db
}

// seedLiveTokens inserts n live access tokens and their matching token-request
// rows, chunked to keep each statement small.
func seedLiveTokens(b *testing.B, db *rhiza.DB, n int) {
	b.Helper()
	for start := 0; start < n; start += benchSeedChunk {
		end := min(start+benchSeedChunk, n)
		var access, requests strings.Builder
		access.WriteString("INSERT INTO oauth_access_tokens (signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms, requested_scopes, granted_scopes, requested_audience, granted_audience) VALUES ")
		requests.WriteString("INSERT INTO oauth_token_requests (signature, request_json) VALUES ")
		accessArgs := make([]any, 0, end-start)
		requestArgs := make([]any, 0, end-start)
		for i := start; i < end; i++ {
			signature := fmt.Sprintf("bench-live-%d", i)
			if i > start {
				access.WriteString(",")
				requests.WriteString(",")
			}
			access.WriteString(fmt.Sprintf("(?, 'bench-request', '%s', 1, %d, %s, %s, %s, %s)", benchSeedClientID, benchLiveExpiryMs, benchSeedRequestArg, benchSeedRequestArg, benchSeedRequestArg, benchSeedRequestArg))
			requests.WriteString("(?, '{}')")
			accessArgs = append(accessArgs, signature)
			requestArgs = append(requestArgs, signature)
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: fmt.Sprintf("bench-oauth-seed-%d-%d", n, start),
			Statements: []rhiza.SQLStatement{
				{SQL: access.String(), Args: accessArgs},
				{SQL: requests.String(), Args: requestArgs},
			},
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCreateAccessTokenSessionWithCleanup measures one issuance-with-
// cleanup cycle at the storage layer against a seeded live-token table.
func BenchmarkCreateAccessTokenSessionWithCleanup(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("liveTokens=%d", size), func(b *testing.B) {
			store, db := benchOAuthStore(b)
			seedLiveTokens(b, db, size)
			request := dynamicLastUsedRequest(store.client, "bench-issue", time.UnixMilli(1))
			ctx := context.Background()

			// One correctness check per size before the timings are trusted:
			// the cycle must really commit both token rows.
			if err := store.CreateAccessTokenSession(ctx, "bench-verify", request); err != nil {
				b.Fatal(err)
			}
			result, err := db.Query(ctx, rhiza.QueryRequest{
				SQL:         "SELECT (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_token_requests)",
				Consistency: rhiza.ConsistencyLinearizable,
			})
			if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(size+1) || result.Rows[0][1] != int64(size+1) {
				b.Fatalf("seeded rows=%#v err=%v, want %d each", result.Rows, err, size+1)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := store.CreateAccessTokenSession(ctx, fmt.Sprintf("bench-access-%d", i), request); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
