//go:build confirmationproof

package browser

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// This measurement counts the actual RevokeSessionID query and Execute
// submissions through the confirmationproof overlay. State setup is outside
// the probe, and advancing the store clock makes every mutation RequestID
// unique so durable request deduplication cannot hide a submission.
func TestRevokeSessionIDCostAndIdempotence(t *testing.T) {
	for _, scenario := range []string{"active", "already-revoked", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			store, issued, now := confirmationFixture(t)
			store.now = func() time.Time { return now }
			id := issued.ID
			var originalRevokedAt int64
			if scenario == "missing" {
				missing := sha256.Sum256([]byte("revoke-cost-missing-session"))
				id = base64.RawURLEncoding.EncodeToString(missing[:])
				if id == issued.ID {
					t.Fatal("synthetic missing ID collided with fixture session")
				}
			} else if scenario == "already-revoked" {
				originalRevokedAt = now.Add(-time.Minute).UnixMilli()
				if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{
					RequestID: "revoke-cost-seed-revoked",
					SQL:       "UPDATE browser_sessions SET revoked_at_unix_ms=? WHERE token_digest=?",
					Args:      []any{originalRevokedAt, id},
				}); err != nil {
					t.Fatal(err)
				}
			}

			probe := &confirmationProbe{}
			var requestIDs []string
			probe.touch = func(request rhiza.ExecuteRequest) {
				if !strings.HasPrefix(strings.TrimSpace(request.SQL), "UPDATE browser_sessions SET revoked_at_unix_ms =") {
					t.Fatalf("unexpected mutation in revoke path")
				}
				requestIDs = append(requestIDs, request.RequestID)
			}

			const iterations = 3
			for i := 0; i < iterations; i++ {
				if scenario == "active" {
					if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{
						RequestID: fmt.Sprintf("revoke-cost-reset-%d", i),
						SQL:       "UPDATE browser_sessions SET revoked_at_unix_ms=NULL WHERE token_digest=?",
						Args:      []any{id},
					}); err != nil {
						t.Fatal(err)
					}
				}
				now = now.Add(time.Millisecond)
				err := store.RevokeSessionID(context.WithValue(t.Context(), confirmationKey{}, probe), id)
				if scenario == "missing" {
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("missing ID result=%v, want ErrNotFound", err)
					}
				} else if err != nil {
					t.Fatalf("revoke result=%v", err)
				}
				if scenario == "already-revoked" {
					result, err := store.db.Query(t.Context(), rhiza.QueryRequest{
						SQL:         "SELECT revoked_at_unix_ms FROM browser_sessions WHERE token_digest=?",
						Args:        []any{id},
						Consistency: rhiza.ConsistencyLinearizable,
					})
					if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
						t.Fatalf("revocation readback=%+v err=%v", result, err)
					}
					got, ok := result.Rows[0][0].(int64)
					if !ok || got != originalRevokedAt {
						t.Fatalf("repeat revoke changed original timestamp: got=%v want=%d", result.Rows[0][0], originalRevokedAt)
					}
				}
			}

			wantQueries, wantMutations := iterations, iterations
			if scenario == "missing" {
				wantMutations = 0
			}
			if probe.queries != wantQueries || probe.executes != wantMutations {
				t.Fatalf("actual submissions: queries=%d mutations=%d, want %d/%d", probe.queries, probe.executes, wantQueries, wantMutations)
			}
			if len(requestIDs) != wantMutations {
				t.Fatalf("captured mutation request IDs=%d, want %d", len(requestIDs), wantMutations)
			}
			seen := make(map[string]struct{}, len(requestIDs))
			for _, requestID := range requestIDs {
				if _, duplicate := seen[requestID]; duplicate {
					t.Fatal("mutation RequestID repeated; measurement could be deduplicated")
				}
				seen[requestID] = struct{}{}
			}
			t.Logf("scenario=%s iterations=%d query_submissions=%d mutation_submissions=%d unique_mutation_request_ids=%d", scenario, iterations, probe.queries, probe.executes, len(seen))
		})
	}
}
