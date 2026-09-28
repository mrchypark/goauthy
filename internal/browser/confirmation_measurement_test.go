//go:build confirmationproof

package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Run one scenario per fresh process/database. Setup and injected competing
// touches are excluded from latency but remain in whole-process coverage counts.
func TestConfirmationMeasurement(t *testing.T) {
	scenario := os.Getenv("GOAUTHY_CONFIRMATION_MEASURE")
	if scenario == "" {
		t.Skip("opt-in paired creator measurement")
	}
	if scenario != "fresh" && scenario != "due" && scenario != "replay" && scenario != "loser" && scenario != "rejected" {
		t.Fatal("invalid scenario")
	}
	s, session, now := confirmationFixture(t)
	s.now = func() time.Time { return now }
	type sample struct {
		MS                          float64
		Queries, Executes           int
		Error                       string
		CleanupBefore, CleanupAfter int64
	}
	samples := make([]sample, 0, 40)
	for i := 0; i < 40; i++ {
		last := now
		if scenario != "fresh" && scenario != "rejected" {
			last = now.Add(-touchInterval - time.Millisecond)
		}
		_, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("setup-%d", i), Statements: []rhiza.SQLStatement{
			{SQL: "UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?", Args: []any{last.UnixMilli(), session.ID}},
			{SQL: "DELETE FROM browser_authorization_interactions"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		p := &confirmationProbe{}
		var injection time.Duration
		if scenario == "rejected" {
			_, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("reject-setup-%d", i), Statements: []rhiza.SQLStatement{
				{SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=NULL WHERE token_digest=?", Args: []any{session.ID}},
				{SQL: "INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES('expired','expired',?,'eA',?,?)", Args: []any{session.ID, now.Add(-time.Hour).UnixMilli(), now.UnixMilli()}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			p.before = func(rhiza.ExecuteRequest) {
				begin := time.Now()
				if _, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("revoke-%d", i), SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE token_digest=?", Args: []any{session.ID}}); err != nil {
					t.Fatal(err)
				}
				injection += time.Since(begin)
			}
		}
		if scenario == "replay" || scenario == "loser" {
			p.touch = func(request rhiza.ExecuteRequest) {
				begin := time.Now()
				competing := request
				if scenario == "loser" {
					competing.RequestID = fmt.Sprintf("competing-%d", i)
					competing.Args = append([]any(nil), request.Args...)
					competing.Args[0] = now.Add(time.Millisecond).UnixMilli()
				}
				result, err := storage.Execute(t.Context(), s.db, competing)
				if err != nil || result.RowsAffected != 1 {
					t.Fatalf("competing touch=%+v %v", result, err)
				}
				injection += time.Since(begin)
			}
		}
		begin := time.Now()
		_, err = s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, fmt.Sprintf("measure-%d", i), []byte("payload"), now.Add(time.Minute))
		elapsed := time.Since(begin) - injection
		row := sample{MS: float64(elapsed) / float64(time.Millisecond), Queries: p.queries, Executes: p.executes}
		if err != nil {
			row.Error = err.Error()
		}
		if scenario == "rejected" {
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected absence: %v", err)
			}
			row.Error = "not_found"
			row.CleanupBefore, row.CleanupAfter = 1, confirmationCount(t, s)
			want := int64(1)
			if os.Getenv("CONFIRMATION_BASELINE") == "1" {
				want = 0
			}
			if row.CleanupAfter != want {
				t.Fatalf("cleanup after rejection=%d want=%d", row.CleanupAfter, want)
			}
			err = nil // Expected rejection is recorded above, not a measurement failure.
		}
		wantQ := 1
		if os.Getenv("CONFIRMATION_BASELINE") == "1" {
			wantQ++
		}
		if scenario == "loser" {
			wantQ++
		}
		wantE := 1
		if scenario != "fresh" && scenario != "rejected" {
			wantE++
		}
		if err != nil || p.queries != wantQ || p.executes != wantE {
			t.Fatalf("counts/result scenario=%s sample=%+v", scenario, row)
		}
		samples = append(samples, row)
		now = now.Add(time.Second) // Distinct touch request IDs across samples.
	}
	values := make([]float64, len(samples))
	for i, s := range samples {
		values[i] = s.MS
	}
	sort.Float64s(values)
	data, _ := json.Marshal(map[string]any{"scenario": scenario, "baseline": os.Getenv("CONFIRMATION_BASELINE") == "1", "n": len(samples), "concurrency": 1, "p50_ms": values[19], "p95_ms": values[37], "p99_ms": values[39], "samples": samples})
	fmt.Printf("CONFIRMATION_MEASUREMENT %s\n", data)
}
