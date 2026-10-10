//go:build confirmationproof

package browser

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	touchContentionReaders = 16
	touchContentionRounds  = 64
	touchContentionSamples = touchContentionReaders * touchContentionRounds
)

type touchCostTotals struct {
	reads, submits, applied, zeroRows, rereads int
}

func (totals *touchCostTotals) add(probe *SessionCostProbe) {
	totals.reads += probe.sessionReads
	totals.submits += probe.touchSubmits
	totals.applied += probe.touchApplied
	totals.zeroRows += probe.touchZeroRows
	totals.rereads += probe.touchRereads
}

func setSessionLastSeen(t *testing.T, store *Store, token string, at time.Time, requestID string) {
	t.Helper()
	digest, err := tokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL:       `UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?`,
		Args:      []any{at.UnixMilli(), digest},
	}); err != nil {
		t.Fatal(err)
	}
}

func seedTouchDue(t *testing.T, store *Store, tokens []string, round int, label string, at time.Time) {
	t.Helper()
	for i, token := range tokens {
		setSessionLastSeen(t, store, token, at, fmt.Sprintf("touch-cost-seed-%s-%d-%d", label, round, i))
	}
}

type touchCostResult struct {
	latency time.Duration
	err     error
	probe   *SessionCostProbe
}

func loadSessionBurst(store *Store, tokens []string, readers int, peer string) []touchCostResult {
	results := make([]touchCostResult, readers)
	if readers == 1 {
		probe := &SessionCostProbe{}
		started := time.Now()
		_, err := store.LoadSessionForPeer(WithSessionCostProbe(context.Background(), probe), tokens[0], peer)
		results[0] = touchCostResult{latency: time.Since(started), err: err, probe: probe}
		return results
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(readers)
	for i := range readers {
		go func(i int) {
			defer wait.Done()
			probe := &SessionCostProbe{}
			ctx := WithSessionCostProbe(context.Background(), probe)
			<-start
			started := time.Now()
			_, err := store.LoadSessionForPeer(ctx, tokens[i], peer)
			results[i] = touchCostResult{latency: time.Since(started), err: err, probe: probe}
		}(i)
	}
	close(start)
	wait.Wait()
	return results
}

func percentile(samples []time.Duration, p float64) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := int(float64(len(ordered))*p+0.999999) - 1 // nearest rank
	if index < 0 {
		index = 0
	}
	return ordered[index]
}

func reportTouchCost(t *testing.T, scenario string, readers int, results []touchCostResult) touchCostTotals {
	t.Helper()
	latencies := make([]time.Duration, 0, len(results))
	var totals touchCostTotals
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("scenario=%s readers=%d load session: %v", scenario, readers, result.err)
		}
		latencies = append(latencies, result.latency)
		totals.add(result.probe)
	}
	t.Logf("scenario=%s concurrency=%d samples=%d reads=%d touch_submits=%d touch_applied=%d touch_zero_rows=%d touch_rereads=%d p50=%s p95=%s p99=%s",
		scenario, readers, len(latencies), totals.reads, totals.submits, totals.applied, totals.zeroRows, totals.rereads,
		percentile(latencies, .50), percentile(latencies, .95), percentile(latencies, .99))
	return totals
}

func TestConcurrentSessionTouchCostDistribution(t *testing.T) {
	store := testStore(t)
	base := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return base }
	issued := make([]IssuedSession, touchContentionReaders)
	tokens := make([]string, touchContentionReaders)
	for i := range issued {
		session, err := store.CreateSession(context.Background(), "user-1", "pwd", base.Add(48*time.Hour), "203.0.113.8")
		if err != nil {
			t.Fatal(err)
		}
		issued[i] = session
		tokens[i] = session.Token
	}
	var tick atomic.Int64
	store.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Millisecond) }

	for _, readers := range []int{1, touchContentionReaders} {
		n := touchContentionSamples
		if readers == 1 {
			n = touchContentionSamples
		}
		stable := make([]touchCostResult, 0, n)
		independentDue := make([]touchCostResult, 0, n)
		sameSessionDue := make([]touchCostResult, 0, n)
		for round := 0; round < n/readers; round++ {
			if readers == 1 {
				stable = append(stable, loadSessionBurst(store, tokens[:1], 1, "203.0.113.8")...)
			} else {
				stable = append(stable, loadSessionBurst(store, tokens[:readers], readers, "203.0.113.8")...)
			}

			cohort := tokens[:readers]
			if readers == 1 {
				cohort = tokens[round%len(tokens) : round%len(tokens)+1]
			}
			seedTouchDue(t, store, cohort, round, fmt.Sprintf("independent-%d", readers), base.Add(-time.Hour))
			independentDue = append(independentDue, loadSessionBurst(store, cohort, readers, "203.0.113.8")...)

			seedTouchDue(t, store, tokens[:1], round, fmt.Sprintf("same-%d", readers), base.Add(-time.Hour))
			shared := make([]string, readers)
			for i := range shared {
				shared[i] = tokens[0]
			}
			sameSessionDue = append(sameSessionDue, loadSessionBurst(store, shared, readers, "203.0.113.8")...)
		}

		stableTotals := reportTouchCost(t, "fresh-session", readers, stable)
		if stableTotals.reads != n || stableTotals.submits != 0 || stableTotals.rereads != 0 {
			t.Fatalf("fresh-session counters=%+v want reads=%d and no touch", stableTotals, n)
		}
		independentTotals := reportTouchCost(t, "distinct-due-sessions", readers, independentDue)
		if independentTotals.reads != n || independentTotals.submits != n || independentTotals.applied != n || independentTotals.zeroRows != 0 || independentTotals.rereads != 0 {
			t.Fatalf("distinct-due counters=%+v want one applied touch per request (%d)", independentTotals, n)
		}
		sameTotals := reportTouchCost(t, "same-session-due", readers, sameSessionDue)
		if sameTotals.reads != n+sameTotals.rereads || sameTotals.submits != sameTotals.applied+sameTotals.zeroRows || sameTotals.rereads != sameTotals.zeroRows {
			t.Fatalf("same-session counters=%+v violate read/touch accounting for %d requests", sameTotals, n)
		}
	}
}

func TestConcurrentSessionTouchAuthorityControls(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*testing.T, *Store, string, time.Time)
		wantError error
	}{
		{name: "unchanged_session"},
		{
			name: "revoked_after_read",
			mutate: func(t *testing.T, store *Store, token string, now time.Time) {
				digest, err := tokenDigest(token)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
					RequestID: "touch-authority-revoke-after-read",
					SQL:       `UPDATE browser_sessions SET revoked_at_unix_ms=? WHERE token_digest=?`,
					Args:      []any{now.UnixMilli(), digest},
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantError: ErrRevoked,
		},
		{
			name: "peer_changed_after_read",
			mutate: func(t *testing.T, store *Store, token string, _ time.Time) {
				digest, err := tokenDigest(token)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
					RequestID: "touch-authority-peer-after-read",
					SQL:       `UPDATE browser_sessions SET peer_ip=? WHERE token_digest=?`,
					Args:      []any{"198.51.100.9", digest},
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantError: ErrPeerIPMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testStore(t)
			base := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
			store.now = func() time.Time { return base }
			session, err := store.CreateSession(context.Background(), "user-1", "pwd", base.Add(time.Hour), "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			setSessionLastSeen(t, store, session.Token, base.Add(-time.Hour), "touch-authority-seed")
			var tick atomic.Int64
			store.now = func() time.Time { return base.Add(touchInterval + time.Duration(tick.Add(1))*time.Millisecond) }

			const readers = touchContentionReaders
			ready := sync.WaitGroup{}
			ready.Add(readers)
			release := make(chan struct{})
			results := make([]error, readers)
			probes := make([]*SessionCostProbe, readers)
			var wait sync.WaitGroup
			wait.Add(readers)
			for i := range readers {
				go func(i int) {
					defer wait.Done()
					probe := &SessionCostProbe{}
					probe.AfterNextSessionRead(func() {
						ready.Done()
						<-release
					})
					probes[i] = probe
					_, results[i] = store.LoadSessionForPeer(WithSessionCostProbe(context.Background(), probe), session.Token, "203.0.113.8")
				}(i)
			}
			ready.Wait()
			if test.mutate != nil {
				test.mutate(t, store, session.Token, base.Add(touchInterval+time.Duration(readers)*time.Millisecond))
			}
			close(release)
			wait.Wait()

			var totals touchCostTotals
			for i, err := range results {
				if test.wantError == nil && err != nil {
					t.Errorf("request %d err=%v want success", i, err)
				} else if test.wantError != nil && !errors.Is(err, test.wantError) {
					t.Errorf("request %d err=%v want %v", i, err, test.wantError)
				}
				totals.add(probes[i])
			}
			if test.wantError == nil {
				if totals.reads != 2*readers-1 || totals.submits != readers || totals.applied != 1 || totals.zeroRows != readers-1 || totals.rereads != readers-1 {
					t.Fatalf("unchanged authority counters=%+v want reads=%d submits=%d applied=1 zero/rereads=%d", totals, 2*readers-1, readers, readers-1)
				}
			} else if totals.reads != 2*readers || totals.submits != readers || totals.applied != 0 || totals.zeroRows != readers || totals.rereads != readers {
				t.Fatalf("rejected authority counters=%+v want reads=%d submits=%d zero/rereads=%d", totals, 2*readers, readers, readers)
			}
		})
	}
}
