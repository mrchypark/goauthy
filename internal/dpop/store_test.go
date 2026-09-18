package dpop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNonceIsBoundOneUseAndOpaque(t *testing.T) {
	ctx, first, second, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	nonce, err := first.IssueNonce(ctx, "client-a", "jkt-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.ConsumeNonce(ctx, nonce, "client-a", "jkt-b", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong binding err=%v", err)
	}
	if err := second.ConsumeNonce(ctx, nonce, "client-a", "jkt-a", now); err != nil {
		t.Fatal(err)
	}
	if err := first.ConsumeNonce(ctx, nonce, "client-a", "jkt-a", now); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replay err=%v", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT nonce_digest FROM dpop_nonces`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] == nonce {
		t.Fatalf("nonce rows=%#v err=%v", rows.Rows, err)
	}
}

func TestNonceConcurrentTwoStoresExactlyOne(t *testing.T) {
	ctx, first, second, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	nonce, err := first.IssueNonce(ctx, "client", "jkt", now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			errs <- store.ConsumeNonce(ctx, nonce, "client", "jkt", now)
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, replay := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrReplay) {
			replay++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || replay != 1 {
		t.Fatalf("success=%d replay=%d", success, replay)
	}
}

func TestReplayConcurrentTwoStoresExactlyOneAndTTL(t *testing.T) {
	ctx, first, second, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	expires := now.Add(time.Minute)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			errs <- store.MarkReplay(ctx, "jkt", "jti", now, expires)
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, replay := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrReplay) {
			replay++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || replay != 1 {
		t.Fatalf("success=%d replay=%d", success, replay)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT replay_digest,expires_at_unix_ms FROM dpop_replays`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] == "jkt" || rows.Rows[0][0] == "jti" || rows.Rows[0][1] != expires.UnixMilli() {
		t.Fatalf("replay rows=%#v err=%v", rows.Rows, err)
	}
	if err := first.MarkReplay(ctx, "jkt", "jti", now, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired replay input err=%v", err)
	}
	if err := first.MarkReplay(ctx, "jkt", "jti", expires, expires.Add(time.Minute)); err != nil {
		t.Fatalf("expired replay was not reclaimed: %v", err)
	}
}

func TestExpiredReplayConcurrentTwoStoresExactlyOne(t *testing.T) {
	ctx, first, second, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if err := first.MarkReplay(ctx, "jkt", "jti", now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Second)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			errs <- store.MarkReplay(ctx, "jkt", "jti", later, later.Add(time.Minute))
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, replay := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrReplay) {
			replay++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || replay != 1 {
		t.Fatalf("success=%d replay=%d", success, replay)
	}
}

func TestNonceExpiry(t *testing.T) {
	ctx, store, _, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	nonce, err := store.IssueNonce(ctx, "client", "jkt", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeNonce(ctx, nonce, "client", "jkt", now.Add(DefaultNonceTTL)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry err=%v", err)
	}
}

func TestLifecycleCleanupIsBoundedAndKeepsLiveState(t *testing.T) {
	ctx, store, _, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	expired := now.Add(-time.Millisecond).UnixMilli()
	live := now.Add(time.Hour).UnixMilli()
	statements := make([]rhiza.SQLStatement, 0, 262)
	for i := range 130 {
		statements = append(statements,
			rhiza.SQLStatement{SQL: `INSERT INTO dpop_nonces (nonce_digest,client_id,jkt,expires_at_unix_ms,consumed_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?, NULL, ?)`, Args: []any{fmt.Sprintf("expired-nonce-%03d", i), "client", "jkt", expired, expired}},
			rhiza.SQLStatement{SQL: `INSERT INTO dpop_replays (replay_digest,expires_at_unix_ms,created_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{fmt.Sprintf("expired-replay-%03d", i), expired, "expired-attempt", expired}},
		)
	}
	statements = append(statements,
		rhiza.SQLStatement{SQL: `INSERT INTO dpop_nonces (nonce_digest,client_id,jkt,expires_at_unix_ms,consumed_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?, NULL, ?)`, Args: []any{"live-nonce", "client", "jkt", live, now.UnixMilli()}},
		rhiza.SQLStatement{SQL: `INSERT INTO dpop_replays (replay_digest,expires_at_unix_ms,created_attempt,created_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"live-replay", live, "live-attempt", now.UnixMilli()}},
	)
	for start := 0; start < len(statements); start += 64 {
		end := start + 64
		if end > len(statements) {
			end = len(statements)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("dpop-test-expired-state-%d", start), Statements: statements[start:end]}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.IssueNonce(ctx, "client", "jkt", now); err != nil {
		t.Fatal(err)
	}
	if got := expiredRows(t, ctx, db, "dpop_nonces", now); got != 2 {
		t.Fatalf("nonce expired rows after one bounded cleanup=%d want=2", got)
	}
	if got := expiredRows(t, ctx, db, "dpop_replays", now); got != 2 {
		t.Fatalf("replay expired rows after one bounded cleanup=%d want=2", got)
	}
	if err := store.MarkReplay(ctx, "fresh-jkt", "fresh-jti", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := expiredRows(t, ctx, db, "dpop_nonces", now); got != 0 {
		t.Fatalf("nonce expired rows after second cleanup=%d", got)
	}
	if got := expiredRows(t, ctx, db, "dpop_replays", now); got != 0 {
		t.Fatalf("replay expired rows after second cleanup=%d", got)
	}
	for _, query := range []string{
		`SELECT 1 FROM dpop_nonces WHERE nonce_digest = 'live-nonce'`,
		`SELECT 1 FROM dpop_replays WHERE replay_digest = 'live-replay'`,
	} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: query, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 {
			t.Fatalf("live row query=%q rows=%#v err=%v", query, result.Rows, err)
		}
	}
}

func expiredRows(t *testing.T, ctx context.Context, db *rhiza.DB, table string, now time.Time) int64 {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + table + ` WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("expired rows table=%s result=%#v err=%v", table, result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("expired rows table=%s count=%#v", table, result.Rows[0][0])
	}
	return count
}

func testStore(t *testing.T) (context.Context, *Store, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dpop-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return ctx, NewStore(db), NewStore(db), db
}
