package device

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeviceGrantLifecycleAndSlowDown(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	grant, err := store.Create(ctx, "client", []string{"goauthy.read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if NormalizeUserCode(" "+grant.UserCode+" ") != NormalizeUserCode(grant.UserCode) {
		t.Fatal("user code normalization failed")
	}
	result, err := store.Poll(ctx, grant.DeviceCode, "client", now)
	if err != nil || result.Status != StatusPending {
		t.Fatalf("pending=%#v err=%v", result, err)
	}
	result, err = store.Poll(ctx, grant.DeviceCode, "client", now.Add(time.Second))
	if err != nil || result.Status != StatusSlowDown {
		t.Fatalf("slow=%#v err=%v", result, err)
	}
	if err := store.Approve(ctx, stringsLower(grant.UserCode), "subject", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err = store.Poll(ctx, grant.DeviceCode, "client", now.Add(7*time.Second))
	if err != nil || result.Status != StatusClaimed || result.ClaimToken == "" || result.Subject != "subject" {
		t.Fatalf("claim=%#v err=%v", result, err)
	}
	if err := store.Complete(ctx, result.ClaimToken, false, now.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err = store.Poll(ctx, grant.DeviceCode, "client", now.Add(9*time.Second))
	if err != nil || result.Status != StatusClaimed {
		t.Fatalf("reclaim=%#v err=%v", result, err)
	}
	if err := store.Complete(ctx, result.ClaimToken, true, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err = store.Poll(ctx, grant.DeviceCode, "client", now.Add(11*time.Second))
	if err != nil || result.Status != StatusExpired {
		t.Fatalf("consumed=%#v err=%v", result, err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT device_code_digest,user_code_digest FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("rows=%#v err=%v", rows.Rows, err)
	}
	if rows.Rows[0][0] == grant.DeviceCode || rows.Rows[0][1] == grant.UserCode {
		t.Fatal("raw device code stored")
	}
}

func TestDeviceGrantDeniedAndExpired(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	grant, err := store.Create(ctx, "client", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(ctx, grant.UserCode, now); err != nil {
		t.Fatal(err)
	}
	got, err := store.Poll(ctx, grant.DeviceCode, "client", now)
	if err != nil || got.Status != StatusDenied {
		t.Fatalf("denied=%#v err=%v", got, err)
	}
	got, err = store.Poll(ctx, "missing", "client", now)
	if err != nil || got.Status != StatusExpired {
		t.Fatalf("missing=%#v err=%v", got, err)
	}
}

func TestDeviceDecisionsRejectAlreadyDecidedAndUnknown(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if err := store.Approve(ctx, "missing", "subject", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown approve error=%v", err)
	}
	grant, err := store.Create(ctx, "client", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(ctx, grant.UserCode, "subject", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(ctx, grant.UserCode, "subject", now.Add(time.Millisecond)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second approve error=%v", err)
	}
	if err := store.Deny(ctx, grant.UserCode, now.Add(2*time.Millisecond)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conflicting decision error=%v", err)
	}
}

func TestConcurrentPollDoesNotOverwriteSchedule(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	grant, err := store.Create(ctx, "client", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan PollResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := NewStore(db).Poll(ctx, grant.DeviceCode, "client", now)
			results <- result
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.Status != StatusPending && result.Status != StatusSlowDown {
			t.Fatalf("status=%q", result.Status)
		}
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT interval_seconds,next_poll_at_unix_ms FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("schedule=%#v err=%v", row.Rows, err)
	}
	interval, intervalOK := row.Rows[0][0].(int64)
	next, nextOK := row.Rows[0][1].(int64)
	// Both callers may read the initial row, or the second may observe the
	// first update and apply RFC 8628 slow_down. Either schedule is coherent.
	if !intervalOK || !nextOK || interval != 5 && interval != 10 || next != now.Add(time.Duration(interval)*time.Second).UnixMilli() {
		t.Fatalf("incoherent schedule=%#v", row.Rows)
	}
}

func TestAllowIsDistributedAndDoesNotStoreRawKey(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3
	start := make(chan struct{})
	allowed := make(chan bool, 10)
	errs := make(chan error, 10)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := NewStore(db).Allow(ctx, "127.0.0.1:1234/client", now, time.Minute, limit)
			allowed <- ok
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(allowed)
	close(errs)
	count := 0
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for ok := range allowed {
		if ok {
			count++
		}
	}
	if count != limit {
		t.Fatalf("allowed=%d want=%d", count, limit)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT key_digest,count FROM oauth_rate_limits`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] == "127.0.0.1:1234/client" || rows.Rows[0][1] != int64(limit) {
		t.Fatalf("rate limit rows=%#v err=%v", rows.Rows, err)
	}
	allowedNext, err := store.Allow(ctx, "127.0.0.1:1234/client", now.Add(time.Minute), time.Minute, limit)
	if err != nil || !allowedNext {
		t.Fatalf("new window allowed=%v err=%v", allowedNext, err)
	}
}

func TestCreateDoesNotMaskInfrastructureFailureAsCollision(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "device-unmigrated", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = NewStore(db).Create(ctx, "client", nil, time.Unix(1_700_000_000, 0).UTC())
	if err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("Create masked infrastructure failure as collision: %v", err)
	}
}

func TestAllowExpiryIsSetAndTriggerDeletesExpired(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	allowed, err := store.Allow(ctx, "127.0.0.1:1234/client", now, time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("first allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT expires_at_unix_ms,last_window_at_unix_ms FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("127.0.0.1:1234/client")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("rate limit row=%#v err=%v", result.Rows, err)
	}
	expiresAt, _ := result.Rows[0][0].(int64)
	lastWindow, _ := result.Rows[0][1].(int64)
	windowStart := now.UnixMilli() / time.Minute.Milliseconds() * time.Minute.Milliseconds()
	if expiresAt != windowStart+time.Minute.Milliseconds()*2 {
		t.Fatalf("expires_at=%d want=%d", expiresAt, windowStart+time.Minute.Milliseconds()*2)
	}
	if lastWindow != now.UnixMilli() {
		t.Fatalf("last_window_at=%d want=%d", lastWindow, now.UnixMilli())
	}

	// Insert an expired peer row to verify trigger cleans it up.
	expiredDigest := digest("127.0.0.1:9999/client")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "test-expired-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{expiredDigest, int64(100), int64(200), int64(50)},
	}); err != nil {
		t.Fatal(err)
	}

	// Trigger fires on next Allow; expired row deleted.
	allowed, err = store.Allow(ctx, "127.0.0.1:1234/client", now.Add(time.Second), time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("second allow: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{expiredDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("expired row not cleaned: rows=%#v err=%v", result.Rows, err)
	}

	// Current row preserved.
	result, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT count FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("127.0.0.1:1234/client")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("current row missing: rows=%#v err=%v", result.Rows, err)
	}
	count, _ := result.Rows[0][0].(int64)
	if count != 2 {
		t.Fatalf("count=%d want=2", count)
	}
}

func TestTriggerCleanupBounded64RowProgress(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	// Insert 70 expired rows.
	for i := range 70 {
		key := digest("10.0.0." + strconv.Itoa(i) + ":1234/client")
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "test-insert-" + strconv.Itoa(i),
			SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
			Args:      []any{key, int64(100), int64(200), int64(50)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	allowed, err := store.Allow(ctx, "127.0.0.1:1234/client", now, time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("first allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ? AND key_digest != ?`,
		Args:        []any{now.UnixMilli(), digest("127.0.0.1:1234/client")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("remaining count: rows=%#v err=%v", result.Rows, err)
	}
	remaining, _ := result.Rows[0][0].(int64)
	if remaining != 6 {
		t.Fatalf("remaining expired rows=%d want=6", remaining)
	}

	allowed, err = store.Allow(ctx, "127.0.0.1:1234/client", now.Add(time.Second), time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("second allow: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ?`,
		Args:        []any{now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("all expired gone: rows=%#v err=%v", result.Rows, err)
	}
}

func TestTriggerCleanupExpiryEquality(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	// Boundary row: expires_at == now (deleted by <=).
	boundaryDigest := digest("127.0.0.1:8888/client")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "test-boundary-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{boundaryDigest, int64(100), now.UnixMilli(), now.UnixMilli() - 1},
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := store.Allow(ctx, "127.0.0.1:1234/client", now, time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{boundaryDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("boundary not cleaned: rows=%#v err=%v", result.Rows, err)
	}

	// Alive row: expires_at == now+1 (survives).
	aliveDigest := digest("127.0.0.1:7777/client")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "test-alive-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{aliveDigest, int64(100), now.UnixMilli() + 1, now.UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err = store.Allow(ctx, "127.0.0.1:1234/client", now, time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("allow2: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{aliveDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("alive row deleted: rows=%#v err=%v", result.Rows, err)
	}
}

func TestAllowActiveRowPreservation(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	allowed, err := store.Allow(ctx, "127.0.0.1:2234/client", now, time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("first allow: allowed=%t err=%v", allowed, err)
	}

	allowed, err = store.Allow(ctx, "127.0.0.1:2234/client", now.Add(time.Second), time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("second allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT count FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("127.0.0.1:2234/client")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("count row=%#v err=%v", result.Rows, err)
	}
	count, _ := result.Rows[0][0].(int64)
	if count != 2 {
		t.Fatalf("count=%d want=2", count)
	}
}

func TestAllowConcurrentCleanupAndAdmission(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	const totalExpired = 5
	type devResult struct {
		allowed bool
		err     error
	}

	for i := range totalExpired {
		key := digest("127.0.0.1:" + strconv.Itoa(3000+i) + "/client")
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "test-concurrent-expired-" + strconv.Itoa(i),
			SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
			Args:      []any{key, int64(100), int64(200), int64(50)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	ready := make(chan struct{}, totalExpired)
	start := make(chan struct{})
	results := make(chan devResult, totalExpired)
	var wg sync.WaitGroup
	for range totalExpired {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			a, err := store.Allow(ctx, "127.0.0.1:3234/client", now, time.Minute, limit)
			results <- devResult{a, err}
		}()
	}

	// Drain all ready tokens then release.
	for range totalExpired {
		<-ready
	}
	close(start)
	wg.Wait()
	close(results)

	accepted, errs := 0, 0
	for r := range results {
		if r.err != nil {
			errs++
		}
		if r.allowed {
			accepted++
		}
	}
	if errs != 0 {
		t.Fatalf("errors=%d want=0", errs)
	}
	if accepted != limit {
		t.Fatalf("accepted=%d want=%d", accepted, limit)
	}

	qr, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ?`,
		Args:        []any{now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(qr.Rows) != 1 || qr.Rows[0][0] != int64(0) {
		t.Fatalf("expired rows after concurrency: rows=%#v err=%v", qr.Rows, err)
	}
}

func TestAllowRestartPersistence(t *testing.T) {
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	const limit = 3

	for range 3 {
		allowed, err := store.Allow(ctx, "127.0.0.1:4234/client", now, time.Minute, limit)
		if err != nil || !allowed {
			t.Fatalf("allow failed: allowed=%t err=%v", allowed, err)
		}
	}

	store2 := NewStore(db)

	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT count FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("127.0.0.1:4234/client")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("persisted row=%#v err=%v", result.Rows, err)
	}
	count, _ := result.Rows[0][0].(int64)
	if count != 3 {
		t.Fatalf("persisted count=%d want=3", count)
	}

	allowed, err := store2.Allow(ctx, "127.0.0.1:4234/client", now.Add(time.Minute), time.Minute, limit)
	if err != nil || !allowed {
		t.Fatalf("restart allow: allowed=%t err=%v", allowed, err)
	}
}

func testStore(t *testing.T) (context.Context, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "device-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return ctx, NewStore(db), db
}
func stringsLower(v string) string {
	b := []byte(v)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
