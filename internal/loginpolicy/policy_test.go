package loginpolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestFailureScheduleBlockAndSuccessReset(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	for attempt := int64(1); attempt <= 6; attempt++ {
		status, err := store.Failure(context.Background(), "192.0.2.10", now)
		if err != nil || status.Failures != attempt || !status.BlockedUntil.IsZero() {
			t.Fatalf("attempt=%d status=%+v err=%v", attempt, status, err)
		}
	}
	blocked, err := store.Failure(context.Background(), "192.0.2.10", now)
	if err != nil || !blocked.BlockedUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("blocked=%+v err=%v", blocked, err)
	}
	if delay := Delay(Status{Failures: 5, Mean: time.Second}, 250*time.Millisecond); delay != 15*time.Second+750*time.Millisecond {
		t.Fatalf("delay=%v", delay)
	}
	if err := store.Success(context.Background(), "192.0.2.10", 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	status, err := store.Check(context.Background(), "192.0.2.10", now)
	if err != nil || status.Failures != 7 || !status.BlockedUntil.Equal(now.Add(time.Minute)) || status.Mean != 500*time.Millisecond {
		t.Fatalf("success altered failure state status=%+v err=%v", status, err)
	}
	stale, err := store.Check(context.Background(), "192.0.2.10", now.Add(failureIdleTTL))
	if err != nil || stale.Failures != 0 || !stale.BlockedUntil.IsZero() {
		t.Fatalf("stale=%+v err=%v", stale, err)
	}
	reset, err := store.Failure(context.Background(), "192.0.2.10", now.Add(failureIdleTTL))
	if err != nil || reset.Failures != 1 {
		t.Fatalf("ttl reset=%+v err=%v", reset, err)
	}
}

func TestAttemptAdmissionIsDistributedAndCapped(t *testing.T) {
	db := testDB(t)
	first, second := NewStore(db), NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	start := make(chan struct{})
	results := make(chan bool, DefaultAttemptLimit+5)
	var wg sync.WaitGroup
	for attempt := 0; attempt < DefaultAttemptLimit+5; attempt++ {
		store := first
		if attempt%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, err := store.Allow(context.Background(), "192.0.2.44", now)
			if err != nil {
				t.Errorf("allow: %v", err)
				return
			}
			results <- allowed
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for allowed := range results {
		if allowed {
			accepted++
		}
	}
	if accepted != DefaultAttemptLimit {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestPasswordResetAdmissionHasIndependentFiveAttemptWindow(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	for attempt := 1; attempt <= PasswordResetAttemptLimit; attempt++ {
		allowed, err := store.AllowPasswordReset(context.Background(), "192.0.2.50", now)
		if err != nil || !allowed {
			t.Fatalf("attempt=%d allowed=%t err=%v", attempt, allowed, err)
		}
	}
	if allowed, err := store.AllowPasswordReset(context.Background(), "192.0.2.50", now); err != nil || allowed {
		t.Fatalf("sixth attempt allowed=%t err=%v", allowed, err)
	}
	if allowed, err := store.Allow(context.Background(), "192.0.2.50", now); err != nil || !allowed {
		t.Fatalf("login quota was not independent: allowed=%t err=%v", allowed, err)
	}
	if allowed, err := store.AllowPasswordReset(context.Background(), "192.0.2.50", now.Add(PasswordResetAttemptWindow)); err != nil || !allowed {
		t.Fatalf("next window allowed=%t err=%v", allowed, err)
	}
}

func TestOpenRegistrationAdmissionIsIndependentAndDeterministic(t *testing.T) {
	store := NewStore(testDB(t))
	now := time.UnixMilli(1_700_000_000_000).UTC()
	for attempt := 1; attempt <= OpenRegistrationAttemptLimit; attempt++ {
		allowed, err := store.AllowOpenRegistration(context.Background(), "192.0.2.60", now)
		if err != nil || !allowed {
			t.Fatalf("attempt=%d allowed=%t err=%v", attempt, allowed, err)
		}
	}
	if allowed, err := store.AllowOpenRegistration(context.Background(), "192.0.2.60", now); err != nil || allowed {
		t.Fatalf("excess registration allowed=%t err=%v", allowed, err)
	}
	if allowed, err := store.AllowPasswordReset(context.Background(), "192.0.2.60", now); err != nil || !allowed {
		t.Fatalf("registration consumed reset quota: allowed=%t err=%v", allowed, err)
	}
	if allowed, err := store.AllowOpenRegistration(context.Background(), "192.0.2.60", now.Add(OpenRegistrationAttemptWindow)); err != nil || !allowed {
		t.Fatalf("next window allowed=%t err=%v", allowed, err)
	}
	for _, ip := range []string{"", "forged", "192.0.2.1:443", "2001:0db8::1"} {
		if allowed, err := store.AllowOpenRegistration(context.Background(), ip, now); err != ErrInvalid || allowed {
			t.Fatalf("ip=%q allowed=%t err=%v", ip, allowed, err)
		}
	}
}

func TestPasswordResetAdmissionRequiresCanonicalIP(t *testing.T) {
	store := NewStore(testDB(t))
	now := time.UnixMilli(1_700_000_000_000).UTC()
	for _, ip := range []string{"", "forged", "192.0.2.1:443", "2001:0db8::1", "2001:db8::1%eth0"} {
		if allowed, err := store.AllowPasswordReset(context.Background(), ip, now); err != ErrInvalid || allowed {
			t.Fatalf("ip=%q allowed=%t err=%v", ip, allowed, err)
		}
	}
}

func TestRateLimitExpiryIsSetAndTriggerDeletesExpired(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	allowed, err := store.Allow(context.Background(), "192.0.2.10", now)
	if err != nil || !allowed {
		t.Fatalf("first allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT expires_at_unix_ms,last_window_at_unix_ms FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("attempt/" + "192.0.2.10")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("rate limit row=%#v err=%v", result.Rows, err)
	}
	expiresAt, _ := result.Rows[0][0].(int64)
	lastWindow, _ := result.Rows[0][1].(int64)
	windowStart := now.UnixMilli() / DefaultAttemptWindow.Milliseconds() * DefaultAttemptWindow.Milliseconds()
	if expiresAt != windowStart+DefaultAttemptWindow.Milliseconds()*2 {
		t.Fatalf("expires_at=%d want=%d", expiresAt, windowStart+DefaultAttemptWindow.Milliseconds()*2)
	}
	if lastWindow != now.UnixMilli() {
		t.Fatalf("last_window_at=%d want=%d", lastWindow, now.UnixMilli())
	}

	// Insert an expired peer row (expires_at < now, but still > last_window_at).
	expiredDigest := digest("attempt/192.0.2.99")
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-expired-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{expiredDigest, int64(100), int64(200), int64(50)},
	}); err != nil {
		t.Fatal(err)
	}

	// Trigger fires on next Allow; expired row (expires_at=200 <= now) is deleted.
	allowed, err = store.Allow(context.Background(), "192.0.2.10", now.Add(time.Second))
	if err != nil || !allowed {
		t.Fatalf("second allow: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{expiredDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("expired row not cleaned: rows=%#v err=%v", result.Rows, err)
	}

	// Current row preserved.
	result, err = db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT count FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("attempt/" + "192.0.2.10")},
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
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	// Insert 70 expired rows. Each satisfies expires_at > last_window_at.
	for i := range 70 {
		key := digest("attempt/10.0.0." + strconv.Itoa(i))
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: "test-insert-" + strconv.Itoa(i),
			SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
			Args:      []any{key, int64(100), int64(200), int64(50)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// First Allow triggers cleanup; at most 64 deleted.
	allowed, err := store.Allow(context.Background(), "192.0.2.10", now)
	if err != nil || !allowed {
		t.Fatalf("first allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ? AND key_digest != ?`,
		Args:        []any{now.UnixMilli(), digest("attempt/" + "192.0.2.10")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("remaining count: rows=%#v err=%v", result.Rows, err)
	}
	remaining, _ := result.Rows[0][0].(int64)
	if remaining != 6 {
		t.Fatalf("remaining expired rows=%d want=6 (70-64=6)", remaining)
	}

	// Second Allow cleans the remaining 6.
	allowed, err = store.Allow(context.Background(), "192.0.2.10", now.Add(time.Second))
	if err != nil || !allowed {
		t.Fatalf("second allow: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ?`,
		Args:        []any{now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("all expired gone: rows=%#v err=%v", result.Rows, err)
	}
}

func TestTriggerCleanupExpiryEquality(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	// Boundary row: expires_at == now (deleted by <=). expires > last_window.
	boundaryDigest := digest("attempt/192.0.2.88")
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-boundary-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{boundaryDigest, int64(100), now.UnixMilli(), now.UnixMilli() - 1},
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := store.Allow(context.Background(), "192.0.2.10", now)
	if err != nil || !allowed {
		t.Fatalf("allow: allowed=%t err=%v", allowed, err)
	}

	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{boundaryDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("boundary not cleaned: rows=%#v err=%v", result.Rows, err)
	}

	// Alive row: expires_at == now+1 (should survive). expires > last_window.
	aliveDigest := digest("attempt/192.0.2.77")
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "test-alive-insert",
		SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
		Args:      []any{aliveDigest, int64(100), now.UnixMilli() + 1, now.UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err = store.Allow(context.Background(), "192.0.2.10", now)
	if err != nil || !allowed {
		t.Fatalf("allow2: allowed=%t err=%v", allowed, err)
	}

	result, err = db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{aliveDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("alive row deleted: rows=%#v err=%v", result.Rows, err)
	}
}

func TestRateLimitCrossDomainIsolation(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	for range DefaultAttemptLimit {
		allowed, err := store.Allow(context.Background(), "192.0.2.30", now)
		if err != nil || !allowed {
			t.Fatalf("login allow failed: allowed=%t err=%v", allowed, err)
		}
	}

	allowed, err := store.Allow(context.Background(), "192.0.2.30", now)
	if err != nil || allowed {
		t.Fatalf("login denied: allowed=%t err=%v", allowed, err)
	}

	allowed, err = store.AllowPasswordReset(context.Background(), "192.0.2.30", now)
	if err != nil || !allowed {
		t.Fatalf("password reset denied: allowed=%t err=%v", allowed, err)
	}

	allowed, err = store.AllowOpenRegistration(context.Background(), "192.0.2.30", now)
	if err != nil || !allowed {
		t.Fatalf("open registration denied: allowed=%t err=%v", allowed, err)
	}
}

func TestRateLimitConcurrentCleanupAndAdmission(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	const totalExpired = DefaultAttemptLimit + 2
	type result struct {
		allowed bool
		err     error
	}

	// Insert expired seed rows.
	for i := range totalExpired {
		key := digest("attempt/192.0.2.4" + strconv.Itoa(i))
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: "test-concurrent-expired-" + strconv.Itoa(i),
			SQL:       `INSERT INTO oauth_rate_limits (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) VALUES (?, ?, 1, ?, ?)`,
			Args:      []any{key, int64(100), int64(200), int64(50)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	ready := make(chan struct{}, totalExpired)
	start := make(chan struct{})
	results := make(chan result, totalExpired)
	var wg sync.WaitGroup
	for range totalExpired {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			a, err := store.Allow(context.Background(), "192.0.2.40", now)
			results <- result{a, err}
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
	if accepted != DefaultAttemptLimit {
		t.Fatalf("accepted=%d want=%d", accepted, DefaultAttemptLimit)
	}

	// All expired rows cleaned up.
	qr, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT COUNT(*) FROM oauth_rate_limits WHERE expires_at_unix_ms <= ?`,
		Args:        []any{now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(qr.Rows) != 1 || qr.Rows[0][0] != int64(0) {
		t.Fatalf("expired rows after concurrency: rows=%#v err=%v", qr.Rows, err)
	}
}

func TestRateLimitRestartPersistence(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	for range 3 {
		allowed, err := store.Allow(context.Background(), "192.0.2.50", now)
		if err != nil || !allowed {
			t.Fatalf("allow failed: allowed=%t err=%v", allowed, err)
		}
	}

	store2 := NewStore(db)

	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL:         `SELECT count FROM oauth_rate_limits WHERE key_digest = ?`,
		Args:        []any{digest("attempt/" + "192.0.2.50")},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("persisted row=%#v err=%v", result.Rows, err)
	}
	count, _ := result.Rows[0][0].(int64)
	if count != 3 {
		t.Fatalf("persisted count=%d want=3", count)
	}

	allowed, err := store2.Allow(context.Background(), "192.0.2.50", now)
	if err != nil || !allowed {
		t.Fatalf("restart allow: allowed=%t err=%v", allowed, err)
	}
}

func TestPasswordResetAdmissionIsDistributedAndCapped(t *testing.T) {
	db := testDB(t)
	first, second := NewStore(db), NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	start := make(chan struct{})
	results := make(chan bool, PasswordResetAttemptLimit+5)
	var wg sync.WaitGroup
	for attempt := 0; attempt < PasswordResetAttemptLimit+5; attempt++ {
		store := first
		if attempt%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, err := store.AllowPasswordReset(context.Background(), "192.0.2.51", now)
			if err != nil {
				t.Errorf("allow password reset: %v", err)
				return
			}
			results <- allowed
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for allowed := range results {
		if allowed {
			accepted++
		}
	}
	if accepted != PasswordResetAttemptLimit {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestFailuresAreDistributedAndIPHeadersAreNotInputs(t *testing.T) {
	db := testDB(t)
	first, second := NewStore(db), NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			if _, err := store.Failure(context.Background(), "2001:db8::1", now); err != nil {
				errs <- err
			}
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("failure: %v", err)
	}
	status, err := first.Check(context.Background(), "2001:db8::1", now)
	if err != nil || status.Failures != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	for _, raw := range []string{"192.0.2.1:1234", "2001:db8::1", "forged"} {
		_, ok := PeerIP(raw)
		if raw == "forged" && ok {
			t.Fatal("invalid peer accepted")
		}
	}
}

func TestPeerIPFromRequestTrustedProxyPolicy(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}
	for _, test := range []struct {
		name       string
		remoteAddr string
		headers    http.Header
		want       string
		ok         bool
	}{
		{name: "direct peer by default", remoteAddr: "198.51.100.1:4567", headers: http.Header{"Forwarded": {"for=203.0.113.8"}}, want: "198.51.100.1", ok: true},
		{name: "trusted forwarded", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8;proto=https"}}, want: "203.0.113.8", ok: true},
		{name: "forwarded and xff conflict fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8"}, "X-Forwarded-For": {"198.51.100.9"}}},
		{name: "empty forwarded and populated xff fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {""}, "X-Forwarded-For": {"198.51.100.9"}}},
		{name: "populated forwarded and empty xff fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8"}, "X-Forwarded-For": {""}}},
		{name: "quoted ipv6 forwarded", remoteAddr: "[2001:db8:1::2]:443", headers: http.Header{"Forwarded": {`for="[2001:0db8::8]:8443"`}}, want: "2001:db8::8", ok: true},
		{name: "xff first untrusted from peer", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"203.0.113.8, 192.0.2.9"}}, want: "203.0.113.8", ok: true},
		{name: "xff attacker-leftmost ignored", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"198.51.100.77, 203.0.113.8"}}, want: "203.0.113.8", ok: true},
		{name: "xff trusted intermediates skipped", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"198.51.100.77, 192.0.2.9, 203.0.113.8"}}, want: "203.0.113.8", ok: true},
		{name: "untrusted spoof ignored", remoteAddr: "198.51.100.1:4567", headers: http.Header{"Forwarded": {"for=203.0.113.8"}, "X-Forwarded-For": {"198.51.100.9"}}, want: "198.51.100.1", ok: true},
		{name: "trusted no header retains peer", remoteAddr: "192.0.2.2:443", want: "192.0.2.2", ok: true},
		{name: "repeated forwarded fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8", "for=198.51.100.9"}}},
		{name: "ambiguous forwarded element fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8, for=198.51.100.9"}}},
		{name: "repeated for fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=203.0.113.8;for=198.51.100.9"}}},
		{name: "malformed forwarded fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"Forwarded": {"for=unknown"}}},
		{name: "repeated xff fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"203.0.113.8", "198.51.100.9"}}},
		{name: "malformed xff fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"unknown"}}},
		{name: "malformed xff chain fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"203.0.113.8, unknown"}}},
		{name: "xff all trusted fails closed", remoteAddr: "192.0.2.2:443", headers: http.Header{"X-Forwarded-For": {"192.0.2.9"}}},
		{name: "invalid direct peer", remoteAddr: "proxy.example:443", headers: http.Header{"Forwarded": {"for=203.0.113.8"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://goauthy.test/", nil)
			req.RemoteAddr, req.Header = test.remoteAddr, test.headers
			got, ok := PeerIPFromRequest(req.RemoteAddr, req.Header, trusted)
			if got != test.want || ok != test.ok {
				t.Fatalf("PeerIPFromRequest() = %q, %t; want %q, %t", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	prefixes, err := ParseTrustedProxyCIDRs([]string{"192.0.2.23/24", "2001:db8::1/64"})
	if err != nil || len(prefixes) != 2 || prefixes[0].String() != "192.0.2.0/24" || prefixes[1].String() != "2001:db8::/64" {
		t.Fatalf("prefixes=%v err=%v", prefixes, err)
	}
	if prefixes, err := ParseTrustedProxyCIDRs([]string{"invalid"}); err != ErrInvalid || prefixes != nil {
		t.Fatalf("invalid prefixes=%v err=%v", prefixes, err)
	}
}

func testDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "login-policy-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
