package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestProofOfWorkIssueFormatAndConsume(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = bytes.NewReader(bytes.Repeat([]byte{1}, 28))
	challenge, err := pow.Issue(context.Background(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if want := makeChallenge(10, 1_060, "AQEBAQEBAQEBAQEB", base64Secret(bytes.Repeat([]byte{1}, 32))); challenge != want {
		t.Fatalf("challenge=%q want=%q", challenge, want)
	}
	solved := solveProof(t, challenge)
	if err := pow.VerifyAndConsume(context.Background(), solved); err != nil {
		t.Fatal(err)
	}
	if err := pow.VerifyAndConsume(context.Background(), solved); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestProofOfWorkAcceptsExpiryEqualityAndRejectsMalformed(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = bytes.NewReader(bytes.Repeat([]byte{2}, 28))
	challenge, err := pow.Issue(context.Background(), 10, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	solved := solveProof(t, challenge)
	pow.now = func() time.Time { return now.Add(time.Second) }
	if err := pow.VerifyAndConsume(context.Background(), solved); err != nil {
		t.Fatalf("expiry equality err=%v", err)
	}
	for _, invalid := range []string{"", challenge, "2:10:1001:AQEBAQEBAQEBAQEB:bad:1", solved + ":extra"} {
		if err := pow.VerifyAndConsume(context.Background(), invalid); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("invalid proof %q err=%v", invalid, err)
		}
	}
}

func TestProofOfWorkConcurrentConsumeExactlyOne(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = &counterReader{}
	challenge, err := pow.Issue(context.Background(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	solved := solveProof(t, challenge)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() { <-start; errs <- pow.VerifyAndConsume(context.Background(), solved) }()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-errs; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
}

func TestProofOfWorkIssueRejectsInvalidParametersAndCleansExpired(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	pow.now = func() time.Time { return time.Unix(1_000, 0).UTC() }
	pow.random = &sequenceReader{}
	for _, difficulty := range []uint8{0, 9, 99} {
		if _, err := pow.Issue(context.Background(), difficulty, time.Minute); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("difficulty=%d err=%v", difficulty, err)
		}
	}
	if _, err := pow.Issue(context.Background(), 10, 0); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("ttl err=%v", err)
	}
	if _, err := pow.IssueForPeer(context.Background(), "192.0.2.1", 10, MaxProofTTL+time.Second); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("long ttl err=%v", err)
	}
	expired := challengeDigest("expired")
	if _, err := storage.Execute(context.Background(), pow.db, rhiza.ExecuteRequest{RequestID: "pow-expired-fixture", SQL: `INSERT INTO identity_password_reset_pow_challenges (challenge,expires_at_unix_seconds,consumed_attempt,consumed_at_unix_seconds) VALUES (?,?,NULL,NULL)`, Args: []any{expired, int64(999)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pow.Issue(context.Background(), 10, time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err := pow.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_reset_pow_challenges WHERE expires_at_unix_seconds < ?`, Args: []any{int64(1_000)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("expired cleanup rows=%#v err=%v", result.Rows, err)
	}
}

func TestProofOfWorkIssueAdmissionBoundaryExpiryAndNeighbor(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = &sequenceReader{}
	for i := 0; i < proofIssueLimit; i++ {
		if _, err := pow.IssueForPeer(context.Background(), "192.0.2.1", 10, time.Second); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if _, err := pow.IssueForPeer(context.Background(), "192.0.2.1", 10, time.Second); !errors.Is(err, ErrProofIssueLimited) {
		t.Fatalf("over-limit err=%v", err)
	}
	if _, err := pow.IssueForPeer(context.Background(), "192.0.2.2", 10, time.Second); err != nil {
		t.Fatalf("neighbor issue: %v", err)
	}
	// An expiry equal to the clock is still live, matching the spow wire
	// contract and VerifyAndConsume's equality rule.
	now = now.Add(time.Second)
	if got := powChallengeCount(t, pow, "expires_at_unix_seconds >= ?", now.Unix()); got != proofIssueLimit+1 {
		t.Fatalf("live challenges at equality=%d", got)
	}
	now = now.Add(time.Second)
	if _, err := pow.IssueForPeer(context.Background(), "192.0.2.3", 10, time.Second); err != nil {
		t.Fatalf("issue after expiry: %v", err)
	}
	if got := powChallengeCount(t, pow, "expires_at_unix_seconds < ?", now.Unix()); got != 0 {
		t.Fatalf("expired challenges=%d", got)
	}
}

func TestProofOfWorkIssueCrossStoreContentionHonorsActiveBound(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = &counterReader{}
	other, err := NewProofOfWork(pow.db, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	other.now = pow.now
	other.random = &counterReader{next: 1_000}
	start := make(chan struct{})
	errs := make(chan error, proofActiveLimit+1)
	for i := 0; i < proofActiveLimit+1; i++ {
		issuer := pow
		if i%2 != 0 {
			issuer = other
		}
		ip := "198.51." + strconv.Itoa(i/254+1) + "." + strconv.Itoa(i%254+1)
		go func() {
			<-start
			_, err := issuer.IssueForPeer(context.Background(), ip, 10, time.Minute)
			errs <- err
		}()
	}
	close(start)
	successes := 0
	for range proofActiveLimit + 1 {
		err := <-errs
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrProofIssueLimited) {
			t.Fatalf("issue err=%v", err)
		}
	}
	if successes != proofActiveLimit {
		t.Fatalf("successes=%d", successes)
	}
	if got := powChallengeCount(t, pow, "expires_at_unix_seconds >= ?", now.Unix()); got != proofActiveLimit {
		t.Fatalf("live challenge rows=%d", got)
	}
}

func TestProofOfWorkIssuePeerRowsStayBoundedAfterConsumption(t *testing.T) {
	t.Parallel()
	pow := testProofOfWork(t)
	now := time.Unix(1_000, 0).UTC()
	pow.now = func() time.Time { return now }
	pow.random = &counterReader{}
	ctx := context.Background()
	for i := 0; i < proofIssuePeers; i++ {
		ip := "203.0." + strconv.Itoa(i/254+1) + "." + strconv.Itoa(i%254+1)
		challenge, err := pow.IssueForPeer(ctx, ip, 10, time.Minute)
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if _, err := storage.Execute(ctx, pow.db, rhiza.ExecuteRequest{RequestID: "pow-test-consume-" + strconv.Itoa(i), SQL: `UPDATE identity_password_reset_pow_challenges SET consumed_attempt = ?, consumed_at_unix_seconds = ? WHERE challenge = ?`, Args: []any{strings.Repeat("f", 22), now.Unix(), challengeDigest(challenge)}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pow.IssueForPeer(ctx, "203.0.3.1", 10, time.Minute); !errors.Is(err, ErrProofIssueLimited) {
		t.Fatalf("peer-cap err=%v", err)
	}
	if got := powIssuePeerCount(t, pow); got != proofIssuePeers {
		t.Fatalf("peer quota rows=%d", got)
	}
	if got := powChallengeCount(t, pow, "expires_at_unix_seconds >= ?", now.Unix()); got != proofActiveLimit {
		t.Fatalf("consumed live challenge rows=%d", got)
	}
	now = now.Add(proofIssueWindow + time.Second)
	if _, err := pow.IssueForPeer(ctx, "203.0.3.1", 10, time.Minute); err != nil {
		t.Fatalf("next-window issue: %v", err)
	}
	if got := powIssuePeerCount(t, pow); got != 1 {
		t.Fatalf("stale peer quota rows=%d", got)
	}
}

func powChallengeCount(t *testing.T, pow *ProofOfWork, where string, args ...any) int {
	t.Helper()
	result, err := pow.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_reset_pow_challenges WHERE ` + where, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("challenge count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("challenge count=%#v", result.Rows)
	}
	return int(count)
}

func powIssuePeerCount(t *testing.T, pow *ProofOfWork) int {
	t.Helper()
	result, err := pow.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_reset_pow_issuance_limits`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("peer quota count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("peer quota count=%#v", result.Rows)
	}
	return int(count)
}

func testProofOfWork(t *testing.T) *ProofOfWork {
	t.Helper()
	// The cross-store barrier submits proofActiveLimit+1 callers at once.
	// Keep the application-capacity oracle independent of DB read admission.
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "pow-test", DataDir: t.TempDir(), MaxConcurrentReads: proofActiveLimit + 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	pow, err := NewProofOfWork(db, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pow
}

func solveProof(t *testing.T, challenge string) string {
	t.Helper()
	parts := strings.Split(challenge, ":")
	difficulty, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	for counter := 0; ; counter++ {
		candidate := challenge + "counter-" + strconv.Itoa(counter)
		if leadingZeroBits(sha256.Sum256([]byte(candidate)), uint8(difficulty)) {
			return candidate
		}
	}
}

func base64Secret(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (r *sequenceReader) Read(value []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	for i := range value {
		value[i] = r.next
	}
	return len(value), nil
}

var _ io.Reader = (*sequenceReader)(nil)

type counterReader struct {
	mu   sync.Mutex
	next uint64
}

func (r *counterReader) Read(value []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	for i := range value {
		value[i] = 0
	}
	if len(value) >= 8 {
		binary.BigEndian.PutUint64(value[len(value)-8:], r.next)
	}
	return len(value), nil
}

var _ io.Reader = (*counterReader)(nil)
