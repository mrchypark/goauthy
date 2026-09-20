package recovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// testOTPDatabase opens a migrated database and applies the OTP table contract.
// The password-plus-OTP interaction table is part of otpSchemaStatements, which
// the storage migration for this schema mirrors.
func testOTPDatabase(t *testing.T) *rhiza.DB {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "otp-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "otp-test-schema", Statements: otpSchemaStatements()}); err != nil {
		t.Fatal(err)
	}
	return db
}

func otpScalar(t *testing.T, db *rhiza.DB, sql string, args ...any) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("query %q returned %d rows", sql, len(result.Rows))
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("query %q returned %#v", sql, result.Rows[0][0])
	}
	return value
}

// TestGenerateOTPEnforcesWindowedRateLimit proves the issuance conflict target
// matches the rate-limit primary key: the bounded window counter increments,
// the rejected issuance rolls back with it, and the next window admits the
// subject again.
func TestGenerateOTPEnforcesWindowedRateLimit(t *testing.T) {
	db := testOTPDatabase(t)
	service, err := NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	service.now = func() time.Time { return now }

	for attempt := range otpRateLimit {
		if _, err := service.GenerateOTP(ctx, "subject-1"); err != nil {
			t.Fatalf("issuance %d error = %v", attempt, err)
		}
	}
	if _, err := service.GenerateOTP(ctx, "subject-1"); !errors.Is(err, ErrOTPRateLimited) {
		t.Fatalf("over-limit error = %v", err)
	}
	// The rejected issuance leaves no code and does not advance the window: the
	// guarded insert and the counter increment share one transaction.
	if got := otpScalar(t, db, `SELECT COUNT(*) FROM identity_email_otp`); got != otpRateLimit {
		t.Fatalf("issued codes = %d, want %d", got, otpRateLimit)
	}
	digest := challengeDigest("subject-1")
	if got := otpScalar(t, db, `SELECT count FROM identity_email_otp_rate_limits WHERE subject_digest=?`, digest); got != otpRateLimit {
		t.Fatalf("window count = %d, want %d", got, otpRateLimit)
	}

	now = now.Add(otpRateWindow)
	if _, err := service.GenerateOTP(ctx, "subject-1"); err != nil {
		t.Fatalf("next window error = %v", err)
	}
	if got := otpScalar(t, db, `SELECT COUNT(*) FROM identity_email_otp_rate_limits WHERE subject_digest=?`, digest); got != 1 {
		t.Fatalf("rate limit rows = %d, want 1", got)
	}
	window := now.Unix() / int64(otpRateWindow/time.Second) * int64(otpRateWindow/time.Second)
	if got := otpScalar(t, db, `SELECT count FROM identity_email_otp_rate_limits WHERE subject_digest=? AND window_start_unix_seconds=?`, digest, window); got != 1 {
		t.Fatalf("next window count = %d, want 1", got)
	}
}

// TestGenerateOTPSimultaneousIssuanceStaysWithinLimit proves the same conflict
// target keeps the bounded counter correct when issuance races itself.
func TestGenerateOTPSimultaneousIssuanceStaysWithinLimit(t *testing.T) {
	db := testOTPDatabase(t)
	service, err := NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	service.now = func() time.Time { return now }

	start := make(chan struct{})
	results := make(chan error, otpRateLimit+2)
	var group sync.WaitGroup
	for range otpRateLimit + 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := service.GenerateOTP(ctx, "subject-1")
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)

	issued := 0
	for err := range results {
		switch {
		case err == nil:
			issued++
		case errors.Is(err, ErrOTPRateLimited):
		default:
			t.Fatalf("unexpected issuance error = %v", err)
		}
	}
	if issued != otpRateLimit {
		t.Fatalf("issued = %d, want %d", issued, otpRateLimit)
	}
	if got := otpScalar(t, db, `SELECT count FROM identity_email_otp_rate_limits WHERE subject_digest=?`, challengeDigest("subject-1")); got != otpRateLimit {
		t.Fatalf("window count = %d, want %d", got, otpRateLimit)
	}
}

// TestOTPInteractionStorePersistsAcrossInstances proves the password-plus-OTP
// binding is shared state: another store instance, standing in for a second
// replica or a restarted process, reads the same binding and expired bindings
// fail closed.
func TestOTPInteractionStorePersistsAcrossInstances(t *testing.T) {
	db := testOTPDatabase(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := strings.Repeat("a", 43)
	interaction := strings.Repeat("b", 43)
	unbound := strings.Repeat("c", 43)

	first := NewOTPInteractionStore(db)
	first.now = func() time.Time { return now }
	if err := first.Store(session, "subject-1", interaction, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	second := NewOTPInteractionStore(db)
	second.now = func() time.Time { return now }
	subject, token, err := second.Load(ctx, session)
	if err != nil || subject != "subject-1" || token != interaction {
		t.Fatalf("loaded subject=%q token=%q err=%v", subject, token, err)
	}
	if _, _, err := second.Load(ctx, unbound); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("unbound session error = %v", err)
	}
	// Without the replicated database the store refuses the binding instead of
	// falling back to process-local state.
	if err := NewOTPInteractionStore().Store(session, "subject-1", interaction, now.Add(time.Minute)); err == nil {
		t.Fatal("binding without a database was accepted")
	}

	second.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, _, err := second.Load(ctx, session); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("expired binding error = %v", err)
	}
}

// TestVerifyOTPAndConsumeInteractionBindsSessionAndCode proves the code and the
// session binding are consumed in one transaction: a rejected code leaves both
// for a bounded retry, another session cannot spend the code, and the bound
// session spends it exactly once.
func TestVerifyOTPAndConsumeInteractionBindsSessionAndCode(t *testing.T) {
	db := testOTPDatabase(t)
	ctx := context.Background()
	service, err := NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	store := NewOTPInteractionStore(db)
	session := strings.Repeat("a", 43)
	otherSession := strings.Repeat("b", 43)

	code, err := service.GenerateOTP(ctx, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(session, "subject-1", strings.Repeat("c", 43), time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", wrongOTPCode(code)); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("rejected code verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); err != nil {
		t.Fatalf("binding consumed by a rejected code: %v", err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, otherSession, "subject-1", code); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("cross-session verification verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); err != nil {
		t.Fatalf("binding consumed by another session: %v", err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", code); !verified || err != nil {
		t.Fatalf("bound verification verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("binding survived verification: %v", err)
	}
	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", code); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("replay verified=%v err=%v", verified, err)
	}
}

func wrongOTPCode(code string) string {
	last := code[len(code)-1] - '0'
	return code[:len(code)-1] + string(rune('0'+(last+1)%10))
}
