package recovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
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

// seedOTPSubject creates the credential rows the verification transaction joins
// against: a live password user and its matching password authentication mode.
func seedOTPSubject(t *testing.T, db *rhiza.DB, subject, username string, passwordGeneration, modeGeneration int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "otp-test-subject-" + subject,
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT OR IGNORE INTO identity_users (subject,username,password_phc,password_generation) VALUES (?,?,?,?)`, Args: []any{subject, username, "phc", passwordGeneration}},
			{SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?,'password',?,0)`, Args: []any{subject, modeGeneration}},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// otpTestToken returns a canonical 43-character browser token and the digest the
// interaction store persists for it. The token has to decode to exactly 32 bytes
// for browser.CanonicalTokenDigest to accept it.
func otpTestToken(t *testing.T, fill byte) (string, string) {
	t.Helper()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
	digest, err := browser.CanonicalTokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	return token, digest
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
	unbound := strings.Repeat("c", 43)
	interaction, interactionDigest := otpTestToken(t, 0x0b)

	first := NewOTPInteractionStore(db)
	first.now = func() time.Time { return now }
	if err := first.Store(session, "subject-1", interaction, 1, 1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	second := NewOTPInteractionStore(db)
	second.now = func() time.Time { return now }
	subject, token, err := second.Load(ctx, session)
	if err != nil || subject != "subject-1" || token != interactionDigest {
		t.Fatalf("loaded subject=%q token=%q err=%v", subject, token, err)
	}
	// The raw continuation token never reaches durable state (GA66-OTP-003).
	if token == interaction {
		t.Fatal("the raw interaction token was persisted")
	}
	if stored := otpScalar(t, db, "SELECT COUNT(*) FROM identity_email_otp_interactions WHERE interaction_digest=?", interactionDigest); stored != 1 {
		t.Fatalf("digest bindings = %d, want 1", stored)
	}
	if _, _, err := second.Load(ctx, unbound); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("unbound session error = %v", err)
	}
	// Without the replicated database the store refuses the binding instead of
	// falling back to process-local state.
	if err := NewOTPInteractionStore().Store(session, "subject-1", interaction, 1, 1, now.Add(time.Minute)); err == nil {
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
	seedOTPSubject(t, db, "subject-1", "alice", 1, 1)
	service, err := NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	store := NewOTPInteractionStore(db)
	session := strings.Repeat("a", 43)
	otherSession := strings.Repeat("b", 43)
	token, interactionDigest := otpTestToken(t, 0x0c)

	code, err := service.GenerateOTP(ctx, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(session, "subject-1", token, 1, 1, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", interactionDigest, wrongOTPCode(code)); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("rejected code verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); err != nil {
		t.Fatalf("binding consumed by a rejected code: %v", err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, otherSession, "subject-1", interactionDigest, code); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("cross-session verification verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); err != nil {
		t.Fatalf("binding consumed by another session: %v", err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", interactionDigest, code); !verified || err != nil {
		t.Fatalf("bound verification verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("binding survived verification: %v", err)
	}
	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", interactionDigest, code); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("replay verified=%v err=%v", verified, err)
	}
}

// TestVerifyOTPAndConsumeInteractionRejectsReplacedBinding reproduces
// GA66-OTP-001: the caller loads interaction A, a second password step replaces
// the binding with B, and the stale verification must fail without spending the
// code or deleting the replacement binding. The replacement must still complete.
func TestVerifyOTPAndConsumeInteractionRejectsReplacedBinding(t *testing.T) {
	db := testOTPDatabase(t)
	ctx := context.Background()
	seedOTPSubject(t, db, "subject-1", "alice", 1, 1)
	service, err := NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	store := NewOTPInteractionStore(db)
	session := strings.Repeat("a", 43)
	expiresAt := time.Now().UTC().Add(time.Minute)

	replacement, replacementDigest := otpTestToken(t, 0x0d)
	staleToken, staleDigest := otpTestToken(t, 0x0e)
	code, err := service.GenerateOTP(ctx, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	// The stale digest is what OTPVerify loaded before the replacement landed.
	if err := store.Store(session, "subject-1", staleToken, 1, 1, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(session, "subject-1", replacement, 1, 1, expiresAt); err != nil {
		t.Fatal(err)
	}

	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", staleDigest, code); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("stale verification verified=%v err=%v", verified, err)
	}
	if consumed := otpScalar(t, db, "SELECT COUNT(*) FROM identity_email_otp WHERE consumed_attempt IS NOT NULL"); consumed != 0 {
		t.Fatalf("stale verification spent the code: consumed=%d", consumed)
	}
	subject, digest, err := store.Load(ctx, session)
	if err != nil || subject != "subject-1" || digest != replacementDigest {
		t.Fatalf("replacement binding lost: subject=%q digest=%q err=%v", subject, digest, err)
	}
	if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", replacementDigest, code); !verified || err != nil {
		t.Fatalf("replacement verification verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("replacement binding survived its own verification: %v", err)
	}
}

// TestVerifyOTPAndConsumeInteractionRejectsStaleFirstFactor proves GA66-OTP-002:
// the binding carries the password and authentication-mode generations the
// password step proved, so a later credential change revokes the pending
// continuation without spending the code or deleting the binding.
func TestVerifyOTPAndConsumeInteractionRejectsStaleFirstFactor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance string
	}{
		{name: "password generation advances", advance: "UPDATE identity_users SET password_generation = password_generation + 1 WHERE subject='subject-1'"},
		{name: "authentication generation advances", advance: "UPDATE identity_authentication_modes SET generation = generation + 1 WHERE subject='subject-1'"},
		{name: "account is disabled", advance: "UPDATE identity_users SET disabled = 1 WHERE subject='subject-1'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testOTPDatabase(t)
			ctx := context.Background()
			seedOTPSubject(t, db, "subject-1", "alice", 1, 1)
			service, err := NewOTPService(db)
			if err != nil {
				t.Fatal(err)
			}
			store := NewOTPInteractionStore(db)
			session := strings.Repeat("a", 43)
			token, digest := otpTestToken(t, 0x0f)
			code, err := service.GenerateOTP(ctx, "subject-1")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Store(session, "subject-1", token, 1, 1, time.Now().UTC().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "otp-stale-first-factor", SQL: tc.advance}); err != nil {
				t.Fatal(err)
			}

			if verified, err := service.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", digest, code); verified || !errors.Is(err, ErrOTPInvalid) {
				t.Fatalf("stale first factor verified=%v err=%v", verified, err)
			}
			if consumed := otpScalar(t, db, "SELECT COUNT(*) FROM identity_email_otp WHERE consumed_attempt IS NOT NULL"); consumed != 0 {
				t.Fatalf("stale first factor spent the code: consumed=%d", consumed)
			}
			if _, _, err := store.Load(ctx, session); err != nil {
				t.Fatalf("stale first factor consumed the binding: %v", err)
			}
		})
	}
}

func wrongOTPCode(code string) string {
	last := code[len(code)-1] - '0'
	return code[:len(code)-1] + string(rune('0'+(last+1)%10))
}

// TestVerifyOTPAndConsumeInteractionRejectsResetPasswordContinuation proves the
// end-to-end GA66-OTP-002 contract: a supported password reset advances the
// password generation, so the pending password-plus-OTP continuation of the old
// proof can neither complete nor spend the code, while a fresh flow with the
// replacement password still succeeds.
func TestVerifyOTPAndConsumeInteractionRejectsResetPasswordContinuation(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	ctx := context.Background()
	otp, err := NewOTPService(service.db)
	if err != nil {
		t.Fatal(err)
	}
	store := NewOTPInteractionStore(service.db)
	session := strings.Repeat("a", 43)
	token, digest := otpTestToken(t, 0x11)
	expiresAt := time.Now().UTC().Add(time.Minute)

	authentication, err := service.identity.Authenticate(ctx, "alice", []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(session, authentication.Subject, token, authentication.PasswordGeneration, authentication.AuthenticationGeneration, expiresAt); err != nil {
		t.Fatal(err)
	}
	staleCode, err := otp.GenerateOTP(ctx, authentication.Subject)
	if err != nil {
		t.Fatal(err)
	}

	// A supported password reset advances the password generation.
	resetToken, _, err := service.identity.IssuePasswordReset(ctx, "subject-1", passwordResetLifetime)
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/"+resetToken, nil)
	get.SetPathValue("subject", "subject-1")
	get.SetPathValue("token", resetToken)
	getResponse := httptest.NewRecorder()
	service.GetReset(getResponse, get)
	var document resetResponse
	if getResponse.Code != http.StatusOK || json.Unmarshal(getResponse.Body.Bytes(), &document) != nil || document.CSRFToken == "" {
		t.Fatalf("reset GET status=%d body=%q", getResponse.Code, getResponse.Body.String())
	}
	cookies := getResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("reset cookies=%#v", cookies)
	}
	put := putResetRequest(t, service, "subject-1", putReset{MagicLinkID: resetToken, Password: "UpdatedPassword2"}, cookies[0], document.CSRFToken)
	if put.Code != http.StatusAccepted {
		t.Fatalf("reset PUT status=%d body=%q", put.Code, put.Body.String())
	}

	if verified, err := otp.VerifyOTPAndConsumeInteraction(ctx, session, "subject-1", digest, staleCode); verified || !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("continuation of the reset password verified=%v err=%v", verified, err)
	}
	if consumed := otpScalar(t, service.db, "SELECT COUNT(*) FROM identity_email_otp WHERE consumed_attempt IS NOT NULL"); consumed != 0 {
		t.Fatalf("continuation of the reset password spent the code: consumed=%d", consumed)
	}
	if _, _, err := store.Load(ctx, session); err != nil {
		t.Fatalf("continuation of the reset password consumed the binding: %v", err)
	}

	// A fresh flow with the replacement password succeeds.
	fresh, err := service.identity.Authenticate(ctx, "alice", []byte("UpdatedPassword2"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PasswordGeneration != authentication.PasswordGeneration+1 {
		t.Fatalf("reset did not advance the password generation: %d", fresh.PasswordGeneration)
	}
	if err := store.Store(session, fresh.Subject, token, fresh.PasswordGeneration, fresh.AuthenticationGeneration, expiresAt); err != nil {
		t.Fatal(err)
	}
	freshCode, err := otp.GenerateOTP(ctx, fresh.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := otp.VerifyOTPAndConsumeInteraction(ctx, session, fresh.Subject, digest, freshCode); !verified || err != nil {
		t.Fatalf("fresh flow verified=%v err=%v", verified, err)
	}
	if _, _, err := store.Load(ctx, session); !errors.Is(err, ErrOTPInteractionNotFound) {
		t.Fatalf("fresh flow left its binding behind: %v", err)
	}
}
