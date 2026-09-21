package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func passwordResetEventRows(t *testing.T, store *Store) [][]any {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:  `SELECT id,timestamp,level,typ,ip,data,text FROM event_log WHERE typ = ? ORDER BY id`,
		Args: []any{string(eventlog.UserPasswordReset)}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Rows
}

func passwordResetEventOrderCount(t *testing.T, store *Store) int64 {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:  `SELECT COUNT(*) FROM event_log_order o JOIN event_log e ON e.id = o.event_id WHERE e.typ = ?`,
		Args: []any{string(eventlog.UserPasswordReset)}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("event order query rows=%#v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(int64)
}

func passwordResetScalar(t *testing.T, store *Store, query string, args ...any) int64 {
	t.Helper()
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("scalar query rows=%#v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(int64)
}

func seedResetProfile(t *testing.T, store *Store, subject, email string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "password-reset-event-profile-" + subject,
		SQL:       `INSERT INTO identity_user_profiles (subject,email,email_verified) VALUES (?,?,1)`,
		Args:      []any{subject, email},
	}); err != nil {
		t.Fatal(err)
	}
}

func seedResetRecoveryEmail(t *testing.T, store *Store, subject, email string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "password-reset-event-recovery-" + subject,
		SQL:       `INSERT INTO identity_recovery_emails (subject,email) VALUES (?,?)`,
		Args:      []any{subject, email},
	}); err != nil {
		t.Fatal(err)
	}
}

func assertResetEventText(t *testing.T, store *Store, want string) {
	t.Helper()
	rows := passwordResetEventRows(t, store)
	if len(rows) != 1 || rows[0][6] != want {
		t.Fatalf("reset event rows=%#v want text=%q", rows, want)
	}
}

func TestPasswordResetAppendsUserPasswordResetEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, usage := range []string{"password_reset", "password_new"} {
		t.Run(usage, func(t *testing.T) {
			store := testResetStore(t, credential.DefaultRules())
			at := time.UnixMilli(1_704_067_200_123).UTC()
			store.now = func() time.Time { return at }
			seedDeterministicRandom(store)

			var subject, token, redirect string
			if usage == "password_reset" {
				subject = "password-reset-event-user"
				bootstrapPassword(t, store, subject, "reset-events@example.test", []byte("CurrentPassword1"))
				seedResetProfile(t, store, subject, "profile-reset@example.test")
				var err error
				token, _, err = store.IssuePasswordReset(ctx, subject, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				registered, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "profile-new@example.test", TTL: time.Minute, RedirectURI: "https://client.example.test/return"})
				if err != nil {
					t.Fatal(err)
				}
				subject, token, redirect = registered.Subject, registered.Token, "https://client.example.test/return"
			}
			if got := passwordResetEventRows(t, store); len(got) != 0 {
				t.Fatalf("issuance emitted reset event: %#v", got)
			}
			challenge := beginPasswordReset(t, store, subject, token)
			if got := passwordResetEventRows(t, store); len(got) != 0 {
				t.Fatalf("begin emitted reset event: %#v", got)
			}
			gotRedirect, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("NewResetPassword2"), "192.0.2.44")
			if err != nil || gotRedirect != redirect {
				t.Fatalf("reset redirect=%q err=%v", gotRedirect, err)
			}
			rows := passwordResetEventRows(t, store)
			if len(rows) != 1 {
				t.Fatalf("reset events=%#v", rows)
			}
			if got := passwordResetEventOrderCount(t, store); got != 1 {
				t.Fatalf("reset event order count=%d", got)
			}
			row := rows[0]
			if row[1] != at.UnixMilli() || row[2] != int64(eventlog.Notice.Rank()) || row[3] != string(eventlog.UserPasswordReset) || row[4] != "192.0.2.44" || row[5] != nil || row[6] != "Reset via Password Reset Form: profile-"+map[string]string{"password_reset": "reset", "password_new": "new"}[usage]+"@example.test" {
				t.Fatalf("event row=%#v", row)
			}
			if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("ReplayPassword3"), "192.0.2.44"); !errors.Is(err, ErrInvalidPasswordReset) {
				t.Fatalf("replay err=%v", err)
			}
			if got := passwordResetEventRows(t, store); len(got) != 1 {
				t.Fatalf("replay changed events=%#v", got)
			}
			if got := passwordResetEventOrderCount(t, store); got != 1 {
				t.Fatalf("replay changed event order count=%d", got)
			}
		})
	}
}

func TestPasswordResetRejectedAttemptsAppendNoEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	at := time.UnixMilli(1_704_067_201_000).UTC()
	store.now = func() time.Time { return at }
	seedDeterministicRandom(store)
	subject := "password-reset-failed-events"
	bootstrapPassword(t, store, subject, "failed-events@example.test", []byte("CurrentPassword1"))
	seedResetProfile(t, store, subject, "failed-profile@example.test")

	policyToken, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	policyChallenge := beginPasswordReset(t, store, subject, policyToken)
	if _, err := store.ResetPassword(ctx, subject, policyToken, policyChallenge.CookieToken, policyChallenge.CSRFToken, []byte("short"), "198.51.100.7"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("policy reset err=%v", err)
	}
	if got := passwordResetEventRows(t, store); len(got) != 0 {
		t.Fatalf("policy failure emitted event=%#v", got)
	}

	stale, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staleChallenge := beginPasswordReset(t, store, subject, stale)
	if err := store.ChangePassword(ctx, subject, []byte("CurrentPassword1"), []byte("ChangedPassword2")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetPassword(ctx, subject, stale, staleChallenge.CookieToken, staleChallenge.CSRFToken, []byte("RejectedPassword3"), "198.51.100.7"); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("stale reset err=%v", err)
	}
	if got := passwordResetEventRows(t, store); len(got) != 0 {
		t.Fatalf("stale reset emitted event=%#v", got)
	}

	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	store.now = func() time.Time { return at.Add(time.Minute) }
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("ExpiredPassword3"), "198.51.100.7"); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("expired reset err=%v", err)
	}
	if got := passwordResetEventRows(t, store); len(got) != 0 {
		t.Fatalf("expired reset emitted event=%#v", got)
	}
}

func TestPasswordResetRecoveryEmailFallbackAndProfilePriority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, withProfile := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery-only", true: "profile-priority"}[withProfile], func(t *testing.T) {
			store := testResetStore(t, credential.DefaultRules())
			at := time.UnixMilli(1_704_067_206_000).UTC()
			store.now = func() time.Time { return at }
			seedDeterministicRandom(store)
			subject := "password-reset-recovery-email"
			bootstrapPassword(t, store, subject, "bootstrap-recovery@example.test", []byte("CurrentPassword1"))
			seedResetRecoveryEmail(t, store, subject, "recovery@example.test")
			want := "recovery@example.test"
			if withProfile {
				seedResetProfile(t, store, subject, "profile-wins@example.test")
				want = "profile-wins@example.test"
			}
			token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			challenge := beginPasswordReset(t, store, subject, token)
			if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("RecoveryPassword2"), "192.0.2.88"); err != nil {
				t.Fatal(err)
			}
			assertResetEventText(t, store, "Reset via Password Reset Form: "+want)
		})
	}
}

func TestPasswordResetRecoveryEmailRaceDoesNotConsumeProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.UnixMilli(1_704_067_207_000).UTC() }
	seedDeterministicRandom(store)
	subject := "password-reset-recovery-race"
	bootstrapPassword(t, store, subject, "recovery-race@example.test", []byte("CurrentPassword1"))
	seedResetRecoveryEmail(t, store, subject, "recovery-original@example.test")
	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	beforePHC := passwordPHC(t, store, "recovery-race@example.test")
	changed := false
	store.random = func(out []byte) (int, error) {
		if !changed {
			changed = true
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "password-reset-recovery-race-update", SQL: `UPDATE identity_recovery_emails SET email=? WHERE subject=?`, Args: []any{"recovery-new@example.test", subject}}); err != nil {
				return 0, err
			}
		}
		for i := range out {
			out[i] = byte(i + 1)
		}
		return len(out), nil
	}
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("RecoveryRacePassword2"), "192.0.2.89"); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("recovery email race err=%v", err)
	}
	if passwordPHC(t, store, "recovery-race@example.test") != beforePHC || passwordResetScalar(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE token_digest=? AND consumed_attempt IS NULL`, store.resetDigest(token)) != 1 || len(passwordResetEventRows(t, store)) != 0 || passwordResetEventOrderCount(t, store) != 0 {
		t.Fatal("recovery email race mutated proof/password/events")
	}
}

func TestPasswordResetEventInsertFailureRollsBackMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	at := time.UnixMilli(1_704_067_202_000).UTC()
	store.now = func() time.Time { return at }
	seedDeterministicRandom(store)
	subject := "password-reset-trigger-events"
	bootstrapPassword(t, store, subject, "trigger-events@example.test", []byte("CurrentPassword1"))
	seedResetProfile(t, store, subject, "trigger-profile@example.test")
	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	beforePHC := passwordPHC(t, store, "trigger-events@example.test")
	beforeGeneration, _ := passwordMetadata(t, store, subject)
	beforeSessions := passwordResetScalar(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject=?`, subject)
	beforeHistory := passwordResetScalar(t, store, `SELECT COUNT(*) FROM identity_password_history WHERE subject=?`, subject)
	beforeOrder := passwordResetScalar(t, store, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "password-reset-event-trigger", SQL: `CREATE TRIGGER reject_password_reset_event BEFORE INSERT ON event_log WHEN NEW.typ = 'UserPasswordReset' BEGIN SELECT RAISE(ABORT, 'reject password reset event'); END`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("TriggerPassword2"), "203.0.113.9"); err == nil {
		t.Fatal("reset succeeded despite event trigger")
	}
	if got := passwordPHC(t, store, "trigger-events@example.test"); got != beforePHC {
		t.Fatal("event failure changed password")
	}
	if generation, _ := passwordMetadata(t, store, subject); generation != beforeGeneration {
		t.Fatalf("event failure changed generation: %d -> %d", beforeGeneration, generation)
	}
	var consumed any
	result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_password_reset_tokens WHERE token_digest = ?`, Args: []any{store.resetDigest(token)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("token query rows=%#v err=%v", result.Rows, err)
	}
	consumed = result.Rows[0][0]
	if consumed != nil || len(passwordResetEventRows(t, store)) != 0 {
		t.Fatalf("event failure consumed token or emitted event: consumed=%v events=%#v", consumed, passwordResetEventRows(t, store))
	}
	if got := passwordResetEventOrderCount(t, store); got != 0 || passwordResetScalar(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject=?`, subject) != beforeSessions || passwordResetScalar(t, store, `SELECT COUNT(*) FROM identity_password_history WHERE subject=?`, subject) != beforeHistory || passwordResetScalar(t, store, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`) != beforeOrder {
		t.Fatalf("event failure emitted event order=%d", got)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "password-reset-event-drop-trigger", SQL: `DROP TRIGGER reject_password_reset_event`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("TriggerPassword2"), "203.0.113.9"); err != nil {
		t.Fatalf("same reset proof after trigger removal err=%v", err)
	}
	if len(passwordResetEventRows(t, store)) != 1 || passwordResetEventOrderCount(t, store) != 1 {
		t.Fatalf("retry event rows=%#v order=%d", passwordResetEventRows(t, store), passwordResetEventOrderCount(t, store))
	}
}

func TestPasswordResetProfileEmailRaceDoesNotConsumeProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.UnixMilli(1_704_067_204_000).UTC() }
	seedDeterministicRandom(store)
	subject := "password-reset-profile-race"
	bootstrapPassword(t, store, subject, "profile-race@example.test", []byte("CurrentPassword1"))
	seedResetProfile(t, store, subject, "profile-race-original@example.test")
	beforePHC := passwordPHC(t, store, "profile-race@example.test")
	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	var changed bool
	store.random = func(out []byte) (int, error) {
		if !changed {
			changed = true
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "password-reset-profile-race-update", SQL: `UPDATE identity_user_profiles SET email=? WHERE subject=?`, Args: []any{"profile-race-new@example.test", subject}}); err != nil {
				return 0, err
			}
		}
		for i := range out {
			out[i] = byte(i + 1)
		}
		return len(out), nil
	}
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("ProfileRacePassword2"), "192.0.2.77"); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("profile email race err=%v", err)
	}
	if passwordPHC(t, store, "profile-race@example.test") != beforePHC || passwordResetScalar(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE token_digest=? AND consumed_attempt IS NULL`, store.resetDigest(token)) != 1 || len(passwordResetEventRows(t, store)) != 0 || passwordResetEventOrderCount(t, store) != 0 {
		t.Fatalf("profile race mutated proof/password/events")
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "password-reset-profile-race-restore", SQL: `UPDATE identity_user_profiles SET email=? WHERE subject=?`, Args: []any{"profile-race-original@example.test", subject}}); err != nil {
		t.Fatal(err)
	}
	seedDeterministicRandom(store)
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("ProfileRacePassword2"), "192.0.2.77"); err != nil {
		t.Fatalf("same proof after profile restore err=%v", err)
	}
}

func TestPasswordResetInvalidSourceIPDoesNotConsumeProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.UnixMilli(1_704_067_205_000).UTC() }
	seedDeterministicRandom(store)
	subject := "password-reset-invalid-ip"
	bootstrapPassword(t, store, subject, "invalid-ip@example.test", []byte("CurrentPassword1"))
	seedResetProfile(t, store, subject, "invalid-ip-profile@example.test")
	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	if _, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, []byte("InvalidIPPassword2"), "not-an-ip"); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("invalid IP err=%v", err)
	}
	if passwordResetScalar(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE token_digest=? AND consumed_attempt IS NULL`, store.resetDigest(token)) != 1 || len(passwordResetEventRows(t, store)) != 0 {
		t.Fatal("invalid IP consumed proof or emitted event")
	}
}

func TestPasswordResetConcurrentConsumersAppendOneEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.UnixMilli(1_704_067_203_000).UTC() }
	seedDeterministicRandom(store)
	subject := "password-reset-concurrent-events"
	bootstrapPassword(t, store, subject, "concurrent-events@example.test", []byte("CurrentPassword1"))
	seedResetProfile(t, store, subject, "concurrent-profile@example.test")
	token, _, err := store.IssuePasswordReset(ctx, subject, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge := beginPasswordReset(t, store, subject, token)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, next := range [][]byte{[]byte("ConcurrentPassword2"), []byte("ConcurrentPassword3")} {
		wg.Add(1)
		go func(next []byte) {
			defer wg.Done()
			<-start
			_, err := store.ResetPassword(ctx, subject, token, challenge.CookieToken, challenge.CSRFToken, next, "192.0.2.55")
			errs <- err
		}(next)
	}
	close(start)
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalidPasswordReset) {
			t.Fatalf("concurrent loser err=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumers=%d", successes)
	}
	if got := passwordResetEventRows(t, store); len(got) != 1 {
		t.Fatalf("concurrent reset events=%#v", got)
	}
	if got := passwordResetEventOrderCount(t, store); got != 1 {
		t.Fatalf("concurrent reset event order count=%d", got)
	}
}
