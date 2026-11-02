package identity

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRegisterOpenUserReissuesProofForOrphanedPendingAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	store.now = func() time.Time { return time.UnixMilli(47_000) }
	seedDeterministicRandom(store)
	pending, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "orphan@example.test", TTL: time.Hour})
	if err != nil || !pending.Created {
		t.Fatalf("initial registration=%#v err=%v", pending, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "review-orphan-drop-proof",
		SQL: `DELETE FROM identity_password_reset_tokens WHERE subject=? AND usage='password_new'`, Args: []any{pending.Subject},
	}); err != nil {
		t.Fatal(err)
	}

	duplicate, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "orphan@example.test", TTL: time.Hour})
	if err != nil || duplicate.Subject != pending.Subject || duplicate.Created || !validResetToken(duplicate.Token) || !duplicate.ExpiresAt.After(store.now()) {
		t.Fatalf("duplicate registration did not reissue the orphan's setup proof: result=%#v err=%v", duplicate, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users WHERE subject='`+pending.Subject+`'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='`+pending.Subject+`' AND email='orphan@example.test'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM rbac_principal_versions WHERE subject='`+pending.Subject+`' AND revision=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='`+pending.Subject+`' AND mode='password' AND generation=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+pending.Subject+`' AND usage='password_new' AND consumed_attempt IS NULL`, 1)
}

func TestConcurrentOpenRegistrationReissuePreservesFirstDeliveredProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	base := time.UnixMilli(49_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	pending, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "race@example.test", TTL: time.Minute})
	if err != nil || !pending.Created {
		t.Fatalf("initial registration=%#v err=%v", pending, err)
	}
	base = base.Add(time.Minute) // The original setup proof is expired, but the pending identity remains eligible.

	// Each duplicate request makes three 32-byte IDs: its attempted new subject,
	// its attempted initial proof, then its reissued proof after the pre-read.
	// Pairing the first two calls makes both requests reach the pre-read before
	// either can transact. At the third call, release one request and hold the
	// other until the first response (and delivered proof) has completed.
	var mu sync.Mutex
	stage, calls := 0, 0
	stageReady := make(chan struct{})
	releaseSecondReissue := make(chan struct{})
	var randomSequence atomic.Uint32
	store.random = func(value []byte) (int, error) {
		mu.Lock()
		currentStage := stage
		calls++
		if currentStage < 2 {
			ready := stageReady
			wait := calls == 1
			if calls == 2 {
				calls = 0
				stage++
				close(stageReady)
				stageReady = make(chan struct{})
			}
			mu.Unlock()
			if wait {
				<-ready
			}
		} else {
			wait := calls > 1
			mu.Unlock()
			if wait {
				<-releaseSecondReissue
			}
		}
		sequence := byte(randomSequence.Add(1))
		for i := range value {
			value[i] = sequence + byte(i)
		}
		return len(value), nil
	}

	type outcome struct {
		result OpenRegistrationResult
		err    error
	}
	results := make(chan outcome, 2)
	register := func() {
		result, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "race@example.test", TTL: time.Hour})
		results <- outcome{result: result, err: err}
	}
	go register()
	go register()

	first := <-results
	if first.err != nil || first.result.Subject != pending.Subject || !first.result.ReissuedPasswordNew || !validResetToken(first.result.Token) {
		close(releaseSecondReissue)
		t.Fatalf("first concurrent reissue=%#v err=%v", first.result, first.err)
	}
	close(releaseSecondReissue)
	second := <-results
	if second.err != nil || second.result.Subject != pending.Subject || second.result.ReissuedPasswordNew || second.result.Token != "" {
		t.Fatalf("losing duplicate reissued or revoked the delivered proof: result=%#v err=%v", second.result, second.err)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT token_digest FROM identity_password_reset_tokens WHERE subject=? AND usage='password_new' AND consumed_attempt IS NULL AND expires_at_unix_ms>?`,
		Args: []any{pending.Subject, base.UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != store.resetDigest(first.result.Token) {
		t.Fatalf("delivered setup proof was replaced or revoked: rows=%v err=%v", rows.Rows, err)
	}
}

func TestPasswordResetIssueCleanupPreservesExpiredPasswordNewProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := testResetStore(t, testRules(1))
	base := time.UnixMilli(48_000)
	store.now = func() time.Time { return base }
	seedDeterministicRandom(store)
	pending, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "pending-reset@example.test", TTL: time.Minute})
	if err != nil || !pending.Created {
		t.Fatalf("pending registration=%#v err=%v", pending, err)
	}
	bootstrapPassword(t, store, "reset-target", "reset-target", []byte("CurrentPassword1"))
	store.now = func() time.Time { return base.Add(time.Minute) }
	if _, _, err := store.IssuePasswordReset(ctx, "reset-target", time.Hour); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+pending.Subject+`' AND usage='password_new' AND consumed_attempt IS NULL`, 1)
}

func TestRegisterOpenUserDoesNotConvertFederatedPasswordlessDuplicate(t *testing.T) {
	t.Parallel()
	store := testFederatedStore(t)
	federated, err := store.CreateFederatedIdentity(context.Background(), FederatedCreationInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "external@example.test",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.RegisterOpenUser(context.Background(), OpenRegistration{Email: "external@example.test", TTL: time.Hour})
	if err != nil || duplicate.Subject != federated.Subject || duplicate.Created || duplicate.Token != "" {
		t.Fatalf("duplicate registration=%#v err=%v", duplicate, err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_external_links WHERE local_subject='`+federated.Subject+`'`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_authentication_modes WHERE subject='`+federated.Subject+`' AND mode='passkey' AND generation=1`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='`+federated.Subject+`' AND usage='password_new'`, 0)
}

func TestImmutablePreferredUsernameSurvivesPolicyTrapButCannotChange(t *testing.T) {
	t.Parallel()
	store, policy := selfProfileFixture(t)
	preferred, _ := NewPreferredUsernamePolicy("optional", "", []string{"keep-preferred"})
	policy.PreferredUsername = preferred
	policy.RevalidateDuringLogin = true

	needs, err := store.NeedsProfileUpdate(context.Background(), policy, "target", "other-client")
	if err != nil || needs {
		t.Fatalf("existing immutable identifier should be grandfathered: needs=%v err=%v", needs, err)
	}

	keep := "keep-preferred"
	input := SelfProfileUpdate{PreferredUsername: &keep, UserValues: &UserValuesRequest{}}
	if _, err := store.UpdateSelfProfileWithGuard(context.Background(), "target", input, policy, selfProfileTestAuthority); err != nil {
		t.Fatalf("unchanged immutable identifier rejected: %v", err)
	}
	change := "new-preferred"
	input.PreferredUsername = &change
	if _, err := store.UpdateSelfProfileWithGuard(context.Background(), "target", input, policy, selfProfileTestAuthority); err != ErrSelfProfileInvalid {
		t.Fatalf("immutable identifier change err=%v", err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND preferred_username='keep-preferred'`, 1)
}
