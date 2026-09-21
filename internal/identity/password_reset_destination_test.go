package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPasswordResetDestinationPreservesProofOnStaleAddress(t *testing.T) {
	t.Parallel()
	s, _ := userUpdateFixture(t)
	ctx := context.Background()
	if raw, _, err := s.IssuePasswordResetForEmail(ctx, "target", "old@example.test", time.Hour); err != nil || raw == "" {
		t.Fatal(err)
	}
	before := userUpdateSnapshot(t, s)
	for _, email := range []string{"other@example.test", "stale@example.test", "Old@example.test", "display <old@example.test>"} {
		if raw, _, err := s.IssuePasswordResetForEmail(ctx, "target", email, time.Hour); !errors.Is(err, ErrInvalidPasswordReset) || raw != "" {
			t.Fatalf("stale/invalid destination returned a proof: %v", err)
		}
		assertUserUpdateSnapshot(t, s, before)
	}
}

func TestPasswordResetDestinationRechecksEmailAtIssueCommit(t *testing.T) {
	t.Parallel()
	s, input := userUpdateFixture(t)
	ctx := context.Background()
	oldToken, _, err := s.IssuePasswordResetForEmail(ctx, "target", input.Email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Use a second store over the real same DB, with its own callback, to
	// commit the administrator change after reset's passwordRecord read.
	updater, err := NewStoreWithPasswordReset(s.db, s.hasher, s.rules, s.resetKey)
	if err != nil {
		t.Fatal(err)
	}
	updater.now, updater.random = s.now, s.random
	originalRandom := s.random
	changed := false
	s.random = func(out []byte) (int, error) {
		changed = true
		input.Email = "new@example.test"
		if _, err := updater.UpdateUserWithGuard(ctx, "target", input, userUpdateTestAuthority); err != nil {
			return 0, err
		}
		return originalRandom(out)
	}
	if token, _, err := s.IssuePasswordResetForEmail(ctx, "target", "old@example.test", time.Hour); !errors.Is(err, ErrInvalidPasswordReset) || token != "" || !changed {
		t.Fatalf("email-change interposition did not prevent stale issuance: %v", err)
	}
	s.random = originalRandom
	assertCount(t, s, `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='target'`, 0)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND email='new@example.test'`, 1)
	if _, err := s.BeginPasswordReset(ctx, "target", oldToken); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("pre-change proof remains usable: %v", err)
	}
	if token, _, err := s.IssuePasswordResetForEmail(ctx, "target", "new@example.test", time.Hour); err != nil || token == "" {
		t.Fatalf("new destination cannot request recovery: %v", err)
	}
}
