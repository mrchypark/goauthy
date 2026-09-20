package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mrchypark/goauthy/internal/housekeeping"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// buildHousekeepingJobs returns the maintenance tasks owned by the shared
// scheduler. Event cleanup, account expiry, open-registration cleanup and
// anonymous-DCR cleanup stay with their dedicated workers in main; registering
// them here as well made every replica run each of those tasks twice through two
// immediate-and-periodic loops (GA-RUNTIME-001). Every task therefore has
// exactly one lifecycle owner.
func buildHousekeepingJobs(
	db *rhiza.DB,
	recoveryService *recovery.Service,
	loginpolicyStore *loginpolicy.Store,
	keyring *oidc.Keyring,
	emailOutbox *recovery.EmailOutbox,
) []housekeeping.Job {
	var jobs []housekeeping.Job

	if loginpolicyStore != nil {
		jobs = append(jobs, housekeeping.Job{
			Name:     "credential-stuffing-cleanup",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return credentialStuffingCleanupStep(ctx, loginpolicyStore)
			},
		})
	}

	if recoveryService != nil {
		jobs = append(jobs, housekeeping.Job{
			Name:     "recovery-token-cleanup",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return recoveryTokenCleanupStep(ctx, recoveryService)
			},
		})
	}

	if keyring != nil && db != nil {
		jobs = append(jobs, housekeeping.Job{
			Name:     "key-removal",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return keyRemovalStep(ctx, db, keyring)
			},
		})
	}

	if emailOutbox != nil {
		jobs = append(jobs, housekeeping.Job{
			Name:     "email-outbox",
			Interval: time.Minute,
			Step: func(ctx context.Context) error {
				return emailOutbox.Step(ctx)
			},
		})
		jobs = append(jobs, housekeeping.Job{
			Name:     "email-outbox-cleanup",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return emailOutboxCleanupStep(ctx, emailOutbox)
			},
		})
	}

	return jobs
}

func credentialStuffingCleanupStep(ctx context.Context, store *loginpolicy.Store) error {
	if store == nil {
		return fmt.Errorf("loginpolicy store is nil")
	}
	_, err := store.CleanupStuffingEntries(ctx, time.Now())
	return err
}

func recoveryTokenCleanupStep(ctx context.Context, svc *recovery.Service) error {
	if svc == nil {
		return fmt.Errorf("recovery service is nil")
	}
	_, err := svc.CleanupExpiredTokens(ctx)
	return err
}

// emailOutboxCleanupStep drains terminal rows past retention one bounded
// replicated batch at a time. A non-positive limit selects the outbox
// package's own batch ceiling, so retention never holds the whole backlog in
// one transaction.
func emailOutboxCleanupStep(ctx context.Context, outbox *recovery.EmailOutbox) error {
	if outbox == nil {
		return fmt.Errorf("email outbox is nil")
	}
	for ctx.Err() == nil {
		removed, err := outbox.Cleanup(ctx, 0)
		if err != nil {
			return fmt.Errorf("email outbox cleanup: %w", err)
		}
		if removed == 0 {
			return nil
		}
	}
	return nil
}

func housekeepingErrorHandler(job string, err error) {
	slog.Error("housekeeping job failed", "job", job, "error", err)
}

const retiredKeyOverlapPeriod = 24 * time.Hour

func keyRemovalStep(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring) error {
	return removeRetiredMasterKey(ctx, db, keyring, time.Now, storage.AcknowledgeMasterKeyRetirementArchival)
}

// removeRetiredMasterKey is the single owner of retired-key deletion. It walks
// every completed generation, honours that generation's own overlap period and
// then requires a fresh durability acknowledgment of it: a visible ready state
// alone can still be missing from the archive, and deleting the key first would
// make that archived ciphertext permanently unreadable (GA-STOR-002). Walking
// the retained generations instead of the singleton barrier is what keeps a
// retired key from being orphaned when the next epoch is prepared first
// (GA66-RETIRE-002). The removal receipt is recorded but not used as a filter,
// so a member that has not yet dropped its own copy of the key still sees the
// generation and cleans up.
func removeRetiredMasterKey(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, now func() time.Time, acknowledge func(context.Context, *rhiza.DB, int64) error) error {
	if db == nil || keyring == nil || now == nil || acknowledge == nil {
		return fmt.Errorf("key-removal: db, keyring, clock, or acknowledgment is nil")
	}
	generations, err := storage.LoadMasterKeyRetirementGenerations(ctx, db)
	if err != nil {
		return fmt.Errorf("key-removal: load retired generations: %w", err)
	}
	for _, generation := range generations {
		if !keyring.HasKey(generation.OldKeyID) {
			continue
		}
		when := now().UTC()
		if when.Sub(generation.ReadyAt) <= retiredKeyOverlapPeriod {
			continue
		}
		if err := acknowledge(ctx, db, generation.Epoch); err != nil {
			return fmt.Errorf("key-removal: acknowledge archival for epoch %d: %w", generation.Epoch, err)
		}
		if err := keyring.RemoveKey(generation.OldKeyID); err != nil {
			return fmt.Errorf("key-removal: remove key %q: %w", generation.OldKeyID, err)
		}
		if err := storage.MarkMasterKeyRetirementGenerationRemoved(ctx, db, generation.Epoch, when); err != nil {
			return fmt.Errorf("key-removal: record removal of epoch %d: %w", generation.Epoch, err)
		}
		slog.Info("removed retired master key", "old_key_id", generation.OldKeyID, "ready_at", generation.ReadyAt, "epoch", generation.Epoch)
	}
	return nil
}
