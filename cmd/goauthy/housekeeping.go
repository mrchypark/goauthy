package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/housekeeping"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func buildHousekeepingJobs(
	eventStore *eventlog.Store,
	eventRetention time.Duration,
	identityStore *identity.Store,
	userExpiryCfg userExpirySettings,
	db *rhiza.DB,
	dcrAnonymous bool,
	dcrCleanupCfg dcr.AnonymousCleanupConfig,
	recoveryService *recovery.Service,
	loginpolicyStore *loginpolicy.Store,
	keyring *oidc.Keyring,
	emailOutbox *recovery.EmailOutbox,
) []housekeeping.Job {
	var jobs []housekeeping.Job

	jobs = append(jobs, housekeeping.Job{
		Name:     "event-cleanup",
		Interval: time.Hour,
		Step: func(ctx context.Context) error {
			return eventCleanupStep(ctx, eventStore, eventRetention)
		},
	})

	if recoveryService != nil {
		jobs = append(jobs, housekeeping.Job{
			Name:     "open-registration-cleanup",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return openRegistrationCleanupStep(ctx, identityStore)
			},
		})
	}

	if dcrAnonymous {
		jobs = append(jobs, housekeeping.Job{
			Name:     "dcr-anonymous-cleanup",
			Interval: time.Hour,
			Step: func(ctx context.Context) error {
				return dcrAnonymousCleanupStep(ctx, db, dcrCleanupCfg)
			},
		})
	}

	if userExpiryCfg.interval > 0 {
		interval := userExpiryCfg.interval
		if interval > maxUserExpiryMinutes*time.Minute {
			interval = maxUserExpiryMinutes * time.Minute
		}
		jobs = append(jobs, housekeeping.Job{
			Name:     "user-expiry",
			Interval: interval,
			Step: func(ctx context.Context) error {
				return userExpiryStep(ctx, identityStore, userExpiryCfg)
			},
		})
	}

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
	}

	return jobs
}

func eventCleanupStep(ctx context.Context, store *eventlog.Store, retention time.Duration) error {
	if store == nil {
		return fmt.Errorf("event store is nil")
	}
	at := time.Now()
	for ctx.Err() == nil {
		removed, err := store.Cleanup(ctx, at, retention)
		if err != nil {
			return fmt.Errorf("event cleanup: %w", err)
		}
		if removed == 0 {
			return nil
		}
	}
	return nil
}

func openRegistrationCleanupStep(ctx context.Context, store *identity.Store) error {
	if store == nil {
		return fmt.Errorf("identity store is nil")
	}
	return cleanupOpenRegistrationTick(ctx, store, time.Now())
}

func dcrAnonymousCleanupStep(ctx context.Context, db *rhiza.DB, config dcr.AnonymousCleanupConfig) error {
	if db == nil {
		return fmt.Errorf("database is nil")
	}
	return dcr.CleanupAnonymousClients(ctx, db, config, time.Now().UTC())
}

func userExpiryStep(ctx context.Context, store *identity.Store, settings userExpirySettings) error {
	if store == nil {
		return fmt.Errorf("identity store is nil")
	}
	return runUserExpiryTick(ctx, store, settings, time.Now().UTC())
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

func housekeepingErrorHandler(job string, err error) {
	slog.Error("housekeeping job failed", "job", job, "error", err)
}

const retiredKeyOverlapPeriod = 24 * time.Hour

func keyRemovalStep(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring) error {
	return removeRetiredMasterKey(ctx, db, keyring, time.Now, storage.AcknowledgeMasterKeyRetirementArchival)
}

// removeRetiredMasterKey is the single owner of retired-key deletion. It
// honours the overlap period and then requires a fresh durability
// acknowledgment of the exact ready barrier: a visible ready state alone can
// still be missing from the archive, and deleting the key first would make
// that archived ciphertext permanently unreadable (GA-STOR-002).
func removeRetiredMasterKey(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, now func() time.Time, acknowledge func(context.Context, *rhiza.DB, int64) error) error {
	if db == nil || keyring == nil || now == nil || acknowledge == nil {
		return fmt.Errorf("key-removal: db, keyring, clock, or acknowledgment is nil")
	}
	barrier, err := storage.LoadMasterKeyRetirement(ctx, db)
	if errors.Is(err, storage.ErrMasterKeyRetirementNotPrepared) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("key-removal: load barrier: %w", err)
	}
	if barrier.State != storage.MasterKeyRetirementReady {
		return nil
	}
	if !keyring.HasKey(barrier.OldKeyID) {
		return nil
	}
	if now().UTC().Sub(barrier.ReadyAt) <= retiredKeyOverlapPeriod {
		return nil
	}
	if err := acknowledge(ctx, db, barrier.Epoch); err != nil {
		return fmt.Errorf("key-removal: acknowledge archival: %w", err)
	}
	if err := keyring.RemoveKey(barrier.OldKeyID); err != nil {
		return fmt.Errorf("key-removal: remove key: %w", err)
	}
	slog.Info("removed retired master key", "old_key_id", barrier.OldKeyID, "ready_at", barrier.ReadyAt)
	return nil
}
