package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/mrchypark/rhiza"
)

// SigningKeyRotationWorker prepublishes a replacement key before rotating it.
// Its fields are immutable after Run begins, so multiple embedded nodes can run
// identical workers safely.
type SigningKeyRotationWorker struct {
	DB             *rhiza.DB
	Keyring        *Keyring
	Issuer         string
	TickInterval   time.Duration
	RotationPeriod time.Duration
	// OnError reports a failed reconciliation pass. It must return promptly.
	OnError func(error)
}

// Run performs one reconciliation immediately and then at TickInterval until
// ctx is cancelled. Runtime reconciliation failures are reported through
// OnError and retried on the next tick; invalid worker configuration returns.
func (w SigningKeyRotationWorker) Run(ctx context.Context) error {
	if err := w.valid(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	w.stepOrReport(ctx, time.Now().UTC())
	ticker := time.NewTicker(w.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			w.stepOrReport(ctx, now.UTC())
		}
	}
}

func (w SigningKeyRotationWorker) stepOrReport(ctx context.Context, now time.Time) {
	if err := w.Step(ctx, now); err != nil && ctx.Err() == nil && w.OnError != nil {
		w.OnError(err)
	}
}

// Step reconciles one rotation pass at the supplied time. Supplying time makes
// the state machine deterministic in tests and keeps all clock use out of SQL.
func (w SigningKeyRotationWorker) Step(ctx context.Context, now time.Time) error {
	if err := w.valid(); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("signing key rotation time is required")
	}
	now = now.UTC()
	if err := CleanupRetiredSigningKeys(ctx, w.DB, now); err != nil {
		return fmt.Errorf("cleanup retired signing keys: %w", err)
	}
	active, err := LoadActiveSigningKey(ctx, w.DB, w.Keyring, w.Issuer)
	if err != nil {
		return fmt.Errorf("load active signing key: %w", err)
	}
	rotationAt := active.CreatedAt.Add(w.RotationPeriod)
	if now.Before(rotationAt.Add(-JWKSCacheMaxAge)) {
		return nil
	}
	prepared, err := PrepareSigningKey(ctx, w.DB, w.Keyring, w.Issuer, now)
	if err != nil {
		return fmt.Errorf("prepare signing key: %w", err)
	}
	if now.Before(rotationAt) || now.Before(prepared.ActivatesAfter) {
		return nil
	}
	if _, err := ActivatePreparedSigningKey(ctx, w.DB, w.Keyring, w.Issuer, active.PublicJWK.KeyID, prepared.PendingKID, now.Add(MinimumSigningKeyRetirement), now); err != nil {
		return fmt.Errorf("activate prepared signing key: %w", err)
	}
	return nil
}

func (w SigningKeyRotationWorker) valid() error {
	if w.DB == nil || w.Keyring == nil || w.Issuer == "" {
		return fmt.Errorf("signing key rotation worker is not configured")
	}
	if w.TickInterval <= 0 || w.RotationPeriod < JWKSCacheMaxAge {
		return fmt.Errorf("invalid signing key rotation intervals")
	}
	return nil
}
