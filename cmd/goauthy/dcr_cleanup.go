package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/rhiza"
)

const dcrAnonymousCleanupInterval = time.Hour

func dcrAnonymousCleanupConfigFromEnv(getenv func(string) string) (dcr.AnonymousCleanupConfig, error) {
	minutes, err := strconv.ParseInt(envValue(getenv, "GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES", "60"), 10, 64)
	if err != nil || minutes < 0 || minutes > 525600 {
		return dcr.AnonymousCleanupConfig{}, errors.New("GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES must be an integer from 0 to 525600")
	}
	inactiveDays, err := strconv.ParseInt(envValue(getenv, "GOAUTHY_DCR_ANONYMOUS_INACTIVE_DAYS", "0"), 10, 64)
	if err != nil || inactiveDays < 0 || inactiveDays > 3650 {
		return dcr.AnonymousCleanupConfig{}, errors.New("GOAUTHY_DCR_ANONYMOUS_INACTIVE_DAYS must be an integer from 0 to 3650")
	}
	limit, err := strconv.ParseInt(envValue(getenv, "GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT", "100"), 10, 64)
	if err != nil || limit < 1 || limit > 1000 {
		return dcr.AnonymousCleanupConfig{}, errors.New("GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT must be an integer from 1 to 1000")
	}
	return dcr.AnonymousCleanupConfig{CleanupMinutes: minutes, InactiveDays: inactiveDays, Limit: limit}, nil
}

// runDCRAnonymousCleanup performs an immediate pass and then repeats it until
// cancellation. main starts it only for the anonymous DCR profile.
func runDCRAnonymousCleanup(ctx context.Context, db *rhiza.DB, config dcr.AnonymousCleanupConfig, interval time.Duration, now func() time.Time, onError func(error)) error {
	if ctx == nil || db == nil || interval <= 0 || now == nil {
		return errors.New("DCR anonymous cleanup scheduler is not configured")
	}
	step := func() {
		if err := dcr.CleanupAnonymousClients(ctx, db, config, now().UTC()); err != nil && ctx.Err() == nil && onError != nil {
			onError(fmt.Errorf("cleanup anonymous dynamic clients: %w", err))
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	step()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			step()
		}
	}
}
