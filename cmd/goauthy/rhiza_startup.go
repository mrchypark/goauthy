package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
)

func rhizaStartupTimeoutFromEnv(getenv func(string) string) (time.Duration, error) {
	return storage.RhizaStartupTimeoutFromEnv(getenv)
}

// waitForRhizaReady bounds only storage startup. Readiness itself remains the
// existing quorum-backed /readyz check after the application is activated.
func waitForRhizaReady(ctx context.Context, timeout time.Duration, ready func() bool) error {
	if ctx == nil || timeout <= 0 || ready == nil {
		return errors.New("invalid rhiza readiness wait")
	}
	startupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for !ready() {
		select {
		case <-startupCtx.Done():
			return fmt.Errorf("wait for rhiza readiness: %w", startupCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}
