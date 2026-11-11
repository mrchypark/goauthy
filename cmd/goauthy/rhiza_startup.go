package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	defaultRhizaStartupTimeout = 10 * time.Minute
	maxRhizaStartupTimeout     = time.Hour
)

func rhizaStartupTimeoutFromEnv(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		return 0, errors.New("rhiza startup timeout requires environment reader")
	}
	raw := getenv("GOAUTHY_RHIZA_STARTUP_TIMEOUT")
	if raw == "" {
		return defaultRhizaStartupTimeout, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout < time.Second || timeout > maxRhizaStartupTimeout {
		return 0, errors.New("GOAUTHY_RHIZA_STARTUP_TIMEOUT must be between 1s and 1h")
	}
	return timeout, nil
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
