package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
)

const (
	userExpiryBatchSize  = 128
	maxUserExpiryMinutes = 525600
)

// ponytail: fixed 128-user batches; a backlog drains one bounded pass per tick.

type userExpirySettings struct {
	interval    time.Duration
	deleteAfter time.Duration
}

func userExpirySettingsFromEnv(getenv func(string) string) (userExpirySettings, error) {
	minutes, err := userExpiryMinutes(getenv("GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES"), 60)
	if err != nil {
		return userExpirySettings{}, fmt.Errorf("GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES must be an integer from 1 to %d", maxUserExpiryMinutes)
	}
	deleteMinutes, err := userExpiryMinutes(getenv("GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES"), 0)
	if err != nil {
		return userExpirySettings{}, fmt.Errorf("GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES must be an integer from 1 to %d", maxUserExpiryMinutes)
	}
	return userExpirySettings{interval: time.Duration(minutes) * time.Minute, deleteAfter: time.Duration(deleteMinutes) * time.Minute}, nil
}

func userExpiryMinutes(value string, fallback int64) (int64, error) {
	if value == "" {
		return fallback, nil
	}
	minutes, err := strconv.ParseInt(value, 10, 64)
	if err != nil || minutes < 1 || minutes > maxUserExpiryMinutes {
		return 0, errors.New("invalid minutes")
	}
	return minutes, nil
}

func runUserExpiry(ctx context.Context, store *identity.Store, settings userExpirySettings, now func() time.Time, onError func(error)) error {
	if ctx == nil || store == nil || now == nil || settings.interval <= 0 || settings.interval > maxUserExpiryMinutes*time.Minute || settings.deleteAfter < 0 || settings.deleteAfter > maxUserExpiryMinutes*time.Minute {
		return errors.New("user expiry scheduler is not configured")
	}
	tick := func() {
		at := now().UTC()
		if err := runUserExpiryTick(ctx, store, settings, at); err != nil {
			if ctx.Err() == nil && onError != nil {
				onError(err)
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	tick()
	ticker := time.NewTicker(settings.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			tick()
		}
	}
}

func runUserExpiryTick(ctx context.Context, store *identity.Store, settings userExpirySettings, at time.Time) error {
	if _, err := store.ExpireUsers(ctx, at, userExpiryBatchSize); err != nil {
		return fmt.Errorf("expire users: %w", err)
	}
	if settings.deleteAfter > 0 {
		if _, err := store.DeleteExpiredUsers(ctx, at, settings.deleteAfter, userExpiryBatchSize); err != nil {
			return fmt.Errorf("delete expired users: %w", err)
		}
	}
	return nil
}
