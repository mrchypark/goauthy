package main

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

const (
	defaultEventRetention = 31 * 24 * time.Hour
	eventCleanupInterval  = time.Hour
)

func eventRetentionFromEnv(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		return 0, errors.New("event retention requires environment reader")
	}
	value := getenv("GOAUTHY_EVENTS_CLEANUP_DAYS")
	if value == "" {
		return defaultEventRetention, nil
	}
	days, err := strconv.Atoi(value)
	if err != nil || days < 1 || days > 3650 {
		return 0, errors.New("GOAUTHY_EVENTS_CLEANUP_DAYS must be between 1 and 3650")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func runEventCleanup(ctx context.Context, store *eventlog.Store, interval, retention time.Duration, now func() time.Time, onError func(error)) error {
	if ctx == nil || store == nil || interval <= 0 || retention <= 0 || now == nil {
		return errors.New("event cleanup is not configured")
	}
	step := func() {
		at := now()
		for ctx.Err() == nil {
			removed, err := store.Cleanup(ctx, at, retention)
			if err != nil {
				if ctx.Err() == nil && onError != nil {
					onError(err)
				}
				return
			}
			if removed == 0 {
				return
			}
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

// tokenIssuedConfigFromEnv preserves the pinned Rauthy generation defaults.
func tokenIssuedConfigFromEnv(getenv func(string) string) (bool, eventlog.Level, error) {
	generate := getenv("GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED")
	if generate != "" && generate != "true" && generate != "false" {
		return false, "", errors.New("GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED must be true or false")
	}
	level := eventlog.Level(getenv("GOAUTHY_EVENT_LEVEL_TOKEN_ISSUED"))
	if level == "" {
		level = eventlog.Info
	}
	if !level.Valid() {
		return false, "", errors.New("GOAUTHY_EVENT_LEVEL_TOKEN_ISSUED must be info, notice, warning or critical")
	}
	return generate != "false", level, nil
}

// recordTokenIssued uses the existing event table and notification polling path.
func recordTokenIssued(ctx context.Context, db *rhiza.DB, users *identity.Store, level eventlog.Level, flow, clientID, subject string) error {
	email := ""
	if subject != "" {
		profile, err := users.ProfileClaimsBySubject(ctx, subject)
		if err != nil {
			return err
		}
		if profile.Email != nil {
			email = *profile.Email
		}
	}
	operation := "token-issued/" + rand.Text()
	event := eventlog.IssuedToken(operation, flow, clientID, email, level, time.Now())
	statement, err := event.Statement("1=1")
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: operation, Statements: []rhiza.SQLStatement{statement}})
	return err
}
