package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
)

type generatedBootstrapConfig struct {
	artifact string
	ttl      time.Duration
}

func generatedBootstrapConfigFromEnv(getenv func(string) string) (generatedBootstrapConfig, error) {
	path := getenv("GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE")
	rawTTL := getenv("GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS")
	if path == "" && rawTTL == "" {
		return generatedBootstrapConfig{}, nil
	}
	if strings.TrimSpace(path) != path || path == "" || rawTTL == "" || strings.TrimSpace(rawTTL) != rawTTL {
		return generatedBootstrapConfig{}, errors.New("generated bootstrap requires an artifact path and explicit TTL seconds")
	}
	seconds, err := strconv.ParseUint(rawTTL, 10, 32)
	if err != nil {
		return generatedBootstrapConfig{}, errors.New("invalid generated bootstrap TTL seconds")
	}
	return generatedBootstrapConfig{artifact: path, ttl: time.Duration(seconds) * time.Second}, nil
}

func bootstrapAPIKeys(ctx context.Context, store *apikey.Store, keyring *oidc.Keyring, input, keyDir string, cfg generatedBootstrapConfig, now time.Time) error {
	if cfg.artifact == "" {
		return store.BootstrapWithMasterKeyDir(ctx, input, keyDir)
	}
	if strings.TrimSpace(input) == "" {
		return errors.New("generated bootstrap requires API-key bootstrap input")
	}
	var deadline time.Time
	if cfg.ttl != 0 {
		deadline = now.Add(cfg.ttl)
	}
	return store.BootstrapWithSharedGeneratedSecrets(ctx, input, keyDir, cfg.artifact, keyring, deadline)
}

func runGeneratedBootstrapPurge(ctx context.Context, store *apikey.Store, keyring *oidc.Keyring, cfg generatedBootstrapConfig, keyDir string, onError func(error)) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		// Authenticate the local export before deleting it; shared expiry retains
		// its initialized tombstone even after all encrypted exports are gone.
		_, localErr := apikey.PurgeGeneratedBootstrapSecrets(cfg.artifact, keyDir, "", time.Now())
		sharedErr := store.PurgeSharedGeneratedSecrets(ctx, keyring)
		if err := errors.Join(localErr, sharedErr); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
