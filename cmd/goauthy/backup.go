package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
	_ "time/tzdata"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/backupconfig"
	"github.com/mrchypark/goauthy/internal/backupschedule"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/thanos-io/objstore"
)

type scheduledBackupConfig struct {
	schedule             *backupschedule.Schedule
	location             *time.Location
	source, destination  rhiza.Config
	separate             bool
	catalog, work, scope string
	recipients           []age.Recipient
	signer               ed25519.PrivateKey
	trustKeys            []ed25519.PublicKey
	lease, timeout       time.Duration
	keepDays, maxEntries int
	retentionPolicy      backup.RetentionPolicy
}

func scheduledBackupFromEnv(getenv func(string) string, source rhiza.Config) (*scheduledBackupConfig, error) {
	enabled := false
	if text := getenv("GOAUTHY_BACKUP_ENABLED"); text != "" {
		value, err := strconv.ParseBool(text)
		if err != nil {
			return nil, errors.New("invalid GOAUTHY_BACKUP_ENABLED")
		}
		enabled = value
	}
	if !enabled {
		return nil, nil
	}
	if source.Local {
		return nil, errors.New("scheduled signed backups do not support the Local archive format")
	}
	c := &scheduledBackupConfig{source: source, catalog: getenv("GOAUTHY_BACKUP_CATALOG_PREFIX"), work: getenv("GOAUTHY_BACKUP_WORK_DIR"), lease: time.Minute, timeout: 15 * time.Minute, keepDays: 30, maxEntries: 4096, retentionPolicy: backup.RetainLatest}
	if source.ObjStoreBucket == "" || c.catalog == "" || c.work == "" {
		return nil, errors.New("scheduled backup requires source object storage, catalog prefix and private work directory")
	}
	if err := backup.ValidateCatalogLocation(c.catalog, path.Join(source.ObjStorePrefix, source.ClusterID)); err != nil {
		return nil, err
	}
	expression := getenv("GOAUTHY_BACKUP_SCHEDULE")
	if expression == "" {
		expression = "0 30 2 * * * *"
	}
	var err error
	c.schedule, err = backupschedule.Parse(expression)
	if err != nil {
		return nil, errors.New("invalid GOAUTHY_BACKUP_SCHEDULE")
	}
	zone := getenv("GOAUTHY_BACKUP_TIMEZONE")
	if zone == "" {
		zone = "Local"
	}
	c.location, err = time.LoadLocation(zone)
	if err != nil {
		return nil, errors.New("invalid GOAUTHY_BACKUP_TIMEZONE")
	}
	for _, option := range []struct {
		name  string
		value *time.Duration
		max   time.Duration
	}{
		{"GOAUTHY_BACKUP_LEASE", &c.lease, time.Hour}, {"GOAUTHY_BACKUP_TIMEOUT", &c.timeout, 24 * time.Hour},
	} {
		if text := getenv(option.name); text != "" {
			v, e := time.ParseDuration(text)
			if e != nil || v < time.Second || v > option.max {
				return nil, fmt.Errorf("invalid %s", option.name)
			}
			*option.value = v
		}
	}
	for _, option := range []struct {
		name     string
		value    *int
		min, max int
	}{
		{"GOAUTHY_BACKUP_KEEP_DAYS", &c.keepDays, 0, 65535}, {"GOAUTHY_BACKUP_MAX_ENTRIES", &c.maxEntries, 1, 1 << 20},
	} {
		if text := getenv(option.name); text != "" {
			v, e := strconv.Atoi(text)
			if e != nil || v < option.min || v > option.max {
				return nil, fmt.Errorf("invalid %s", option.name)
			}
			*option.value = v
		}
	}
	if text := getenv("GOAUTHY_BACKUP_RETENTION_POLICY"); text != "" {
		c.retentionPolicy = backup.RetentionPolicy(text)
	}
	if c.retentionPolicy != backup.RetainLatest && c.retentionPolicy != backup.ExpireAll {
		return nil, errors.New("invalid GOAUTHY_BACKUP_RETENTION_POLICY")
	}
	c.recipients, err = backupconfig.ReadRecipients(getenv("GOAUTHY_BACKUP_RECIPIENT_FILE"))
	if err != nil {
		return nil, errors.New("invalid backup recipient file")
	}
	c.signer, _, err = backupconfig.ReadCatalogKey(getenv("GOAUTHY_BACKUP_SIGNING_KEY_FILE"), true)
	if err != nil {
		return nil, errors.New("invalid backup signing key file")
	}
	public := c.signer.Public().(ed25519.PublicKey)
	c.trustKeys = []ed25519.PublicKey{public}
	if name := getenv("GOAUTHY_BACKUP_TRUST_KEY_FILE"); name != "" {
		c.trustKeys, err = backupconfig.ReadCatalogTrustKeys(name)
		if err != nil {
			return nil, errors.New("invalid backup trust key file")
		}
		trusted := false
		for _, key := range c.trustKeys {
			trusted = trusted || public.Equal(key)
		}
		if !trusted {
			return nil, errors.New("backup trust bundle must include current signer")
		}
	}
	c.destination, c.separate, err = backupconfig.DestinationConfig(getenv, source)
	if err != nil {
		return nil, errors.New("invalid backup destination configuration")
	}
	// Scope includes storage identities, never credentials or a changing schedule.
	identity, _ := json.Marshal([]string{source.ClusterID, source.ObjStoreProvider, source.ObjStoreEndpoint, source.ObjStoreBucket, source.ObjStorePrefix, c.destination.ObjStoreProvider, c.destination.ObjStoreEndpoint, c.destination.ObjStoreBucket, c.catalog})
	c.scope = fmt.Sprintf("scheduled-backup/%x", sha256.Sum256(identity))
	return c, nil
}

type scheduledBackupRuntime struct {
	config              *scheduledBackupConfig
	source, destination objstore.Bucket
	mu                  sync.Mutex
	degraded            bool
}

// openBackupObjectStore is the provider factory the runtime opens with, kept as a
// variable so tests can substitute a bucket without a live provider.
var openBackupObjectStore = storage.OpenObjectStore

func newScheduledBackupRuntime(_ context.Context, c *scheduledBackupConfig) (*scheduledBackupRuntime, error) {
	if c == nil {
		return nil, nil
	}
	if err := os.MkdirAll(c.work, 0700); err != nil {
		return nil, errors.New("cannot create backup work directory")
	}
	info, err := os.Stat(c.work)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("backup work directory must be private")
	}
	if err := backup.CleanupWorkDir(c.work); err != nil {
		return nil, errors.New("cannot clean backup work directory")
	}
	return &scheduledBackupRuntime{config: c}, nil
}

func (r *scheduledBackupRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	if r.config.separate && r.destination != nil {
		err = r.destination.Close()
	}
	if r.source != nil {
		err = errors.Join(err, r.source.Close())
	}
	r.source, r.destination = nil, nil
	return err
}

// ensureReady keeps an optional remote backup target from gating identity
// startup. The worker retries this setup before every due slot after an outage.
func (r *scheduledBackupRuntime) ensureReady(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.source != nil && r.destination != nil {
		return nil
	}
	c := r.config
	initCtx, cancelInit := context.WithTimeout(ctx, 30*time.Second)
	defer cancelInit()
	source, err := openBackupObjectStore(initCtx, c.source)
	if err != nil {
		r.degraded = true
		return errors.New("cannot open backup source")
	}
	destination := source
	if c.separate {
		destination, err = openBackupObjectStore(initCtx, c.destination)
		if err != nil {
			_ = source.Close()
			r.degraded = true
			return errors.New("cannot open backup destination")
		}
	}
	cleanup := func() {
		if c.separate {
			_ = destination.Close()
		}
		_ = source.Close()
	}
	// Verification reads complete artifacts, so it uses the configured operation
	// budget rather than startup's short initialization window.
	checkCtx, cancelCheck := context.WithTimeout(ctx, max(c.timeout, 30*time.Second))
	defer cancelCheck()
	if _, err := backup.TrimCatalog(checkCtx, destination, c.catalog, c.trustKeys, time.Now(), c.keepDays, c.maxEntries, true, c.retentionPolicy); err != nil {
		cleanup()
		r.degraded = true
		return errors.New("cannot validate backup destination catalog")
	}
	// Only remove artifacts older than the longest possible attempt plus a
	// settlement window, so a concurrent publisher cannot lose its upload.
	before := time.Now().UTC().Add(-(c.timeout + c.lease + 5*time.Minute))
	if _, err := backup.SweepUncommittedArtifacts(checkCtx, destination, c.catalog, c.trustKeys, before, true); err != nil {
		cleanup()
		r.degraded = true
		return errors.New("cannot clean backup destination orphans")
	}
	r.source, r.destination = source, destination
	if r.degraded {
		slog.Info("scheduled backup recovered", "state", "ready")
	}
	r.degraded = false
	return nil
}

func (r *scheduledBackupRuntime) Run(ctx context.Context, db *rhiza.DB) error {
	c := r.config
	if ctx.Err() != nil {
		return nil
	}
	if err := r.ensureReady(ctx); err != nil {
		slog.Warn("scheduled backup degraded", "state", "degraded", "reason", backup.FailureMessage(err))
	}
	stage := "ownership"
	return c.schedule.Run(ctx, db, c.scope, c.location, c.lease, c.timeout, func(jobCtx context.Context) error {
		stage = "validation"
		if err := r.ensureReady(jobCtx); err != nil {
			return err
		}
		stage = "capacity"
		// Publication precedes retention, so reserve the slot the next completion
		// needs before uploading anything; an oversized catalog is already
		// unlistable and blocks both pruning and startup.
		if _, err := backup.TrimCatalog(jobCtx, r.destination, c.catalog, c.trustKeys, time.Now(), c.keepDays, backup.RetentionTarget(c.maxEntries, 1), true, c.retentionPolicy); err != nil {
			return err
		}
		stage = "create"
		_, err := backup.Create(jobCtx, r.source, r.destination, path.Join(c.source.ObjStorePrefix, c.source.ClusterID), c.source.ClusterID, c.catalog, c.recipients, c.signer, c.work, backup.Limits{MaxFiles: 65536, MaxFileBytes: 1 << 30, MaxTotalBytes: 8 << 30})
		if err != nil {
			return err
		}
		stage = "retention"
		_, err = backup.TrimCatalog(jobCtx, r.destination, c.catalog, c.trustKeys, time.Now(), c.keepDays, c.maxEntries, true, c.retentionPolicy)
		if err == nil {
			stage = "completion"
		}
		return err
	}, func(due time.Time, executed bool, err error) {
		defer func() { stage = "ownership" }()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if stage == "ownership" {
				switch {
				case errors.Is(err, backupschedule.ErrLeaseAcquire):
					stage = "lease_acquire"
				case errors.Is(err, backupschedule.ErrCompletionRead):
					stage = "completion_read"
				}
			}
			if stage == "capacity" {
				stage = "capacity_reservation"
			}
			slog.Error("scheduled backup attempt failed", "scheduled_at", due.UTC(), "stage", stage, "reason", backup.FailureMessage(err))
			return
		}
		if executed {
			slog.Info("scheduled backup completed", "scheduled_at", due.UTC())
		}
	})
}
