package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/mrchypark/goauthy/internal/backup"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/rhiza"
)

func TestScheduledBackupConfigDisabledDoesNotReadFiles(t *testing.T) {
	config, err := scheduledBackupFromEnv(func(name string) string {
		if name != "GOAUTHY_BACKUP_ENABLED" {
			t.Fatalf("disabled configuration read %s", name)
		}
		return ""
	}, rhiza.Config{})
	if err != nil || config != nil {
		t.Fatalf("disabled config = %#v, %v", config, err)
	}
}

func TestScheduledBackupConfigRejectsInvalidValues(t *testing.T) {
	for name, value := range map[string]string{
		"GOAUTHY_BACKUP_ENABLED":          "maybe",
		"GOAUTHY_BACKUP_RETENTION_POLICY": "unknown",
		"GOAUTHY_BACKUP_SCHEDULE":         "not cron",
		"GOAUTHY_BACKUP_TIMEZONE":         "Mars/Olympus",
		"GOAUTHY_BACKUP_LEASE":            "0s",
		"GOAUTHY_BACKUP_TIMEOUT":          "25h",
		"GOAUTHY_BACKUP_KEEP_DAYS":        "65536",
		"GOAUTHY_BACKUP_MAX_ENTRIES":      "1048577",
	} {
		t.Run(name, func(t *testing.T) {
			env, source := scheduledTestConfigKeys(t)
			env[name] = value
			if _, err := scheduledBackupFromEnv(scheduledTestEnv(env), source); err == nil {
				t.Fatalf("accepted %s=%q", name, value)
			}
		})
	}
}

func TestScheduledBackupConfigRejectsMissingAndOverlappingLocations(t *testing.T) {
	for name := range map[string]struct{}{
		"GOAUTHY_BACKUP_CATALOG_PREFIX":   {},
		"GOAUTHY_BACKUP_WORK_DIR":         {},
		"GOAUTHY_BACKUP_RECIPIENT_FILE":   {},
		"GOAUTHY_BACKUP_SIGNING_KEY_FILE": {},
	} {
		t.Run("missing "+name, func(t *testing.T) {
			env, source := scheduledTestConfigKeys(t)
			delete(env, name)
			if _, err := scheduledBackupFromEnv(scheduledTestEnv(env), source); err == nil {
				t.Fatalf("accepted missing %s", name)
			}
		})
	}
	for _, catalog := range []string{"source", "source/cluster/catalog", "source/cluster"} {
		t.Run("overlap "+catalog, func(t *testing.T) {
			env, source := scheduledTestConfigKeys(t)
			env["GOAUTHY_BACKUP_CATALOG_PREFIX"] = catalog
			if _, err := scheduledBackupFromEnv(scheduledTestEnv(env), source); err == nil {
				t.Fatalf("accepted overlapping catalog %q", catalog)
			}
		})
	}
}

func TestScheduledBackupConfigLoadsNativeKeysAndDefaults(t *testing.T) {
	env, source := scheduledTestConfigKeys(t)
	config, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	if config == nil || len(config.recipients) != 1 || len(config.signer) != ed25519.PrivateKeySize || config.schedule == nil || config.location != time.Local {
		t.Fatalf("invalid parsed configuration: %#v", config)
	}
	if config.lease != time.Minute || config.timeout != 15*time.Minute || config.keepDays != 30 || config.maxEntries != 4096 {
		t.Fatalf("unexpected defaults: lease=%s timeout=%s days=%d entries=%d", config.lease, config.timeout, config.keepDays, config.maxEntries)
	}
	if config.separate || !reflect.DeepEqual(config.destination, source) || config.scope == "" {
		t.Fatalf("unexpected source destination configuration: %#v", config)
	}
}

func TestScheduledBackupConfigDestinationDoesNotInheritSourceCredentials(t *testing.T) {
	env, source := scheduledTestConfigKeys(t)
	env["GOAUTHY_BACKUP_OBJECT_STORE_PROVIDER"] = "s3"
	env["GOAUTHY_BACKUP_OBJECT_STORE_BUCKET"] = "recovery"
	config, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	if !config.separate || config.destination.ObjStoreBucket != "recovery" || config.destination.ObjStoreAccessKey != "" || config.destination.ObjStoreSecretKey != "" {
		t.Fatalf("destination inherited source credentials: %#v", config.destination)
	}
}

func TestScheduledBackupPrivateWorkDirectoryRejectsBeforeObjectStore(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0755); err != nil {
		t.Fatal(err)
	}
	_, err := newScheduledBackupRuntime(context.Background(), &scheduledBackupConfig{work: work})
	if err == nil || !strings.Contains(err.Error(), "work directory must be private") {
		t.Fatalf("runtime error = %v", err)
	}
}

func scheduledTestConfigKeys(t *testing.T) (map[string]string, rhiza.Config) {
	t.Helper()
	root := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient := filepath.Join(root, "recipient.txt")
	signing := filepath.Join(root, "catalog.pem")
	work := filepath.Join(root, "work")
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recipient, []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signing, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GOAUTHY_BACKUP_ENABLED": "true", "GOAUTHY_BACKUP_CATALOG_PREFIX": "catalog", "GOAUTHY_BACKUP_WORK_DIR": work,
		"GOAUTHY_BACKUP_RECIPIENT_FILE": recipient, "GOAUTHY_BACKUP_SIGNING_KEY_FILE": signing,
		"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "cluster", "GOAUTHY_NODE_ID": "node", "GOAUTHY_DATA_DIR": filepath.Join(root, "data"),
	}
	return env, rhiza.Config{ClusterID: "cluster", ObjStoreProvider: "s3", ObjStoreBucket: "source", ObjStorePrefix: "source", ObjStoreAccessKey: "source-access", ObjStoreSecretKey: "source-secret"}
}

func scheduledTestEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestScheduledBackupConfigScopeSurvivesCredentialAndScheduleChanges(t *testing.T) {
	env, source := scheduledTestConfigKeys(t)
	first, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	env["GOAUTHY_BACKUP_SCHEDULE"] = "@hourly"
	source.ObjStoreAccessKey = "rotated-access"
	source.ObjStoreSecretKey = "rotated-secret"
	rotated, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	if first.scope != rotated.scope {
		t.Fatal("credential/schedule rotation changed shared job ownership scope")
	}
	env["GOAUTHY_BACKUP_CATALOG_PREFIX"] = "other-catalog"
	other, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	if first.scope == other.scope {
		t.Fatal("independent catalog shares job ownership scope")
	}
}

func TestScheduledBackupTrustRotationConfig(t *testing.T) {
	env, source := scheduledTestConfigKeys(t)
	original, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil {
		t.Fatal(err)
	}
	oldPublic := original.signer.Public().(ed25519.PublicKey)
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustFile := filepath.Join(t.TempDir(), "trust.pem")
	env["GOAUTHY_BACKUP_TRUST_KEY_FILE"] = trustFile
	writeTrust := func(keys ...ed25519.PublicKey) {
		t.Helper()
		var raw []byte
		for _, key := range keys {
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
		}
		if err := os.WriteFile(trustFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTrust(newPublic)
	if _, err := scheduledBackupFromEnv(scheduledTestEnv(env), source); err == nil {
		t.Fatal("accepted trust excluding current signer")
	}
	writeTrust(oldPublic, newPublic)
	staged, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil || len(staged.trustKeys) != 2 || staged.scope != original.scope {
		t.Fatal("overlap trust changed ownership or failed", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env["GOAUTHY_BACKUP_SIGNING_KEY_FILE"], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	rotated, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil || rotated.scope != original.scope || !rotated.signer.Public().(ed25519.PublicKey).Equal(newPublic) {
		t.Fatal("rotation failed or changed ownership", err)
	}
}

func TestScheduledBackupRetentionPolicy(t *testing.T) {
	env, source := scheduledTestConfigKeys(t)
	original, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
	if err != nil || original.retentionPolicy != backup.RetainLatest {
		t.Fatalf("default: %v %v", original, err)
	}
	for _, days := range []string{"0", "65535"} {
		env["GOAUTHY_BACKUP_KEEP_DAYS"] = days
		env["GOAUTHY_BACKUP_RETENTION_POLICY"] = "expire-all"
		config, err := scheduledBackupFromEnv(scheduledTestEnv(env), source)
		if err != nil || config.retentionPolicy != backup.ExpireAll || config.scope != original.scope {
			t.Fatalf("policy days=%s: %v", days, err)
		}
	}
}
