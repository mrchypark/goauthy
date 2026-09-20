package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/thanos-io/objstore"
)

// slowArtifactBucket stands in for a healthy artifact whose complete read needs
// longer than a short deadline: the read fails unless the context still allows
// the full cost. Metadata operations pass through untouched.
type slowArtifactBucket struct {
	objstore.Bucket
	artifact string
	read     time.Duration
	reads    int
}

func (b *slowArtifactBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if name != b.artifact {
		return b.Bucket.Get(ctx, name)
	}
	b.reads++
	// ponytail: the read cost is compared against the remaining deadline instead
	// of sleeping for minutes, so the test stays instant; upgrade to a paced
	// reader only if the deadline arithmetic itself needs coverage.
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < b.read {
		return nil, errors.New("artifact read outlasts the deadline")
	}
	return b.Bucket.Get(ctx, name)
}

// TestScheduledBackupRuntimeStartupVerifiesArtifactWithinOperationBudget covers a
// catalog below capacity with fast metadata and a healthy artifact that takes
// longer than the fixed 30s startup deadline to read. Recoverability verification
// must still run, but on the configured backup-operation budget, so startup stays
// supported.
func TestScheduledBackupRuntimeStartupVerifiesArtifactWithinOperationBudget(t *testing.T) {
	for _, policy := range []backup.RetentionPolicy{backup.RetainLatest, backup.ExpireAll} {
		t.Run(string(policy), func(t *testing.T) {
			ctx := context.Background()
			bucket := objstore.NewInMemBucket()
			defer bucket.Close()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "catalog/cluster-a"
			artifact, err := os.CreateTemp(t.TempDir(), "artifact-*.age")
			if err != nil {
				t.Fatal(err)
			}
			defer artifact.Close()
			if _, err := artifact.Write(append([]byte("age-encryption.org/v1\n"), bytes.Repeat([]byte{'x'}, 4096)...)); err != nil {
				t.Fatal(err)
			}
			entry, err := backup.Publish(ctx, bucket, prefix, "source/a", artifact, private, time.Now().Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			slow := &slowArtifactBucket{Bucket: bucket, artifact: path.Join(prefix, "artifacts", entry.ID+".age"), read: 45 * time.Second}
			openBackupObjectStore = func(context.Context, rhiza.Config) (objstore.Bucket, error) { return slow, nil }
			t.Cleanup(func() { openBackupObjectStore = storage.OpenObjectStore })
			runtime, err := newScheduledBackupRuntime(ctx, &scheduledBackupConfig{
				work: filepath.Join(t.TempDir(), "work"), catalog: prefix, keepDays: 30, maxEntries: 4096,
				timeout: 15 * time.Minute, retentionPolicy: policy, trustKeys: []ed25519.PublicKey{public},
			})
			if err != nil {
				t.Fatalf("startup rejected a healthy catalog: %v", err)
			}
			defer runtime.Close()
			if slow.reads == 0 {
				t.Fatal("startup skipped artifact verification")
			}
			if entries, err := backup.ListCompleted(ctx, bucket, prefix, []ed25519.PublicKey{public}, 1); err != nil || len(entries) != 1 {
				t.Fatalf("entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestScheduledBackupRuntimeS3(t *testing.T) {
	endpoint := os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires disposable S3 fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	root := t.TempDir()
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := filepath.Join(root, "recipients")
	if err := os.WriteFile(recipient, []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldPublic, oldKey := scheduledRuntimeSigningKey(t, root, "old-signer")
	newPublic, newKey := scheduledRuntimeSigningKey(t, root, "new-signer")
	newTrust := scheduledRuntimeTrustBundle(t, root, "new-trust", newPublic)
	allTrust := scheduledRuntimeTrustBundle(t, root, "all-trust", oldPublic, newPublic)
	prefix := fmt.Sprintf("server-backup-%d", time.Now().UnixNano())
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "scheduled", "GOAUTHY_NODE_ID": "source", "GOAUTHY_DATA_DIR": filepath.Join(root, "source"),
		"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER": "s3", "GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT": endpoint, "GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": os.Getenv("GOAUTHY_RECOVERY_S3_BUCKET"), "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": prefix,
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY"), "GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY"), "GOAUTHY_RHIZA_OBJECT_STORE_INSECURE": "true", "GOAUTHY_RHIZA_OBJECT_STORE_REGION": "us-east-1",
		"GOAUTHY_BACKUP_ENABLED": "true", "GOAUTHY_BACKUP_TIMEZONE": "UTC", "GOAUTHY_BACKUP_CATALOG_PREFIX": prefix + "-catalog", "GOAUTHY_BACKUP_WORK_DIR": filepath.Join(root, "work"), "GOAUTHY_BACKUP_RECIPIENT_FILE": recipient, "GOAUTHY_BACKUP_SIGNING_KEY_FILE": oldKey,
	}
	getenv := func(name string) string { return env[name] }
	source, err := storage.RhizaConfigFromEnv(getenv)
	if err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "schema", SQL: "CREATE TABLE scheduled_markers (name TEXT PRIMARY KEY)"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "row", SQL: "INSERT INTO scheduled_markers VALUES ('retained')"}); err != nil {
		t.Fatal(err)
	}
	env["GOAUTHY_BACKUP_SCHEDULE"] = scheduledRuntimeOneShot(time.Now().UTC().Add(5 * time.Second))
	config, err := scheduledBackupFromEnv(getenv, source)
	if err != nil {
		t.Fatal(err)
	}
	if config.retentionPolicy != backup.RetainLatest {
		t.Fatalf("default retention policy = %q", config.retentionPolicy)
	}
	oldRuntime, err := newScheduledBackupRuntime(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	scheduledRuntimeRun(t, ctx, oldRuntime, db)
	files, err := os.ReadDir(config.work)
	if err != nil || len(files) != 0 {
		t.Fatalf("worker left scratch: %v", err)
	}
	oldEntries, err := backup.ListCompleted(ctx, oldRuntime.destination, config.catalog, []ed25519.PublicKey{oldPublic}, 100)
	if err != nil || len(oldEntries) != 1 {
		t.Fatalf("completed catalog count=%d err=%v", len(oldEntries), err)
	}
	oldID := oldEntries[0].ID
	foreignCiphertext, _, err := backup.FetchCompleted(ctx, oldRuntime.destination, config.catalog, oldID, config.trustKeys, config.work, 16<<30)
	if err != nil {
		t.Fatal(err)
	}
	foreignFile, err := os.Open(foreignCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	foreign, publishErr := backup.Publish(ctx, oldRuntime.destination, config.catalog, "foreign-source", foreignFile, config.signer, time.Now().AddDate(0, 0, -40))
	closeErr := foreignFile.Close()
	removeErr := os.Remove(foreignCiphertext)
	if publishErr != nil || closeErr != nil || removeErr != nil {
		t.Fatalf("seed expired foreign backup: %v %v %v", publishErr, closeErr, removeErr)
	}
	planned, err := backup.PruneWithPolicy(ctx, oldRuntime.destination, config.catalog, config.trustKeys, time.Now(), config.keepDays, config.maxEntries, false, backup.RetainLatest)
	if err != nil || len(planned) != 0 {
		t.Fatalf("default retain-latest plan=%v err=%v", planned, err)
	}
	if err := oldRuntime.Close(); err != nil {
		t.Fatal(err)
	}

	// A new signer alone is insufficient while an old, valid completion exists.
	env["GOAUTHY_BACKUP_SIGNING_KEY_FILE"] = newKey
	env["GOAUTHY_BACKUP_TRUST_KEY_FILE"] = newTrust
	denied, err := scheduledBackupFromEnv(getenv, source)
	if err != nil {
		t.Fatal(err)
	}
	if runtime, err := newScheduledBackupRuntime(ctx, denied); err == nil {
		_ = runtime.Close()
		t.Fatal("accepted old catalog record without old trusted key")
	}

	env["GOAUTHY_BACKUP_TRUST_KEY_FILE"] = allTrust
	env["GOAUTHY_BACKUP_RETENTION_POLICY"] = string(backup.ExpireAll)
	env["GOAUTHY_BACKUP_SCHEDULE"] = scheduledRuntimeOneShot(time.Now().UTC().Add(5 * time.Second))
	rotated, err := scheduledBackupFromEnv(getenv, source)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.retentionPolicy != backup.ExpireAll {
		t.Fatalf("rotated retention policy = %q", rotated.retentionPolicy)
	}
	if config.scope != rotated.scope {
		t.Fatalf("key rotation changed backup scope: %q != %q", config.scope, rotated.scope)
	}
	newRuntime, err := newScheduledBackupRuntime(ctx, rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer newRuntime.Close()
	scheduledRuntimeRun(t, ctx, newRuntime, db)
	for _, object := range []string{
		path.Join(rotated.catalog, "artifacts", foreign.ID+".age"),
		path.Join(rotated.catalog, "completed", foreign.ID+".json"),
	} {
		if exists, err := newRuntime.destination.Exists(ctx, object); err != nil || exists {
			t.Fatalf("expire-all retained foreign object %q exists=%t err=%v", object, exists, err)
		}
	}
	entries, err := backup.ListCompleted(ctx, newRuntime.destination, rotated.catalog, []ed25519.PublicKey{oldPublic, newPublic}, 100)
	if err != nil || len(entries) != 2 {
		t.Fatalf("rotated catalog count=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		fetched, _, err := backup.FetchCompleted(ctx, newRuntime.destination, rotated.catalog, entry.ID, []ed25519.PublicKey{oldPublic, newPublic}, rotated.work, 16<<30)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(fetched)
		if err != nil {
			t.Fatal(err)
		}
		limits := backup.Limits{MaxFiles: 65536, MaxFileBytes: 1 << 30, MaxTotalBytes: 8 << 30}
		staged, extractErr := backup.Extract(file, []age.Identity{identity}, rotated.work, limits)
		closeErr := file.Close()
		removeErr := os.Remove(fetched)
		if extractErr != nil || closeErr != nil || removeErr != nil {
			t.Fatalf("extract %s: %v %v %v", entry.ID, extractErr, closeErr, removeErr)
		}
		target := source
		target.ObjStorePrefix = prefix + "-restore-" + entry.ID
		target.DataDir = filepath.Join(root, "restored-"+entry.ID)
		if _, err := backup.Restore(ctx, newRuntime.source, path.Join(target.ObjStorePrefix, target.ClusterID), target.ClusterID, staged, rotated.work); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(staged.Dir); err != nil {
			t.Fatal(err)
		}
		restored, err := rhiza.Open(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		result, queryErr := restored.Query(ctx, rhiza.QueryRequest{SQL: "SELECT name FROM scheduled_markers", Consistency: rhiza.ConsistencyLinearizable})
		closeErr = restored.Close()
		if queryErr != nil || closeErr != nil || len(result.Rows) != 1 || result.Rows[0][0] != "retained" {
			t.Fatalf("restored %s data=%v query=%v close=%v", entry.ID, result.Rows, queryErr, closeErr)
		}
	}
	seenOld := false
	for _, entry := range entries {
		seenOld = seenOld || entry.ID == oldID
	}
	if !seenOld {
		t.Fatalf("old completion %q disappeared after rotation", oldID)
	}
}

func scheduledRuntimeSigningKey(t *testing.T, root, name string) (ed25519.PublicKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, name+".pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return public, file
}

func scheduledRuntimeTrustBundle(t *testing.T, root, name string, keys ...ed25519.PublicKey) string {
	t.Helper()
	var bundle bytes.Buffer
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := pem.Encode(&bundle, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(root, name+".pem")
	if err := os.WriteFile(file, bundle.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return file
}

func scheduledRuntimeOneShot(due time.Time) string {
	due = due.UTC().Truncate(time.Second)
	return fmt.Sprintf("%d %d %d %d %d %d %d", due.Second(), due.Minute(), due.Hour(), due.Day(), due.Month(), int(due.Weekday())+1, due.Year())
}

func scheduledRuntimeRun(t *testing.T, ctx context.Context, runtime *scheduledBackupRuntime, db *rhiza.DB) {
	t.Helper()
	due, err := runtime.config.schedule.Next(ctx, time.Now().In(runtime.config.location))
	if err != nil || due.IsZero() {
		t.Fatalf("next scheduled backup due=%s err=%v", due, err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx, db) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scheduled runtime: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("scheduled runtime did not finish")
	}
	markerKey := fmt.Sprintf("goauthy/backup-completed/%x", sha256.Sum256([]byte(runtime.config.scope)))
	marker, err := db.KVGet(ctx, rhiza.KVGetRequest{Key: markerKey, Consistency: "linearizable"})
	if err != nil || !marker.Found || string(marker.Value) != strconv.FormatInt(due.Unix(), 10) {
		t.Fatalf("completion marker found=%t value=%q due=%d err=%v", marker.Found, marker.Value, due.Unix(), err)
	}
}
