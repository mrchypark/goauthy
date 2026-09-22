package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	kitlog "github.com/go-kit/log"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
	thanoss3 "github.com/thanos-io/objstore/providers/s3"
)

// TestNoPVCPublicRhizaSnapshotCapture is a prototype for the public Rhiza
// manager capture contract, integrated with the encrypted bundle and Restore.
func TestNoPVCPublicRhizaSnapshotCapture(t *testing.T) {
	t.Parallel()
	timeout := 90 * time.Second
	if os.Getenv("GOAUTHY_EXPORT_GC_TEST") == "1" {
		timeout = 4 * time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source-objects")
	config := noPVCExportConfig(t, root, filepath.Join(root, "writer"), sourceDir)
	keyDir := filepath.Join(root, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "test-key"), []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Migrate(ctx, db); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	users, err := identity.NewStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("Disposable export prototype password 7!"))
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := users.BootstrapUser(ctx, "export-user", "export@example.test", phc); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	const issuer = "https://export.example.test"
	key, err := oidc.EnsureSigningKey(ctx, db, keyring, issuer, time.Now())
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public-kid"), []byte(key.PublicJWK.KeyID), 0600); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := verifyNoPVCGeneratedAPIKey(ctx, db, keyring, root, config.DataDir, true); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	verifyNoPVCInitialArchiveCapture(t, ctx, db, config, keyring, root, issuer, key.PublicJWK.KeyID)
	// Close publishes a certified checkpoint in this deterministic single-node fixture.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	prefix := path.Join(config.ObjStorePrefix, config.ClusterID)
	retiredRoot := noPVCExportOnlyCheckpointRoot(t, ctx, config, prefix)
	live, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatalf("reopen source writer: %v", err)
	}
	closeLive := true
	defer func() {
		if closeLive {
			if err := live.Close(); err != nil {
				t.Errorf("close source writer: %v", err)
			}
		}
	}()
	mustNoPVCExportExecute(t, ctx, live, "export-before-schema", `CREATE TABLE export_snapshot_markers (name TEXT PRIMARY KEY)`)
	mustNoPVCExportExecute(t, ctx, live, "export-before-marker", `INSERT INTO export_snapshot_markers(name) VALUES('before-snapshot')`)
	if err := live.Close(); err != nil {
		t.Fatalf("close source writer for selected checkpoint: %v", err)
	}
	closeLive = false
	live, err = rhiza.Open(ctx, config)
	if err != nil {
		t.Fatalf("reopen source writer at selected checkpoint: %v", err)
	}
	closeLive = true
	mustNoPVCExportExecute(t, ctx, live, "export-archive-before-marker", `INSERT INTO export_snapshot_markers(name) VALUES('archive-before-snapshot')`)
	productStaged := productionNoPVCExport(t, ctx, config, prefix, func() {
		mustNoPVCExportExecute(t, ctx, live, "export-during-product", `INSERT INTO export_snapshot_markers(name) VALUES('during-product-export')`)
	})
	captured, checkpointRoot := captureNoPVCExport(t, ctx, config, prefix, func(snapshotTip uint64, selected *checkpoint.Checkpoint, renew func() error) {
		mustNoPVCExportExecute(t, ctx, live, "export-after-marker", `INSERT INTO export_snapshot_markers(name) VALUES('after-snapshot')`)
		bucket := noPVCExportBucket(t, config)
		defer func() {
			if err := bucket.Close(); err != nil {
				t.Errorf("close source archive observer bucket: %v", err)
			}
		}()
		observer := recovery.NewManager(bucket, prefix, 1)
		defer observer.Close()
		if err := observer.Load(ctx); err != nil {
			t.Fatalf("load source archive after post-snapshot write: %v", err)
		}
		if uint64(observer.Tip()) <= snapshotTip {
			t.Fatalf("source archive did not advance after post-snapshot write: tip=%d snapshot=%d", observer.Tip(), snapshotTip)
		}
		if os.Getenv("GOAUTHY_EXPORT_GC_TEST") == "1" {
			if err := live.Close(); !errors.Is(err, recovery.ErrArchiveBusy) {
				t.Fatalf("close source writer while export pin is active: %v", err)
			}
			closeLive = false
			noPVCExportWaitPinnedGC(t, ctx, config, prefix, retiredRoot, selected, renew)
		}
	})
	if closeLive {
		if err := live.Close(); err != nil {
			t.Fatalf("close source writer after snapshot: %v", err)
		}
		closeLive = false
	}
	if len(captured) == 0 || checkpointRoot == nil {
		t.Fatal("public Rhiza snapshot capture returned no recovery objects")
	}
	staged := productStaged
	for _, section := range []string{"checkpoint/roots/", "checkpoint/blocks/", "archive/head.bin", "archive/blocks/"} {
		t.Run("reject-"+strings.ReplaceAll(section, "/", "-"), func(t *testing.T) {
			changed := make(map[string][]byte, len(captured))
			changedName := ""
			for name, data := range captured {
				changed[name] = data
				if changedName == "" && strings.HasPrefix(name, prefix+"/"+section) {
					changed[name] = bytes.Clone(data)
					changed[name][0] ^= 1
					changedName = name
				}
			}
			if changedName == "" {
				t.Fatal("missing corruption target")
			}
			// Recompute the manifest and encrypt validly: rejection must come
			// from Rhiza verification, not age or the outer inventory digest.
			invalid := encryptedNoPVCExport(t, config, prefix, changed, checkpointRoot)
			if _, err := backup.ReadManifest(invalid.Dir, invalid.Inventory); err != nil {
				t.Fatalf("corruption fixture manifest is invalid: %v", err)
			}
			destination := path.Join(config.ObjStorePrefix+"-invalid-"+strings.ReplaceAll(section, "/", "-"), config.ClusterID)
			bucket := noPVCExportBucket(t, config)
			defer bucket.Close()
			if _, err := backup.Restore(ctx, bucket, destination, config.ClusterID, invalid, t.TempDir()); err == nil {
				t.Fatal("restore accepted corrupt Rhiza object")
			}
			for object, want := range map[string]bool{"goauthy-restore.json": true, "checkpoint/CURRENT": false} {
				exists, err := bucket.Exists(ctx, path.Join(destination, object))
				if err != nil || exists != want {
					t.Fatalf("failed restore %s exists=%v want=%v: %v", object, exists, want, err)
				}
			}
		})
	}

	targetDir := filepath.Join(root, "target-objects")
	recoveredConfig := noPVCExportConfig(t, root, filepath.Join(root, "recovered"), targetDir)
	recoveredConfig.ObjStorePrefix = config.ObjStorePrefix + "-restore"
	restoreNoPVCExport(t, ctx, recoveredConfig, path.Join(recoveredConfig.ObjStorePrefix, recoveredConfig.ClusterID), staged)
	recovered, err := rhiza.Open(ctx, recoveredConfig)
	if err != nil {
		t.Fatalf("open clean prefix restored by public managers: %v", err)
	}
	defer recovered.Close()
	recoveredUsers, err := identity.NewStore(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if noPVCExportMarkerCount(t, ctx, recovered, "during-product-export") != 0 {
		t.Fatal("product export included a write after its snapshot boundary")
	}
	user, err := recoveredUsers.Authenticate(ctx, "export@example.test", []byte("Disposable export prototype password 7!"))
	if err != nil || user.Subject != "export-user" {
		t.Fatal("restored account authentication failed", err)
	}
	loaded, err := oidc.LoadActiveSigningKey(ctx, recovered, keyring, issuer)
	if err != nil || loaded.PublicJWK.KeyID != key.PublicJWK.KeyID {
		t.Fatal("restored signing key changed", err)
	}
	if err := verifyNoPVCGeneratedAPIKey(ctx, recovered, keyring, root, recoveredConfig.DataDir, false); err != nil {
		t.Fatal(err)
	}
	if got := noPVCExportMarkerCount(t, ctx, recovered, "before-snapshot"); got != 1 {
		t.Fatalf("pre-snapshot marker count=%d want 1", got)
	}
	if got := noPVCExportMarkerCount(t, ctx, recovered, "archive-before-snapshot"); got != 1 {
		t.Fatalf("archive pre-snapshot marker count=%d want 1", got)
	}
	if got := noPVCExportMarkerCount(t, ctx, recovered, "after-snapshot"); got != 0 {
		t.Fatalf("post-snapshot marker count=%d want 0", got)
	}
}

func noPVCExportConfig(t *testing.T, root, dataDir, objectDir string) rhiza.Config {
	t.Helper()
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "export-cluster",
		"GOAUTHY_NODE_ID": "export-node", "GOAUTHY_DATA_DIR": dataDir,
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": "export-test", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": "export-prefix",
	}
	config, err := storage.RhizaConfigFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	config.ObjStoreProvider, config.ObjStoreDir = "filesystem", objectDir
	if endpoint := os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT"); endpoint != "" {
		config.ObjStoreProvider, config.ObjStoreDir = "s3", ""
		config.ObjStoreEndpoint, config.ObjStoreBucket = endpoint, os.Getenv("GOAUTHY_RECOVERY_S3_BUCKET")
		config.ObjStoreRegion, config.ObjStoreAccessKey = "us-east-1", os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY")
		config.ObjStoreSecretKey, config.ObjStoreInsecure = os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY"), true
		if config.ObjStoreBucket == "" || config.ObjStoreAccessKey == "" || config.ObjStoreSecretKey == "" {
			t.Fatal("GOAUTHY_RECOVERY_S3_BUCKET, ACCESS_KEY, and SECRET_KEY are required with endpoint")
		}
	}
	config.ObjStoreDurability = rhiza.ObjectStoreDurabilityBeforeAck
	config.CheckpointInterval = time.Hour
	return config
}

func mustNoPVCExportExecute(t *testing.T, ctx context.Context, db *rhiza.DB, requestID, sql string) {
	t.Helper()
	if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql}); err != nil {
		t.Fatalf("execute %s: %v", requestID, err)
	}
}

func noPVCExportMarkerCount(t *testing.T, ctx context.Context, db *rhiza.DB, marker string) int64 {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM export_snapshot_markers WHERE name=?`, Args: []any{marker}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("query marker %q: %v", marker, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("query marker %q returned %T, want int64", marker, result.Rows[0][0])
	}
	return count
}

func noPVCExportBucket(t *testing.T, config rhiza.Config) objstore.Bucket {
	t.Helper()
	if config.ObjStoreProvider == "filesystem" {
		bucket, err := filesystem.NewBucket(config.ObjStoreDir)
		if err != nil {
			t.Fatal(err)
		}
		return bucket
	}
	bucket, err := thanoss3.NewBucketWithConfig(kitlog.NewNopLogger(), thanoss3.Config{Bucket: config.ObjStoreBucket, Endpoint: config.ObjStoreEndpoint, Region: config.ObjStoreRegion, Insecure: config.ObjStoreInsecure, AWSSDKAuth: false, AccessKey: config.ObjStoreAccessKey, SecretKey: config.ObjStoreSecretKey}, "goauthy-export-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return bucket
}

func noPVCExportOnlyCheckpointRoot(t *testing.T, ctx context.Context, config rhiza.Config, prefix string) string {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	var roots []string
	if err := bucket.Iter(ctx, prefix+"/checkpoint/roots", func(name string) error {
		if strings.HasSuffix(name, ".json") {
			roots = append(roots, name)
		}
		return nil
	}, objstore.WithRecursiveIter()); err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Fatalf("initial source checkpoint roots=%d want 1", len(roots))
	}
	return roots[0]
}

func noPVCExportWaitPinnedGC(t *testing.T, ctx context.Context, config rhiza.Config, prefix, retired string, selected *checkpoint.Checkpoint, renew func() error) {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	gc := checkpoint.NewManager(bucket, prefix, t.TempDir(), 1)
	if err := gc.Load(ctx); err != nil {
		t.Fatalf("load current checkpoint before pinned GC: %v", err)
	}
	current := gc.Latest()
	if current == nil || current.Index <= selected.Index || current.RootHash == selected.RootHash {
		t.Fatalf("CURRENT did not advance beyond selected pinned root: current=%v selected=%d", current, selected.Index)
	}
	renewed := false
	for {
		err := gc.GarbageCollectFrom(ctx, nil, 1, 0, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, checkpoint.ErrPublisherBusy) {
			t.Fatalf("public checkpoint GC: %v", err)
		}
		if err := renew(); err != nil {
			t.Fatalf("renew paired export pins during GC wait: %v", err)
		}
		renewed = true
		select {
		case <-ctx.Done():
			t.Fatalf("publisher lease did not clear before deadline: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if !renewed {
		t.Fatal("GC succeeded without observing active publisher lease")
	}
	exists, err := bucket.Exists(ctx, retired)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("checkpoint GC kept unpinned retired root")
	}
	if _, err := gc.OpenRoot(ctx, selected.Index, selected.RootHash); err != nil {
		t.Fatalf("checkpoint GC removed selected pinned root: %v", err)
	}
	archive := recovery.NewManager(bucket, prefix, 1)
	defer archive.Close()
	if err := archive.Cleanup(ctx, 0); err != nil {
		t.Fatalf("public archive GC: %v", err)
	}
}

func captureNoPVCExport(t *testing.T, ctx context.Context, config rhiza.Config, prefix string, afterPinned func(uint64, *checkpoint.Checkpoint, func() error)) (map[string][]byte, *checkpoint.Checkpoint) {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	capture := &noPVCExportCaptureBucket{Bucket: bucket, prefix: prefix, objects: make(map[string][]byte), partial: make(map[string]struct{})}
	archive := recovery.NewManager(capture, prefix, 1)
	defer archive.Close()
	snapshot, err := archive.BeginRecoverySnapshot(ctx, "no-pvc-export-prototype", 3*time.Minute)
	if err != nil {
		t.Fatalf("begin archive recovery snapshot: %v", err)
	}
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			if err := snapshot.Close(context.Background()); err != nil {
				t.Errorf("close archive recovery snapshot: %v", err)
			}
		}
	}()
	seal, base, ok := snapshot.RecoveryBase()
	if !ok {
		t.Fatal("archive recovery snapshot has no certified checkpoint base")
	}
	checkpoints := checkpoint.NewManager(capture, prefix, t.TempDir(), 1)
	root, err := checkpoints.OpenRoot(ctx, uint64(seal.Index), seal.RootHash)
	if err != nil {
		t.Fatalf("open selected checkpoint root: %v", err)
	}
	if root.Hash != seal.StateHash {
		t.Fatal("selected checkpoint root does not match archive recovery seal")
	}
	pin, err := checkpoints.PinRecoveryRoot(ctx, root, "no-pvc-export-prototype", 3*time.Minute)
	if err != nil {
		t.Fatalf("pin selected checkpoint root: %v", err)
	}
	pinOpen := true
	defer func() {
		if pinOpen {
			if err := pin.Close(context.Background()); err != nil {
				t.Errorf("close checkpoint recovery pin: %v", err)
			}
		}
	}()
	root, err = pin.Root()
	if err != nil {
		t.Fatalf("read pinned checkpoint root: %v", err)
	}
	renew := func() error {
		if err := pin.Renew(ctx, 3*time.Minute); err != nil {
			return err
		}
		return snapshot.Renew(ctx, 3*time.Minute)
	}
	if err := renew(); err != nil {
		t.Fatalf("renew checkpoint recovery pin: %v", err)
	}
	snapshotTip := uint64(snapshot.Tip())
	if afterPinned != nil {
		afterPinned(snapshotTip, root, renew)
	}
	if uint64(snapshot.Tip()) != snapshotTip {
		t.Fatal("pinned archive snapshot tip changed after source advancement")
	}
	for next := base.Slot + 1; next <= snapshot.Tip(); {
		values, _, err := snapshot.DecisionsFrom(ctx, next, 256)
		if err != nil || len(values) == 0 {
			t.Fatalf("validate pinned archive at slot %d: %v", next, err)
		}
		next = values[len(values)-1].Slot + 1
	}
	files, err := checkpoints.DownloadAndVerifyRootFiles(ctx, root, t.TempDir())
	if err != nil {
		t.Fatalf("download pinned checkpoint files: %v", err)
	}
	for _, file := range files {
		if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if err := capture.complete(); err != nil {
		t.Fatal(err)
	}
	objects := capture.copyObjects()
	if err := pin.Close(ctx); err != nil {
		t.Fatalf("close checkpoint recovery pin: %v", err)
	}
	pinOpen = false
	if err := snapshot.Close(ctx); err != nil {
		t.Fatalf("close archive recovery snapshot: %v", err)
	}
	snapshotOpen = false
	return objects, root
}

func verifyNoPVCInitialArchiveCapture(t *testing.T, ctx context.Context, db *rhiza.DB, config rhiza.Config, keyring *oidc.Keyring, root, issuer, keyID string) {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	prefix := path.Join(config.ObjStorePrefix, config.ClusterID)
	if exists, err := bucket.Exists(ctx, path.Join(prefix, "checkpoint/CURRENT")); err != nil || exists {
		t.Fatalf("initial capture requires no CURRENT: %v", err)
	}
	mustNoPVCExportExecute(t, ctx, db, "initial-marker-schema", `CREATE TABLE initial_archive_markers (name TEXT PRIMARY KEY)`)
	mustNoPVCExportExecute(t, ctx, db, "initial-marker-before", `INSERT INTO initial_archive_markers(name) VALUES('before')`)
	capture := &noPVCExportCaptureBucket{Bucket: bucket, prefix: prefix, objects: map[string][]byte{}, partial: map[string]struct{}{}}
	archive := recovery.NewManager(capture, prefix, 1)
	defer archive.Close()
	if err := archive.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := archive.RecoveryBase(); ok {
		t.Fatal("initial archive unexpectedly has checkpoint base")
	}
	tip := archive.Tip()
	if tip == 0 {
		t.Fatal("initial archive has no decisions")
	}
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	limits := backup.Limits{MaxFiles: 4096, MaxFileBytes: 64 << 20, MaxTotalBytes: 256 << 20}
	work := t.TempDir()
	manifest, err := backup.Export(ctx, bucket, prefix, config.ClusterID, &artifact, []age.Recipient{key.Recipient()}, work, limits)
	if err != nil || manifest.FormatVersion != 2 || manifest.RecoveryMode != "archive-only" || manifest.ArchiveTip != uint64(tip) {
		t.Fatalf("initial product export boundary: %+v %v", manifest, err)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("initial export cleanup: %v", err)
	}
	staged, err := backup.Extract(&artifact, []age.Identity{key}, t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	mustNoPVCExportExecute(t, ctx, db, "initial-marker-after", `INSERT INTO initial_archive_markers(name) VALUES('after')`)
	observer := recovery.NewManager(bucket, prefix, 1)
	defer observer.Close()
	if err := observer.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if observer.Tip() <= tip || archive.Tip() != tip {
		t.Fatal("initial archive tip did not stay fixed while source advanced")
	}
	// Simulate retention deleting one immutable object after Load. The public
	// reader must reject it; restoring the original bytes allows a fresh read.
	deleted := false
	for name, data := range capture.copyObjects() {
		if !strings.HasPrefix(name, prefix+"/archive/blocks/") {
			continue
		}
		if err := bucket.Delete(ctx, name); err != nil {
			t.Fatal(err)
		}
		deleted = true
		_, _, readErr := observer.DecisionsFrom(ctx, 1, int(observer.Tip()))
		restoreErr := bucket.Upload(ctx, name, bytes.NewReader(data), objstore.WithIfNotExists())
		if restoreErr != nil {
			t.Fatalf("restore retention-race fixture: %v", restoreErr)
		}
		if readErr == nil {
			t.Fatal("archive reader accepted a deleted required block")
		}
		break
	}
	if !deleted {
		t.Fatal("no archive block available for retention-race control")
	}
	next := tip
	next = 1
	for next <= tip {
		values, gotTip, err := archive.DecisionsFrom(ctx, next, 256)
		if err != nil || len(values) == 0 || gotTip != tip {
			t.Fatalf("read initial archive: %v", err)
		}
		for _, value := range values {
			if value.Slot != next || value.Slot > tip {
				t.Fatal("initial archive decision gap")
			}
			next++
		}
	}
	if len(capture.partial) != 0 {
		t.Fatal("initial archive capture incomplete")
	}
	objects := capture.copyObjects()
	if _, ok := objects[prefix+"/archive/head.bin"]; !ok {
		t.Fatal("initial archive head was not captured")
	}
	target := noPVCExportConfig(t, root, filepath.Join(root, "initial-restored"), filepath.Join(root, "initial-target-objects"))
	target.ObjStorePrefix = config.ObjStorePrefix + "-initial-restore"
	destination := path.Join(target.ObjStorePrefix, target.ClusterID)
	out := noPVCExportBucket(t, target)
	defer out.Close()
	// A structurally valid manifest must still match the actual remote tip.
	manifestPath := filepath.Join(staged.Dir, backup.ManifestEntry)
	originalManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := manifest
	wrong.ArchiveTip++
	wrongJSON, err := backup.MarshalManifest(wrong)
	if err != nil {
		t.Fatal(err)
	}
	badStage := backup.Extracted{Dir: staged.Dir, Inventory: append([]backup.Inventory(nil), staged.Inventory...)}
	for i := range badStage.Inventory {
		if badStage.Inventory[i].Name == backup.ManifestEntry {
			badStage.Inventory[i].Size = int64(len(wrongJSON))
		}
	}
	if err := os.WriteFile(manifestPath, wrongJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.ReadManifest(badStage.Dir, badStage.Inventory); err != nil {
		t.Fatalf("wrong-tip fixture failed structural validation: %v", err)
	}
	badPrefix := path.Join(target.ObjStorePrefix+"-wrong-tip", target.ClusterID)
	if _, err := backup.Restore(ctx, out, badPrefix, target.ClusterID, badStage, t.TempDir()); err == nil {
		t.Fatal("restore accepted a manifest tip different from its archive")
	}
	if exists, err := out.Exists(ctx, path.Join(badPrefix, "checkpoint/CURRENT")); err != nil || exists {
		t.Fatalf("failed initial restore created CURRENT: %v", err)
	}
	if err := os.WriteFile(manifestPath, originalManifest, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(ctx, out, destination, target.ClusterID, staged, t.TempDir()); err != nil {
		t.Fatalf("initial product restore: %v", err)
	}
	if exists, err := out.Exists(ctx, path.Join(destination, "checkpoint/CURRENT")); err != nil || exists {
		t.Fatalf("archive-only restore created CURRENT before open: %v", err)
	}
	restored, err := rhiza.Open(ctx, target)
	if err != nil {
		t.Fatalf("open initial archive capture: %v", err)
	}
	defer restored.Close()
	rows, err := restored.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM initial_archive_markers ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "before" {
		t.Fatalf("initial snapshot boundary failed: %v %v", rows.Rows, err)
	}
	users, err := identity.NewStore(restored)
	if err != nil {
		t.Fatal(err)
	}
	if user, err := users.Authenticate(ctx, "export@example.test", []byte("Disposable export prototype password 7!")); err != nil || user.Subject != "export-user" {
		t.Fatalf("initial account recovery: %v", err)
	}
	if key, err := oidc.LoadActiveSigningKey(ctx, restored, keyring, issuer); err != nil || key.PublicJWK.KeyID != keyID {
		t.Fatalf("initial signing key recovery: %v", err)
	}
	if err := verifyNoPVCGeneratedAPIKey(ctx, restored, keyring, root, target.DataDir, false); err != nil {
		t.Fatal(err)
	}
}

func productionNoPVCExport(t *testing.T, ctx context.Context, config rhiza.Config, prefix string, during func()) backup.Extracted {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	observed := &noPVCExportInterleaveBucket{Bucket: bucket, prefix: prefix, during: during, renewed: make(chan struct{}), waitRenew: os.Getenv("GOAUTHY_EXPORT_GC_TEST") == "1"}
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.CreateTemp(t.TempDir(), "product-*.age")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	limits := backup.Limits{MaxFiles: 4096, MaxFileBytes: 64 << 20, MaxTotalBytes: 256 << 20}
	work := t.TempDir()
	if _, err := backup.Export(ctx, observed, prefix, config.ClusterID, artifact, []age.Recipient{key.Recipient()}, work, limits); err != nil {
		t.Fatalf("product export: %v", err)
	}
	if !observed.called.Load() {
		t.Fatal("source write did not interleave with product export")
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("export scratch cleanup: %v", err)
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	staged, err := backup.Extract(artifact, []age.Identity{key}, t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	// A final lease renewal failure must reject even a fully written artifact.
	failure := errors.New("injected final checkpoint pin renewal failure")
	failing := &noPVCExportLeaseFailureBucket{Bucket: bucket, failure: failure}
	failedWork := t.TempDir()
	if _, err := backup.Export(ctx, failing, prefix, config.ClusterID, io.Discard, []age.Recipient{key.Recipient()}, failedWork, limits); !errors.Is(err, failure) {
		t.Fatalf("export ignored final pin failure: %v", err)
	}
	if failing.pinWrites.Load() < 3 {
		t.Fatal("renewal failure was not reached")
	}
	if entries, err := os.ReadDir(failedWork); err != nil || len(entries) != 0 {
		t.Fatalf("failed export scratch cleanup: %v", err)
	}
	return staged
}

type noPVCExportLeaseFailureBucket struct {
	objstore.Bucket
	failure   error
	pinWrites atomic.Int32
}

func (b *noPVCExportLeaseFailureBucket) Upload(ctx context.Context, name string, r io.Reader, options ...objstore.ObjectUploadOption) error {
	if strings.Contains(name, "/checkpoint/recovery-pins/") && b.pinWrites.Add(1) == 3 {
		return b.failure
	}
	return b.Bucket.Upload(ctx, name, r, options...)
}

type noPVCExportInterleaveBucket struct {
	objstore.Bucket
	prefix                      string
	during                      func()
	called                      atomic.Bool
	waitRenew                   bool
	checkpointPins, archivePins atomic.Int32
	renewed                     chan struct{}
	renewOnce                   sync.Once
}

func (b *noPVCExportInterleaveBucket) Upload(ctx context.Context, name string, r io.Reader, options ...objstore.ObjectUploadOption) error {
	if err := b.Bucket.Upload(ctx, name, r, options...); err != nil {
		return err
	}
	if strings.HasPrefix(name, b.prefix+"/checkpoint/recovery-pins/") {
		b.checkpointPins.Add(1)
	}
	if strings.HasPrefix(name, b.prefix+"/archive/recovery-pins/") {
		b.archivePins.Add(1)
	}
	if b.checkpointPins.Load() >= 3 && b.archivePins.Load() >= 3 {
		b.renewOnce.Do(func() { close(b.renewed) })
	}
	return nil
}

func (b *noPVCExportInterleaveBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if strings.HasPrefix(name, b.prefix+"/checkpoint/blocks/") && b.called.CompareAndSwap(false, true) {
		b.during()
		if b.waitRenew {
			// Acquisition plus immediate renewal account for the first two
			// writes. Export is blocked here, so the third pair is periodic.
			select {
			case <-b.renewed:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(45 * time.Second):
				return nil, errors.New("paired periodic export renewal not observed")
			}
		}
	}
	return b.Bucket.Get(ctx, name)
}

func encryptedNoPVCExport(t *testing.T, config rhiza.Config, prefix string, captured map[string][]byte, checkpointRoot *checkpoint.Checkpoint) backup.Extracted {
	t.Helper()
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(captured))
	for name := range captured {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]backup.Entry, 0, len(names))
	manifest := backup.SnapshotManifest{
		FormatVersion: 1, RhizaVersion: "v0.12.3", SourcePrefix: prefix, ClusterID: config.ClusterID,
		ConfigID: uint64(checkpointRoot.ConfigID), CheckpointIndex: checkpointRoot.Index,
		CheckpointRootHash:  fmt.Sprintf("%x", checkpointRoot.RootHash),
		CheckpointStateHash: fmt.Sprintf("%x", checkpointRoot.Hash),
	}
	for _, name := range names {
		relative, ok := strings.CutPrefix(name, prefix+"/")
		if !ok {
			t.Fatal("captured object escaped source prefix")
		}
		size := int64(len(captured[name]))
		digest := sha256.Sum256(captured[name])
		manifest.Objects = append(manifest.Objects, backup.ManifestObject{Name: relative, Size: size, SHA256: fmt.Sprintf("%x", digest)})
		entries = append(entries, backup.Entry{Name: backup.ObjectEntryPrefix + relative, Size: size, Reader: bytes.NewReader(captured[name])})
	}
	metadata, err := backup.MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, backup.Entry{Name: backup.ManifestEntry, Size: int64(len(metadata)), Reader: bytes.NewReader(metadata)})
	limits := backup.Limits{MaxFiles: 4096, MaxFileBytes: 64 << 20, MaxTotalBytes: 256 << 20}
	f, err := os.CreateTemp(t.TempDir(), "snapshot-*.age")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := backup.Write(f, []age.Recipient{key.Recipient()}, entries, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	staged, err := backup.Extract(f, []age.Identity{key}, t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.Inventory) != len(captured)+1 {
		t.Fatal("encrypted snapshot inventory lost objects")
	}
	return staged
}

func restoreNoPVCExport(t *testing.T, ctx context.Context, config rhiza.Config, prefix string, staged backup.Extracted) {
	t.Helper()
	bucket := noPVCExportBucket(t, config)
	defer bucket.Close()
	if _, err := backup.Restore(ctx, bucket, prefix, config.ClusterID, staged, t.TempDir()); err != nil {
		t.Fatalf("restore encrypted snapshot: %v", err)
	}
	readCurrent := func() []byte {
		r, err := bucket.Get(ctx, path.Join(prefix, "checkpoint/CURRENT"))
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(r)
		if err := errors.Join(readErr, r.Close()); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := readCurrent()
	if _, err := backup.Restore(ctx, bucket, prefix, config.ClusterID, staged, t.TempDir()); err == nil {
		t.Fatal("restore overwrote occupied destination")
	}
	if !bytes.Equal(before, readCurrent()) {
		t.Fatal("rejected restore changed CURRENT")
	}
}

type noPVCExportCaptureBucket struct {
	objstore.Bucket
	prefix  string
	mu      sync.Mutex
	objects map[string][]byte
	partial map[string]struct{}
}

func (b *noPVCExportCaptureBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	r, err := b.Bucket.Get(ctx, name)
	if err != nil || !b.allowed(name) {
		return r, err
	}
	return &noPVCExportCaptureReader{ReadCloser: r, bucket: b, name: name}, nil
}

func (b *noPVCExportCaptureBucket) allowed(name string) bool {
	return name == b.prefix+"/archive/head.bin" ||
		strings.HasPrefix(name, b.prefix+"/archive/blocks/") ||
		strings.HasPrefix(name, b.prefix+"/checkpoint/roots/") ||
		strings.HasPrefix(name, b.prefix+"/checkpoint/blocks/")
}

func (b *noPVCExportCaptureBucket) record(name string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if prior, ok := b.objects[name]; ok && !bytes.Equal(prior, data) {
		b.partial[name] = struct{}{}
		return
	}
	b.objects[name] = append([]byte(nil), data...)
}

func (b *noPVCExportCaptureBucket) incomplete(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.partial == nil {
		b.partial = make(map[string]struct{})
	}
	b.partial[name] = struct{}{}
}

func (b *noPVCExportCaptureBucket) complete() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.partial) != 0 {
		return fmt.Errorf("captured recovery object was not fully read")
	}
	if _, ok := b.objects[b.prefix+"/archive/head.bin"]; !ok {
		return fmt.Errorf("captured recovery object set has no archive head")
	}
	for _, prefix := range []string{"/archive/blocks/", "/checkpoint/roots/", "/checkpoint/blocks/"} {
		found := false
		for name := range b.objects {
			if strings.HasPrefix(name, b.prefix+prefix) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("captured recovery object set has no %s object", strings.Trim(prefix, "/"))
		}
	}
	return nil
}

func (b *noPVCExportCaptureBucket) copyObjects() map[string][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	copy := make(map[string][]byte, len(b.objects))
	for name, data := range b.objects {
		copy[name] = append([]byte(nil), data...)
	}
	return copy
}

type noPVCExportCaptureReader struct {
	io.ReadCloser
	bucket *noPVCExportCaptureBucket
	name   string
	data   bytes.Buffer
	eof    bool
	closed bool
}

func (r *noPVCExportCaptureReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		_, _ = r.data.Write(p[:n])
	}
	if err == io.EOF {
		r.eof = true
	}
	return n, err
}

func (r *noPVCExportCaptureReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.ReadCloser.Close()
	if err == nil && r.eof {
		r.bucket.record(r.name, r.data.Bytes())
	} else {
		r.bucket.incomplete(r.name)
	}
	return err
}
