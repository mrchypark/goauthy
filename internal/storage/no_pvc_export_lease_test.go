package storage_test

import (
	"context"
	"errors"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore/providers/filesystem"
)

// Expiring a lease via Close avoids timing-dependent sleeps. Reusing an owner
// must not allow its stale handle to revoke or renew the replacement's lease.
func TestNoPVCExportLeaseFencesStaleHandles(t *testing.T) {
	t.Setenv("GOAUTHY_RECOVERY_S3_ENDPOINT", "") // This test owns a filesystem bucket.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	objects := filepath.Join(dir, "objects")
	config := noPVCExportConfig(t, dir, filepath.Join(dir, "writer"), objects)
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "lease-probe", SQL: "CREATE TABLE lease_probe (id INTEGER PRIMARY KEY)"})
	closeErr := db.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	bucket, err := filesystem.NewBucket(objects)
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	prefix := path.Join(config.ObjStorePrefix, config.ClusterID)
	archive := recovery.NewManager(bucket, prefix, 1)
	defer archive.Close()
	oldSnapshot, err := archive.BeginRecoverySnapshot(ctx, "lease-probe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seal, _, ok := oldSnapshot.RecoveryBase()
	if !ok {
		t.Fatal("missing certified base")
	}
	checkpoints := checkpoint.NewManager(bucket, prefix, t.TempDir(), 1)
	root, err := checkpoints.OpenRoot(ctx, uint64(seal.Index), seal.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	oldPin, err := checkpoints.PinRecoveryRoot(ctx, root, "lease-probe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(oldSnapshot.Renew(ctx, time.Minute), oldPin.Renew(ctx, time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(oldSnapshot.Close(ctx), oldPin.Close(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := oldSnapshot.Renew(ctx, time.Minute); !errors.Is(err, recovery.ErrArchiveBusy) {
		t.Fatalf("closed archive lease renewal: %v", err)
	}
	if err := oldPin.Renew(ctx, time.Minute); !errors.Is(err, checkpoint.ErrPublisherFenced) {
		t.Fatalf("closed checkpoint lease renewal: %v", err)
	}
	replacement, err := archive.BeginRecoverySnapshot(ctx, "lease-probe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replacementPin, err := checkpoints.PinRecoveryRoot(ctx, root, "lease-probe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldSnapshot.Close(ctx); !errors.Is(err, recovery.ErrArchiveBusy) {
		t.Fatalf("stale archive close: %v", err)
	}
	if err := oldPin.Close(ctx); !errors.Is(err, checkpoint.ErrPublisherFenced) {
		t.Fatalf("stale checkpoint close: %v", err)
	}
	if err := errors.Join(replacement.Renew(ctx, time.Minute), replacementPin.Renew(ctx, time.Minute)); err != nil {
		t.Fatal("replacement lease was damaged", err)
	}
	if err := errors.Join(replacement.Close(ctx), replacementPin.Close(ctx)); err != nil {
		t.Fatal(err)
	}
}
