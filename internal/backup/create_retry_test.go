package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
)

func TestCreateRetriesMovingArchiveHeadBeforePublication(t *testing.T) {
	ctx := t.Context()
	source, sourcePrefix := createRetrySource(t, ctx)
	fault := &createRetryHeadBucket{Bucket: source, head: path.Join(sourcePrefix, "archive/head.bin"), changes: 1}
	destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
	key, identity := createRetryKeys(t)
	work := t.TempDir()
	entry, err := Create(ctx, fault, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits)
	if err != nil {
		t.Fatal(err)
	}
	if fault.mutations() != 1 || destination.uploads != 2 {
		t.Fatalf("head mutations=%d uploads=%d, want 1 and 2", fault.mutations(), destination.uploads)
	}
	trust := []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}
	completed, err := ListCompleted(ctx, destination, "catalog", trust, 2)
	if err != nil || len(completed) != 1 || completed[0] != entry {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	fetched, got, err := FetchCompleted(ctx, destination, "catalog", entry.ID, trust, t.TempDir(), entry.Size)
	if err != nil || got != entry {
		t.Fatalf("fetch=%+v err=%v", got, err)
	}
	artifact, err := os.ReadFile(fetched)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := Extract(bytes.NewReader(artifact), []age.Identity{identity}, t.TempDir(), createRetryLimits)
	if err != nil {
		t.Fatalf("final artifact contains retry bytes or is invalid: %v", err)
	}
	if _, err := ReadManifest(staged.Dir, staged.Inventory); err != nil {
		t.Fatal(err)
	}
	createRetryScratchEmpty(t, work)
}

func TestCreateMovingArchiveHeadExhaustsBeforePublication(t *testing.T) {
	ctx := t.Context()
	source, sourcePrefix := createRetrySource(t, ctx)
	fault := &createRetryHeadBucket{Bucket: source, head: path.Join(sourcePrefix, "archive/head.bin"), changes: -1}
	destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
	key, identity := createRetryKeys(t)
	work := t.TempDir()
	started := time.Now()
	snapshotAttempts := 0
	entry, err := createWithExporter(ctx, fault, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits, func(ctx context.Context, source objstore.Bucket, sourcePrefix, clusterID string, dst io.Writer, recipients []age.Recipient, workParent string, limits Limits) (SnapshotManifest, error) {
		snapshotAttempts++
		return Export(ctx, source, sourcePrefix, clusterID, dst, recipients, workParent, limits)
	})
	if err == nil || entry.ID != "" || err.Error() != "shared archive state changed too often" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	if snapshotAttempts != 6 || fault.mutations() == 0 || destination.uploads != 0 || time.Since(started) < 3*time.Second {
		t.Fatalf("snapshot attempts=%d head mutations=%d uploads=%d elapsed=%v", snapshotAttempts, fault.mutations(), destination.uploads, time.Since(started))
	}
	createRetryScratchEmpty(t, work)
}

func TestCreateMovingArchiveHeadCancellationStopsRetryWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source, sourcePrefix := createRetrySource(t, ctx)
	fault := &createRetryHeadBucket{Bucket: source, head: path.Join(sourcePrefix, "archive/head.bin"), changes: -1, changed: make(chan struct{})}
	destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
	key, identity := createRetryKeys(t)
	work := t.TempDir()
	go func() {
		<-fault.changed
		cancel()
	}()
	started := time.Now()
	snapshotAttempts := 0
	_, err := createWithExporter(ctx, fault, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits, func(ctx context.Context, source objstore.Bucket, sourcePrefix, clusterID string, dst io.Writer, recipients []age.Recipient, workParent string, limits Limits) (SnapshotManifest, error) {
		snapshotAttempts++
		return Export(ctx, source, sourcePrefix, clusterID, dst, recipients, workParent, limits)
	})
	if !errors.Is(err, context.Canceled) || snapshotAttempts != 1 || fault.mutations() == 0 || time.Since(started) >= 2*time.Second || destination.uploads != 0 {
		t.Fatalf("err=%v snapshot attempts=%d mutations=%d elapsed=%v uploads=%d", err, snapshotAttempts, fault.mutations(), time.Since(started), destination.uploads)
	}
	createRetryScratchEmpty(t, work)
}

func TestCreateRetriesExactRecoveryAdmissionBusy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		busyErrors int
		wantErr    bool
	}{
		{name: "released", busyErrors: 1},
		{name: "exhausted", busyErrors: 6, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var source objstore.Bucket = catalogBucket(t)
			sourcePrefix := "live/cluster"
			if !tc.wantErr {
				source, sourcePrefix = createRetrySource(t, t.Context())
			}
			destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
			key, identity := createRetryKeys(t)
			work := t.TempDir()
			calls := 0
			entry, err := createWithExporter(t.Context(), source, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits, func(ctx context.Context, source objstore.Bucket, sourcePrefix, clusterID string, dst io.Writer, recipients []age.Recipient, workParent string, limits Limits) (SnapshotManifest, error) {
				calls++
				if calls <= tc.busyErrors {
					return SnapshotManifest{}, fmt.Errorf("%w", checkpoint.ErrRecoveryAdmissionBusy)
				}
				return Export(ctx, source, sourcePrefix, clusterID, dst, recipients, workParent, limits)
			})
			wantCalls := tc.busyErrors + 1
			if tc.wantErr {
				wantCalls = 6
			}
			wantUploads := 2
			if tc.wantErr {
				wantUploads = 0
			}
			if calls != wantCalls || (err != nil) != tc.wantErr || (tc.wantErr && (!errors.Is(err, checkpoint.ErrRecoveryAdmissionBusy) || err.Error() != checkpoint.ErrRecoveryAdmissionBusy.Error())) || (!tc.wantErr && entry.ID == "") || destination.uploads != wantUploads {
				t.Fatalf("entry=%+v err=%v calls=%d uploads=%d", entry, err, calls, destination.uploads)
			}
			createRetryScratchEmpty(t, work)
		})
	}
}

var createRetryLimits = Limits{MaxFiles: 128, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20}

func createRetryKeys(t *testing.T) (ed25519.PrivateKey, *age.X25519Identity) {
	t.Helper()
	key, _ := catalogKey(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return key, identity
}

func createRetrySource(t *testing.T, ctx context.Context) (objstore.Bucket, string) {
	t.Helper()
	root := t.TempDir()
	prefix := "live/cluster"
	config := rhiza.Config{ClusterID: "cluster", NodeID: "node", DataDir: path.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: path.Join(root, "objects"), ObjStorePrefix: "live", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Second}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "create-retry-schema", SQL: "CREATE TABLE retry_markers (name TEXT PRIMARY KEY)"}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	closeRetrySourceAfterCertifiedCheckpoint(t, ctx, db, config)
	base, err := filesystem.NewBucket(config.ObjStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	copy := objstore.NewInMemBucket()
	if err := base.Iter(ctx, "", func(name string) error {
		r, err := base.Get(ctx, name)
		if err != nil {
			return err
		}
		defer r.Close()
		return copy.Upload(ctx, name, r)
	}, objstore.WithRecursiveIter()); err != nil {
		t.Fatal(err)
	}
	archive := recovery.NewManager(copy, prefix, 1)
	defer archive.Close()
	if err := archive.Load(ctx); err != nil {
		t.Fatal(err)
	}
	seal, _, ok := archive.RecoveryBase()
	checkpoints := checkpoint.NewManager(copy, prefix, t.TempDir(), 1)
	if !ok {
		t.Fatal("copied native source has no certified checkpoint")
	}
	checkpointRoot, err := checkpoints.OpenRoot(ctx, uint64(seal.Index), seal.RootHash)
	if err != nil || checkpointRoot.Hash != seal.StateHash {
		t.Fatalf("copied native source checkpoint does not match certified seal: root=%v err=%v", checkpointRoot, err)
	}
	return copy, prefix
}

func closeRetrySourceAfterCertifiedCheckpoint(t *testing.T, ctx context.Context, db *rhiza.DB, config rhiza.Config) {
	t.Helper()
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = db.Close()
		}
	})
	bucket, err := filesystem.NewBucket(config.ObjStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := bucket.Close(); err != nil {
			t.Errorf("close checkpoint observer bucket: %v", err)
		}
	}()
	prefix := path.Join(config.ObjStorePrefix, config.ClusterID)
	checkpoints := checkpoint.NewManager(bucket, prefix, t.TempDir(), 1)
	archive := recovery.NewManager(bucket, prefix, 1)
	defer archive.Close()
	for {
		if err := checkpoints.Load(ctx); err != nil {
			t.Fatalf("read certified checkpoint pointer: %v", err)
		}
		root := checkpoints.Latest()
		if root != nil {
			if err := archive.Load(ctx); err != nil {
				t.Fatalf("read certified archive seal: %v", err)
			}
			seal, _, sealed := archive.RecoveryBase()
			if sealed && uint64(seal.Index) == root.Index && seal.RootHash == root.RootHash && root.Hash == seal.StateHash {
				released, err := retrySourcePublisherReleased(ctx, bucket, path.Join(prefix, "checkpoint/PUBLISHER"), root)
				if err != nil {
					t.Fatalf("read checkpoint publisher release: %v", err)
				}
				if released {
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for certified checkpoint and publisher release: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	selected := checkpoints.Latest()
	closeErr := db.Close()
	closed = true
	if closeErr != nil {
		t.Fatalf("close source after publisher release: %v", closeErr)
	}
	admitted, err := checkpoints.OpenRoot(ctx, selected.Index, selected.RootHash)
	if err != nil {
		t.Fatalf("admit exact checkpoint after close: %v", err)
	}
	if admitted.Index != selected.Index || admitted.RootHash != selected.RootHash || admitted.Hash != selected.Hash {
		t.Fatalf("admitted checkpoint changed: got index=%d root=%x hash=%x; want index=%d root=%x hash=%x", admitted.Index, admitted.RootHash, admitted.Hash, selected.Index, selected.RootHash, selected.Hash)
	}
}

func retrySourcePublisherReleased(ctx context.Context, bucket objstore.Bucket, key string, root *checkpoint.Checkpoint) (bool, error) {
	reader, err := bucket.Get(ctx, key)
	if err != nil {
		if bucket.IsObjNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, 64<<10))
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return false, err
	}
	var claim checkpoint.PublisherClaim
	if err := json.Unmarshal(data, &claim); err != nil {
		return false, fmt.Errorf("decode public publisher claim: %w", err)
	}
	releasedAt := time.UnixMilli(claim.LeaseUntilMS)
	now := time.Now()
	return claim.Purpose == "publisher" && claim.BoundIndex == root.Index && claim.RootHash == fmt.Sprintf("%x", root.RootHash) && !releasedAt.After(now) && now.Sub(releasedAt) <= 30*time.Second, nil
}

func createRetryScratchEmpty(t *testing.T, work string) {
	t.Helper()
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatalf("scratch=%v err=%v", entries, err)
	}
}

type createRetryHeadBucket struct {
	objstore.Bucket
	head    string
	changes int // -1 changes every load; positive changes that many loads.
	changed chan struct{}
	mu      sync.Mutex
	calls   int
	done    int
	once    sync.Once
}

func (b *createRetryHeadBucket) Attributes(ctx context.Context, name string) (objstore.ObjectAttributes, error) {
	attrs, err := b.Bucket.Attributes(ctx, name)
	if err != nil || name != b.head {
		return attrs, err
	}
	b.mu.Lock()
	b.calls++
	mutate := b.calls%3 == 0 && b.changes != 0
	if mutate && b.changes > 0 {
		b.changes--
	}
	b.mu.Unlock()
	if !mutate {
		return attrs, nil
	}
	r, err := b.Bucket.Get(ctx, name)
	if err != nil {
		return objstore.ObjectAttributes{}, err
	}
	data, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return objstore.ObjectAttributes{}, err
	}
	if err := b.Bucket.Upload(ctx, name, bytes.NewReader(data)); err != nil {
		return objstore.ObjectAttributes{}, err
	}
	b.mu.Lock()
	b.done++
	b.mu.Unlock()
	if b.changed != nil {
		b.once.Do(func() { close(b.changed) })
	}
	return b.Bucket.Attributes(ctx, name)
}

func (b *createRetryHeadBucket) mutations() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.done
}

func TestCreateDoesNotRetryOtherSnapshotErrors(t *testing.T) {
	for name, injected := range map[string]error{
		"transport":                     errors.New("provider unavailable"),
		"integrity":                     errors.New("invalid archive checksum"),
		"cleanup":                       errors.Join(errors.New("shared archive head changed during chain load"), errors.New("scratch cleanup failed")),
		"busy-cleanup":                  errors.Join(checkpoint.ErrPublisherBusy, errors.New("scratch cleanup failed")),
		"admission-busy-cleanup":        errors.Join(checkpoint.ErrRecoveryAdmissionBusy, errors.New("scratch cleanup failed")),
		"admission-busy-canceled":       errors.Join(checkpoint.ErrRecoveryAdmissionBusy, context.Canceled),
		"admission-busy-unknown-commit": errors.Join(checkpoint.ErrRecoveryAdmissionBusy, rhiza.ErrCommitUnknown),
		"fenced":                        checkpoint.ErrPublisherFenced,
	} {
		t.Run(name, func(t *testing.T) {
			source, prefix := createRetrySource(t, t.Context())
			fault := &createRetryErrorBucket{Bucket: source, err: injected}
			destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
			key, identity := createRetryKeys(t)
			work := t.TempDir()
			_, err := Create(t.Context(), fault, destination, prefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits)
			if err == nil || fault.calls != 1 || destination.uploads != 0 {
				t.Fatalf("err=%v calls=%d uploads=%d", err, fault.calls, destination.uploads)
			}
			createRetryScratchEmpty(t, work)
		})
	}
}

type createRetryErrorBucket struct {
	objstore.Bucket
	err   error
	calls int
}

func (b *createRetryErrorBucket) Attributes(context.Context, string) (objstore.ObjectAttributes, error) {
	b.calls++
	return objstore.ObjectAttributes{}, b.err
}
