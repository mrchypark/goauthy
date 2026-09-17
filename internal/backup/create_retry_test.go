package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
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
	entry, err := Create(ctx, fault, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits)
	if err == nil || entry.ID != "" || err.Error() != "shared archive head changed during chain load" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	if fault.mutations() != 6 || destination.uploads != 0 || time.Since(started) < 3*time.Second {
		t.Fatalf("head mutations=%d uploads=%d elapsed=%v", fault.mutations(), destination.uploads, time.Since(started))
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
	_, err := Create(ctx, fault, destination, sourcePrefix, "cluster", "catalog", []age.Recipient{identity.Recipient()}, key, work, createRetryLimits)
	if !errors.Is(err, context.Canceled) || fault.mutations() != 1 || time.Since(started) >= 2*time.Second || destination.uploads != 0 {
		t.Fatalf("err=%v mutations=%d elapsed=%v uploads=%d", err, fault.mutations(), time.Since(started), destination.uploads)
	}
	createRetryScratchEmpty(t, work)
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
	config := rhiza.Config{ClusterID: "cluster", NodeID: "node", DataDir: path.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: path.Join(root, "objects"), ObjStorePrefix: "live", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "create-retry-schema", SQL: "CREATE TABLE retry_markers (name TEXT PRIMARY KEY)"}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
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
	if _, _, ok := archive.RecoveryBase(); !ok {
		t.Fatal("native source has no certified checkpoint")
	}
	return copy, prefix
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
		"transport":    errors.New("provider unavailable"),
		"integrity":    errors.New("invalid archive checksum"),
		"cleanup":      errors.Join(errors.New("shared archive head changed during chain load"), errors.New("scratch cleanup failed")),
		"busy-cleanup": errors.Join(checkpoint.ErrPublisherBusy, errors.New("scratch cleanup failed")),
		"fenced":       checkpoint.ErrPublisherFenced,
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
