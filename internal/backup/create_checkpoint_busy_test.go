package backup

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	kitlog "github.com/go-kit/log"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/thanos-io/objstore"
	thanoss3 "github.com/thanos-io/objstore/providers/s3"
)

func TestCreateCheckpointPublisherClaimBlocksThenReleases(t *testing.T) {
	ctx := context.Background()
	source, sourcePrefix := createRetrySource(t, ctx)
	assertCreateCheckpointPublisherClaim(t, source, catalogBucket(t), sourcePrefix, "catalog")
}

func TestCreateCheckpointPublisherS3(t *testing.T) {
	endpoint := os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("GOAUTHY_RECOVERY_S3_ENDPOINT is required")
	}
	bucketName, accessKey, secretKey := os.Getenv("GOAUTHY_RECOVERY_S3_BUCKET"), os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY"), os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY")
	if bucketName == "" || accessKey == "" || secretKey == "" {
		t.Fatal("GOAUTHY_RECOVERY_S3_BUCKET, ACCESS_KEY, and SECRET_KEY are required with endpoint")
	}
	bucket, err := thanoss3.NewBucketWithConfig(kitlog.NewNopLogger(), thanoss3.Config{Bucket: bucketName, Endpoint: endpoint, Region: "us-east-1", Insecure: true, AWSSDKAuth: false, AccessKey: accessKey, SecretKey: secretKey}, "goauthy-checkpoint-busy-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup registration is LIFO: prefixes are removed before the S3 client closes.
	t.Cleanup(func() { _ = bucket.Close() })
	source, sourcePrefix := createRetrySource(t, t.Context())
	id := cryptorand.Text()
	remoteSource, remoteCatalog := path.Join("checkpoint-busy-source", id, "cluster"), path.Join("checkpoint-busy-catalog", id)
	t.Cleanup(func() {
		deleteCheckpointBusyPrefix(t, bucket, remoteSource)
		deleteCheckpointBusyPrefix(t, bucket, remoteCatalog)
	})
	copyCheckpointBusySource(t, source, bucket, sourcePrefix, remoteSource)
	assertCreateCheckpointPublisherClaim(t, bucket, bucket, remoteSource, remoteCatalog)
	assertCreateRetriesCheckpointPublisherClaimAfterRelease(t, bucket, bucket, remoteSource, path.Join(remoteCatalog, "transient"))
}

func assertCreateCheckpointPublisherClaim(t *testing.T, source, destinationBase objstore.Bucket, sourcePrefix, catalogPrefix string) {
	t.Helper()
	ctx := t.Context()
	manager := checkpoint.NewManager(source, sourcePrefix, t.TempDir(), 1)
	claim, err := manager.AcquirePublisherClaim(ctx, "backup-test-publisher", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			if err := manager.ReleasePublisherClaim(context.Background(), claim); err != nil {
				t.Errorf("release publisher claim: %v", err)
			}
		}
	}()

	counting := &checkpointPublisherClaimBucket{Bucket: source, publisher: path.Join(sourcePrefix, "checkpoint", "PUBLISHER")}
	destination := &catalogCountingBucket{Bucket: destinationBase}
	signer, identity := createRetryKeys(t)
	work := t.TempDir()
	entry, err := Create(ctx, counting, destination, sourcePrefix, "cluster", catalogPrefix, []age.Recipient{identity.Recipient()}, signer, work, createRetryLimits)
	if !errors.Is(err, checkpoint.ErrPublisherBusy) || entry.ID != "" || destination.uploads != 0 {
		t.Fatalf("entry=%+v err=%v uploads=%d", entry, err, destination.uploads)
	}
	if counting.readsCount() != 6 {
		t.Fatalf("publisher claim reads=%d, want 6 retry attempts", counting.readsCount())
	}
	createRetryScratchEmpty(t, work)

	if err := manager.ReleasePublisherClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
	released = true
	entry, err = Create(ctx, source, destination, sourcePrefix, "cluster", catalogPrefix, []age.Recipient{identity.Recipient()}, signer, work, createRetryLimits)
	if err != nil || entry.ID == "" || destination.uploads != 2 {
		t.Fatalf("entry=%+v err=%v uploads=%d", entry, err, destination.uploads)
	}
	verifyCheckpointBusyBackup(t, destinationBase, catalogPrefix, entry, signer, identity, work)
	createRetryScratchEmpty(t, work)
}

func TestCreateRetriesCheckpointPublisherClaimAfterRelease(t *testing.T) {
	ctx := context.Background()
	source, sourcePrefix := createRetrySource(t, ctx)
	assertCreateRetriesCheckpointPublisherClaimAfterRelease(t, source, catalogBucket(t), sourcePrefix, "catalog")
}

func assertCreateRetriesCheckpointPublisherClaimAfterRelease(t *testing.T, source, destinationBase objstore.Bucket, sourcePrefix, catalogPrefix string) {
	t.Helper()
	ctx := t.Context()
	manager := checkpoint.NewManager(source, sourcePrefix, t.TempDir(), 1)
	claim, err := manager.AcquirePublisherClaim(ctx, "backup-test-publisher", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			if err := manager.ReleasePublisherClaim(context.Background(), claim); err != nil {
				t.Errorf("release publisher claim: %v", err)
			}
		}
	}()
	counting := &checkpointPublisherClaimBucket{
		Bucket:       source,
		publisher:    path.Join(sourcePrefix, "checkpoint", "PUBLISHER"),
		releaseAfter: 2,
		release: func() error {
			return manager.ReleasePublisherClaim(context.Background(), claim)
		},
	}
	destination := &catalogCountingBucket{Bucket: destinationBase}
	signer, identity := createRetryKeys(t)
	work := t.TempDir()
	entry, err := Create(ctx, counting, destination, sourcePrefix, "cluster", catalogPrefix, []age.Recipient{identity.Recipient()}, signer, work, createRetryLimits)
	if err != nil || entry.ID == "" || destination.uploads != 2 {
		t.Fatalf("entry=%+v err=%v uploads=%d", entry, err, destination.uploads)
	}
	if err := counting.releaseError(); err != nil {
		t.Fatalf("release after first claim read: %v", err)
	}
	if counting.readsCount() < 5 {
		t.Fatalf("publisher claim reads=%d, want retry after the released busy attempt", counting.readsCount())
	}
	verifyCheckpointBusyBackup(t, destinationBase, catalogPrefix, entry, signer, identity, work)
	released = true
	createRetryScratchEmpty(t, work)
}

func copyCheckpointBusySource(t *testing.T, source, destination objstore.Bucket, sourcePrefix, destinationPrefix string) {
	t.Helper()
	if err := source.Iter(t.Context(), sourcePrefix+"/", func(name string) error {
		reader, err := source.Get(t.Context(), name)
		if err != nil {
			return err
		}
		defer reader.Close()
		return destination.Upload(t.Context(), path.Join(destinationPrefix, strings.TrimPrefix(name, sourcePrefix+"/")), reader, objstore.WithIfNotExists())
	}, objstore.WithRecursiveIter()); err != nil {
		t.Fatal(err)
	}
}

func deleteCheckpointBusyPrefix(t *testing.T, bucket objstore.Bucket, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var names []string
	if err := bucket.Iter(ctx, prefix+"/", func(name string) error {
		names = append(names, name)
		return nil
	}, objstore.WithRecursiveIter()); err != nil {
		t.Errorf("list cleanup prefix %q: %v", prefix, err)
		return
	}
	for _, name := range names {
		if err := bucket.Delete(ctx, name); err != nil && !bucket.IsObjNotFoundErr(err) {
			t.Errorf("delete cleanup object %q: %v", name, err)
		}
	}
}

func verifyCheckpointBusyBackup(t *testing.T, bucket objstore.Bucket, catalogPrefix string, entry CatalogEntry, signer ed25519.PrivateKey, identity age.Identity, work string) {
	t.Helper()
	trust := []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}
	fetched, _, err := FetchCompleted(t.Context(), bucket, catalogPrefix, entry.ID, trust, work, entry.Size)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(fetched)
	if err != nil {
		t.Fatal(err)
	}
	staged, extractErr := Extract(file, []age.Identity{identity}, work, createRetryLimits)
	closeErr := file.Close()
	removeErr := os.Remove(fetched)
	if extractErr != nil || closeErr != nil || removeErr != nil {
		t.Fatalf("extract=%v close=%v remove=%v", extractErr, closeErr, removeErr)
	}
	if _, err := ReadManifest(staged.Dir, staged.Inventory); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(staged.Dir); err != nil {
		t.Fatal(err)
	}
}

type checkpointPublisherClaimBucket struct {
	objstore.Bucket
	publisher    string
	release      func() error
	releaseAfter int

	mu         sync.Mutex
	reads      int
	releaseErr error
	once       sync.Once
}

func (b *checkpointPublisherClaimBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	reader, err := b.Bucket.Get(ctx, name)
	if err != nil || name != b.publisher {
		return reader, err
	}
	b.mu.Lock()
	b.reads++
	read := b.reads
	b.mu.Unlock()
	return &checkpointClaimReader{ReadCloser: reader, release: func() {
		if b.release == nil || read != b.releaseAfter {
			return
		}
		b.once.Do(func() {
			b.mu.Lock()
			b.releaseErr = b.release()
			b.mu.Unlock()
		})
	}}, nil
}

func (b *checkpointPublisherClaimBucket) readsCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reads
}

func (b *checkpointPublisherClaimBucket) releaseError() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.releaseErr
}

type checkpointClaimReader struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (r *checkpointClaimReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(r.release)
	return err
}
