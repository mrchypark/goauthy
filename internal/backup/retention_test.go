package backup

import (
	"bytes"
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thanos-io/objstore"
)

func TestPruneKeepsNewestEntryForEachSource(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	oldA := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -30))
	newA := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -20))
	newB := retentionPublish(t, bucket, private, prefix, "source/b", now.AddDate(0, 0, -25))
	retentionPut(t, bucket, "source/a/sentinel", "a")
	retentionPut(t, bucket, "source/b/sentinel", "b")

	deleted, err := Prune(ctx, bucket, prefix, public, now, 7, 8, true)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{oldA}) {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	retentionAbsent(t, bucket, prefix, oldA)
	retentionPresent(t, bucket, prefix, newA)
	retentionPresent(t, bucket, prefix, newB)
	retentionObjectPresent(t, bucket, "source/a/sentinel")
	retentionObjectPresent(t, bucket, "source/b/sentinel")
}

func TestPruneCutoffAndDryRun(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -8))
	boundary := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -7))
	keeper := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -1))
	counting := &retentionDeleteBucket{Bucket: bucket}

	deleted, err := Prune(ctx, counting, prefix, public, now, 7, 8, false)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{old}) || len(counting.deleted) != 0 {
		t.Fatalf("dry run deleted=%+v calls=%v err=%v", deleted, counting.deleted, err)
	}
	retentionPresent(t, bucket, prefix, old)
	retentionPresent(t, bucket, prefix, boundary)
	retentionPresent(t, bucket, prefix, keeper)
	deleted, err = Prune(ctx, bucket, prefix, public, now, 7, 8, true)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{old}) {
		t.Fatalf("apply deleted=%+v err=%v", deleted, err)
	}
	retentionAbsent(t, bucket, prefix, old)
	retentionPresent(t, bucket, prefix, boundary)
	retentionPresent(t, bucket, prefix, keeper)
	for _, invalid := range []struct {
		now  time.Time
		days int
	}{{now, -1}, {now, 65536}, {time.Time{}, 7}} {
		if _, err := Prune(ctx, bucket, prefix, public, invalid.now, invalid.days, 8, true); err == nil {
			t.Fatal("invalid retention configuration accepted")
		}
	}
}

func TestPruneRejectsBadReceiptsBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	for _, bad := range []struct {
		name string
		key  func() []byte
	}{
		{"malformed", func() []byte { return []byte("not json") }},
		{"wrong-key", nil},
	} {
		t.Run(bad.name, func(t *testing.T) {
			base := catalogBucket(t)
			defer base.Close()
			// Recreate the records per subtest so a malformed receipt cannot affect the next case.
			old := retentionPublish(t, base, private, prefix, "source/a", now.AddDate(0, 0, -30))
			keeper := retentionPublish(t, base, private, prefix, "source/a", now.AddDate(0, 0, -20))
			key := public
			if bad.key != nil {
				retentionPut(t, base, path.Join(prefix, "completed", "ABCDEFGHIJKLMNOPQRSTUVWXYZ.json"), string(bad.key()))
			} else {
				_, key = catalogKey(t)
			}
			counting := &retentionDeleteBucket{Bucket: base}
			if _, err := Prune(ctx, counting, prefix, key, now, 7, 8, true); err == nil {
				t.Fatal("bad receipt accepted")
			}
			if len(counting.deleted) != 0 {
				t.Fatalf("deleted before rejecting receipt: %v", counting.deleted)
			}
			retentionPresent(t, base, prefix, old)
			retentionPresent(t, base, prefix, keeper)
		})
	}
}

func TestPruneRejectsFutureEntryBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -30))
	retentionPublish(t, bucket, private, prefix, "source/a", now.Add(time.Second))
	counting := &retentionDeleteBucket{Bucket: bucket}
	if _, err := Prune(ctx, counting, prefix, public, now, 7, 8, true); err == nil {
		t.Fatal("future entry accepted")
	}
	if len(counting.deleted) != 0 {
		t.Fatalf("deleted before rejecting future entry: %v", counting.deleted)
	}
	retentionPresent(t, bucket, prefix, old)
}

func TestPruneRejectsCorruptKeeperBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -30))
	keeper := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -20))
	retentionPut(t, bucket, path.Join(prefix, "artifacts", keeper.ID+".age"), "corrupt")
	counting := &retentionDeleteBucket{Bucket: bucket}
	if _, err := Prune(ctx, counting, prefix, public, now, 7, 8, true); err == nil {
		t.Fatal("corrupt keeper accepted")
	}
	if len(counting.deleted) != 0 {
		t.Fatalf("deleted before verifying keeper: %v", counting.deleted)
	}
	retentionPresent(t, bucket, prefix, old)
}

func TestPruneResumesAfterCompletionDeleteFailure(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -30))
	keeper := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -20))
	failing := &retentionDeleteBucket{Bucket: bucket, fail: path.Join(prefix, "completed", old.ID+".json")}
	deleted, err := Prune(ctx, failing, prefix, public, now, 7, 8, true)
	if err == nil || len(deleted) != 0 {
		t.Fatalf("partial deletion deleted=%+v err=%v", deleted, err)
	}
	retentionObjectAbsent(t, bucket, path.Join(prefix, "artifacts", old.ID+".age"))
	retentionObjectPresent(t, bucket, path.Join(prefix, "completed", old.ID+".json"))
	retentionPresent(t, bucket, prefix, keeper)
	deleted, err = Prune(ctx, bucket, prefix, public, now, 7, 8, true)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{old}) {
		t.Fatalf("retry deleted=%+v err=%v", deleted, err)
	}
	retentionAbsent(t, bucket, prefix, old)
}

func TestPruneConcurrentApplyUsesSameListing(t *testing.T) {
	base := catalogBucket(t)
	defer base.Close()
	private, public := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := retentionPublish(t, base, private, prefix, "source/a", now.AddDate(0, 0, -30))
	keeper := retentionPublish(t, base, private, prefix, "source/a", now.AddDate(0, 0, -1))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	bucket := &retentionIterBarrierBucket{Bucket: base, reached: make(chan struct{}, 2), release: release}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := Prune(ctx, bucket, prefix, public, now, 7, 8, true)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-bucket.reached:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(release)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	completed, err := ListCompleted(context.Background(), base, prefix, public, 8)
	if err != nil || !slices.Equal(completed, []CatalogEntry{keeper}) {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	retentionAbsent(t, base, prefix, old)
}

func retentionPublish(t *testing.T, bucket objstore.Bucket, key []byte, prefix, source string, created time.Time) CatalogEntry {
	t.Helper()
	entry, err := Publish(context.Background(), bucket, prefix, source, catalogFile(t, catalogArtifact(t, []byte(source+created.String()))), key, created)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func retentionPut(t *testing.T, bucket objstore.Bucket, name, value string) {
	t.Helper()
	if err := bucket.Upload(context.Background(), name, bytes.NewBufferString(value)); err != nil {
		t.Fatal(err)
	}
}

func retentionPresent(t *testing.T, bucket objstore.Bucket, prefix string, entry CatalogEntry) {
	t.Helper()
	retentionObjectPresent(t, bucket, path.Join(prefix, "artifacts", entry.ID+".age"))
	retentionObjectPresent(t, bucket, path.Join(prefix, "completed", entry.ID+".json"))
}

func retentionAbsent(t *testing.T, bucket objstore.Bucket, prefix string, entry CatalogEntry) {
	t.Helper()
	retentionObjectAbsent(t, bucket, path.Join(prefix, "artifacts", entry.ID+".age"))
	retentionObjectAbsent(t, bucket, path.Join(prefix, "completed", entry.ID+".json"))
}

func retentionObjectPresent(t *testing.T, bucket objstore.Bucket, name string) {
	t.Helper()
	exists, err := bucket.Exists(context.Background(), name)
	if err != nil || !exists {
		t.Fatalf("object %q exists=%v err=%v", name, exists, err)
	}
}

func retentionObjectAbsent(t *testing.T, bucket objstore.Bucket, name string) {
	t.Helper()
	exists, err := bucket.Exists(context.Background(), name)
	if err != nil || exists {
		t.Fatalf("object %q exists=%v err=%v", name, exists, err)
	}
}

type retentionDeleteBucket struct {
	objstore.Bucket
	deleted []string
	fail    string
}

type retentionIterBarrierBucket struct {
	objstore.Bucket
	reached chan struct{}
	release <-chan struct{}
}

func (b *retentionIterBarrierBucket) Iter(ctx context.Context, dir string, f func(string) error, options ...objstore.IterOption) error {
	if err := b.Bucket.Iter(ctx, dir, f, options...); err != nil {
		return err
	}
	select {
	case b.reached <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *retentionDeleteBucket) Delete(ctx context.Context, name string) error {
	b.deleted = append(b.deleted, name)
	if name == b.fail {
		return errors.New("injected completion delete failure")
	}
	if strings.HasSuffix(name, "/") {
		return errors.New("unexpected recursive deletion")
	}
	return b.Bucket.Delete(ctx, name)
}
