package backup

import (
	"context"
	"path"
	"slices"
	"testing"
	"time"
)

func TestPruneWithPolicyKeepsLatestOrExpiresAll(t *testing.T) {
	now := time.Unix(6_000_000_000, 0)
	for _, test := range []struct {
		name     string
		policy   RetentionPolicy
		usePrune bool
		want     int
		keepB    bool
	}{
		{name: "default-keep-latest", usePrune: true, want: 1, keepB: true},
		{name: "expire-all", policy: ExpireAll, want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			bucket := catalogBucket(t)
			defer bucket.Close()
			private, trust := catalogKey(t)
			prefix := "catalog/cluster-a"
			oldA := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -8))
			boundaryA := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -7))
			oldB := retentionPublish(t, bucket, private, prefix, "source/b", now.AddDate(0, 0, -9))
			retentionPut(t, bucket, path.Join(prefix, "artifacts", "unsigned-orphan.age"), "orphan")
			var deleted []CatalogEntry
			var err error
			if test.usePrune {
				deleted, err = Prune(context.Background(), bucket, prefix, trust, now, 7, 8, true)
			} else {
				deleted, err = PruneWithPolicy(context.Background(), bucket, prefix, trust, now, 7, 8, true, test.policy)
			}
			if err != nil || len(deleted) != test.want || !slices.Contains(deleted, oldA) {
				t.Fatalf("deleted=%+v err=%v", deleted, err)
			}
			retentionAbsent(t, bucket, prefix, oldA)
			retentionPresent(t, bucket, prefix, boundaryA) // strict cutoff preserves equality.
			if test.keepB {
				retentionPresent(t, bucket, prefix, oldB)
			} else {
				retentionAbsent(t, bucket, prefix, oldB)
			}
			retentionObjectPresent(t, bucket, path.Join(prefix, "artifacts", "unsigned-orphan.age"))
		})
	}
}

func TestPruneWithPolicyExpireAllResumesMissingArtifact(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, trust := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	entry := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -8))
	if err := bucket.Delete(ctx, path.Join(prefix, "artifacts", entry.ID+".age")); err != nil {
		t.Fatal(err)
	}
	deleted, err := PruneWithPolicy(ctx, bucket, prefix, trust, now, 7, 8, true, ExpireAll)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{entry}) {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	retentionAbsent(t, bucket, prefix, entry)
}

func TestPruneWithPolicyAcceptsZeroAndMaximumU16Days(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(6_000_000_000, 0)
	for _, test := range []struct {
		name    string
		days    int
		created time.Time
	}{
		{name: "zero", days: 0, created: now.Add(-time.Second)},
		{name: "maximum-u16", days: 65535, created: now.AddDate(0, 0, -65536)},
	} {
		t.Run(test.name, func(t *testing.T) {
			bucket := catalogBucket(t)
			defer bucket.Close()
			private, trust := catalogKey(t)
			prefix := "catalog/cluster-a"
			entry := retentionPublish(t, bucket, private, prefix, "source/a", test.created)
			deleted, err := PruneWithPolicy(ctx, bucket, prefix, trust, now, test.days, 8, true, ExpireAll)
			if err != nil || !slices.Equal(deleted, []CatalogEntry{entry}) {
				t.Fatalf("deleted=%+v err=%v", deleted, err)
			}
			retentionAbsent(t, bucket, prefix, entry)
		})
	}
}

func TestPruneWithPolicyRejectsBadTrustBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, _ := catalogKey(t)
	_, untrusted := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	entry := retentionPublish(t, bucket, private, prefix, "source/a", now.AddDate(0, 0, -8))
	counting := &retentionDeleteBucket{Bucket: bucket}
	if _, err := PruneWithPolicy(ctx, counting, prefix, untrusted, now, 0, 8, true, ExpireAll); err == nil {
		t.Fatal("untrusted catalog was pruned")
	}
	if len(counting.deleted) != 0 {
		t.Fatalf("deleted before rejecting trust: %v", counting.deleted)
	}
	retentionPresent(t, bucket, prefix, entry)
}
