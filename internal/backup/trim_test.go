package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"testing"
	"time"

	"github.com/thanos-io/objstore"
)

// trimPublishUploads a uniquely named artifact so retained bytes identify the
// exact publication they came from.
func trimPublish(t *testing.T, bucket objstore.Bucket, key []byte, prefix, source, label string, created time.Time) (CatalogEntry, []byte) {
	t.Helper()
	artifact := catalogArtifact(t, []byte(source+" "+label))
	entry, err := Publish(context.Background(), bucket, prefix, source, catalogFile(t, artifact), key, created)
	if err != nil {
		t.Fatal(err)
	}
	return entry, artifact
}

// TestTrimCatalogBoundsOversizedCatalog reproduces the publication-before-retention
// state: the catalog exceeds the accepted capacity, so it is neither listable nor
// prunable until a bounded trim recovers it.
func TestTrimCatalogBoundsOversizedCatalog(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	now := time.Unix(1_800_000_000, 0)
	newest, _ := trimPublish(t, bucket, private, prefix, "source/a", "newest", now.Add(-time.Minute))
	oldest, _ := trimPublish(t, bucket, private, prefix, "source/a", "oldest", now.Add(-time.Hour))
	if _, err := ListCompleted(ctx, bucket, prefix, public, 1); err == nil {
		t.Fatal("oversized catalog listed within the accepted capacity")
	}
	if _, err := PruneWithPolicy(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest); err == nil {
		t.Fatal("oversized catalog was pruned before being bounded")
	}
	retentionPresent(t, bucket, prefix, oldest)
	removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest)
	if err != nil || !slices.Equal(removed, []CatalogEntry{oldest}) {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	retentionAbsent(t, bucket, prefix, oldest)
	retentionPresent(t, bucket, prefix, newest)
	entries, err := ListCompleted(ctx, bucket, prefix, public, 1)
	if err != nil || !slices.Equal(entries, []CatalogEntry{newest}) {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

// TestTrimCatalogEvictsKeeperWithMissingArtifact checks that capacity pressure
// bounds the catalog even when age retention protects the entry and its artifact
// is already gone.
func TestTrimCatalogEvictsKeeperWithMissingArtifact(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	now := time.Unix(1_800_000_000, 0)
	keeper, _ := trimPublish(t, bucket, private, prefix, "source/a", "keeper", now.Add(-time.Minute))
	oldest, _ := trimPublish(t, bucket, private, prefix, "source/a", "oldest", now.Add(-time.Hour))
	if err := bucket.Delete(ctx, catalogArtifactPath(prefix, keeper.ID)); err != nil {
		t.Fatal(err)
	}
	removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest)
	if err != nil || !slices.Equal(removed, []CatalogEntry{oldest, keeper}) {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	retentionAbsent(t, bucket, prefix, oldest)
	if exists, err := bucket.Exists(ctx, path.Join(prefix, "completed", keeper.ID+".json")); err != nil || exists {
		t.Fatalf("unreachable receipt retained exists=%v err=%v", exists, err)
	}
	if entries, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

// TestRetentionCapacityReservationPublishesWithinAcceptedLimit walks the scheduled
// runtime's publication and retention sequence at the minimum accepted capacity.
// Reservation runs before publication, so each attempt publishes successfully and
// leaves a listable catalog holding at least one recoverable backup.
func TestRetentionCapacityReservationPublishesWithinAcceptedLimit(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	work := t.TempDir()
	base := time.Unix(1_800_000_000, 0)
	for attempt := 0; attempt < 3; attempt++ {
		now := base.Add(time.Duration(attempt) * time.Minute)
		if _, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, RetentionTarget(1, 1), true, RetainLatest); err != nil {
			t.Fatal(err)
		}
		if _, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil {
			t.Fatalf("attempt %d catalog is not listable before publication: %v", attempt, err)
		}
		entry, want := trimPublish(t, bucket, private, prefix, "source/a", fmt.Sprint("attempt-", attempt), now.Add(-time.Second))
		if _, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest); err != nil {
			t.Fatal(err)
		}
		entries, err := ListCompleted(ctx, bucket, prefix, public, 1)
		if err != nil || !slices.Equal(entries, []CatalogEntry{entry}) {
			t.Fatalf("attempt %d entries=%+v err=%v", attempt, entries, err)
		}
		name, got, err := FetchCompleted(ctx, bucket, prefix, entries[0].ID, public, work, entry.Size)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := os.ReadFile(name)
		removeErr := os.Remove(name)
		if err := errors.Join(readErr, removeErr); err != nil || !bytes.Equal(data, want) || got != entries[0] {
			t.Fatalf("attempt %d recovered=%t got=%+v err=%v", attempt, bytes.Equal(data, want), got, err)
		}
	}
}
