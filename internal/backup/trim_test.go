package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/thanos-io/objstore"
)

// trimPublish uploads a uniquely named artifact so retained bytes identify the
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

// trimFetch recovers an entry and asserts the surviving bytes are exactly the
// ones the publication uploaded.
func trimFetch(t *testing.T, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, work string, entry CatalogEntry, want []byte) {
	t.Helper()
	name, got, err := FetchCompleted(context.Background(), bucket, prefix, entry.ID, keys, work, entry.Size)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := os.ReadFile(name)
	removeErr := os.Remove(name)
	if err := errors.Join(readErr, removeErr); err != nil || got != entry || !bytes.Equal(data, want) {
		t.Fatalf("recovered=%t got=%+v want=%+v err=%v", bytes.Equal(data, want), got, entry, err)
	}
}

// trimUnusableNewest publishes an older valid backup and a newer one, then makes
// the newer artifact unusable by deleting it or overwriting it with same-size
// bytes. It returns the older entry with its artifact bytes and the newer entry.
func trimUnusableNewest(t *testing.T, bucket objstore.Bucket, key []byte, prefix string, older, newer time.Time, corrupt bool) (CatalogEntry, []byte, CatalogEntry) {
	t.Helper()
	valid, want := trimPublish(t, bucket, key, prefix, "source/a", "older", older)
	unusable, _ := trimPublish(t, bucket, key, prefix, "source/a", "newer", newer)
	name := catalogArtifactPath(prefix, unusable.ID)
	if corrupt {
		if err := bucket.Upload(context.Background(), name, bytes.NewReader(bytes.Repeat([]byte{'x'}, int(unusable.Size)))); err != nil {
			t.Fatal(err)
		}
	} else if err := bucket.Delete(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	return valid, want, unusable
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
// still bounds the catalog when the newest receipt's artifact is already gone,
// without deleting the backup that still restores: the unrecoverable receipt is
// evicted and the older entry becomes the keeper.
func TestTrimCatalogEvictsKeeperWithMissingArtifact(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	now := time.Unix(1_800_000_000, 0)
	oldest, want, keeper := trimUnusableNewest(t, bucket, private, prefix, now.Add(-time.Hour), now.Add(-time.Minute), false)
	removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest)
	if err != nil || !slices.Equal(removed, []CatalogEntry{keeper}) {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	retentionAbsent(t, bucket, prefix, keeper)
	if entries, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil || !slices.Equal(entries, []CatalogEntry{oldest}) {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	trimFetch(t, bucket, prefix, public, t.TempDir(), oldest, want)
}

// TestTrimCatalogKeepsUnexpiredEntriesWithinCapacity pins the fix for a capacity
// pass that evicted unexpired backups with no capacity pressure at all: below and
// exactly at the target, every unexpired record survives under both policies.
func TestTrimCatalogKeepsUnexpiredEntriesWithinCapacity(t *testing.T) {
	for _, policy := range []RetentionPolicy{RetainLatest, ExpireAll} {
		for _, target := range []int{4, 3} {
			t.Run(fmt.Sprintf("%s/target-%d", policy, target), func(t *testing.T) {
				ctx := context.Background()
				bucket := catalogBucket(t)
				defer bucket.Close()
				private, public := catalogKey(t)
				prefix := "catalog/cluster-a"
				now := time.Unix(1_800_000_000, 0)
				var want []CatalogEntry
				artifacts := make(map[string][]byte)
				for i := range 3 {
					entry, artifact := trimPublish(t, bucket, private, prefix, "source/a", fmt.Sprint("recent-", i), now.Add(time.Duration(i-3)*time.Hour))
					want = append(want, entry)
					artifacts[entry.ID] = artifact
				}
				removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, target, true, policy)
				if err != nil || len(removed) != 0 {
					t.Fatalf("removed=%+v err=%v", removed, err)
				}
				entries, err := ListCompleted(ctx, bucket, prefix, public, 4)
				if err != nil || !slices.Equal(entries, want) {
					t.Fatalf("entries=%+v err=%v", entries, err)
				}
				for _, entry := range entries {
					trimFetch(t, bucket, prefix, public, t.TempDir(), entry, artifacts[entry.ID])
				}
			})
		}
	}
}

// TestTrimCatalogEvictsOnlyExcessAboveCapacity checks that an oversized catalog
// loses exactly its required excess, oldest first, and keeps the newest backups
// recoverable under both policies.
func TestTrimCatalogEvictsOnlyExcessAboveCapacity(t *testing.T) {
	for _, policy := range []RetentionPolicy{RetainLatest, ExpireAll} {
		t.Run(string(policy), func(t *testing.T) {
			ctx := context.Background()
			bucket := catalogBucket(t)
			defer bucket.Close()
			private, public := catalogKey(t)
			prefix := "catalog/cluster-a"
			now := time.Unix(1_800_000_000, 0)
			var entries []CatalogEntry
			artifacts := make(map[string][]byte)
			for i := range 4 {
				entry, artifact := trimPublish(t, bucket, private, prefix, "source/a", fmt.Sprint("record-", i), now.Add(time.Duration(i-4)*time.Hour))
				entries = append(entries, entry)
				artifacts[entry.ID] = artifact
			}
			removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 2, true, policy)
			if err != nil || !slices.Equal(removed, entries[:2]) {
				t.Fatalf("removed=%+v err=%v", removed, err)
			}
			retentionAbsent(t, bucket, prefix, entries[0])
			retentionAbsent(t, bucket, prefix, entries[1])
			kept, err := ListCompleted(ctx, bucket, prefix, public, 2)
			if err != nil || !slices.Equal(kept, entries[2:]) {
				t.Fatalf("kept=%+v err=%v", kept, err)
			}
			for _, entry := range kept {
				trimFetch(t, bucket, prefix, public, t.TempDir(), entry, artifacts[entry.ID])
			}
		})
	}
}

// TestTrimCatalogEvictsKeepersOnlyAfterOtherEntries drives capacity pressure below
// the number of sources: age retention removes the expired record, keepers are
// evicted only after every other candidate, and the newest recoverable backup
// survives.
func TestTrimCatalogEvictsKeepersOnlyAfterOtherEntries(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	now := time.Unix(1_800_000_000, 0)
	expired, _ := trimPublish(t, bucket, private, prefix, "source/a", "expired", now.AddDate(0, 0, -40))
	keeperA, _ := trimPublish(t, bucket, private, prefix, "source/a", "keeper-a", now.Add(-3*time.Hour))
	olderB, _ := trimPublish(t, bucket, private, prefix, "source/b", "older-b", now.Add(-2*time.Hour))
	keeperB, want := trimPublish(t, bucket, private, prefix, "source/b", "keeper-b", now.Add(-time.Hour))
	removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest)
	if err != nil || !slices.Equal(removed, []CatalogEntry{expired, keeperA, olderB}) {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	if entries, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil || !slices.Equal(entries, []CatalogEntry{keeperB}) {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	trimFetch(t, bucket, prefix, public, t.TempDir(), keeperB, want)
}

// TestTrimCatalogKeepsRecoverableBackupWhenNewestArtifactUnusable covers a newest
// artifact that is missing or same-size corrupt while an older backup is still
// valid. Whether or not age retention would have expired that older backup, the
// trim must leave a fetchable backup behind and drop the receipt that cannot
// restore.
func TestTrimCatalogKeepsRecoverableBackupWhenNewestArtifactUnusable(t *testing.T) {
	for _, test := range []struct {
		name    string
		corrupt bool
		created time.Time
	}{
		{name: "missing-outside-retention", created: time.Unix(1_800_000_000, 0).AddDate(0, 0, -40)},
		{name: "corrupt-inside-retention", corrupt: true, created: time.Unix(1_800_000_000, 0).Add(-time.Hour)},
		{name: "corrupt-outside-retention", corrupt: true, created: time.Unix(1_800_000_000, 0).AddDate(0, 0, -40)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			bucket := catalogBucket(t)
			defer bucket.Close()
			private, public := catalogKey(t)
			prefix := "catalog/cluster-a"
			now := time.Unix(1_800_000_000, 0)
			valid, want, unusable := trimUnusableNewest(t, bucket, private, prefix, test.created, now.Add(-time.Minute), test.corrupt)
			removed, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, RetainLatest)
			if err != nil || !slices.Equal(removed, []CatalogEntry{unusable}) {
				t.Fatalf("removed=%+v err=%v", removed, err)
			}
			retentionAbsent(t, bucket, prefix, unusable)
			if entries, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil || !slices.Equal(entries, []CatalogEntry{valid}) {
				t.Fatalf("entries=%+v err=%v", entries, err)
			}
			trimFetch(t, bucket, prefix, public, t.TempDir(), valid, want)
		})
	}
}

type trimGetFailureBucket struct {
	objstore.Bucket
	fail string
}

func (b *trimGetFailureBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if name == b.fail {
		return nil, errors.New("injected artifact read failure")
	}
	return b.Bucket.Get(ctx, name)
}

// TestTrimCatalogAbortsWhenArtifactCannotBeRead checks that an unreadable artifact
// is not treated as an unusable one: the read failure aborts the trim before any
// deletion, so a transient error cannot cost the only backup that still restores.
func TestTrimCatalogAbortsWhenArtifactCannotBeRead(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	now := time.Unix(1_800_000_000, 0)
	older, _ := trimPublish(t, bucket, private, prefix, "source/a", "older", now.Add(-time.Hour))
	newer, _ := trimPublish(t, bucket, private, prefix, "source/a", "newer", now.Add(-time.Minute))
	failing := &trimGetFailureBucket{Bucket: bucket, fail: catalogArtifactPath(prefix, newer.ID)}
	counting := &retentionDeleteBucket{Bucket: failing}
	if _, err := TrimCatalog(ctx, counting, prefix, public, now, 30, 1, true, RetainLatest); err == nil {
		t.Fatal("unreadable artifact accepted")
	}
	if len(counting.deleted) != 0 {
		t.Fatalf("deleted before verifying artifacts: %v", counting.deleted)
	}
	retentionPresent(t, bucket, prefix, older)
	retentionPresent(t, bucket, prefix, newer)
}

// TestRetentionCapacityReservationPublishesWithinAcceptedLimit walks the scheduled
// runtime's publication and retention sequence at the minimum accepted capacity.
// Reservation runs before publication, so each attempt publishes successfully and
// leaves a listable catalog holding at least one recoverable backup.
func TestRetentionCapacityReservationPublishesWithinAcceptedLimit(t *testing.T) {
	for _, policy := range []RetentionPolicy{RetainLatest, ExpireAll} {
		t.Run(string(policy), func(t *testing.T) {
			// ExpireAll trims by age alone, so it must never consume the publication
			// the reservation pass just admitted on capacity.
			retentionCapacityReservation(t, policy)
		})
	}
}

func retentionCapacityReservation(t *testing.T, policy RetentionPolicy) {
	t.Helper()
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	prefix := "catalog/cluster-a"
	work := t.TempDir()
	base := time.Unix(1_800_000_000, 0)
	for attempt := 0; attempt < 3; attempt++ {
		now := base.Add(time.Duration(attempt) * time.Minute)
		if _, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, RetentionTarget(1, 1), true, policy); err != nil {
			t.Fatal(err)
		}
		if _, err := ListCompleted(ctx, bucket, prefix, public, 1); err != nil {
			t.Fatalf("attempt %d catalog is not listable before publication: %v", attempt, err)
		}
		entry, want := trimPublish(t, bucket, private, prefix, "source/a", fmt.Sprint("attempt-", attempt), now.Add(-time.Second))
		if _, err := TrimCatalog(ctx, bucket, prefix, public, now, 30, 1, true, policy); err != nil {
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
