package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"sort"
	"time"

	"github.com/thanos-io/objstore"
)

// TrimCatalog bounds a catalog to target entries after age retention and returns
// the entries the bounded catalog no longer references. Unlike PruneWithPolicy
// it lists without an entry cap, so an already oversized catalog remains both
// listable and prunable: evicted artifacts are deleted before their receipts, and
// an entry whose artifact is already missing does not block the receipt deletion.
// Age retention selects first; capacity pressure then evicts only the excess over
// target. A keeper is the newest entry of its source whose artifact still
// verifies, so a receipt that cannot be restored never outlives the last backup
// that still can, and the newest recoverable entry is never evicted.
func TrimCatalog(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, now time.Time, keepDays, target int, apply bool, policy RetentionPolicy) ([]CatalogEntry, error) {
	if target < 0 {
		return nil, errors.New("invalid backup retention target")
	}
	return trimCatalog(ctx, bucket, prefix, keys, now, keepDays, max(target, 1), apply, policy)
}

// RetentionTarget reserves publication slots below a configured capacity bound.
func RetentionTarget(maxEntries, reserve int) int {
	return max(maxEntries-reserve, 1)
}

func trimCatalog(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, now time.Time, keepDays, target int, apply bool, policy RetentionPolicy) (removed []CatalogEntry, err error) {
	if now.Unix() <= 0 || keepDays < 0 || keepDays > 65535 || policy != RetainLatest && policy != ExpireAll {
		return nil, errors.New("invalid backup retention policy")
	}
	entries, err := listCatalogEntries(ctx, bucket, prefix, keys)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.CreatedAt > now.Unix() {
			return nil, errors.New("catalog timestamp is in the future")
		}
	}
	// A signed receipt proves publication, not that its artifact can still be
	// fetched, so keepers are chosen from entries whose bytes verify. Reading is
	// memoized: a source's newest entry usually decides it.
	verified := make(map[string]bool, len(entries))
	recoverable := func(entry CatalogEntry) (bool, error) {
		if ok, known := verified[entry.ID]; known {
			return ok, nil
		}
		ok, err := artifactRecoverable(ctx, bucket, prefix, entry)
		if err != nil {
			return false, err
		}
		verified[entry.ID] = ok
		return ok, nil
	}
	// entries is sorted oldest to newest, including a stable ID tie-breaker, so a
	// newest-first pass finds each source's newest recoverable entry as its keeper
	// and the newest recoverable entry overall, the last copy worth protecting.
	keepers := make(map[string]CatalogEntry)
	newest := ""
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if policy == RetainLatest {
			if _, found := keepers[entry.SourcePrefix]; found {
				continue
			}
		}
		ok, err := recoverable(entry)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if newest == "" {
			newest = entry.ID
		}
		if policy == RetainLatest {
			keepers[entry.SourcePrefix] = entry
		}
	}
	cutoff := now.UTC().AddDate(0, 0, -keepDays).Unix()
	evict := make(map[string]bool)
	for _, entry := range entries {
		if entry.CreatedAt < cutoff && (policy == ExpireAll || entry.ID != keepers[entry.SourcePrefix].ID) {
			evict[entry.ID] = true
		}
	}
	// Age retention decides first. Capacity pressure then evicts extra entries only
	// while the catalog still exceeds target, oldest first: keepers go after every
	// other candidate so age retention holds while the bound allows it, and the
	// newest recoverable entry never goes, so an unusable receipt is evicted ahead
	// of the backup that still restores.
	keeper := func(entry CatalogEntry) bool { return entry.ID == keepers[entry.SourcePrefix].ID }
	remaining := len(entries) - len(evict)
	evictExcess := func(keepersOnly bool) {
		for _, entry := range entries {
			if remaining <= target {
				return
			}
			if evict[entry.ID] || entry.ID == newest || keeper(entry) != keepersOnly {
				continue
			}
			evict[entry.ID] = true
			remaining--
		}
	}
	evictExcess(false)
	evictExcess(true)
	var selected []CatalogEntry
	for _, entry := range entries {
		if evict[entry.ID] {
			selected = append(selected, entry)
		}
	}
	if !apply {
		return selected, nil
	}
	for _, entry := range selected {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		// Deleting an already missing artifact is a no-op; the receipt must go
		// either way so the catalog keeps listing.
		if err := bucket.Delete(ctx, catalogArtifactPath(prefix, entry.ID)); err != nil && !bucket.IsObjNotFoundErr(err) {
			return removed, err
		}
		if err := bucket.Delete(ctx, path.Join(prefix, "completed", entry.ID+".json")); err != nil && !bucket.IsObjNotFoundErr(err) {
			return removed, err
		}
		removed = append(removed, entry)
	}
	return removed, nil
}

// listCatalogEntries authenticates and sorts the whole catalog. It applies no
// entry cap so an oversized catalog can be pruned, and it performs no mutation.
func listCatalogEntries(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey) ([]CatalogEntry, error) {
	if bucket == nil || !validName(prefix) || validateCatalogTrustKeys(keys) != nil {
		return nil, errors.New("invalid catalog listing configuration")
	}
	var entries []CatalogEntry
	err := bucket.Iter(ctx, path.Join(prefix, "completed")+"/", func(name string) error {
		entry, err := readCatalogEntry(ctx, bucket, name, keys)
		if err != nil {
			return err
		}
		if name != path.Join(prefix, "completed", entry.ID+".json") || entry.CatalogPrefix != prefix || relatedPrefix(prefix, entry.SourcePrefix) {
			return errors.New("invalid catalog record location")
		}
		entries = append(entries, entry)
		return nil
	}, objstore.WithRecursiveIter())
	if err != nil {
		return nil, err
	}
	sortCatalogEntries(entries)
	return entries, nil
}

func sortCatalogEntries(entries []CatalogEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt == entries[j].CreatedAt {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].CreatedAt < entries[j].CreatedAt
	})
}

// artifactRecoverable reports whether an entry's artifact still fetches with
// exactly the bytes its signed receipt records. A missing artifact is a
// definitive negative; any other read failure is returned so the caller aborts
// without deleting instead of mistaking an unreadable artifact for an unusable
// one.
func artifactRecoverable(ctx context.Context, bucket objstore.Bucket, prefix string, entry CatalogEntry) (bool, error) {
	reader, err := bucket.Get(ctx, catalogArtifactPath(prefix, entry.ID))
	if err != nil {
		if bucket.IsObjNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(reader, entry.Size+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return false, err
	}
	return n == entry.Size && hex.EncodeToString(digest.Sum(nil)) == entry.SHA256, nil
}

func catalogArtifactPath(prefix, id string) string {
	return path.Join(prefix, "artifacts", id+".age")
}
