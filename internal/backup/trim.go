package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
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
// The newest entry of each source is retained while capacity allows; capacity
// pressure may evict it, but never the last reachable entry.
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
	entries, reachable, err := listCatalogEntries(ctx, bucket, prefix, keys)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.CreatedAt > now.Unix() {
			return nil, errors.New("catalog timestamp is in the future")
		}
	}
	cutoff := now.UTC().AddDate(0, 0, -keepDays).Unix()
	keepers := make(map[string]CatalogEntry)
	if policy == RetainLatest {
		// entries is sorted oldest to newest, including a stable ID tie-breaker.
		for _, entry := range entries {
			keepers[entry.SourcePrefix] = entry
		}
	}
	evict := make(map[string]bool)
	for _, entry := range entries {
		if entry.CreatedAt < cutoff && (policy == ExpireAll || entry.ID != keepers[entry.SourcePrefix].ID) {
			evict[entry.ID] = true
		}
	}
	// Capacity pressure evicts the oldest remaining entry, including a keeper
	// that age retention would protect. Only a reachable last entry is protected:
	// a receipt whose artifact is already missing cannot keep the catalog over its
	// bound and unlistable.
	remaining := len(entries) - len(evict)
	for _, entry := range entries {
		// Age retention already selected the entry, or the reachable newest
		// entry is the last one standing inside the bound.
		if evict[entry.ID] || (remaining <= target && entry.ID == keepers[entry.SourcePrefix].ID && reachable[entry.ID]) {
			continue
		}
		evict[entry.ID] = true
		remaining--
	}
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
		if reachable[entry.ID] {
			if err := bucket.Delete(ctx, catalogArtifactPath(prefix, entry.ID)); err != nil && !bucket.IsObjNotFoundErr(err) {
				return removed, err
			}
		}
		if err := bucket.Delete(ctx, path.Join(prefix, "completed", entry.ID+".json")); err != nil && !bucket.IsObjNotFoundErr(err) {
			return removed, err
		}
		removed = append(removed, entry)
	}
	return removed, nil
}

// listCatalogEntries authenticates and sorts the whole catalog, recording which
// artifacts are still readable. It applies no entry cap so an oversized catalog
// can be pruned, and it performs no mutation.
func listCatalogEntries(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey) ([]CatalogEntry, map[string]bool, error) {
	if bucket == nil || !validName(prefix) || validateCatalogTrustKeys(keys) != nil {
		return nil, nil, errors.New("invalid catalog listing configuration")
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
		return nil, nil, err
	}
	sortCatalogEntries(entries)
	reachable := make(map[string]bool, len(entries))
	for _, entry := range entries {
		exists, err := bucket.Exists(ctx, catalogArtifactPath(prefix, entry.ID))
		if err != nil {
			return nil, nil, err
		}
		reachable[entry.ID] = exists
	}
	return entries, reachable, nil
}

func sortCatalogEntries(entries []CatalogEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt == entries[j].CreatedAt {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].CreatedAt < entries[j].CreatedAt
	})
}

func catalogArtifactPath(prefix, id string) string {
	return path.Join(prefix, "artifacts", id+".age")
}
