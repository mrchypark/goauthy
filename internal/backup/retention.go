package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path"
	"time"

	"github.com/thanos-io/objstore"
)

type RetentionPolicy string

const (
	RetainLatest RetentionPolicy = "keep-latest"
	ExpireAll    RetentionPolicy = "expire-all"
)

// Prune selects expired completed artifacts while retaining the newest signed
// entry for each source prefix. Every keeper is verified before any deletion.
// apply=false returns the same plan without mutation. Apply removes artifacts
// before receipts; a failed receipt deletion is safely resumed on the next run.
// Concurrent publishers/pruners are allowed; arbitrary external deletion or
// modification of protected artifacts is outside this cooperative guarantee.
func Prune(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, now time.Time, keepDays, maxEntries int, apply bool) ([]CatalogEntry, error) {
	return PruneWithPolicy(ctx, bucket, prefix, keys, now, keepDays, maxEntries, apply, RetainLatest)
}

// PruneWithPolicy selects expired completed artifacts under the chosen policy.
// RetainLatest protects the newest entry for each source; ExpireAll follows
// Rauthy's upstream behavior and can delete every expired entry.
func PruneWithPolicy(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, now time.Time, keepDays, maxEntries int, apply bool, policy RetentionPolicy) ([]CatalogEntry, error) {
	if now.Unix() <= 0 || keepDays < 0 || keepDays > 65535 || policy != RetainLatest && policy != ExpireAll {
		return nil, errors.New("invalid backup retention policy")
	}
	entries, err := ListCompleted(ctx, bucket, prefix, keys, maxEntries)
	if err != nil {
		return nil, err
	}
	keepers := make(map[string]CatalogEntry)
	for _, entry := range entries {
		if entry.CreatedAt > now.Unix() {
			return nil, errors.New("catalog timestamp is in the future")
		}
		if policy == RetainLatest {
			// ListCompleted sorts oldest to newest, including a stable ID tie-breaker.
			keepers[entry.SourcePrefix] = entry
		}
	}
	for _, entry := range keepers {
		if err := verifyCatalogArtifact(ctx, bucket, prefix, entry); err != nil {
			return nil, err
		}
	}
	cutoff := now.UTC().AddDate(0, 0, -keepDays).Unix()
	var selected []CatalogEntry
	for _, entry := range entries {
		if entry.CreatedAt < cutoff && (policy == ExpireAll || entry.ID != keepers[entry.SourcePrefix].ID) {
			selected = append(selected, entry)
		}
	}
	if !apply {
		return selected, nil
	}
	var removed []CatalogEntry
	for _, entry := range selected {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := bucket.Delete(ctx, path.Join(prefix, "artifacts", entry.ID+".age")); err != nil && !bucket.IsObjNotFoundErr(err) {
			return removed, err
		}
		if err := bucket.Delete(ctx, path.Join(prefix, "completed", entry.ID+".json")); err != nil && !bucket.IsObjNotFoundErr(err) {
			return removed, err
		}
		removed = append(removed, entry)
	}
	return removed, nil
}
