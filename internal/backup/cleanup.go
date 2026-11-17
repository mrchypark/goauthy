package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/thanos-io/objstore"
)

var backupScratchPrefixes = []string{
	".goauthy-create-",
	".goauthy-export-",
	".goauthy-backup-",
	".goauthy-catalog-",
}

// CleanupWorkDir removes scratch entries owned by backup operations. Callers
// must dedicate the parent directory to one server process; unrelated entries
// are left untouched.
func CleanupWorkDir(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		owned := false
		for _, prefix := range backupScratchPrefixes {
			owned = owned || strings.HasPrefix(entry.Name(), prefix)
		}
		if owned {
			if err := os.RemoveAll(filepath.Join(parent, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// SweepUncommittedArtifacts removes aged artifacts without a trusted completion
// receipt. It authenticates the complete catalog before planning deletion, uses
// provider timestamps to avoid racing an in-flight publication, and deletes
// nothing unless the whole plan succeeded.
func SweepUncommittedArtifacts(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, before time.Time, apply bool) (_ []string, err error) {
	if bucket == nil || !validName(prefix) || validateCatalogTrustKeys(keys) != nil || before.IsZero() {
		return nil, errors.New("invalid backup orphan sweep configuration")
	}
	entries, err := listCatalogEntries(ctx, bucket, prefix, keys)
	if err != nil {
		return nil, err
	}
	completed := make(map[string]bool, len(entries))
	for _, entry := range entries {
		completed[entry.ID] = true
	}
	artifactPrefix := path.Join(prefix, "artifacts") + "/"
	var candidates []string
	err = bucket.Iter(ctx, artifactPrefix, func(name string) error {
		id, found := strings.CutPrefix(name, artifactPrefix)
		id, suffix := strings.CutSuffix(id, ".age")
		if !found || !suffix || strings.Contains(id, "/") || !validCatalogID(id) || completed[id] {
			return nil
		}
		attrs, err := bucket.Attributes(ctx, name)
		if err != nil {
			return err
		}
		if attrs.LastModified.IsZero() {
			return errors.New("orphan artifact has no modification time")
		}
		if attrs.LastModified.Before(before) {
			candidates = append(candidates, name)
		}
		return nil
	}, objstore.WithRecursiveIter())
	if err != nil || !apply {
		return candidates, err
	}
	var removed []string
	for _, name := range candidates {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := bucket.Delete(ctx, name); err != nil {
			if bucket.IsObjNotFoundErr(err) {
				continue
			}
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, nil
}
