package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
)

// Restore verifies a staged manifest, copies it to a fresh exclusive prefix,
// and promotes CURRENT only after Rhiza validates the remote archive and root.
// The target must be offline and exclusively owned by the caller.
func Restore(ctx context.Context, bucket objstore.Bucket, prefix, clusterID string, staged Extracted, workParent string) (_ SnapshotManifest, err error) {
	manifest, err := ReadManifest(staged.Dir, staged.Inventory)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if manifest.ClusterID != clusterID || !restorePrefix(prefix, clusterID) || relatedPrefix(prefix, manifest.SourcePrefix) {
		return SnapshotManifest{}, errors.New("invalid restore destination")
	}
	options := bucket.SupportedObjectUploadOptions()
	if !slices.Contains(options, objstore.IfNotExists) || !slices.Contains(options, objstore.IfMatch) {
		return SnapshotManifest{}, errors.New("restore requires conditional object writes")
	}
	prefix = path.Clean(prefix)
	empty := true
	if err := bucket.Iter(ctx, prefix+"/", func(string) error { empty = false; return nil }, objstore.WithRecursiveIter()); err != nil {
		return SnapshotManifest{}, err
	}
	if !empty {
		return SnapshotManifest{}, errors.New("restore destination is not empty")
	}
	marker := path.Join(prefix, "goauthy-restore.json")
	if err := bucket.Upload(ctx, marker, bytes.NewReader([]byte(`{"format_version":1}`)), objstore.WithIfNotExists()); err != nil {
		return SnapshotManifest{}, err
	}
	root, err := os.OpenRoot(staged.Dir)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer root.Close()
	for _, object := range manifest.Objects {
		file, err := root.Open(objectPath(object.Name))
		if err != nil {
			return SnapshotManifest{}, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != object.Size {
			return SnapshotManifest{}, errors.Join(errors.New("staged restore object changed"), statErr, file.Close())
		}
		// The provider recognizes *os.File's exact size and retry seek support.
		// The caller retains exclusive ownership of staging until upload ends.
		err = bucket.Upload(ctx, path.Join(prefix, object.Name), file, objstore.WithIfNotExists())
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return SnapshotManifest{}, err
		}
	}
	if manifest.RecoveryMode == "archive-only" {
		archive := recovery.NewManager(bucket, prefix, uint(manifest.ConfigID))
		defer archive.Close()
		if err := archive.Load(ctx); err != nil {
			return SnapshotManifest{}, err
		}
		if err := validateInitialArchive(ctx, archive, manifest.ArchiveTip); err != nil {
			return SnapshotManifest{}, err
		}
		return manifest, nil
	}
	managerDir, err := os.MkdirTemp(workParent, ".goauthy-checkpoints-")
	if err != nil {
		return SnapshotManifest{}, err
	}
	scratchRemoved := false
	defer func() {
		if !scratchRemoved {
			if cleanupErr := os.RemoveAll(managerDir); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	checkpoints := checkpoint.NewManager(bucket, prefix, managerDir, uint(manifest.ConfigID))
	rootHash, err := hash(manifest.CheckpointRootHash)
	if err != nil {
		return SnapshotManifest{}, err
	}
	opened, err := checkpoints.OpenRoot(ctx, manifest.CheckpointIndex, rootHash)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if opened.ConfigID != uint(manifest.ConfigID) || fmt.Sprintf("%x", opened.Hash) != manifest.CheckpointStateHash {
		return SnapshotManifest{}, errors.New("restored checkpoint does not match manifest")
	}
	if _, err := checkpoints.DownloadAndVerifyRootFiles(ctx, opened, managerDir); err != nil {
		return SnapshotManifest{}, err
	}
	archive := recovery.NewManager(bucket, prefix, uint(manifest.ConfigID))
	defer archive.Close()
	if err := archive.Load(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	seal, base, ok := archive.RecoveryBase()
	if !ok || uint64(seal.Index) != manifest.CheckpointIndex || seal.RootHash != rootHash || fmt.Sprintf("%x", seal.StateHash) != manifest.CheckpointStateHash {
		return SnapshotManifest{}, errors.New("restored archive base does not match manifest")
	}
	const maxSlot = ^uint64(0)
	if uint64(base.Slot) == maxSlot {
		return SnapshotManifest{}, errors.New("invalid restored archive")
	}
	for next, tip := base.Slot+1, archive.Tip(); next <= tip; {
		values, _, err := archive.DecisionsFrom(ctx, next, 256)
		if err != nil {
			return SnapshotManifest{}, fmt.Errorf("validate restored archive: %w", err)
		}
		if len(values) == 0 {
			return SnapshotManifest{}, errors.New("invalid restored archive")
		}
		for _, value := range values {
			if value.Slot != next || value.Slot > tip {
				return SnapshotManifest{}, errors.New("invalid restored archive")
			}
			if uint64(next) == maxSlot {
				return SnapshotManifest{}, errors.New("invalid restored archive")
			}
			next++
		}
	}
	if err := os.RemoveAll(managerDir); err != nil {
		return SnapshotManifest{}, err
	}
	scratchRemoved = true
	if err := checkpoints.PromoteCertifiedCurrent(ctx, opened); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

func hash(value string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		return out, errors.New("invalid checkpoint root hash")
	}
	copy(out[:], decoded)
	return out, nil
}
func restorePrefix(prefix, cluster string) bool {
	return validName(prefix) && validName(cluster) && !strings.Contains(cluster, "/") && (prefix == cluster || strings.HasSuffix(prefix, "/"+cluster))
}
func relatedPrefix(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// A successful finite capture needs every immutable block, even without a pin.
// Retention racing a read fails the operation; it cannot authorize a partial DR.
func validateInitialArchive(ctx context.Context, archive *recovery.Manager, tip uint64) error {
	if _, _, ok := archive.RecoveryBase(); ok || tip == 0 || tip == ^uint64(0) || uint64(archive.Tip()) != tip {
		return errors.New("invalid archive-only recovery boundary")
	}
	next := archive.Tip()
	next = 1
	for uint64(next) <= tip {
		values, gotTip, err := archive.DecisionsFrom(ctx, next, 256)
		if err != nil {
			return fmt.Errorf("validate initial archive: %w", err)
		}
		if len(values) == 0 || uint64(gotTip) != tip {
			return errors.New("initial archive gap or changed tip")
		}
		for _, value := range values {
			if value.Slot != next || uint64(value.Slot) > tip {
				return errors.New("invalid initial archive range")
			}
			next++
		}
	}
	return nil
}
