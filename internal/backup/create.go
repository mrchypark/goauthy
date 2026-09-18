package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
)

// Create exports a fresh encrypted snapshot and publishes its signed completion
// to a separately supplied destination. Only private temporary local files are
// used; callers own both buckets. Any error means no success may be declared,
// including cleanup errors after remote publication (which cannot be rolled back).
func Create(ctx context.Context, source, destination objstore.Bucket, sourcePrefix, clusterID, catalogPrefix string, recipients []age.Recipient, key ed25519.PrivateKey, workParent string, limits Limits) (_ CatalogEntry, err error) {
	if source == nil || !restorePrefix(sourcePrefix, clusterID) || len(recipients) == 0 || workParent == "" {
		return CatalogEntry{}, errors.New("invalid backup creation configuration")
	}
	if err := validatePublication(destination, catalogPrefix, sourcePrefix, key, time.Now()); err != nil {
		return CatalogEntry{}, err
	}
	if _, err := limits.streamLimit(); err != nil {
		return CatalogEntry{}, err
	}
	file, err := os.CreateTemp(workParent, ".goauthy-create-")
	if err != nil {
		return CatalogEntry{}, err
	}
	defer func() { err = errors.Join(err, file.Close(), os.Remove(file.Name())) }()
	for attempt := 0; ; attempt++ {
		if err = file.Truncate(0); err != nil {
			return CatalogEntry{}, err
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return CatalogEntry{}, err
		}
		_, err = Export(ctx, source, sourcePrefix, clusterID, file, recipients, workParent, limits)
		if err == nil {
			break
		}
		// Rhiza rejects a moving head or maintenance lock during snapshot acquisition.
		// Retry only these exact native failures, before any remote publication;
		// joined cleanup failures and other integrity/transport errors fail closed.
		if attempt == 5 || (err.Error() != "shared archive head changed during chain load" && err.Error() != recovery.ErrArchiveBusy.Error() && err.Error() != checkpoint.ErrPublisherBusy.Error()) {
			return CatalogEntry{}, err
		}
		timer := time.NewTimer((100 * time.Millisecond) << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return CatalogEntry{}, ctx.Err()
		case <-timer.C:
		}
	}
	if err = file.Sync(); err != nil {
		return CatalogEntry{}, err
	}
	return Publish(ctx, destination, catalogPrefix, sourcePrefix, file, key, time.Now())
}
