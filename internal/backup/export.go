package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
)

// Export writes an encrypted recovery snapshot. Callers must discard dst on
// ANY error and publish it only after success. Temporary plaintext is private;
// limits bound captured objects, not Rhiza's own decoding buffers.
func Export(ctx context.Context, bucket objstore.Bucket, prefix, clusterID string, dst io.Writer, recipients []age.Recipient, workParent string, limits Limits) (_ SnapshotManifest, err error) {
	if bucket == nil || dst == nil || len(recipients) == 0 || !restorePrefix(prefix, clusterID) {
		return SnapshotManifest{}, errors.New("invalid snapshot export configuration")
	}
	if _, err := limits.streamLimit(); err != nil {
		return SnapshotManifest{}, err
	}
	stage, err := os.MkdirTemp(workParent, ".goauthy-export-")
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	capture, err := newCaptureBucket(bucket, prefix, stage, limits)
	if err != nil {
		return SnapshotManifest{}, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	archive := recovery.NewManager(capture, prefix, 1)
	defer archive.Close()
	// Probe without capturing: the checkpoint branch reloads under its pin.
	probe := recovery.NewManager(bucket, prefix, 1)
	probeErr := probe.Load(ctx)
	_, _, hasBase := probe.RecoveryBase()
	probe.Close()
	if probeErr != nil {
		return SnapshotManifest{}, probeErr
	}
	if !hasBase {
		if err := archive.Load(ctx); err != nil {
			return SnapshotManifest{}, err
		}
		if _, _, ok := archive.RecoveryBase(); ok {
			return SnapshotManifest{}, errors.New("checkpoint appeared during export; retry")
		}
		if err := validateInitialArchive(ctx, archive, uint64(archive.Tip())); err != nil {
			return SnapshotManifest{}, err
		}
		manifest := SnapshotManifest{FormatVersion: 2, RhizaVersion: "v0.12.3", SourcePrefix: prefix, ClusterID: clusterID, ConfigID: 1, RecoveryMode: "archive-only", ArchiveTip: uint64(archive.Tip())}
		return writeCaptured(ctx, capture, manifest, dst, recipients, limits)
	}
	owner := "goauthy-export-" + rand.Text()
	const lease = 3 * time.Minute
	snapshot, err := archive.BeginRecoverySnapshot(ctx, owner, lease)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		err = errors.Join(err, snapshot.Close(cleanup))
	}()
	seal, base, ok := snapshot.RecoveryBase()
	if !ok {
		return SnapshotManifest{}, errors.New("snapshot has no certified checkpoint")
	}
	checkpoints := checkpoint.NewManager(capture, prefix, stage, 1)
	root, err := checkpoints.OpenRoot(ctx, uint64(seal.Index), seal.RootHash)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if root.Hash != seal.StateHash {
		return SnapshotManifest{}, errors.New("snapshot checkpoint state mismatch")
	}
	pin, err := checkpoints.PinRecoveryRoot(ctx, root, owner, lease)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		err = errors.Join(err, pin.Close(cleanup))
	}()
	var renewMu sync.Mutex
	renew := func() error {
		renewMu.Lock()
		defer renewMu.Unlock()
		if err := pin.Renew(ctx, lease); err != nil {
			return err
		}
		return snapshot.Renew(ctx, lease)
	}
	if err := renew(); err != nil {
		return SnapshotManifest{}, err
	}
	stopRenew, renewed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopRenew:
				return
			case <-ticker.C:
				if err := renew(); err != nil {
					cancel(fmt.Errorf("renew snapshot pins: %w", err))
					return
				}
			}
		}
	}()
	defer func() { close(stopRenew); <-renewed; err = errors.Join(err, context.Cause(ctx)) }()
	if uint64(base.Slot) == ^uint64(0) {
		return SnapshotManifest{}, errors.New("invalid snapshot archive base")
	}
	for next, tip := base.Slot+1, snapshot.Tip(); next <= tip; {
		values, _, err := snapshot.DecisionsFrom(ctx, next, 256)
		if err != nil {
			return SnapshotManifest{}, err
		}
		if len(values) == 0 {
			return SnapshotManifest{}, errors.New("snapshot archive gap")
		}
		for _, value := range values {
			if value.Slot != next || value.Slot > tip || uint64(next) == ^uint64(0) {
				return SnapshotManifest{}, errors.New("invalid snapshot archive range")
			}
			next++
		}
	}
	files, err := checkpoints.DownloadAndVerifyRootFiles(ctx, root, stage)
	if err != nil {
		return SnapshotManifest{}, err
	}
	for _, file := range files {
		if err := os.Remove(file.Path); err != nil {
			return SnapshotManifest{}, err
		}
	}
	manifest := SnapshotManifest{FormatVersion: 1, RhizaVersion: "v0.12.3", SourcePrefix: prefix, ClusterID: clusterID, ConfigID: 1, CheckpointIndex: root.Index, CheckpointRootHash: fmt.Sprintf("%x", root.RootHash), CheckpointStateHash: fmt.Sprintf("%x", root.Hash)}
	manifest, err = writeCaptured(ctx, capture, manifest, dst, recipients, limits)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if err := renew(); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

func writeCaptured(ctx context.Context, capture *captureBucket, manifest SnapshotManifest, dst io.Writer, recipients []age.Recipient, limits Limits) (_ SnapshotManifest, err error) {
	objects, err := capture.finish()
	if err != nil {
		return SnapshotManifest{}, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Name < objects[j].Name })
	entries := make([]Entry, 0, len(objects)+1)
	for _, object := range objects {
		manifest.Objects = append(manifest.Objects, object.ManifestObject)
		file := &exportFileReader{name: object.FilePath}
		defer func() { err = errors.Join(err, file.Close()) }()
		entries = append(entries, Entry{Name: ObjectEntryPrefix + object.Name, Size: object.Size, Reader: file})
	}
	metadata, err := MarshalManifest(manifest)
	if err != nil {
		return SnapshotManifest{}, err
	}
	entries = append(entries, Entry{Name: ManifestEntry, Size: int64(len(metadata)), Reader: bytes.NewReader(metadata)})
	if err := Write(exportWriter{ctx, dst}, recipients, entries, limits); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

// Open one staged object at a time instead of retaining a descriptor per object.
type exportFileReader struct {
	name   string
	file   *os.File
	closed bool
}

func (r *exportFileReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.file == nil {
		file, err := os.Open(r.name)
		if err != nil {
			return 0, err
		}
		r.file = file
	}
	n, err := r.file.Read(p)
	if err != nil {
		if closeErr := r.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	return n, err
}

func (r *exportFileReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

type exportWriter struct {
	ctx context.Context
	dst io.Writer
}

func (w exportWriter) Write(p []byte) (int, error) {
	if err := context.Cause(w.ctx); err != nil {
		return 0, err
	}
	n, err := w.dst.Write(p)
	return n, errors.Join(err, context.Cause(w.ctx))
}
