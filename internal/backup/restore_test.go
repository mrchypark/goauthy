package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
)

func TestRestoreDestinationBinding(t *testing.T) {
	for _, test := range []struct {
		prefix, cluster string
		want            bool
	}{
		{"restore/cluster", "cluster", true},
		{"cluster", "cluster", true},
		{"restore/other", "cluster", false},
		{"/restore/cluster", "cluster", false},
		{"restore/cluster", "nested/cluster", false},
	} {
		if got := restorePrefix(test.prefix, test.cluster); got != test.want {
			t.Fatalf("restorePrefix(%q, %q) = %v, want %v", test.prefix, test.cluster, got, test.want)
		}
	}
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"source/cluster", "destination/cluster", false},
		{"source/cluster", "source/cluster", true},
		{"source/cluster", "source", true},
		{"source", "source/cluster", true},
	} {
		if got := relatedPrefix(test.a, test.b); got != test.want {
			t.Fatalf("relatedPrefix(%q, %q) = %v, want %v", test.a, test.b, got, test.want)
		}
	}
}

func TestRestoreRejectsBeforeWritingAndNeverPromotesMalformedRoot(t *testing.T) {
	ctx := context.Background()
	base, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	staged := malformedRestoreStage(t)
	counted := &countBucket{Bucket: base}
	if _, err := Restore(ctx, counted, "restore/cluster-a", "wrong", staged, t.TempDir()); err == nil {
		t.Fatal("identity mismatch succeeded")
	}
	if counted.count() != 0 {
		t.Fatal("identity mismatch wrote destination")
	}
	if err := base.Upload(ctx, "occupied/cluster-a/existing", bytes.NewReader([]byte("keep"))); err != nil {
		t.Fatal(err)
	}
	before := counted.count()
	if _, err := Restore(ctx, counted, "occupied/cluster-a", "cluster-a", staged, t.TempDir()); err == nil {
		t.Fatal("occupied destination succeeded")
	}
	r, err := base.Get(ctx, "occupied/cluster-a/existing")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil || closeErr != nil || string(data) != "keep" || counted.count() != before {
		t.Fatal("occupied destination changed")
	}
	if _, err := Restore(ctx, counted, "restore/cluster-a", "cluster-a", staged, t.TempDir()); err == nil {
		t.Fatal("malformed root succeeded")
	}
	exists, err := base.Exists(ctx, "restore/cluster-a/checkpoint/CURRENT")
	if err != nil || exists {
		t.Fatal("CURRENT was published")
	}
}

func TestRestoreUploadFailureAndMarkerContention(t *testing.T) {
	ctx := context.Background()
	base, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	staged := malformedRestoreStage(t)
	failing := &countBucket{Bucket: base, failObject: true}
	if _, err := Restore(ctx, failing, "failure/cluster-a", "cluster-a", staged, t.TempDir()); err == nil {
		t.Fatal("injected upload failure succeeded")
	}
	exists, err := base.Exists(ctx, "failure/cluster-a/checkpoint/CURRENT")
	if err != nil || exists {
		t.Fatal("CURRENT after upload failure")
	}
	contended := &countBucket{Bucket: base, markerReady: make(chan struct{})}
	raceCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Restore(raceCtx, contended, "race/cluster-a", "cluster-a", staged, t.TempDir())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("malformed restore succeeded")
		}
	}
	if contended.markerSuccesses() != 1 {
		t.Fatalf("marker owners = %d, want 1", contended.markerSuccesses())
	}
	if contended.markerAttemptCount() != 2 {
		t.Fatalf("marker attempts = %d, want 2", contended.markerAttemptCount())
	}
}

func TestRestoreObjectUploadHasExactSizeAndCanRewind(t *testing.T) {
	ctx := context.Background()
	base, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	checked := &sizeCheckingBucket{Bucket: base}
	if _, err := Restore(ctx, checked, "sized/cluster-a", "cluster-a", malformedRestoreStage(t), t.TempDir()); err == nil {
		t.Fatal("malformed root unexpectedly restored")
	}
	if checked.checked == 0 {
		t.Fatal("no non-marker object upload was size-checked")
	}
	if checked.mismatch {
		t.Fatal("restore object reader had size or seek mismatch")
	}
}

func malformedRestoreStage(t *testing.T) Extracted {
	t.Helper()
	objects := completeObjects(map[string][]byte{"archive/head.bin": []byte("bad-root")})
	manifest := testManifest(objects)
	stage, inventory := writeManifestStage(t, manifest, objects)
	return Extracted{Dir: stage, Inventory: inventory}
}

type countBucket struct {
	objstore.Bucket
	mu                               sync.Mutex
	uploads, markers, markerAttempts int
	markerReady                      chan struct{}
	failObject                       bool
}

func (b *countBucket) Upload(ctx context.Context, name string, r io.Reader, options ...objstore.ObjectUploadOption) error {
	b.mu.Lock()
	b.uploads++
	fail := b.failObject && strings.HasSuffix(name, "archive/head.bin")
	if strings.HasSuffix(name, "goauthy-restore.json") && b.markerReady != nil {
		b.markerAttempts++
		if b.markerAttempts == 2 {
			close(b.markerReady)
		}
	}
	b.mu.Unlock()
	if fail {
		return errors.New("injected upload failure")
	}
	if strings.HasSuffix(name, "goauthy-restore.json") && b.markerReady != nil {
		select {
		case <-b.markerReady:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	err := b.Bucket.Upload(ctx, name, r, options...)
	if err == nil && strings.HasSuffix(name, "goauthy-restore.json") {
		b.mu.Lock()
		b.markers++
		b.mu.Unlock()
	}
	return err
}
func (b *countBucket) count() int           { b.mu.Lock(); defer b.mu.Unlock(); return b.uploads }
func (b *countBucket) markerSuccesses() int { b.mu.Lock(); defer b.mu.Unlock(); return b.markers }
func (b *countBucket) markerAttemptCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.markerAttempts
}

type sizeCheckingBucket struct {
	objstore.Bucket
	checked  int
	mismatch bool
}

func (b *sizeCheckingBucket) Upload(ctx context.Context, name string, r io.Reader, options ...objstore.ObjectUploadOption) error {
	if !strings.HasSuffix(name, "goauthy-restore.json") {
		b.checked++
		good := false
		defer func() {
			if !good {
				b.mismatch = true
			}
		}()
		size, err := objstore.TryToGetSize(r)
		if err != nil {
			return err
		}
		seeker, ok := r.(io.Seeker)
		if !ok {
			return errors.New("restore reader is not seekable")
		}
		first, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if int64(len(first)) != size {
			return errors.New("restore reader size mismatch")
		}
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return err
		}
		second, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(first, second) {
			return errors.New("restore reader rewind mismatch")
		}
		good = true
	}
	return b.Bucket.Upload(ctx, name, r, options...)
}
