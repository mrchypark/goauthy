package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
)

func TestCaptureBucketCommitsOnlyEOFClosedReads(t *testing.T) {
	ctx := context.Background()
	bucket, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	if err := bucket.Upload(ctx, "source/cluster-a/archive/head.bin", bytes.NewReader([]byte("head"))); err != nil {
		t.Fatal(err)
	}
	capture, err := newCaptureBucket(bucket, "source/cluster-a", t.TempDir(), Limits{MaxFiles: 4, MaxFileBytes: 1024, MaxTotalBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	r, err := capture.Get(ctx, "source/cluster-a/archive/head.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	objects, err := capture.finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Name != "archive/head.bin" {
		t.Fatal("capture inventory mismatch")
	}
}

func TestCaptureByteLimitsIncludeActiveFiles(t *testing.T) {
	ctx := context.Background()
	b, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	put := func(n, s string) {
		if err := b.Upload(ctx, n, bytes.NewReader([]byte(s))); err != nil {
			t.Fatal(err)
		}
	}
	put("p/c/archive/head.bin", "1234")
	put("p/c/checkpoint/roots/r", "5678")
	put("p/c/checkpoint/blocks/b", "12345")
	dir := t.TempDir()
	c, err := newCaptureBucket(b, "p/c", dir, Limits{MaxFiles: 3, MaxFileBytes: 4, MaxTotalBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	readClose := func(n string) error {
		r, e := c.Get(ctx, n)
		if e != nil {
			return e
		}
		_, e = io.ReadAll(r)
		if e != nil {
			_ = r.Close()
			return e
		}
		return r.Close()
	}
	if err := readClose("p/c/archive/head.bin"); err != nil {
		t.Fatal(err)
	}
	if err := readClose("p/c/checkpoint/roots/r"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.finish(); err != nil {
		t.Fatal(err)
	}
	var disk int64
	files, _ := filepath.Glob(filepath.Join(dir, ".capture-*"))
	for _, f := range files {
		info, e := os.Stat(f)
		if e != nil {
			t.Fatal(e)
		}
		disk += info.Size()
	}
	if disk != 8 {
		t.Fatalf("staged bytes=%d want8", disk)
	}
	c2, err := newCaptureBucket(b, "p/c", t.TempDir(), Limits{MaxFiles: 3, MaxFileBytes: 4, MaxTotalBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c2.Get(ctx, "p/c/checkpoint/blocks/b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("per-file +1 accepted")
	}
	_ = r.Close()
	if _, err := c2.finish(); err == nil {
		t.Fatal("per-file failure accepted")
	}
	c3, err := newCaptureBucket(b, "p/c", t.TempDir(), Limits{MaxFiles: 3, MaxFileBytes: 5, MaxTotalBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	r1, e := c3.Get(ctx, "p/c/archive/head.bin")
	if e != nil {
		t.Fatal(e)
	}
	r2, e := c3.Get(ctx, "p/c/checkpoint/blocks/b")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadAll(r1); e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadAll(r2); e == nil {
		t.Fatal("aggregate +1 accepted with active readers")
	}
	_ = r1.Close()
	_ = r2.Close()
	if _, e := c3.finish(); e == nil {
		t.Fatal("aggregate failure accepted")
	}
}

func TestCaptureRejectsActiveLimitsAndConflicts(t *testing.T) {
	ctx := context.Background()
	b, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	put := func(n, s string) {
		if err := b.Upload(ctx, n, bytes.NewReader([]byte(s))); err != nil {
			t.Fatal(err)
		}
	}
	put("p/c/archive/head.bin", "one")
	put("p/c/checkpoint/roots/r", "two")
	c, err := newCaptureBucket(b, "p/c", t.TempDir(), Limits{MaxFiles: 1, MaxFileBytes: 8, MaxTotalBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Get(ctx, "p/c/archive/head.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.finish(); err == nil {
		t.Fatal("active accepted")
	}
	_, _ = io.ReadAll(r)
	_ = r.Close()
	if _, err := c.Get(ctx, "p/c/checkpoint/roots/r"); err == nil {
		t.Fatal("count limit accepted")
	}
	c2, err := newCaptureBucket(b, "p/c", t.TempDir(), Limits{MaxFiles: 2, MaxFileBytes: 8, MaxTotalBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	read := func() {
		r, e := c2.Get(ctx, "p/c/archive/head.bin")
		if e != nil {
			t.Fatal(e)
		}
		_, _ = io.ReadAll(r)
		if e = r.Close(); e != nil {
			t.Fatal(e)
		}
	}
	read()
	read()
	if _, e := c2.finish(); e != nil {
		t.Fatal(e)
	}
	put("p/c/archive/head.bin", "new")
	r, e := c2.Get(ctx, "p/c/archive/head.bin")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.ReadAll(r)
	_ = r.Close()
	if _, e := c2.finish(); e == nil {
		t.Fatal("conflict accepted")
	}
}

func TestCaptureRejectsReaderFailures(t *testing.T) {
	ctx := context.Background()
	b, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Upload(ctx, "p/c/archive/head.bin", bytes.NewReader([]byte("head"))); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read", "close"} {
		t.Run(mode, func(t *testing.T) {
			c, err := newCaptureBucket(&faultBucket{Bucket: b, mode: mode}, "p/c", t.TempDir(), Limits{MaxFiles: 2, MaxFileBytes: 8, MaxTotalBytes: 8})
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.Get(ctx, "p/c/archive/head.bin")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.ReadAll(r)
			_ = r.Close()
			if _, err := c.finish(); err == nil {
				t.Fatal("fault accepted")
			}
		})
	}
}

type faultBucket struct {
	objstore.Bucket
	mode string
}

func (b *faultBucket) Get(ctx context.Context, n string) (io.ReadCloser, error) {
	r, e := b.Bucket.Get(ctx, n)
	if e != nil {
		return nil, e
	}
	return &faultReader{ReadCloser: r, mode: b.mode}, nil
}

type faultReader struct {
	io.ReadCloser
	mode string
	done bool
}

func (r *faultReader) Read(p []byte) (int, error) {
	if r.mode == "read" && !r.done {
		r.done = true
		return 0, errors.New("read fault")
	}
	return r.ReadCloser.Read(p)
}
func (r *faultReader) Close() error {
	if r.mode == "close" {
		_ = r.ReadCloser.Close()
		return errors.New("close fault")
	}
	return r.ReadCloser.Close()
}

func TestCaptureBucketRejectsPartialRead(t *testing.T) {
	ctx := context.Background()
	bucket, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	if err := bucket.Upload(ctx, "source/cluster-a/archive/head.bin", bytes.NewReader([]byte("head"))); err != nil {
		t.Fatal(err)
	}
	capture, err := newCaptureBucket(bucket, "source/cluster-a", t.TempDir(), Limits{MaxFiles: 4, MaxFileBytes: 1024, MaxTotalBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	r, err := capture.Get(ctx, "source/cluster-a/archive/head.bin")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if _, err := capture.finish(); err == nil {
		t.Fatal("partial capture accepted")
	}
}
