package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	stdhash "hash"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/thanos-io/objstore"
)

type capturedObject struct {
	ManifestObject
	FilePath string
}
type captureRecord struct {
	object capturedObject
	active bool
}
type captureBucket struct {
	objstore.Bucket
	prefix, dir string
	limits      Limits
	mu          sync.Mutex
	records     map[string]captureRecord
	total       int64
	failed      error
}

func newCaptureBucket(bucket objstore.Bucket, prefix, dir string, limits Limits) (*captureBucket, error) {
	if bucket == nil || !validName(prefix) || !limits.valid() {
		return nil, errors.New("invalid capture bucket")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, errors.New("invalid capture directory")
	}
	return &captureBucket{Bucket: bucket, prefix: prefix, dir: dir, limits: limits, records: map[string]captureRecord{}}, nil
}

func (b *captureBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	r, err := b.Bucket.Get(ctx, name)
	if err != nil || !b.allowed(name) {
		return r, err
	}
	rel := strings.TrimPrefix(name, b.prefix+"/")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed != nil {
		_ = r.Close()
		return nil, b.failed
	}
	if existing, ok := b.records[rel]; ok && existing.active {
		_ = r.Close()
		return nil, b.fail(errors.New("capture reader already active"))
	}
	if _, exists := b.records[rel]; !exists && len(b.records) >= b.limits.MaxFiles {
		_ = r.Close()
		return nil, b.fail(errors.New("capture limits exceeded"))
	}
	f, err := os.CreateTemp(b.dir, ".capture-")
	if err != nil {
		_ = r.Close()
		return nil, b.fail(err)
	}
	old := b.records[rel]
	b.records[rel] = captureRecord{object: old.object, active: true}
	return &captureReader{ReadCloser: r, file: f, bucket: b, name: rel, hash: sha256.New()}, nil
}
func (b *captureBucket) allowed(name string) bool {
	if !strings.HasPrefix(name, b.prefix+"/") {
		return false
	}
	return validObjectName(strings.TrimPrefix(name, b.prefix+"/"))
}
func (b *captureBucket) fail(err error) error {
	if b.failed == nil {
		b.failed = err
	}
	return b.failed
}
func (b *captureBucket) finish() ([]capturedObject, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed != nil {
		return nil, b.failed
	}
	out := make([]capturedObject, 0, len(b.records))
	for _, r := range b.records {
		if r.active {
			return nil, errors.New("capture reader remains open")
		}
		out = append(out, r.object)
	}
	return out, nil
}

type captureReader struct {
	io.ReadCloser
	file        *os.File
	bucket      *captureBucket
	name        string
	hash        stdhash.Hash
	size        int64
	eof, closed bool
}

func (r *captureReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, errors.New("capture reader is closed")
	}
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.bucket.mu.Lock()
		ok := int64(n) <= r.bucket.limits.MaxFileBytes-r.size && int64(n) <= r.bucket.limits.MaxTotalBytes-r.bucket.total
		if ok {
			r.bucket.total += int64(n)
			r.size += int64(n)
		} else {
			r.bucket.fail(errors.New("capture limits exceeded"))
		}
		r.bucket.mu.Unlock()
		if !ok {
			return 0, errors.New("capture limits exceeded")
		}
		if _, e := r.file.Write(p[:n]); e != nil {
			r.bucket.mu.Lock()
			r.bucket.fail(e)
			r.bucket.mu.Unlock()
			return n, e
		}
		_, _ = r.hash.Write(p[:n])
	}
	if err == io.EOF {
		r.eof = true
	} else if err != nil {
		r.bucket.mu.Lock()
		r.bucket.fail(err)
		r.bucket.mu.Unlock()
	}
	return n, err
}
func (r *captureReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	sourceErr := r.ReadCloser.Close()
	fileErr := r.file.Close()
	r.bucket.mu.Lock()
	defer r.bucket.mu.Unlock()
	rec := r.bucket.records[r.name]
	rec.active = false
	if !r.eof || sourceErr != nil || fileErr != nil {
		r.bucket.fail(errors.Join(errors.New("incomplete capture"), sourceErr, fileErr, os.Remove(r.file.Name())))
		return r.bucket.failed
	}
	sum := r.hash.Sum(nil)
	obj := capturedObject{ManifestObject: ManifestObject{Name: r.name, Size: r.size, SHA256: hex.EncodeToString(sum)}, FilePath: r.file.Name()}
	if old, ok := r.bucket.records[r.name]; ok && old.object.FilePath != "" {
		if old.object.Size != obj.Size || old.object.SHA256 != obj.SHA256 {
			r.bucket.fail(errors.Join(errors.New("conflicting capture"), os.Remove(obj.FilePath)))
			return r.bucket.failed
		}
		if err := os.Remove(obj.FilePath); err != nil {
			return r.bucket.fail(err)
		}
		r.bucket.total -= obj.Size
		old.active = false
		r.bucket.records[r.name] = old
		return nil
	}
	rec.object = obj
	r.bucket.records[r.name] = rec
	return nil
}
