package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
)

func TestCatalogPublishListFetch(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	artifactBytes := catalogArtifact(t, []byte("exact encrypted artifact bytes"))
	artifact := catalogFile(t, artifactBytes)
	entry, err := Publish(ctx, bucket, "catalog/cluster-a", "source/cluster-a", artifact, private, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	completed, err := ListCompleted(ctx, bucket, "catalog/cluster-a", public, 2)
	if err != nil || !slices.Equal(completed, []CatalogEntry{entry}) {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	work := t.TempDir()
	fetched, got, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, public, work, entry.Size)
	if err != nil || got != entry {
		t.Fatalf("FetchCompleted entry=%+v err=%v", got, err)
	}
	data, err := os.ReadFile(fetched)
	if err != nil || !bytes.Equal(data, artifactBytes) {
		t.Fatalf("fetched bytes=%q err=%v", data, err)
	}
	if err := os.Remove(fetched); err != nil {
		t.Fatal(err)
	}

	_, wrongPublic := catalogKey(t)
	if _, err := ListCompleted(ctx, bucket, "catalog/cluster-a", wrongPublic, 2); err == nil {
		t.Fatal("wrong public key listed catalog")
	}
	if _, _, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, wrongPublic, work, entry.Size); err == nil {
		t.Fatal("wrong public key fetched catalog")
	}
}

func TestCatalogRejectsCorruptionAndCleansFetchScratch(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	entry := catalogPublish(t, bucket, private, "catalog/cluster-a", "source/cluster-a")
	work := t.TempDir()
	artifact := path.Join("catalog/cluster-a", "artifacts", entry.ID+".age")
	original, err := bucket.Get(ctx, artifact)
	if err != nil {
		t.Fatal(err)
	}
	corruptedBytes, readErr := io.ReadAll(original)
	if err := errors.Join(readErr, original.Close()); err != nil {
		t.Fatal(err)
	}
	corruptedBytes[len(corruptedBytes)-1] ^= 1
	if err := bucket.Upload(ctx, artifact, bytes.NewReader(corruptedBytes)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, public, work, entry.Size); err == nil {
		t.Fatal("corrupt artifact fetched")
	}
	catalogScratchEmpty(t, work)
	if err := bucket.Delete(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if _, _, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, public, work, entry.Size); err == nil {
		t.Fatal("missing artifact fetched")
	}
	catalogScratchEmpty(t, work)

	entry = catalogPublish(t, bucket, private, "catalog/cluster-a", "source/cluster-b")
	receipt := path.Join("catalog/cluster-a", "completed", entry.ID+".json")
	r, err := bucket.Get(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(r)
	if err := errors.Join(readErr, r.Close()); err != nil {
		t.Fatal(err)
	}
	var signed signedEntry
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	var changed CatalogEntry
	if err := json.Unmarshal(signed.Entry, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Size++ // Keep the valid 64-byte signature but invalidate its covered JSON.
	signed.Entry, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	modified, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := bucket.Upload(ctx, receipt, bytes.NewReader(modified)); err != nil {
		t.Fatal(err)
	}
	if _, err := ListCompleted(ctx, bucket, "catalog/cluster-a", public, 4); err == nil {
		t.Fatal("modified signed payload listed")
	}
	if _, _, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, public, work, entry.Size); err == nil {
		t.Fatal("modified signed payload fetched")
	}
	catalogScratchEmpty(t, work)
}

func TestCatalogPublicationBoundaries(t *testing.T) {
	ctx := context.Background()
	bucket := catalogBucket(t)
	defer bucket.Close()
	private, public := catalogKey(t)
	artifact := catalogFile(t, catalogArtifact(t, []byte("boundary")))
	if _, err := Publish(ctx, bucket, "catalog/cluster-a", "catalog/cluster-a/source", artifact, private, time.Now()); err == nil {
		t.Fatal("overlapping source prefix published")
	}
	entry := catalogPublish(t, bucket, private, "catalog/cluster-a", "source/cluster-a")
	receipt := path.Join("catalog/cluster-a", "completed", entry.ID+".json")
	r, err := bucket.Get(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	record, readErr := io.ReadAll(r)
	if err := errors.Join(readErr, r.Close()); err != nil {
		t.Fatal(err)
	}
	if err := bucket.Upload(ctx, path.Join("other", "completed", entry.ID+".json"), bytes.NewReader(record)); err != nil {
		t.Fatal(err)
	}
	if _, err := ListCompleted(ctx, bucket, "other", public, 1); err == nil {
		t.Fatal("relocated signed receipt listed")
	}
	if _, _, err := FetchCompleted(ctx, bucket, "other", entry.ID, public, t.TempDir(), entry.Size); err == nil {
		t.Fatal("relocated signed receipt fetched")
	}
	work := t.TempDir()
	if _, _, err := FetchCompleted(ctx, bucket, "catalog/cluster-a", entry.ID, public, work, entry.Size-1); err == nil {
		t.Fatal("oversize artifact fetched")
	}
	catalogScratchEmpty(t, work)
	catalogPublish(t, bucket, private, "catalog/cluster-a", "source/cluster-b")
	if _, err := ListCompleted(ctx, bucket, "catalog/cluster-a", public, 1); err == nil {
		t.Fatal("entry limit accepted")
	}

	bad := CatalogEntry{Version: 1, ID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", CreatedAt: 1, SourcePrefix: "overlap/source", CatalogPrefix: "overlap", Size: entry.Size, SHA256: entry.SHA256}
	if err := bucket.Upload(ctx, path.Join("overlap", "completed", bad.ID+".json"), bytes.NewReader(catalogReceipt(t, private, bad))); err != nil {
		t.Fatal(err)
	}
	if _, err := ListCompleted(ctx, bucket, "overlap", public, 1); err == nil {
		t.Fatal("overlapping source prefix listed")
	}
	if _, _, err := FetchCompleted(ctx, bucket, "overlap", bad.ID, public, work, entry.Size); err == nil {
		t.Fatal("overlapping source prefix fetched")
	}
	counted := &catalogCountingBucket{Bucket: bucket}
	if _, err := Publish(ctx, counted, "catalog/cluster-a", strings.Repeat("a", 4096), catalogFile(t, catalogArtifact(t, []byte("oversized"))), private, time.Now()); err == nil || counted.uploads != 0 {
		t.Fatalf("oversized record err=%v uploads=%d", err, counted.uploads)
	}
}

func TestCatalogIncompleteAndFailedPublicationRemainUnlisted(t *testing.T) {
	ctx := context.Background()
	base := catalogBucket(t)
	defer base.Close()
	private, public := catalogKey(t)
	artifact := catalogArtifact(t, []byte("orphan"))
	if err := base.Upload(ctx, "catalog/cluster-a/artifacts/incomplete.age", bytes.NewReader(artifact)); err != nil {
		t.Fatal(err)
	}
	entries, err := ListCompleted(ctx, base, "catalog/cluster-a", public, 1)
	if err != nil || len(entries) != 0 {
		t.Fatalf("incomplete entries=%+v err=%v", entries, err)
	}

	failing := &catalogFailBucket{Bucket: base, failCompleted: true}
	file := catalogFile(t, artifact)
	if _, err := Publish(ctx, failing, "catalog/cluster-a", "source/cluster-a", file, private, time.Now()); err == nil {
		t.Fatal("completion upload failure succeeded")
	}
	if failing.artifact == "" {
		t.Fatal("artifact was not uploaded before completion failure")
	}
	exists, err := base.Exists(ctx, failing.artifact)
	if err != nil || !exists {
		t.Fatalf("orphan exists=%v err=%v", exists, err)
	}
	entries, err = ListCompleted(ctx, base, "catalog/cluster-a", public, 2)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed publication listed entries=%+v err=%v", entries, err)
	}
	ambiguous := &catalogAmbiguousUploadBucket{Bucket: base}
	if _, err := Publish(ctx, ambiguous, "catalog/cluster-a", "source/cluster-b", catalogFile(t, catalogArtifact(t, []byte("ambiguous"))), private, time.Now()); err == nil {
		t.Fatal("ambiguous artifact upload succeeded")
	}
	exists, err = base.Exists(ctx, ambiguous.artifact)
	if err != nil || !exists {
		t.Fatalf("ambiguous orphan exists=%v err=%v", exists, err)
	}
	entries, err = ListCompleted(ctx, base, "catalog/cluster-a", public, 2)
	if err != nil || len(entries) != 0 {
		t.Fatalf("ambiguous publication listed entries=%+v err=%v", entries, err)
	}
	corrupt := &catalogReadbackCorruptBucket{Bucket: base}
	if _, err := Publish(ctx, corrupt, "catalog/cluster-a", "source/cluster-c", catalogFile(t, catalogArtifact(t, []byte("readback"))), private, time.Now()); err == nil {
		t.Fatal("corrupt readback succeeded")
	}
	exists, err = base.Exists(ctx, corrupt.artifact)
	if err != nil || !exists {
		t.Fatalf("corrupt-readback orphan exists=%v err=%v", exists, err)
	}
	entries, err = ListCompleted(ctx, base, "catalog/cluster-a", public, 2)
	if err != nil || len(entries) != 0 {
		t.Fatalf("corrupt readback listed entries=%+v err=%v", entries, err)
	}
}

func TestCatalogCompletionRecordIsImmutable(t *testing.T) {
	ctx := context.Background()
	base := catalogBucket(t)
	defer base.Close()
	private, _ := catalogKey(t)
	conflict := &catalogConflictBucket{Bucket: base}
	if _, err := Publish(ctx, conflict, "catalog/cluster-a", "source/cluster-a", catalogFile(t, catalogArtifact(t, []byte("immutable"))), private, time.Now()); err == nil {
		t.Fatal("receipt collision succeeded")
	}
	if !conflict.conditional || conflict.receipt == "" {
		t.Fatalf("completion conditional=%v receipt=%q", conflict.conditional, conflict.receipt)
	}
	r, err := base.Get(ctx, conflict.receipt)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(r)
	if err := errors.Join(readErr, r.Close()); err != nil || string(got) != "existing receipt" {
		t.Fatalf("receipt=%q err=%v", got, err)
	}
}

func TestCatalogTrustBundleRotatesWithoutLosingCompletedBackups(t *testing.T) {
	ctx := context.Background()
	bucket := objstore.NewInMemBucket()
	oldSigner, oldTrust := catalogKey(t)
	newSigner, newTrust := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	old := trustBundlePublish(t, bucket, oldSigner, prefix, "source/a", "AAAAAAAAAAAAAAAAAAAAAAAAAA", now.AddDate(0, 0, -30))
	new := trustBundlePublish(t, bucket, newSigner, prefix, "source/a", "BBBBBBBBBBBBBBBBBBBBBBBBBB", now.AddDate(0, 0, -20))
	trust := append(oldTrust, newTrust...)

	entries, err := ListCompleted(ctx, bucket, prefix, trust, 8)
	if err != nil || !slices.Equal(entries, []CatalogEntry{old, new}) {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	for _, entry := range entries {
		name, got, err := FetchCompleted(ctx, bucket, prefix, entry.ID, trust, t.TempDir(), entry.Size)
		if err != nil || got != entry {
			t.Fatalf("fetch entry=%+v got=%+v err=%v", entry, got, err)
		}
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := Prune(ctx, bucket, prefix, trust, now, 7, 8, true)
	if err != nil || !slices.Equal(deleted, []CatalogEntry{old}) {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	retentionAbsent(t, bucket, prefix, old)
	retentionPresent(t, bucket, prefix, new)
}

func TestCatalogTrustBundleRejectsRevokedSignerBeforePruning(t *testing.T) {
	ctx := context.Background()
	bucket := objstore.NewInMemBucket()
	trustedSigner, trust := catalogKey(t)
	revokedSigner, _ := catalogKey(t)
	now := time.Unix(1_800_000_000, 0)
	prefix := "catalog/cluster-a"
	trusted := trustBundlePublish(t, bucket, trustedSigner, prefix, "source/a", "AAAAAAAAAAAAAAAAAAAAAAAAAA", now.AddDate(0, 0, -30))
	revoked := trustBundlePublish(t, bucket, revokedSigner, prefix, "source/b", "BBBBBBBBBBBBBBBBBBBBBBBBBB", now.AddDate(0, 0, -20))
	counting := &retentionDeleteBucket{Bucket: bucket}
	if _, err := Prune(ctx, counting, prefix, trust, now, 7, 8, true); err == nil {
		t.Fatal("revoked signer was accepted")
	}
	if len(counting.deleted) != 0 {
		t.Fatalf("deleted before rejecting revoked signer: %v", counting.deleted)
	}
	retentionPresent(t, bucket, prefix, trusted)
	retentionPresent(t, bucket, prefix, revoked)
}

func TestCatalogTrustBundleRejectsInvalidBundlesBeforeIO(t *testing.T) {
	ctx := context.Background()
	bucket := objstore.NewInMemBucket()
	signer, trust := catalogKey(t)
	prefix := "catalog/cluster-a"
	entry := trustBundlePublish(t, bucket, signer, prefix, "source/a", "AAAAAAAAAAAAAAAAAAAAAAAAAA", time.Unix(1_700_000_000, 0))
	tooMany := make([]ed25519.PublicKey, MaxCatalogTrustKeys+1)
	for i := range tooMany {
		tooMany[i] = make(ed25519.PublicKey, ed25519.PublicKeySize)
		tooMany[i][0] = byte(i)
	}
	for _, invalid := range [][]ed25519.PublicKey{
		nil,
		{},
		{make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
		{trust[0], trust[0]},
		tooMany,
	} {
		t.Run("invalid", func(t *testing.T) {
			counting := &catalogReadCountingBucket{Bucket: bucket}
			if _, err := ListCompleted(ctx, counting, prefix, invalid, 8); err == nil {
				t.Fatal("invalid bundle listed catalog")
			}
			if _, _, err := FetchCompleted(ctx, counting, prefix, entry.ID, invalid, t.TempDir(), entry.Size); err == nil {
				t.Fatal("invalid bundle fetched catalog")
			}
			if _, err := Prune(ctx, counting, prefix, invalid, time.Unix(1_800_000_000, 0), 7, 8, true); err == nil {
				t.Fatal("invalid bundle pruned catalog")
			}
			if counting.gets != 0 || counting.iters != 0 {
				t.Fatalf("invalid bundle performed I/O: gets=%d iters=%d", counting.gets, counting.iters)
			}
			if _, ok := bucket.Objects()[path.Join(prefix, "completed", entry.ID+".json")]; !ok {
				t.Fatal("invalid bundle mutated catalog")
			}
		})
	}
}

func trustBundlePublish(t *testing.T, bucket objstore.Bucket, signer ed25519.PrivateKey, prefix, source, id string, created time.Time) CatalogEntry {
	t.Helper()
	artifact := catalogArtifact(t, []byte(id))
	digest := sha256.Sum256(artifact)
	entry := CatalogEntry{Version: 1, ID: id, CreatedAt: created.Unix(), SourcePrefix: source, CatalogPrefix: prefix, Size: int64(len(artifact)), SHA256: fmt.Sprintf("%x", digest)}
	if err := bucket.Upload(context.Background(), path.Join(prefix, "artifacts", id+".age"), bytes.NewReader(artifact)); err != nil {
		t.Fatal(err)
	}
	if err := bucket.Upload(context.Background(), path.Join(prefix, "completed", id+".json"), bytes.NewReader(catalogReceipt(t, signer, entry))); err != nil {
		t.Fatal(err)
	}
	return entry
}

func catalogBucket(t *testing.T) *filesystem.Bucket {
	t.Helper()
	bucket, err := filesystem.NewBucket(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(bucket.SupportedObjectUploadOptions(), objstore.IfNotExists) {
		_ = bucket.Close()
		t.Skip("filesystem object store lacks conditional-write support")
	}
	return bucket
}

func catalogKey(t *testing.T) (ed25519.PrivateKey, []ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private, []ed25519.PublicKey{public}
}

func catalogArtifact(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes()
}

func catalogFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "artifact-*.age")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	return file
}

func catalogPublish(t *testing.T, bucket objstore.Bucket, key ed25519.PrivateKey, prefix, source string) CatalogEntry {
	t.Helper()
	entry, err := Publish(context.Background(), bucket, prefix, source, catalogFile(t, catalogArtifact(t, []byte(source))), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func catalogReceipt(t *testing.T, key ed25519.PrivateKey, entry CatalogEntry) []byte {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(signedEntry{Entry: raw, Signature: ed25519.Sign(key, raw)})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func catalogScratchEmpty(t *testing.T, parent string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(parent, ".goauthy-catalog-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("fetch left scratch=%v err=%v", matches, err)
	}
}

type catalogFailBucket struct {
	objstore.Bucket
	failCompleted bool
	artifact      string
}

func (b *catalogFailBucket) Upload(ctx context.Context, name string, reader io.Reader, options ...objstore.ObjectUploadOption) error {
	if strings.Contains(name, "/artifacts/") {
		b.artifact = name
	}
	if b.failCompleted && strings.Contains(name, "/completed/") {
		return errors.New("injected completion failure")
	}
	return b.Bucket.Upload(ctx, name, reader, options...)
}

type catalogConflictBucket struct {
	objstore.Bucket
	receipt     string
	conditional bool
}

type catalogCountingBucket struct {
	objstore.Bucket
	uploads int
}

type catalogReadCountingBucket struct {
	objstore.Bucket
	gets  int
	iters int
}

func (b *catalogReadCountingBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	b.gets++
	return b.Bucket.Get(ctx, name)
}

func (b *catalogReadCountingBucket) Iter(ctx context.Context, dir string, f func(string) error, options ...objstore.IterOption) error {
	b.iters++
	return b.Bucket.Iter(ctx, dir, f, options...)
}

func (b *catalogCountingBucket) Upload(ctx context.Context, name string, reader io.Reader, options ...objstore.ObjectUploadOption) error {
	b.uploads++
	return b.Bucket.Upload(ctx, name, reader, options...)
}

type catalogAmbiguousUploadBucket struct {
	objstore.Bucket
	artifact string
}

func (b *catalogAmbiguousUploadBucket) Upload(ctx context.Context, name string, reader io.Reader, options ...objstore.ObjectUploadOption) error {
	err := b.Bucket.Upload(ctx, name, reader, options...)
	if err == nil && strings.Contains(name, "/artifacts/") {
		b.artifact = name
		return errors.New("injected ambiguous artifact upload")
	}
	return err
}

type catalogReadbackCorruptBucket struct {
	objstore.Bucket
	artifact string
}

func (b *catalogReadbackCorruptBucket) Upload(ctx context.Context, name string, reader io.Reader, options ...objstore.ObjectUploadOption) error {
	if strings.Contains(name, "/artifacts/") {
		b.artifact = name
	}
	return b.Bucket.Upload(ctx, name, reader, options...)
}

func (b *catalogReadbackCorruptBucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	reader, err := b.Bucket.Get(ctx, name)
	if err != nil || name != b.artifact {
		return reader, err
	}
	data, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	data[0] ^= 1
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *catalogConflictBucket) Upload(ctx context.Context, name string, reader io.Reader, options ...objstore.ObjectUploadOption) error {
	if !strings.Contains(name, "/completed/") {
		return b.Bucket.Upload(ctx, name, reader, options...)
	}
	b.receipt = name
	b.conditional = objstore.ApplyObjectUploadOptions(options...).IfNotExists
	if err := b.Bucket.Upload(ctx, name, strings.NewReader("existing receipt")); err != nil {
		return err
	}
	return b.Bucket.Upload(ctx, name, reader, options...)
}
