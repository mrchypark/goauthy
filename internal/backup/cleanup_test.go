package backup

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/thanos-io/objstore"
)

func TestCleanupWorkDirRemovesOnlyOwnedScratch(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{".goauthy-create-1", ".goauthy-backup-2", ".goauthy-catalog-3"} {
		if err := os.WriteFile(filepath.Join(parent, name), []byte("scratch"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(parent, ".goauthy-export-4", "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keeper", ".goauthy-unowned"} {
		if err := os.WriteFile(filepath.Join(parent, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CleanupWorkDir(parent); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != ".goauthy-unowned" || entries[1].Name() != "keeper" {
		t.Fatalf("remaining entries=%v", entries)
	}
}

type agedOrphanBucket struct {
	objstore.Bucket
	aged map[string]bool
}

func (b *agedOrphanBucket) Attributes(ctx context.Context, name string) (objstore.ObjectAttributes, error) {
	attrs, err := b.Bucket.Attributes(ctx, name)
	if err == nil && b.aged[name] {
		attrs.LastModified = time.Unix(1, 0)
	}
	return attrs, err
}

func TestSweepUncommittedArtifactsIsSafeAndIdempotent(t *testing.T) {
	ctx := context.Background()
	base := catalogBucket(t)
	defer base.Close()
	private, trust := catalogKey(t)
	prefix := "catalog/cluster-a"
	completed := catalogPublish(t, base, private, prefix, "source/cluster-a")
	orphanID := "AAAAAAAAAAAAAAAAAAAAAAAAAA"
	recentID := "BBBBBBBBBBBBBBBBBBBBBBBBBB"
	orphan := path.Join(prefix, "artifacts", orphanID+".age")
	recent := path.Join(prefix, "artifacts", recentID+".age")
	unknown := path.Join(prefix, "artifacts", "not-a-catalog-id.age")
	for _, name := range []string{orphan, recent, unknown} {
		if err := base.Upload(ctx, name, bytes.NewBufferString("ciphertext")); err != nil {
			t.Fatal(err)
		}
	}
	bucket := &agedOrphanBucket{Bucket: base, aged: map[string]bool{orphan: true, unknown: true}}
	plan, err := SweepUncommittedArtifacts(ctx, bucket, prefix, trust, time.Unix(2, 0), false)
	if err != nil || len(plan) != 1 || plan[0] != orphan {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	removed, err := SweepUncommittedArtifacts(ctx, bucket, prefix, trust, time.Unix(2, 0), true)
	if err != nil || len(removed) != 1 || removed[0] != orphan {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	for _, name := range []string{recent, unknown, path.Join(prefix, "artifacts", completed.ID+".age")} {
		if found, err := base.Exists(ctx, name); err != nil || !found {
			t.Fatalf("protected object %q exists=%t err=%v", name, found, err)
		}
	}
	removed, err = SweepUncommittedArtifacts(ctx, bucket, prefix, trust, time.Unix(2, 0), true)
	if err != nil || len(removed) != 0 {
		t.Fatalf("repeat removed=%v err=%v", removed, err)
	}
}

func TestSweepUncommittedArtifactsFailsClosedOnCatalogDamage(t *testing.T) {
	ctx := context.Background()
	base := catalogBucket(t)
	defer base.Close()
	private, trust := catalogKey(t)
	prefix := "catalog/cluster-a"
	entry := catalogPublish(t, base, private, prefix, "source/cluster-a")
	orphan := path.Join(prefix, "artifacts", "CCCCCCCCCCCCCCCCCCCCCCCCCC.age")
	if err := base.Upload(ctx, orphan, bytes.NewBufferString("orphan")); err != nil {
		t.Fatal(err)
	}
	if err := base.Upload(ctx, path.Join(prefix, "completed", entry.ID+".json"), bytes.NewBufferString("damaged")); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepUncommittedArtifacts(ctx, &agedOrphanBucket{Bucket: base, aged: map[string]bool{orphan: true}}, prefix, trust, time.Unix(2, 0), true); err == nil {
		t.Fatal("swept with a damaged catalog")
	}
	if found, err := base.Exists(ctx, orphan); err != nil || !found {
		t.Fatalf("orphan exists=%t err=%v", found, err)
	}
}
