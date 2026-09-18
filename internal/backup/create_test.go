package backup

import (
	"context"
	"filippo.io/age"
	"os"
	"testing"
)

func TestCreateFailedExportNeverPublishes(t *testing.T) {
	source := catalogBucket(t)
	defer source.Close()
	destination := &catalogCountingBucket{Bucket: catalogBucket(t)}
	defer destination.Close()
	key, _ := catalogKey(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	entry, err := Create(context.Background(), source, destination, "live/cluster", "cluster", "backups", []age.Recipient{identity.Recipient()}, key, work, Limits{MaxFiles: 100, MaxFileBytes: 1 << 20, MaxTotalBytes: 2 << 20})
	if err == nil || entry.ID != "" {
		t.Fatalf("declared success for empty source: %v", err)
	}
	if destination.uploads != 0 {
		t.Fatal("failed export published remote objects")
	}
	files, err := os.ReadDir(work)
	if err != nil || len(files) != 0 {
		t.Fatalf("failed export leaked scratch: %v", err)
	}
}
