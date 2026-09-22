package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Rhiza applies every migration statement through replicated consensus, which
// costs several seconds for a fresh database under -race. The migrated schema
// is therefore built once per NodeID and each test opens a private copy, which
// keeps per-test isolation at a fraction of the cost. The NodeID is preserved
// because a copied database keeps its WAL recorder membership.

type cmdTemplateEntry struct {
	once sync.Once
	dir  string
	err  error
}

var cmdTemplates sync.Map // NodeID -> *cmdTemplateEntry

func TestMain(m *testing.M) {
	code := m.Run()
	cmdTemplates.Range(func(_, value any) bool {
		if entry, ok := value.(*cmdTemplateEntry); ok && entry.dir != "" {
			_ = os.RemoveAll(entry.dir)
		}
		return true
	})
	os.Exit(code)
}

// cmdMigratedTemplate returns the directory of a migrated database built once
// for nodeID.
func cmdMigratedTemplate(t *testing.T, nodeID string) string {
	t.Helper()
	value, _ := cmdTemplates.LoadOrStore(nodeID, &cmdTemplateEntry{})
	entry := value.(*cmdTemplateEntry)
	entry.once.Do(func() {
		directory, err := os.MkdirTemp("", "goauthy-cmd-"+nodeID+"-template-")
		if err != nil {
			entry.err = err
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: directory})
		if err != nil {
			_ = os.RemoveAll(directory)
			entry.err = fmt.Errorf("open %s test template: %w", nodeID, err)
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			_ = db.Close()
			_ = os.RemoveAll(directory)
			entry.err = fmt.Errorf("migrate %s test template: %w", nodeID, err)
			return
		}
		if err := db.Close(); err != nil {
			_ = os.RemoveAll(directory)
			entry.err = fmt.Errorf("close %s test template: %w", nodeID, err)
			return
		}
		entry.dir = directory
	})
	if entry.err != nil {
		t.Fatal(entry.err)
	}
	return entry.dir
}

// migratedDataDir returns a private copy of the migrated template for nodeID.
func migratedDataDir(t *testing.T, nodeID string) string {
	t.Helper()
	directory := t.TempDir()
	if err := copyDirTree(cmdMigratedTemplate(t, nodeID), directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func copyDirTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
}

// testHash routes password hashing through one package-level hasher, because
// credential.Hash shares a single hasher whose 100ms work limit is exceeded
// when several parallel tests hash passwords at once.
var testHasherOnce sync.Once
var testHasherInstance *credential.Hasher

func testHash(ctx context.Context, password []byte) (string, error) {
	testHasherOnce.Do(func() {
		var err error
		testHasherInstance, err = credential.NewHasher(credential.Policy{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1, MaxConcurrency: 8, WaitTimeout: 5 * time.Second})
		if err != nil {
			panic(err)
		}
	})
	return testHasherInstance.Hash(ctx, password)
}
