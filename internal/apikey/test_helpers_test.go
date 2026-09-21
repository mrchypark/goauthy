package apikey

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Rhiza applies every migration statement through replicated consensus, which
// costs several seconds for a fresh database under -race. The migrated schema is
// therefore built once per NodeID and each test opens a private copy of it,
// which keeps per-test isolation and still exercises the idempotent migrate path.

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

type templateResult struct {
	dir string
	err error
}

var (
	templateDirs sync.Map
	templateOnce sync.Map
)

func migratedTemplate(t *testing.T, nodeID string) string {
	t.Helper()
	once, _ := templateOnce.LoadOrStore(nodeID, &sync.Once{})
	once.(*sync.Once).Do(func() {
		directory, err := os.MkdirTemp("", "goauthy-apikey-template-"+nodeID+"-")
		if err != nil {
			templateDirs.Store(nodeID, templateResult{err: err})
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: directory})
		if err != nil {
			_ = os.RemoveAll(directory)
			templateDirs.Store(nodeID, templateResult{err: fmt.Errorf("open template for %s: %w", nodeID, err)})
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			_ = db.Close()
			_ = os.RemoveAll(directory)
			templateDirs.Store(nodeID, templateResult{err: fmt.Errorf("migrate template for %s: %w", nodeID, err)})
			return
		}
		_ = db.Close()
		templateDirs.Store(nodeID, templateResult{dir: directory})
	})
	result, ok := templateDirs.Load(nodeID)
	if !ok {
		t.Fatalf("template for %s not in cache", nodeID)
	}
	r := result.(templateResult)
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.dir
}

func openTestDB(t *testing.T, nodeID string) *rhiza.DB {
	t.Helper()
	directory := t.TempDir()
	if err := copyDirTree(migratedTemplate(t, nodeID), directory); err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: directory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func openTestDBWithConfig(t *testing.T, nodeID string, extra rhiza.Config) *rhiza.DB {
	t.Helper()
	directory := t.TempDir()
	if err := copyDirTree(migratedTemplate(t, nodeID), directory); err != nil {
		t.Fatal(err)
	}
	extra.NodeID = nodeID
	extra.DataDir = directory
	db, err := rhiza.Open(context.Background(), extra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMain(m *testing.M) {
	code := m.Run()
	templateDirs.Range(func(key, value any) bool {
		r := value.(templateResult)
		if r.dir != "" {
			_ = os.RemoveAll(r.dir)
		}
		return true
	})
	os.Exit(code)
}
