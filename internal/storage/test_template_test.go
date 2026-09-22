package storage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/rhiza"
)

type templateResult struct {
	dir string
	err error
}

var (
	templateDirs sync.Map
	templateOnce sync.Map
)

// copyDirTree reproduces a template database directory inside a test-owned
// directory. The copy is an independent database with its own sqlite.db, WAL
// and recorder state, so tests stay isolated from one another.
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

// migratedTemplate returns the shared migrated template directory for nodeID,
// building it on first use. Every test binary is isolated because the
// templates are keyed by NodeID inside this process.
func migratedTemplate(nodeID string) (string, error) {
	once, _ := templateOnce.LoadOrStore(nodeID, &sync.Once{})
	once.(*sync.Once).Do(func() {
		directory, err := os.MkdirTemp("", "goauthy-storage-template-"+sanitizeNodeID(nodeID)+"-")
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
		if err := Migrate(context.Background(), db); err != nil {
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
		return "", fmt.Errorf("template for %s not in cache", nodeID)
	}
	built := result.(templateResult)
	if built.err != nil {
		return "", built.err
	}
	return built.dir, nil
}

// testDatabaseDir copies the migrated template for nodeID into a directory the
// test owns. Callers still run Migrate against the copy so the idempotent path
// stays exercised.
func testDatabaseDir(t *testing.T, nodeID string) string {
	t.Helper()
	template, err := migratedTemplate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := copyDirTree(template, directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func sanitizeNodeID(nodeID string) string {
	return strings.Map(func(character rune) rune {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-',
			character == '.':
			return character
		}
		return '_'
	}, nodeID)
}

func TestMain(m *testing.M) {
	// Templates are built on first use rather than here. Several tests in this
	// package re-exec the test binary as a subprocess, so anything TestMain does
	// is paid again by every child; a warm-up build would blow the subprocess
	// budget of the no-PVC recovery tests.
	code := m.Run()

	templateDirs.Range(func(_, value any) bool {
		if built := value.(templateResult); built.dir != "" {
			_ = os.RemoveAll(built.dir)
		}
		return true
	})
	os.Exit(code)
}
