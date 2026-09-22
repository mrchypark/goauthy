package branding

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	faviconTemplateOnce sync.Once
	faviconTemplateDir  string
	faviconTemplateErr  error
)

func buildFaviconTemplate() {
	faviconTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-branding-favicon")
		if err != nil {
			faviconTemplateErr = err
			return
		}
		faviconTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "client-favicon-test", DataDir: dir})
		if err != nil {
			faviconTemplateErr = err
			return
		}
		defer db.Close()
		faviconTemplateErr = storage.Migrate(ctx, db)
	})
}

func TestMain(m *testing.M) {
	buildFaviconTemplate()
	if faviconTemplateErr != nil {
		panic(faviconTemplateErr)
	}
	code := m.Run()
	os.RemoveAll(faviconTemplateDir)
	os.Exit(code)
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
