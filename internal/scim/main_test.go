package scim

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
	scmTemplateOnce sync.Once
	scmTemplateDir  string
	scmTemplateErr  error
)

func buildSCIMTemplate(t *testing.T) string {
	t.Helper()
	scmTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "scim-template-*")
		if err != nil {
			scmTemplateErr = err
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "scim-outbox-test", DataDir: dir})
		if err != nil {
			scmTemplateErr = err
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			_ = db.Close()
			scmTemplateErr = err
			return
		}
		_ = db.Close()
		scmTemplateDir = dir
	})
	if scmTemplateErr != nil {
		t.Fatal(scmTemplateErr)
	}
	return scmTemplateDir
}

func cpDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		sp := filepath.Join(src, e.Name())
		dp := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(dp, 0o700); err != nil {
				t.Fatal(err)
			}
			cpDir(t, sp, dp)
		} else {
			data, err := os.ReadFile(sp)
			if err != nil {
				t.Fatal(err)
			}
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dp, data, info.Mode()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if scmTemplateDir != "" {
		os.RemoveAll(scmTemplateDir)
	}
	os.Exit(code)
}
