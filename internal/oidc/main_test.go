package oidc

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
	oidcTemplateOnce sync.Once
	oidcTemplateDir  string
	oidcTemplateErr  error
)

func buildOIDCTemplate(t *testing.T) string {
	t.Helper()
	oidcTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "oidc-template-*")
		if err != nil {
			oidcTemplateErr = err
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: dir})
		if err != nil {
			oidcTemplateErr = err
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			_ = db.Close()
			oidcTemplateErr = err
			return
		}
		_ = db.Close()
		oidcTemplateDir = dir
	})
	if oidcTemplateErr != nil {
		t.Fatal(oidcTemplateErr)
	}
	return oidcTemplateDir
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
	if oidcTemplateDir != "" {
		os.RemoveAll(oidcTemplateDir)
	}
	os.Exit(code)
}
