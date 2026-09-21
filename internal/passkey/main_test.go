package passkey

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
	pkTemplateOnce sync.Once
	pkTemplateDir  string
	pkTemplateErr  error
)

func buildPasskeyTemplate(t *testing.T) string {
	t.Helper()
	pkTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "passkey-template-*")
		if err != nil {
			pkTemplateErr = err
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "passkey-test", DataDir: dir})
		if err != nil {
			pkTemplateErr = err
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			_ = db.Close()
			pkTemplateErr = err
			return
		}
		_ = db.Close()
		pkTemplateDir = dir
	})
	if pkTemplateErr != nil {
		t.Fatal(pkTemplateErr)
	}
	return pkTemplateDir
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
	if pkTemplateDir != "" {
		os.RemoveAll(pkTemplateDir)
	}
	os.Exit(code)
}
