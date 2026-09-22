package account

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	accountTestTemplateOnce sync.Once
	accountTestTemplateDir  string
	accountTestTemplateErr  error

	passkeyTestTemplateOnce sync.Once
	passkeyTestTemplateDir  string
	passkeyTestTemplateErr  error

	conversionTestTemplateOnce sync.Once
	conversionTestTemplateDir  string
	conversionTestTemplateErr  error
)

func buildAccountTestTemplate() {
	accountTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-account-test")
		if err != nil {
			accountTestTemplateErr = err
			return
		}
		accountTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-test", DataDir: dir})
		if err != nil {
			accountTestTemplateErr = err
			return
		}
		defer db.Close()
		statements := append(browser.SchemaStatements(), identity.SchemaStatements()...)
		statements = append(statements, rhiza.SQLStatement{SQL: `CREATE TABLE IF NOT EXISTS identity_external_links (
			provider_id TEXT NOT NULL,
			external_key TEXT NOT NULL,
			local_subject TEXT NOT NULL,
			linked_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (provider_id, external_key),
			UNIQUE (local_subject, provider_id)
		) STRICT`})
		_, accountTestTemplateErr = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "account-test-schema", Statements: statements})
	})
}

func buildPasskeyTestTemplate() {
	passkeyTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-account-passkey")
		if err != nil {
			passkeyTestTemplateErr = err
			return
		}
		passkeyTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-passkey-test", DataDir: dir})
		if err != nil {
			passkeyTestTemplateErr = err
			return
		}
		defer db.Close()
		passkeyTestTemplateErr = storage.Migrate(ctx, db)
	})
}

func buildConversionTestTemplate() {
	conversionTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-account-conversion")
		if err != nil {
			conversionTestTemplateErr = err
			return
		}
		conversionTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "account-conversion-test", DataDir: dir})
		if err != nil {
			conversionTestTemplateErr = err
			return
		}
		defer db.Close()
		conversionTestTemplateErr = storage.Migrate(ctx, db)
	})
}

func TestMain(m *testing.M) {
	buildAccountTestTemplate()
	if accountTestTemplateErr != nil {
		panic(accountTestTemplateErr)
	}
	buildPasskeyTestTemplate()
	if passkeyTestTemplateErr != nil {
		panic(passkeyTestTemplateErr)
	}
	buildConversionTestTemplate()
	if conversionTestTemplateErr != nil {
		panic(conversionTestTemplateErr)
	}
	code := m.Run()
	os.RemoveAll(accountTestTemplateDir)
	os.RemoveAll(passkeyTestTemplateDir)
	os.RemoveAll(conversionTestTemplateDir)
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
