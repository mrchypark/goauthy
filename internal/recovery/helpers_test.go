package recovery

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
	recoveryTestTemplateOnce sync.Once
	recoveryTestTemplateDir  string
	recoveryTestTemplateErr  error

	opTestTemplateOnce sync.Once
	opTestTemplateDir  string
	opTestTemplateErr  error

	powTestTemplateOnce sync.Once
	powTestTemplateDir  string
	powTestTemplateErr  error

	emailOutboxTemplateOnce sync.Once
	emailOutboxTemplateDir  string
	emailOutboxTemplateErr  error
)

const outboxRetirementGenerations = `CREATE TABLE IF NOT EXISTS master_key_retirement_generations (
	epoch INTEGER PRIMARY KEY CHECK (epoch > 0),
	old_key_id TEXT NOT NULL CHECK (length(old_key_id) BETWEEN 1 AND 64 AND old_key_id NOT GLOB '*[^A-Za-z0-9._-]*'),
	replacement_key_id TEXT NOT NULL CHECK (length(replacement_key_id) BETWEEN 1 AND 64 AND replacement_key_id NOT GLOB '*[^A-Za-z0-9._-]*' AND replacement_key_id <> old_key_id),
	ready_at_unix_ms INTEGER CHECK (ready_at_unix_ms IS NULL OR ready_at_unix_ms >= 0),
	removed_at_unix_ms INTEGER CHECK (removed_at_unix_ms IS NULL OR (ready_at_unix_ms IS NOT NULL AND removed_at_unix_ms >= ready_at_unix_ms))
) STRICT`

func buildRecoveryTestTemplate() {
	recoveryTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-recovery-test")
		if err != nil {
			recoveryTestTemplateErr = err
			return
		}
		recoveryTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "recovery-test", DataDir: dir})
		if err != nil {
			recoveryTestTemplateErr = err
			return
		}
		defer db.Close()
		recoveryTestTemplateErr = storage.Migrate(ctx, db)
	})
}

func buildOTPTestTemplate() {
	opTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-recovery-otp")
		if err != nil {
			opTestTemplateErr = err
			return
		}
		opTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "otp-test", DataDir: dir})
		if err != nil {
			opTestTemplateErr = err
			return
		}
		defer db.Close()
		if err := storage.Migrate(ctx, db); err != nil {
			opTestTemplateErr = err
			return
		}
		opTestTemplateErr = func() error {
			_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "otp-test-schema", Statements: otpSchemaStatements()})
			return err
		}()
	})
}

func buildPowTestTemplate() {
	powTestTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-recovery-pow")
		if err != nil {
			powTestTemplateErr = err
			return
		}
		powTestTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "pow-test", DataDir: dir, MaxConcurrentReads: proofActiveLimit + 1})
		if err != nil {
			powTestTemplateErr = err
			return
		}
		defer db.Close()
		powTestTemplateErr = storage.Migrate(ctx, db)
	})
}

func buildEmailOutboxTemplate() {
	emailOutboxTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rhiza-recovery-outbox")
		if err != nil {
			emailOutboxTemplateErr = err
			return
		}
		emailOutboxTemplateDir = dir
		ctx := context.Background()
		db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "email-outbox-test", DataDir: dir})
		if err != nil {
			emailOutboxTemplateErr = err
			return
		}
		defer db.Close()
		statements := append(emailOutboxSchemaStatements(),
			rhiza.SQLStatement{SQL: outboxRetirementBarrier},
			rhiza.SQLStatement{SQL: outboxRetirementGenerations})
		_, emailOutboxTemplateErr = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "email-outbox-test-schema", Statements: statements})
	})
}

func TestMain(m *testing.M) {
	buildRecoveryTestTemplate()
	if recoveryTestTemplateErr != nil {
		panic(recoveryTestTemplateErr)
	}
	buildOTPTestTemplate()
	if opTestTemplateErr != nil {
		panic(opTestTemplateErr)
	}
	buildPowTestTemplate()
	if powTestTemplateErr != nil {
		panic(powTestTemplateErr)
	}
	buildEmailOutboxTemplate()
	if emailOutboxTemplateErr != nil {
		panic(emailOutboxTemplateErr)
	}
	code := m.Run()
	os.RemoveAll(recoveryTestTemplateDir)
	os.RemoveAll(opTestTemplateDir)
	os.RemoveAll(powTestTemplateDir)
	os.RemoveAll(emailOutboxTemplateDir)
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
