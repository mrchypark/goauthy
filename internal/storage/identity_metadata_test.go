package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV56IdentityMetadataDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dataDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "identity-metadata", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := migrateSchemaV56(ctx, db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT created_at_unix_ms, last_login_at_unix_ms FROM identity_users WHERE subject = ?`,
		Args:        []any{"missing"},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 0 {
		db.Close()
		t.Fatalf("metadata probe=%v err=%v", row.Rows, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = rhiza.Open(ctx, rhiza.Config{NodeID: "identity-metadata", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-metadata-row", SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES (?,?,?)`, Args: []any{"legacy", "legacy", "phc"}}); err != nil {
		t.Fatal(err)
	}
	row, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT created_at_unix_ms, last_login_at_unix_ms FROM identity_users WHERE subject = ?`, Args: []any{"legacy"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(0) || row.Rows[0][1] != nil {
		t.Fatalf("legacy metadata=%v err=%v", row.Rows, err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-metadata-negative-created", SQL: `UPDATE identity_users SET created_at_unix_ms = -1 WHERE subject = ?`, Args: []any{"legacy"}}); err == nil {
		t.Fatal("negative created_at_unix_ms accepted")
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-metadata-negative-login", SQL: `UPDATE identity_users SET last_login_at_unix_ms = -1 WHERE subject = ?`, Args: []any{"legacy"}}); err == nil {
		t.Fatal("negative last_login_at_unix_ms accepted")
	}
}

func TestMigrationV56PreservesV55IdentityRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "identity-partial", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-v55-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (55)`},
		{SQL: `CREATE TABLE identity_users (subject TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, password_phc TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1))) STRICT`},
		{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES (?,?,?)`, Args: []any{"legacy", "legacy", "phc"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV56(ctx, db); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT created_at_unix_ms, last_login_at_unix_ms FROM identity_users WHERE subject = ?`, Args: []any{"legacy"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(0) || row.Rows[0][1] != nil {
		t.Fatalf("repaired metadata=%v err=%v", row.Rows, err)
	}
}

func TestMigrationV56RejectsPartialMarkedSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "identity-partial-marked", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-partial-marked-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (56)`},
		{SQL: `CREATE TABLE identity_users (subject TEXT PRIMARY KEY NOT NULL, created_at_unix_ms INTEGER NOT NULL DEFAULT 0) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV56(ctx, db); err == nil {
		t.Fatal("marked partial schema accepted")
	}
}

func TestMigrationV56ConcurrentCallers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "identity-concurrent", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "identity-concurrent-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (55)`},
		{SQL: `CREATE TABLE identity_users (subject TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, password_phc TEXT NOT NULL) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errs <- migrateSchemaV56(ctx, db)
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
}
