package storage

import (
	"context"
	"testing"

	"github.com/mrchypark/rhiza"
)

func languageFixture(t *testing.T, node string) *rhiza.DB {
	t.Helper()
	return languageFixtureAt(t, node, t.TempDir())
}

func languageFixtureAt(t *testing.T, node, dataDir string) *rhiza.DB {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: node, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: node + "-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations (version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (56)`},
		{SQL: `CREATE TABLE identity_users (subject TEXT PRIMARY KEY NOT NULL, created_at_unix_ms INTEGER NOT NULL DEFAULT 0, last_login_at_unix_ms INTEGER) STRICT`},
	}}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func TestMigrationV57LanguageLegacyValidAndIdempotent(t *testing.T) {
	ctx := context.Background()
	db := languageFixture(t, "language-v57")
	defer db.Close()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "language-rows", SQL: `INSERT INTO identity_users(subject) VALUES ('legacy'),('new')`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV57(ctx, db); err != nil {
		t.Fatal(err)
	}
	for i, language := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "language-set-" + string(rune('a'+i)), SQL: `UPDATE identity_users SET language=? WHERE subject='new'`, Args: []any{language}}); err != nil {
			t.Fatalf("language %s: %v", language, err)
		}
	}
	for i, language := range []string{"DE", "en-US", "zh-Hans", "", "xx"} {
		if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "language-invalid-" + string(rune('a'+i)), SQL: `UPDATE identity_users SET language=? WHERE subject='new'`, Args: []any{language}}); err == nil {
			t.Fatalf("invalid language %q accepted", language)
		}
	}
	if err := migrateSchemaV57(ctx, db); err != nil {
		t.Fatal(err)
	}
	r, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT language FROM identity_users ORDER BY subject`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 2 || r.Rows[0][0] != nil || r.Rows[1][0] != "zhhans" {
		t.Fatalf("languages=%v err=%v", r.Rows, err)
	}
}

func TestMigrationV57RejectsPartialStateAndConcurrentCallers(t *testing.T) {
	ctx := context.Background()
	db := languageFixture(t, "language-concurrent")
	defer db.Close()
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() { <-start; errs <- migrateSchemaV57(ctx, db) }()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	partial := languageFixture(t, "language-partial")
	defer partial.Close()
	if _, err := Execute(ctx, partial, rhiza.ExecuteRequest{RequestID: "language-partial-mark", SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES (57)`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV57(ctx, partial); err == nil {
		t.Fatal("marked partial schema accepted")
	}
}

func TestMigrationV57RejectsUnmarkedColumnAndMissingTable(t *testing.T) {
	ctx := context.Background()
	partial := languageFixture(t, "language-unmarked")
	defer partial.Close()
	if _, err := Execute(ctx, partial, rhiza.ExecuteRequest{RequestID: "language-unmarked-column", SQL: `ALTER TABLE identity_users ADD COLUMN language TEXT`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV57(ctx, partial); err == nil {
		t.Fatal("unmarked language column accepted")
	}

	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "language-missing", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "language-missing-marker-table", SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV57(ctx, db); err == nil {
		t.Fatal("missing identity_users accepted")
	}
}

func TestMigrationV57PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := languageFixtureAt(t, "language-reopen", dir)
	if err := migrateSchemaV57(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "language-reopen-set", SQL: `INSERT INTO identity_users(subject,language) VALUES ('persisted','ko')`}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "language-reopen", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT language FROM identity_users WHERE subject='persisted'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != "ko" {
		t.Fatalf("reopened language=%v err=%v", r.Rows, err)
	}
}
