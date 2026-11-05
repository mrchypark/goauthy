package storage

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestMigrationV112PreservesV111DataAndRecoversUnknownCommit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	storeDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID: "passkey-retention-v112-recovery", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: storeDir,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v111-retention-preservation-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(111)`},
		{SQL: `CREATE TABLE identity_users(subject TEXT PRIMARY KEY,username TEXT NOT NULL,password_phc TEXT NOT NULL) STRICT`},
		{SQL: `INSERT INTO identity_users VALUES('account-1','user-1','password-phc')`},
		{SQL: `CREATE TABLE identity_password_history(subject TEXT,generation INTEGER,password_phc TEXT,changed_at_unix_ms INTEGER,PRIMARY KEY(subject,generation)) STRICT`},
		{SQL: `INSERT INTO identity_password_history VALUES('account-1',7,'older-password-phc',1234)`},
		{SQL: `CREATE TABLE browser_sessions(token_digest TEXT PRIMARY KEY,subject TEXT,created_at_unix_ms INTEGER,expires_at_unix_ms INTEGER,last_seen_at_unix_ms INTEGER) STRICT`},
		{SQL: `INSERT INTO browser_sessions VALUES('session-digest','account-1',10,20,15)`},
		{SQL: `CREATE TABLE api_keys(name TEXT PRIMARY KEY,secret_digest TEXT,created_at_unix_ms INTEGER) STRICT`},
		{SQL: `INSERT INTO api_keys VALUES('operator','secret-digest',30)`},
		{SQL: `CREATE TABLE master_key_retirement_generations(epoch INTEGER PRIMARY KEY,old_key_id TEXT,replacement_key_id TEXT,ready_at_unix_ms INTEGER) STRICT`},
		{SQL: `INSERT INTO master_key_retirement_generations VALUES(4,'key-old','key-current',40)`},
	}}); err != nil {
		t.Fatal(err)
	}

	storeBackup := storeDir + "-unavailable"
	if err := os.Rename(storeDir, storeBackup); err != nil {
		t.Fatal(err)
	}
	restored := false
	restoreStore := func() {
		if restored {
			return
		}
		_ = os.Remove(storeDir)
		_ = os.Rename(storeBackup, storeDir)
		restored = true
	}
	t.Cleanup(restoreStore)
	if err := os.WriteFile(storeDir, []byte("object store unavailable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV112(ctx, db); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("migration with unavailable before-ack store err=%v, want unknown commit", err)
	}
	restoreStore()
	if err := migrateSchemaV112(ctx, db); err != nil {
		t.Fatalf("recover migration after unknown commit: %v", err)
	}
	if err := migrateSchemaV112(ctx, db); err != nil {
		t.Fatalf("idempotent migration retry: %v", err)
	}
	marker, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM goauthy_schema_migrations WHERE version=112`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(marker.Rows) != 1 || marker.Rows[0][0] != int64(1) {
		t.Fatalf("v112 marker=%v err=%v", marker.Rows, err)
	}
	for _, check := range []struct {
		query string
		want  any
	}{
		{`SELECT password_phc FROM identity_users WHERE subject='account-1'`, "password-phc"},
		{`SELECT password_phc FROM identity_password_history WHERE subject='account-1' AND generation=7`, "older-password-phc"},
		{`SELECT token_digest FROM browser_sessions WHERE subject='account-1'`, "session-digest"},
		{`SELECT name FROM api_keys WHERE name='operator'`, "operator"},
		{`SELECT old_key_id FROM master_key_retirement_generations WHERE epoch=4`, "key-old"},
	} {
		row, err := db.Query(ctx, rhiza.QueryRequest{SQL: check.query, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != check.want {
			t.Errorf("preservation query %q row=%v err=%v, want %v", check.query, row.Rows, err, check.want)
		}
	}
}

func TestMigrationV112ConcurrentInitialization(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "passkey-retention-v112-concurrent", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "v111-retention-concurrent-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE goauthy_schema_migrations(version INTEGER PRIMARY KEY) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(111)`},
	}}); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			errs <- migrateSchemaV112(ctx, db)
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent v112 initialization: %v", err)
		}
	}
	if err := migrateSchemaV112(ctx, db); err != nil {
		t.Fatalf("repeat v112 initialization: %v", err)
	}
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='passkey_cookie_key_retention'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(state.Rows) != 1 || state.Rows[0][0] != int64(1) {
		t.Fatalf("retention table state=%v err=%v", state.Rows, err)
	}
}
