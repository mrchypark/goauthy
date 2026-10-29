package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/recovery"
)

func initTestConfig(root string) rhiza.Config {
	return rhiza.Config{Local: true, ClusterID: "init-main-recovery", NodeID: "local-node", DataDir: filepath.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"), ObjStorePrefix: "application", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck}
}

func initTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// run is the entrypoint logic called by main after production environment
// parsing. Filesystem injection avoids adding a production provider or engine.
func TestRestoreInitMainAbruptDataLoss(t *testing.T) {
	root := os.Getenv("GOAUTHY_INIT_LIFECYCLE_TEST_ROOT")
	if root == "" {
		root = initTestRoot(t)
		for _, phase := range []string{"init-fresh", "write", "init-recover", "recover"} {
			if phase == "init-recover" {
				if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(root, "data")); !os.IsNotExist(err) {
					t.Fatalf("DataDir loss incomplete: %v", err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRestoreInitMainAbruptDataLoss$", "-test.v")
			cmd.Env = append(os.Environ(), "GOAUTHY_INIT_LIFECYCLE_TEST_ROOT="+root, "GOAUTHY_INIT_LIFECYCLE_TEST_PHASE="+phase)
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("%s: %v\n%s", phase, err, out)
			}
			t.Logf("%s completed", phase)
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	config := initTestConfig(root) // Identical configuration in init and main.
	phase := os.Getenv("GOAUTHY_INIT_LIFECYCLE_TEST_PHASE")
	if phase == "init-fresh" || phase == "init-recover" {
		if _, err := os.Stat(config.DataDir); !os.IsNotExist(err) {
			t.Fatalf("init expected absent DataDir: %v", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatalf("actual init entrypoint logic: %v", err)
		}
		binding := initReadBinding(t, config.DataDir)
		if binding.StoreUUID == "" || binding.ConfigDigest == "" {
			t.Fatal("init did not establish a native Local identity")
		}
		if phase == "init-fresh" {
			data, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "initial-binding.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		} else if !reflect.DeepEqual(binding, initReadBindingFile(t, filepath.Join(root, "initial-binding.json"))) {
			t.Fatal("restore init changed the original archive identity")
		}
		return
	}
	if phase != "write" && phase != "recover" {
		t.Fatalf("invalid test phase %q", phase)
	}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close main verifier: %v", err)
		}
	})
	initWaitReady(t, ctx, db)
	if !reflect.DeepEqual(initReadBinding(t, config.DataDir), initReadBindingFile(t, filepath.Join(root, "initial-binding.json"))) {
		t.Fatal("main changed the identity established by init")
	}
	if phase == "write" {
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM sqlite_master WHERE name='goauthy_schema_migrations'", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
			t.Fatalf("init unexpectedly ran application migrations: %v %v", rows.Rows, err)
		}
	} else {
		initVerifySchema111(t, ctx, db) // Missing restored schema must not be recreated.
		initVerifyRow(t, ctx, db)
	}
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("archive-enabled main migrations: %v", err)
	}
	initVerifySchema111(t, ctx, db)
	request := rhiza.ExecuteRequest{RequestID: "ack-before-abrupt-loss", SQL: "INSERT INTO init_main_proof VALUES (1, 'acknowledged')"}
	if phase == "write" {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "init-main-schema", SQL: "CREATE TABLE init_main_proof (id INTEGER PRIMARY KEY,payload TEXT NOT NULL)"}); err != nil {
			t.Fatal(err)
		}
		response, err := storage.Execute(ctx, db, request)
		if err != nil || response.Status != rhiza.MutationCommitted || response.RowsAffected != 1 {
			t.Fatalf("receipt=%+v err=%v", response.MutationReceipt, err)
		}
		data, err := json.Marshal(response.MutationReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "receipt.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Lose the writer without Close or deferred publication.
	}
	data, err := os.ReadFile(filepath.Join(root, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original rhiza.MutationReceipt
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	response, err := storage.Execute(ctx, db, request)
	if err != nil || response.MutationReceipt != original {
		t.Fatalf("replay=%+v original=%+v err=%v", response.MutationReceipt, original, err)
	}
	initVerifyRow(t, ctx, db)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "post-recovery", SQL: "INSERT INTO init_main_proof VALUES (2, 'new-write')"}); err != nil {
		t.Fatalf("main was not writable after recovery: %v", err)
	}
}

func TestRestoreInitRefusesChangedBoundHistory(t *testing.T) {
	if root := os.Getenv("GOAUTHY_INIT_REFUSAL_TEST_ROOT"); root != "" {
		config := initTestConfig(root)
		switch os.Getenv("GOAUTHY_INIT_REFUSAL_TEST_CASE") {
		case "changed-node":
			config.NodeID = "different-node"
		case "wrong-target":
			config.ObjStorePrefix = "different-archive"
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		if err := run(ctx, config); err == nil {
			t.Fatal("init accepted changed or missing bound history")
		}
		return
	}
	for _, name := range []string{"changed-node", "wrong-target", "missing-archive", "corrupt-binding"} {
		t.Run(name, func(t *testing.T) {
			root := initTestRoot(t)
			config := initTestConfig(root)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if err := run(ctx, config); err != nil {
				t.Fatal(err)
			}
			db, err := rhiza.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			initWaitReady(t, ctx, db)
			_, writeErr := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "retained-schema", SQL: "CREATE TABLE retained (id INTEGER PRIMARY KEY)"})
			if err := errors.Join(writeErr, db.Close()); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing-archive":
				if err := os.RemoveAll(filepath.Join(config.ObjStoreDir, config.ObjStorePrefix, config.ClusterID)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-binding":
				if err := os.WriteFile(filepath.Join(config.DataDir, "local-backup.json"), []byte("{broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			localBefore, remoteBefore := initTreeDigests(t, config.DataDir), initTreeDigests(t, config.ObjStoreDir)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRestoreInitRefusesChangedBoundHistory$", "-test.v")
			cmd.Env = append(os.Environ(), "GOAUTHY_INIT_REFUSAL_TEST_ROOT="+root, "GOAUTHY_INIT_REFUSAL_TEST_CASE="+name)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("refusal process: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(localBefore, initTreeDigests(t, config.DataDir)) {
				t.Error("refused init changed surviving local evidence")
			}
			if !reflect.DeepEqual(remoteBefore, initTreeDigests(t, config.ObjStoreDir)) {
				t.Error("refused init changed retained archive objects")
			}
		})
	}
}

func TestRestoreInitRejectsUnsupportedConfiguration(t *testing.T) {
	for _, name := range []string{"non-local", "async"} {
		t.Run(name, func(t *testing.T) {
			config := initTestConfig(initTestRoot(t))
			if name == "non-local" {
				config.Local = false
			} else {
				config.ObjStoreDurability = rhiza.ObjectStoreDurabilityAsync
			}
			if err := run(t.Context(), config); err == nil {
				t.Fatal("init accepted an unsupported recovery configuration")
			}
			for _, dir := range []string{config.DataDir, config.ObjStoreDir} {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatalf("rejected init created %s: %v", dir, err)
				}
			}
		})
	}
}

func initReadBinding(t *testing.T, dataDir string) recovery.LocalBinding {
	t.Helper()
	return initReadBindingFile(t, filepath.Join(dataDir, "local-backup.json"))
}

func initReadBindingFile(t *testing.T, filename string) recovery.LocalBinding {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var binding recovery.LocalBinding
	if err := json.Unmarshal(data, &binding); err != nil {
		t.Fatal(err)
	}
	return binding
}

func initWaitReady(t *testing.T, ctx context.Context, db *rhiza.DB) {
	t.Helper()
	for !db.Ready() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func initVerifySchema111(t *testing.T, ctx context.Context, db *rhiza.DB) {
	t.Helper()
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT MAX(version) FROM goauthy_schema_migrations", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(111) {
		t.Fatalf("schema=%v err=%v; want 111", rows.Rows, err)
	}
}

func initVerifyRow(t *testing.T, ctx context.Context, db *rhiza.DB) {
	t.Helper()
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id,payload FROM init_main_proof", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != "acknowledged" {
		t.Fatalf("restored rows=%v err=%v", rows.Rows, err)
	}
}

func initTreeDigests(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		files[rel] = fmt.Sprintf("%x", sha256.Sum256(data))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}
