package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore/providers/filesystem"
)

// Driven by scripts/test-rhiza-local-upgrade.sh using two separately compiled
// copies of this test, never an existing application directory.
func TestLocalArchiveVersionCompatibilityPhases(t *testing.T) {
	phase := os.Getenv("GOAUTHY_LOCAL_COMPAT_PHASE")
	if phase == "" {
		t.Skip("requires the isolated cross-version launcher")
	}
	expected := os.Getenv("GOAUTHY_LOCAL_COMPAT_VERSION")
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("missing build info")
	}
	matched := false
	for _, dep := range info.Deps {
		if dep.Path == "github.com/mrchypark/rhiza" {
			if dep.Version != expected || dep.Replace != nil {
				t.Fatalf("SDK=%+v want %s without replacement", dep, expected)
			}
			matched = true
		}
	}
	if !matched {
		t.Fatal("SDK build info missing")
	}
	root := os.Getenv("GOAUTHY_INIT_LIFECYCLE_TEST_ROOT")
	if root == "" {
		t.Fatal("missing isolated root")
	}
	config := initTestConfig(root)
	// The disposable master key is a separate recovery input, never part of
	// DataDir or its archive. No production key or plaintext is logged.
	keyDir := filepath.Join(filepath.Dir(root), "keys")
	if phase == "seed" {
		if err := os.Mkdir(keyDir, 0700); err != nil {
			t.Fatal("create synthetic key directory")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal("generate synthetic key")
		}
		if err := os.WriteFile(filepath.Join(keyDir, "compat-key"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
			t.Fatal("write synthetic key")
		}
	}
	keyring, err := oidc.LoadKeyring(keyDir, "compat-key")
	if err != nil {
		t.Fatal("load synthetic keyring")
	}
	plaintext := []byte("synthetic local archive byte continuity fixture")
	const purpose = "goauthy-local-compatibility"
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if phase == "seed" {
		config.ObjStoreProvider, config.ObjStoreDir, config.ObjStorePrefix = "", "", ""
		config.ObjStoreDurability = ""
	} else if err := run(ctx, config); err != nil {
		t.Fatalf("init Open/Close: %v", err)
	}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	initWaitReady(t, ctx, db)
	request := rhiza.ExecuteRequest{RequestID: "compat-tail", SQL: "INSERT INTO compat_rows VALUES (1, 'ack-tail')"}
	if phase == "seed" {
		if err := storage.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		for _, req := range []rhiza.ExecuteRequest{
			{RequestID: "compat-schema", SQL: "CREATE TABLE compat_rows (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)"},
			{RequestID: "compat-base", SQL: "INSERT INTO compat_rows VALUES (0, 'snapshot')"},
		} {
			if _, err := storage.Execute(ctx, db, req); err != nil {
				t.Fatal(err)
			}
		}
		sealed, err := keyring.SealEnvelope(purpose, plaintext)
		if err != nil {
			t.Fatal("seal synthetic blob")
		}
		for _, req := range []rhiza.ExecuteRequest{
			{RequestID: "compat-sealed-schema", SQL: "CREATE TABLE compat_sealed (id INTEGER PRIMARY KEY, envelope BLOB NOT NULL)"},
			{RequestID: "compat-sealed", SQL: "INSERT INTO compat_sealed VALUES (1, ?)", Args: []any{sealed}},
		} {
			if _, err := storage.Execute(ctx, db, req); err != nil {
				t.Fatal("persist synthetic sealed blob")
			}
		}
		return
	}
	initVerifySchema(t, ctx, db) // Never recreate a missing recovered application schema.
	sealedRows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT envelope FROM compat_sealed WHERE id=1", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(sealedRows.Rows) != 1 || len(sealedRows.Rows[0]) != 1 {
		t.Fatal("synthetic sealed blob missing")
	}
	sealed, ok := sealedRows.Rows[0][0].([]byte)
	if !ok {
		t.Fatal("synthetic sealed blob has wrong type")
	}
	opened, err := keyring.OpenEnvelope(purpose, sealed)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatal("synthetic sealed blob decryption mismatch")
	}
	t.Logf("SDK=%s phase=%s synthetic encrypted blob verified; key outside DataDir", expected, phase)
	if phase == "write" {
		response, err := storage.Execute(ctx, db, request)
		if err != nil || response.Status != rhiza.MutationCommitted || response.RowsAffected != 1 {
			t.Fatalf("ACK=%+v err=%v", response, err)
		}
		bucket, err := filesystem.NewBucket(config.ObjStoreDir)
		if err != nil {
			t.Fatal(err)
		}
		archive, err := recovery.OpenLocalArchive(ctx, bucket, path.Join(config.ObjStorePrefix, string(config.ClusterID), "local/v1"))
		if err != nil {
			t.Fatal(err)
		}
		snapshot := archive.Snapshot()
		if snapshot == nil || snapshot.Seal.Index == 0 || uint64(snapshot.Seal.Index) >= response.Slot || uint64(archive.Tip()) < response.Slot {
			t.Fatalf("snapshot=%+v tip=%d ACK=%d", snapshot, archive.Tip(), response.Slot)
		}
		if err := bucket.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(response.MutationReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "compat-receipt.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("SDK=%s nonempty snapshot=%d ACK tail=%d", expected, snapshot.Seal.Index, response.Slot)
		fmt.Println("COMPAT-WRITER-ACK-COMPLETE")
		os.Exit(0) // No Close: the receipt must already have remote durability.
	}
	if phase != "retained" && phase != "cold" && phase != "second" {
		t.Fatalf("unknown phase %s", phase)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id, payload FROM compat_rows ORDER BY id", Consistency: rhiza.ConsistencyLinearizable})
	want := 2
	if phase == "second" {
		want = 3
	}
	if err != nil || len(rows.Rows) != want || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != "snapshot" || rows.Rows[1][0] != int64(1) || rows.Rows[1][1] != "ack-tail" {
		t.Fatalf("restored=%v err=%v want=%d", rows.Rows, err, want)
	}
	if phase == "second" && (rows.Rows[2][0] != int64(2) || rows.Rows[2][1] != "new-write") {
		t.Fatalf("second restore lost new write: %v", rows.Rows)
	}
	data, err := os.ReadFile(filepath.Join(root, "compat-receipt.json"))
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
	rows, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT id FROM compat_rows ORDER BY id", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != want {
		t.Fatalf("duplicate replay rows=%v err=%v", rows.Rows, err)
	}
	if phase != "second" {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "compat-new", SQL: "INSERT INTO compat_rows VALUES (2, 'new-write')"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("SDK=%s phase=%s snapshot+tail, receipt, no duplicates verified", expected, phase)
}
