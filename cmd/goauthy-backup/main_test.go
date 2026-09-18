package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/backupschedule"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestArgumentsFailBeforeConfiguration(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"export"}, {"restore", "-file", "x", "-key-file", "x", "-work-dir", "x"}, {"export", "-file", "x", "-key-file", "x", "-work-dir", "x", "-max-files", "0"}} {
		if err := run(context.Background(), args, func(string) string { t.Fatal("read config for invalid arguments"); return "" }, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestOperatorS3Roundtrip(t *testing.T) {
	endpoint := os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires disposable S3 fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root := t.TempDir()
	env := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "standalone", "GOAUTHY_CLUSTER_ID": "operator-test", "GOAUTHY_NODE_ID": "source", "GOAUTHY_DATA_DIR": filepath.Join(root, "source"),
		"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER": "s3", "GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT": endpoint,
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": os.Getenv("GOAUTHY_RECOVERY_S3_BUCKET"), "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": fmt.Sprintf("operator-%d", time.Now().UnixNano()),
		"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY": os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY"), "GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY": os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY"),
		"GOAUTHY_RHIZA_OBJECT_STORE_INSECURE": "true", "GOAUTHY_RHIZA_OBJECT_STORE_REGION": "us-east-1", "GOAUTHY_RHIZA_CHECKPOINT_INTERVAL": "1h",
	}
	getenv := func(k string) string { return env[k] }
	config, err := storage.RhizaConfigFromEnv(getenv)
	if err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	execute := func(id, sql string) {
		t.Helper()
		if _, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: id, SQL: sql}); err != nil {
			t.Fatal(err)
		}
	}
	execute("schema", `CREATE TABLE backup_markers (name TEXT PRIMARY KEY)`)
	execute("before", `INSERT INTO backup_markers VALUES ('before')`)
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keyPath, recipients := filepath.Join(root, "identity"), filepath.Join(root, "recipients")
	if err := os.WriteFile(keyPath, []byte(key.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recipients, []byte(key.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	assertClean := func(t *testing.T) {
		t.Helper()
		if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
			t.Fatalf("scratch not cleaned: %v (%d entries)", err, len(entries))
		}
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	signingPath, trustPath := filepath.Join(root, "signing.pem"), filepath.Join(root, "trust.pem")
	if err := os.WriteFile(signingPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("scheduled", func(t *testing.T) { testScheduledS3(t, db, config, key, signer, work) })
	sourcePrefix := env["GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"]
	for _, mode := range []string{"initial", "checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			env["GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"] = sourcePrefix
			artifact := filepath.Join(root, mode+".age")
			exportArgs := []string{"export", "-file", artifact, "-key-file", recipients, "-work-dir", work}
			var output bytes.Buffer
			if err := run(ctx, exportArgs, getenv, &output); err != nil {
				t.Fatal(err)
			}
			digest := strings.TrimSpace(output.String())
			ciphertext, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) || digest != fmt.Sprintf("%x", sha256.Sum256(ciphertext)) {
				t.Fatal("invalid encrypted output or digest")
			}
			inspected, err := backup.Extract(bytes.NewReader(ciphertext), []age.Identity{key}, t.TempDir(), backup.Limits{MaxFiles: 65536, MaxFileBytes: 1 << 30, MaxTotalBytes: 8 << 30})
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := backup.ReadManifest(inspected.Dir, inspected.Inventory)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "initial" && (manifest.FormatVersion != 2 || manifest.RecoveryMode != "archive-only") {
				t.Fatal("initial test did not exercise archive-only")
			}
			if mode == "checkpoint" && (manifest.FormatVersion != 1 || manifest.CheckpointIndex == 0) {
				t.Fatal("checkpoint test did not exercise certified checkpoint")
			}
			if info, err := os.Stat(artifact); err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("artifact permissions")
			}
			if err := run(ctx, exportArgs, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("overwrote existing artifact")
			}
			assertClean(t)
			same, err := os.ReadFile(artifact)
			if err != nil || !bytes.Equal(same, ciphertext) {
				t.Fatal("existing artifact changed")
			}
			catalogPrefix := sourcePrefix + "-catalog-" + mode
			var published bytes.Buffer
			if err := run(ctx, []string{"publish", "-file", artifact, "-key-file", signingPath, "-catalog-prefix", catalogPrefix}, getenv, &published); err != nil {
				t.Fatal(err)
			}
			var entry backup.CatalogEntry
			if err := json.Unmarshal(published.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			var listed bytes.Buffer
			if err := run(ctx, []string{"list", "-key-file", trustPath, "-catalog-prefix", catalogPrefix}, getenv, &listed); err != nil {
				t.Fatal(err)
			}
			var entries []backup.CatalogEntry
			if err := json.Unmarshal(listed.Bytes(), &entries); err != nil || len(entries) != 1 || entries[0] != entry {
				t.Fatalf("signed catalog listing: %v", err)
			}
			fetched := filepath.Join(root, mode+"-fetched.age")
			fetchArgs := []string{"fetch", "-file", fetched, "-key-file", trustPath, "-catalog-prefix", catalogPrefix, "-id", entry.ID, "-work-dir", work}
			if err := run(ctx, fetchArgs, getenv, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(fetched)
			if err != nil || !bytes.Equal(got, ciphertext) {
				t.Fatal("signed remote fetch changed artifact")
			}
			if err := run(ctx, fetchArgs, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("fetch overwrote existing artifact")
			}
			assertClean(t)
			retentionConfig, err := storage.RhizaConfigFromEnv(getenv)
			if err != nil {
				t.Fatal(err)
			}
			retentionBucket, err := storage.OpenObjectStore(ctx, retentionConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer retentionBucket.Close()
			oldFile, err := os.Open(fetched)
			if err != nil {
				t.Fatal(err)
			}
			old, oldErr := backup.Publish(ctx, retentionBucket, catalogPrefix, path.Join(config.ObjStorePrefix, config.ClusterID), oldFile, signer, time.Now().AddDate(0, 0, -40))
			closeErr := oldFile.Close()
			if oldErr != nil || closeErr != nil {
				t.Fatalf("old fixture: %v %v", oldErr, closeErr)
			}
			pruneArgs := []string{"prune", "-key-file", trustPath, "-catalog-prefix", catalogPrefix}
			var plan bytes.Buffer
			if err := run(ctx, pruneArgs, getenv, &plan); err != nil {
				t.Fatal(err)
			}
			var planned []backup.CatalogEntry
			if err := json.Unmarshal(plan.Bytes(), &planned); err != nil || len(planned) != 1 || planned[0] != old {
				t.Fatalf("retention plan: %v", err)
			}
			oldObject := path.Join(catalogPrefix, "artifacts", old.ID+".age")
			if exists, err := retentionBucket.Exists(ctx, oldObject); err != nil || !exists {
				t.Fatal("dry run deleted artifact")
			}
			var applied bytes.Buffer
			if err := run(ctx, append(pruneArgs, "-apply"), getenv, &applied); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(applied.Bytes(), &planned); err != nil || len(planned) != 1 || planned[0] != old {
				t.Fatalf("retention apply: %v", err)
			}
			for _, name := range []string{oldObject, path.Join(catalogPrefix, "completed", old.ID+".json")} {
				if exists, err := retentionBucket.Exists(ctx, name); err != nil || exists {
					t.Fatal("expired artifact/receipt remains")
				}
			}
			foreignFile, err := os.Open(fetched)
			if err != nil {
				t.Fatal(err)
			}
			foreign, publishErr := backup.Publish(ctx, retentionBucket, catalogPrefix, "retired-source", foreignFile, signer, time.Now().AddDate(0, 0, -40))
			if closeErr := foreignFile.Close(); publishErr != nil || closeErr != nil {
				t.Fatalf("foreign fixture: %v %v", publishErr, closeErr)
			}
			var defaultPlan bytes.Buffer
			if err := run(ctx, pruneArgs, getenv, &defaultPlan); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(defaultPlan.Bytes(), &planned); err != nil || len(planned) != 0 {
				t.Fatalf("default removed latest foreign backup: %v", err)
			}
			strictArgs := append(append([]string{}, pruneArgs...), "-retention-policy", "expire-all")
			var strictPlan bytes.Buffer
			if err := run(ctx, strictArgs, getenv, &strictPlan); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(strictPlan.Bytes(), &planned); err != nil || len(planned) != 1 || planned[0] != foreign {
				t.Fatalf("expire-all plan: %v", err)
			}
			foreignObject := path.Join(catalogPrefix, "artifacts", foreign.ID+".age")
			if exists, err := retentionBucket.Exists(ctx, foreignObject); err != nil || !exists {
				t.Fatal("expire-all dry run deleted artifact")
			}
			if err := run(ctx, append(strictArgs, "-apply"), getenv, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{foreignObject, path.Join(catalogPrefix, "completed", foreign.ID+".json")} {
				if exists, err := retentionBucket.Exists(ctx, name); err != nil || exists {
					t.Fatal("expire-all retained expired latest artifact/receipt")
				}
			}
			remaining, err := backup.ListCompleted(ctx, retentionBucket, catalogPrefix, []ed25519.PublicKey{pub}, 4)
			if err != nil || len(remaining) != 1 || remaining[0] != entry {
				t.Fatalf("retention removed newest: %v", err)
			}
			// Create is the complete single-trigger path used by automation:
			// only its remote receipt survives, with no retained local export.
			createPrefix := catalogPrefix + "-create"
			var created bytes.Buffer
			if err := run(ctx, []string{"create", "-recipient-file", recipients, "-signing-key-file", signingPath, "-catalog-prefix", createPrefix, "-work-dir", work}, getenv, &created); err != nil {
				t.Fatal(err)
			}
			var createdEntry backup.CatalogEntry
			if err := json.Unmarshal(created.Bytes(), &createdEntry); err != nil || createdEntry.SourcePrefix != path.Join(config.ObjStorePrefix, config.ClusterID) {
				t.Fatalf("created receipt: %v", err)
			}
			assertClean(t)
			artifact = filepath.Join(root, mode+"-created.age")
			if err := run(ctx, []string{"fetch", "-file", artifact, "-key-file", trustPath, "-catalog-prefix", createPrefix, "-id", createdEntry.ID, "-work-dir", work}, getenv, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			ciphertext, err = os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			digest = createdEntry.SHA256
			targetPrefix := sourcePrefix + "-" + mode
			env["GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"] = targetPrefix
			restoreArgs := []string{"restore", "-file", artifact, "-key-file", keyPath, "-work-dir", work, "-sha256", digest}
			bad := append([]string(nil), restoreArgs...)
			bad[len(bad)-1] = strings.Repeat("0", 64)
			if err := run(ctx, bad, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted wrong digest")
			}
			assertClean(t)
			targetConfig, err := storage.RhizaConfigFromEnv(getenv)
			if err != nil {
				t.Fatal(err)
			}
			bucket, err := storage.OpenObjectStore(ctx, targetConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer bucket.Close()
			marker := path.Join(targetPrefix, config.ClusterID, "goauthy-restore.json")
			if exists, err := bucket.Exists(ctx, marker); err != nil || exists {
				t.Fatal("digest failure wrote target")
			}
			wrongKey, err := age.GenerateHybridIdentity()
			if err != nil {
				t.Fatal(err)
			}
			wrongPath := filepath.Join(root, mode+"-wrong-key")
			if err := os.WriteFile(wrongPath, []byte(wrongKey.String()+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			bad = append([]string(nil), restoreArgs...)
			bad[4] = wrongPath
			if err := run(ctx, bad, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted wrong identity")
			}
			assertClean(t)
			if exists, err := bucket.Exists(ctx, marker); err != nil || exists {
				t.Fatal("decryption failure wrote target")
			}
			// Correct outer digest cannot excuse a broken final age authenticator.
			corrupt := append([]byte(nil), ciphertext...)
			corrupt[len(corrupt)-1] ^= 1
			corruptPath := filepath.Join(root, mode+"-corrupt.age")
			if err := os.WriteFile(corruptPath, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			bad = append([]string(nil), restoreArgs...)
			bad[2] = corruptPath
			bad[len(bad)-1] = fmt.Sprintf("%x", sha256.Sum256(corrupt))
			if err := run(ctx, bad, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted corrupt authenticated ciphertext")
			}
			assertClean(t)
			if exists, err := bucket.Exists(ctx, marker); err != nil || exists {
				t.Fatal("age authentication failure wrote target")
			}
			if err := run(ctx, restoreArgs, getenv, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if err := run(ctx, restoreArgs, getenv, &bytes.Buffer{}); err == nil {
				t.Fatal("restored into occupied prefix")
			}
			assertClean(t)
			targetConfig.DataDir = filepath.Join(root, mode+"-restored")
			restored, err := rhiza.Open(ctx, targetConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			result, err := restored.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name FROM backup_markers ORDER BY name`, Consistency: rhiza.ConsistencyLinearizable})
			expectedRows := 1
			if mode == "checkpoint" {
				expectedRows = 2
			}
			if err != nil || len(result.Rows) != expectedRows || result.Rows[0][0] != "before" || (mode == "checkpoint" && result.Rows[1][0] != "suffix") {
				t.Fatalf("restored data %v %v", result.Rows, err)
			}
			if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
				t.Fatalf("scratch not cleaned %v", err)
			}
		})
		if mode == "initial" {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = nil
			db, err = rhiza.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			execute("suffix", `INSERT INTO backup_markers VALUES ('suffix')`)
		}
	}
}

func testScheduledS3(t *testing.T, db *rhiza.DB, config rhiza.Config, identity *age.HybridIdentity, signer ed25519.PrivateKey, work string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	bucket, err := storage.OpenObjectStore(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	schedule, err := backupschedule.Parse("* * * * * * *")
	if err != nil {
		t.Fatal(err)
	}
	source := path.Join(config.ObjStorePrefix, config.ClusterID)
	catalog := config.ObjStorePrefix + "-scheduled-catalog"
	limits := backup.Limits{MaxFiles: 65536, MaxFileBytes: 1 << 30, MaxTotalBytes: 8 << 30}
	var entry backup.CatalogEntry
	var operationErr error
	reports := 0
	err = schedule.Run(ctx, db, "operator/"+catalog, time.UTC, 30*time.Second, 20*time.Second, func(jobCtx context.Context) error {
		var err error
		entry, err = backup.Create(jobCtx, bucket, bucket, source, config.ClusterID, catalog, []age.Recipient{identity.Recipient()}, signer, work, limits)
		if err != nil {
			return err
		}
		_, err = backup.Prune(jobCtx, bucket, catalog, []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}, time.Now(), 30, 100, true)
		return err
	}, func(_ time.Time, executed bool, err error) {
		reports++
		operationErr = err
		if !executed {
			t.Error("scheduled callback did not execute")
		}
		cancel()
	})
	if reports != 1 || operationErr != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("scheduled reports=%d job=%v run=%v", reports, operationErr, err)
	}
	if files, err := os.ReadDir(work); err != nil || len(files) != 0 {
		t.Fatalf("scheduled scratch leaked: %v", err)
	}
	restoreCtx, restoreCancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer restoreCancel()
	fetched, remote, err := backup.FetchCompleted(restoreCtx, bucket, catalog, entry.ID, []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}, work, 16<<30)
	if err != nil || remote != entry {
		t.Fatalf("scheduled fetch: %v", err)
	}
	defer os.Remove(fetched)
	file, err := os.Open(fetched)
	if err != nil {
		t.Fatal(err)
	}
	staged, extractErr := backup.Extract(file, []age.Identity{identity}, work, limits)
	closeErr := file.Close()
	if extractErr != nil || closeErr != nil {
		t.Fatalf("scheduled extract: %v %v", extractErr, closeErr)
	}
	defer os.RemoveAll(staged.Dir)
	targetConfig := config
	targetConfig.ObjStorePrefix = config.ObjStorePrefix + "-scheduled-restore"
	targetConfig.DataDir = t.TempDir()
	if _, err := backup.Restore(restoreCtx, bucket, path.Join(targetConfig.ObjStorePrefix, config.ClusterID), config.ClusterID, staged, work); err != nil {
		t.Fatal(err)
	}
	restored, err := rhiza.Open(restoreCtx, targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	result, err := restored.Query(restoreCtx, rhiza.QueryRequest{SQL: "SELECT name FROM backup_markers", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "before" {
		t.Fatalf("scheduled restore: %v %v", result.Rows, err)
	}
}
