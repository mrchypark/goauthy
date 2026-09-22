package apikey

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// This is an isolated process/filesystem-object-store crash test. It does not
// qualify HA replication, S3 semantics, or a power-loss filesystem guarantee.
func TestSharedGeneratedBootstrapRecoversAfterSIGKILL(t *testing.T) {
	t.Parallel()
	root := os.Getenv("GOAUTHY_SHARED_BOOTSTRAP_CRASH_ROOT")
	if root != "" {
		runSharedGeneratedBootstrapCrashChild(t, root)
		return
	}

	root = t.TempDir()
	if err := setupSharedGeneratedBootstrapCrashFiles(root); err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSharedGeneratedBootstrapRecoversAfterSIGKILL$")
	cmd.Env = append(os.Environ(), "GOAUTHY_SHARED_BOOTSTRAP_CRASH_ROOT="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := waitForSharedBootstrapCrashMarker(childCtx, filepath.Join(root, "ready")); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("shared bootstrap child exited without SIGKILL")
	}
	if err := childCtx.Err(); err != nil {
		t.Fatal(err)
	}

	// Recovery has its own budget; child startup must not consume it.
	ctx, cancelRecovery := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancelRecovery()
	now := sharedGeneratedBootstrapCrashNow()
	deadline := now.Add(time.Hour)
	keyDir := filepath.Join(root, "keys")
	artifact := filepath.Join(root, "artifact")
	keyring, err := oidc.LoadKeyring(keyDir, "crash-key")
	if err != nil {
		t.Fatal(err)
	}
	before, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "crash-key", now)
	if err != nil || len(before) != 1 {
		t.Fatalf("read killed-process artifact count=%d err=%v", len(before), err)
	}
	winner := before[0].Value
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}

	db := openSharedGeneratedBootstrapCrashDB(t, root, "recover")
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(time.Minute) }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, filepath.Join(root, "bootstrap.json"), keyDir, artifact, keyring, deadline.Add(24*time.Hour)); err != nil {
		t.Fatalf("recover shared Generate after SIGKILL: %v", err)
	}
	after, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "crash-key", now.Add(time.Minute))
	if err != nil || len(after) != 1 || after[0].Value != winner {
		t.Fatalf("recovered artifact count=%d matches=%t err=%v", len(after), len(after) == 1 && after[0].Value == winner, err)
	}
	if _, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "crash-key", deadline); !errors.Is(err, ErrGeneratedBootstrapExpired) {
		t.Fatalf("recovery extended original deadline: %v", err)
	}
	if _, err := store.Authenticate(ctx, "API-Key "+winner); err != nil {
		t.Fatalf("recovered winner authentication failed: %v", err)
	}
	assertBootstrapCount(t, db, 1)
}

func runSharedGeneratedBootstrapCrashChild(t *testing.T, root string) {
	ctx := context.Background()
	db := openSharedGeneratedBootstrapCrashDB(t, root, "writer")
	keyDir := filepath.Join(root, "keys")
	keyring, err := oidc.LoadKeyring(keyDir, "crash-key")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := sharedGeneratedBootstrapCrashNow()
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, filepath.Join(root, "bootstrap.json"), keyDir, filepath.Join(root, "artifact"), keyring, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func openSharedGeneratedBootstrapCrashDB(t *testing.T, root, dataName string) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{
		NodeID: "shared-generated-crash", DataDir: filepath.Join(root, dataName),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"),
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Migrate(context.Background(), db); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return db
}

func setupSharedGeneratedBootstrapCrashFiles(root string) error {
	keyDir := filepath.Join(root, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "crash-key"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "bootstrap.json"), []byte(`[{"name":"runner","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]`), 0600)
}

func sharedGeneratedBootstrapCrashNow() time.Time {
	return time.Unix(2_100_000_000, 0).UTC()
}

func waitForSharedBootstrapCrashMarker(ctx context.Context, path string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
