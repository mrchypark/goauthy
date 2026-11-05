package apikey

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// This is an isolated process/filesystem-object-store crash test. It does not
// qualify HA replication, S3 semantics, or a power-loss filesystem guarantee.
func TestSharedGeneratedBootstrapRecoversAfterSIGKILL(t *testing.T) {
	// Keep this subprocess/migration fixture outside this package's parallel
	// workload. This does not isolate it from other packages or qualify latency.
	root := os.Getenv("GOAUTHY_SHARED_BOOTSTRAP_CRASH_ROOT")
	if root != "" {
		runSharedGeneratedBootstrapCrashChild(t, root)
		return
	}

	root = t.TempDir()
	if err := setupSharedGeneratedBootstrapCrashFiles(root); err != nil {
		t.Fatal(err)
	}
	nowStartup := time.Now()
	var testDeadline time.Time
	if deadline, ok := t.Deadline(); ok {
		testDeadline = deadline
	}
	startupDeadline := sharedBootstrapCrashStartupDeadline(nowStartup, testDeadline)
	if !startupDeadline.After(nowStartup) {
		t.Fatal("insufficient test deadline for startup plus independent 45-second recovery")
	}
	childCtx, cancel := context.WithDeadline(t.Context(), startupDeadline)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSharedGeneratedBootstrapRecoversAfterSIGKILL$")
	cmd.Env = append(os.Environ(), "GOAUTHY_SHARED_BOOTSTRAP_CRASH_ROOT="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childExited := make(chan struct{})
	var childErr error
	go func() {
		childErr = cmd.Wait()
		close(childExited)
	}()
	reapChild := func() bool {
		select {
		case <-childExited:
			return true
		default:
		}
		_ = cmd.Process.Kill()
		select {
		case <-childExited:
			return true
		case <-time.After(5 * time.Second):
			t.Errorf("shared bootstrap child %d did not exit after SIGKILL", cmd.Process.Pid)
			return false
		}
	}
	t.Cleanup(func() { reapChild() })
	if err := waitForSharedBootstrapCrashMarker(childCtx, filepath.Join(root, "ready"), childExited); err != nil {
		if !reapChild() {
			t.Fatal("shared bootstrap child cleanup incomplete")
		}
		t.Fatalf("shared bootstrap startup: phase=%s elapsed=%s wait=%v child=%v", sharedBootstrapCrashPhase(root), time.Since(nowStartup), err, childErr)
	}
	if err := cmd.Process.Kill(); err != nil {
		reapChild()
		t.Fatalf("SIGKILL after bootstrap ready: phase=%s err=%v", sharedBootstrapCrashPhase(root), err)
	}
	if !reapChild() {
		t.Fatal("shared bootstrap child cleanup incomplete")
	}
	var exitErr *exec.ExitError
	if !errors.As(childErr, &exitErr) {
		t.Fatal("shared bootstrap child did not exit from SIGKILL")
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("shared bootstrap child exited without SIGKILL: %v", childErr)
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

	db := openSharedGeneratedBootstrapCrashDB(t, ctx, root, "recover")
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
	ctx := t.Context()
	db := openSharedGeneratedBootstrapCrashDB(t, ctx, root, "writer")
	writeSharedBootstrapCrashPhase(t, root, "keyring")
	keyDir := filepath.Join(root, "keys")
	keyring, err := oidc.LoadKeyring(keyDir, "crash-key")
	if err != nil {
		t.Fatal(err)
	}
	writeSharedBootstrapCrashPhase(t, root, "store")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := sharedGeneratedBootstrapCrashNow()
	store.now = func() time.Time { return now }
	writeSharedBootstrapCrashPhase(t, root, "bootstrap")
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, filepath.Join(root, "bootstrap.json"), keyDir, filepath.Join(root, "artifact"), keyring, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	writeSharedBootstrapCrashPhase(t, root, "bootstrap-complete")
	if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func openSharedGeneratedBootstrapCrashDB(t *testing.T, ctx context.Context, root, dataName string) *rhiza.DB {
	t.Helper()
	if dataName == "writer" {
		writeSharedBootstrapCrashPhase(t, root, "open")
	}
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID: "shared-generated-crash", DataDir: filepath.Join(root, dataName),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"),
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dataName == "writer" {
		writeSharedBootstrapCrashPhase(t, root, "migrate")
	}
	if err := storage.Migrate(ctx, db); err != nil {
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

var errSharedBootstrapCrashChildExited = errors.New("shared bootstrap child exited before ready")

func waitForSharedBootstrapCrashMarker(ctx context.Context, path string, childExited <-chan struct{}) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-childExited:
			return errSharedBootstrapCrashChildExited
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-childExited:
			return errSharedBootstrapCrashChildExited
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Startup includes Open, full migrations and bootstrap. Reserve recovery's
// unchanged 45 seconds and five seconds for cleanup inside the enclosing test.
func sharedBootstrapCrashStartupDeadline(now, testDeadline time.Time) time.Time {
	deadline := now.Add(2 * time.Minute)
	if !testDeadline.IsZero() && testDeadline.Add(-50*time.Second).Before(deadline) {
		deadline = testDeadline.Add(-50 * time.Second)
	}
	return deadline
}

func writeSharedBootstrapCrashPhase(t *testing.T, root, phase string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "phase"), []byte(phase), 0600); err != nil {
		t.Fatal(err)
	}
}

// Only fixed phase names are reported, never arbitrary child logs or file data.
func sharedBootstrapCrashPhase(root string) string {
	phase, err := os.ReadFile(filepath.Join(root, "phase"))
	if err == nil {
		switch string(phase) {
		case "open", "migrate", "keyring", "store", "bootstrap", "bootstrap-complete":
			return string(phase)
		}
	}
	return "unavailable"
}
