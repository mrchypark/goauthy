//go:build !windows

package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thanos-io/objstore/providers/filesystem"
)

// The filesystem bucket opens a block with os.OpenFile. A FIFO therefore lets
// this test distinguish the certified-block Verify read from DownloadRootFiles.
// This is a deterministic local boundary, not an S3/MinIO qualification.
func TestNoPVCInterruptedCheckpointDownloadRecovers(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	run := func(ctx context.Context, testRoot, phase, dataDir string) ([]byte, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCAccountAndSigningKeyRecovery$")
		cmd.Env = append(os.Environ(),
			"GOAUTHY_RECOVERY_TEST_ROOT="+testRoot, "GOAUTHY_RECOVERY_TEST_PHASE="+phase,
			"GOAUTHY_RECOVERY_DATA_DIR="+dataDir, "GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_GCS_BUCKET=",
		)
		return cmd.CombinedOutput()
	}
	writeCtx, writeCancel := context.WithTimeout(t.Context(), 90*time.Second)
	writeOut, writeErr := run(writeCtx, root, "write-checkpoint", filepath.Join(root, "writer"))
	writeCancel()
	if writeErr != nil {
		t.Fatalf("write checkpoint: %v\n%s", writeErr, writeOut)
	}

	blockPath, original := checkpointSQLiteBlock(t, root)
	objects := filepath.Join(root, "objects")
	before := objectTreeSHA256(t, objects)
	saved := filepath.Join(root, "checkpoint-block-original")
	if err := os.Rename(blockPath, saved); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mkfifo", "-m", "600", blockPath).CombinedOutput(); err != nil {
		t.Fatalf("make checkpoint FIFO: %v: %s", err, out)
	}
	partial := filepath.Join(root, "interrupted")
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCAccountAndSigningKeyRecovery$")
	cmd.Env = append(os.Environ(),
		"GOAUTHY_RECOVERY_TEST_ROOT="+root, "GOAUTHY_RECOVERY_TEST_PHASE=recover",
		"GOAUTHY_RECOVERY_DATA_DIR="+partial, "GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_GCS_BUCKET=",
	)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	// Before any restore directory exists, this reader is only the checkpoint
	// validator. Supplying the intact block lets that phase complete.
	verifyDone := make(chan error, 1)
	go func() { verifyDone <- writeFIFO(ctx, blockPath, original) }()
	select {
	case err := <-verifyDone:
		if err != nil {
			t.Fatalf("serve certified-block validation: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("certified-block validation did not read the FIFO: %v", ctx.Err())
	}
	if !waitForCheckpointRestoreDir(ctx, partial) {
		t.Fatal("checkpoint download temporary directory was not created")
	}

	// This next FIFO reader is DownloadRootFiles. The observed prefix in its
	// sqlite output proves a block byte was read and written before SIGKILL.
	prefix := original[:64]
	downloadDone := make(chan error, 1)
	go func() { downloadDone <- writeFIFOPrefixAndHold(ctx, blockPath, prefix) }()
	if !checkpointPrefixWritten(partial, prefix) {
		t.Fatal("checkpoint download did not write the controlled object bytes")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("checkpoint recovery subprocess survived SIGKILL")
	} else if !killedBySIGKILL(err) {
		t.Fatalf("checkpoint recovery exited for a reason other than SIGKILL: %v", err)
	}
	cancel()
	select {
	case err := <-downloadDone:
		if err != nil && err != io.ErrClosedPipe {
			t.Fatalf("controlled checkpoint download did not unblock after SIGKILL: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controlled checkpoint FIFO writer remained after SIGKILL")
	}
	if err := os.Remove(blockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, blockPath); err != nil {
		t.Fatal(err)
	}
	assertObjectTreeSHA256(t, objects, before)
	fixtureRoot := t.TempDir()
	if err := snapshotFilesystemObjects(t.Context(), objects, filepath.Join(fixtureRoot, "objects")); err != nil {
		t.Fatalf("snapshot original object store: %v", err)
	}
	assertObjectTreeSHA256(t, filepath.Join(fixtureRoot, "objects"), before)
	if err := os.MkdirAll(filepath.Join(fixtureRoot, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test-key", "public-kid", "generated-token", "password-refresh-token"} {
		source := filepath.Join(root, name)
		destination := filepath.Join(fixtureRoot, name)
		if name == "test-key" {
			source = filepath.Join(root, "keys", name)
			destination = filepath.Join(fixtureRoot, "keys", name)
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	recoverCtx, recoverCancel := context.WithTimeout(t.Context(), 90*time.Second)
	recoverOut, recoverErr := run(recoverCtx, root, "recover", partial)
	recoverCancel()
	if recoverErr != nil {
		t.Fatalf("same partial data directory recovery: %v\n%s", recoverErr, recoverOut)
	}
	freshCtx, freshCancel := context.WithTimeout(t.Context(), 90*time.Second)
	freshOut, freshErr := run(freshCtx, fixtureRoot, "recover", filepath.Join(fixtureRoot, "fresh"))
	freshCancel()
	if freshErr != nil {
		t.Fatalf("fresh data directory recovery: %v\n%s", freshErr, freshOut)
	}
}

func checkpointSQLiteBlock(t *testing.T, root string) (string, []byte) {
	t.Helper()
	var current string
	if err := filepath.WalkDir(filepath.Join(root, "objects"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "CURRENT" {
			if current != "" {
				return fmt.Errorf("multiple checkpoint pointers")
			}
			current = path
		}
		return nil
	}); err != nil || current == "" {
		t.Fatalf("find checkpoint pointer: %v", err)
	}
	var pointer struct {
		Index    uint64 `json:"index"`
		RootHash string `json:"root_hash"`
	}
	currentData, err := os.ReadFile(current)
	if err != nil || json.Unmarshal(currentData, &pointer) != nil || pointer.Index == 0 || len(pointer.RootHash) != 64 {
		t.Fatalf("invalid checkpoint pointer: %v", err)
	}
	rootPath := filepath.Join(filepath.Dir(current), "roots", fmt.Sprintf("%020d_%s.json", pointer.Index, pointer.RootHash))
	var checkpoint struct {
		Files []struct {
			Role   string `json:"role"`
			Blocks []struct {
				Hash       string `json:"hash"`
				Generation uint64 `json:"generation"`
			} `json:"blocks"`
		} `json:"files"`
	}
	rootData, err := os.ReadFile(rootPath)
	if err != nil || json.Unmarshal(rootData, &checkpoint) != nil {
		t.Fatalf("read checkpoint root: %v", err)
	}
	for _, file := range checkpoint.Files {
		if file.Role != "sqlite" || len(file.Blocks) == 0 {
			continue
		}
		block := file.Blocks[0]
		if len(block.Hash) != 64 {
			t.Fatal("invalid SQLite checkpoint block hash")
		}
		name := block.Hash + ".block"
		if block.Generation != 0 {
			name = fmt.Sprintf("%s_%020d.block", block.Hash, block.Generation)
		}
		path := filepath.Join(filepath.Dir(current), "blocks", name)
		data, err := os.ReadFile(path)
		if err != nil || len(data) < 64 {
			t.Fatalf("read SQLite checkpoint block: %v", err)
		}
		return path, data
	}
	t.Fatal("checkpoint has no SQLite block")
	return "", nil
}

func writeFIFO(ctx context.Context, path string, data []byte) error {
	f, err := openFIFOReader(ctx, path)
	if err != nil {
		return err
	}
	defer f.Close()
	for len(data) > 0 {
		n, err := f.Write(data)
		data = data[n:]
		if err == nil {
			continue
		}
		if !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}

func openFIFOReader(ctx context.Context, path string) (*os.File, error) {
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.ENXIO) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func writeFIFOPrefixAndHold(ctx context.Context, path string, prefix []byte) error {
	f, err := openFIFOReader(ctx, path)
	if err != nil {
		return err
	}
	if n, err := f.Write(prefix); err != nil {
		_ = f.Close()
		return err
	} else if n != len(prefix) {
		_ = f.Close()
		return io.ErrShortWrite
	}
	<-ctx.Done()
	return f.Close()
}

func waitForCheckpointRestoreDir(ctx context.Context, dataDir string) bool {
	for {
		if recoveryTempDirExists(dataDir) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func recoveryTempDirExists(dataDir string) bool {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".rhiza-checkpoint-restore-") {
			return true
		}
	}
	return false
}

func checkpointPrefixWritten(dataDir string, want []byte) bool {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		entries, _ := os.ReadDir(dataDir)
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".rhiza-checkpoint-restore-") {
				continue
			}
			got, err := os.ReadFile(filepath.Join(dataDir, entry.Name(), "sqlite.db"))
			if err == nil && len(got) >= len(want) && bytes.Equal(got[:len(want)], want) {
				return true
			}
		}
		select {
		case <-deadline.C:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func killedBySIGKILL(err error) bool {
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func objectTreeSHA256(t *testing.T, root string) map[string]string {
	t.Helper()
	got := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		got[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func assertObjectTreeSHA256(t *testing.T, root string, want map[string]string) {
	t.Helper()
	got := objectTreeSHA256(t, root)
	if len(got) != len(want) {
		t.Fatalf("object-store fixture changed during interrupted recovery: got=%v want=%v", got, want)
	}
	for key, value := range got {
		if want[key] != value {
			t.Fatalf("object-store fixture changed during interrupted recovery: got=%v want=%v", got, want)
		}
	}
}

func snapshotFilesystemObjects(ctx context.Context, source, destination string) error {
	bucket, err := filesystem.NewBucket(destination)
	if err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		return bucket.Upload(ctx, filepath.ToSlash(name), bytes.NewReader(data))
	})
}
