//go:build linux

package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in test uses strace to hold the tracee after the journal's atomic
// rename and before writeRestoreState's parent-directory fsync. It tests a
// SIGKILL, not power-loss durability.
func TestNoPVCInterruptedJournalInstallationRecovers(t *testing.T) {
	if os.Getenv("GOAUTHY_JOURNAL_STRACE_TEST") != "1" {
		t.Skip("set GOAUTHY_JOURNAL_STRACE_TEST=1 to enable Linux strace interruption testing")
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatalf("GOAUTHY_JOURNAL_STRACE_TEST=1 requires strace: %v", err)
	}
	for _, phase := range []string{"prepared", "sqlite-backed-up", "graph-installed", "sqlite-installed", "committed"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			writeCtx, writeCancel := context.WithTimeout(t.Context(), 90*time.Second)
			out, err := runNoPVCJournalPhase(writeCtx, root, "write-checkpoint", filepath.Join(root, "writer"))
			writeCancel()
			if err != nil {
				t.Fatalf("write checkpoint: %v\n%s", err, out)
			}
			objects := filepath.Join(root, "objects")
			originalObjects := objectTreeSHA256(t, objects)
			freshRoot := t.TempDir()
			if err := snapshotFilesystemObjects(t.Context(), objects, filepath.Join(freshRoot, "objects")); err != nil {
				t.Fatalf("snapshot objects: %v", err)
			}
			assertObjectTreeSHA256(t, filepath.Join(freshRoot, "objects"), originalObjects)
			copyNoPVCJournalIdentity(t, root, freshRoot)

			partial := filepath.Join(root, "partial")
			journal := filepath.Join(partial, "sqlite.db.restore-state.json")
			pidFile := filepath.Join(root, "tracee.pid")
			traceFile := filepath.Join(root, "journal.strace")
			stderrFile := filepath.Join(root, "journal.strace.stderr")
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			cmd := exec.CommandContext(ctx, "strace",
				"-f", "--kill-on-exit", "-y", "-P", journal, "-P", partial,
				"-e", "trace=rename,renameat,renameat2,fsync",
				"-e", "inject=rename:delay_exit=2s",
				"-e", "inject=renameat:delay_exit=2s",
				"-e", "inject=renameat2:delay_exit=2s",
				"-o", traceFile,
				"sh", "-c", `printf '%s\n' "$$" > "$1"; exec "$2" -test.run='^TestNoPVCAccountAndSigningKeyRecovery$'`,
				"sh", pidFile, os.Args[0],
			)
			cmd.Env = noPVCJournalEnv(root, "recover", partial)
			stderr, err := os.OpenFile(stderrFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			defer stderr.Close()
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				_ = stderr.Close()
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

			pid := waitNoPVCJournalTracee(t, ctx, pidFile, cmd.Process.Pid)
			waitNoPVCJournalPhase(t, ctx, journal, phase)
			assertNoPVCJournalLayout(t, partial, phase)
			assertObjectTreeSHA256(t, objects, originalObjects)
			if !noPVCJournalTraceeIdentity(pid, cmd.Process.Pid) {
				t.Fatalf("tracee PID %d identity changed before SIGKILL", pid)
			}
			if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
				t.Fatalf("SIGKILL tracee %d: %v", pid, err)
			}
			waitErr := cmd.Wait()
			if closeErr := stderr.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if !killedBySIGKILL(waitErr) {
				t.Fatalf("strace did not report tracee SIGKILL: %v\n%s", waitErr, noPVCJournalTraceDiagnostic(stderrFile))
			}
			cancel()
			waitNoPVCJournalTraceEvidence(t, traceFile, journal, partial, pid)
			waitNoPVCJournalExited(t, pid)
			state := readNoPVCJournalState(t, journal)
			if state.Phase != phase {
				t.Fatalf("journal phase after SIGKILL=%q want %q", state.Phase, phase)
			}
			assertNoPVCJournalLayout(t, partial, phase)
			assertObjectTreeSHA256(t, objects, originalObjects)

			recoverCtx, recoverCancel := context.WithTimeout(t.Context(), 90*time.Second)
			out, err = runNoPVCJournalPhase(recoverCtx, root, "recover", partial)
			recoverCancel()
			if err != nil {
				t.Fatalf("same partial data directory recovery: %v\n%s", err, out)
			}
			assertNoPVCJournalFinalized(t, partial)

			freshCtx, freshCancel := context.WithTimeout(t.Context(), 90*time.Second)
			out, err = runNoPVCJournalPhase(freshCtx, freshRoot, "recover", filepath.Join(freshRoot, "fresh"))
			freshCancel()
			if err != nil {
				t.Fatalf("fresh original-object snapshot recovery: %v\n%s", err, out)
			}
		})
	}
}

func noPVCJournalEnv(root, phase, dataDir string) []string {
	return append(os.Environ(),
		"GOAUTHY_RECOVERY_TEST_ROOT="+root,
		"GOAUTHY_RECOVERY_TEST_PHASE="+phase,
		"GOAUTHY_RECOVERY_DATA_DIR="+dataDir,
		"GOAUTHY_RECOVERY_S3_ENDPOINT=",
		"GOAUTHY_RECOVERY_GCS_BUCKET=",
	)
}

func runNoPVCJournalPhase(ctx context.Context, root, phase, dataDir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCAccountAndSigningKeyRecovery$")
	cmd.Env = noPVCJournalEnv(root, phase, dataDir)
	return cmd.CombinedOutput()
}

func copyNoPVCJournalIdentity(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(destination, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ source, destination string }{
		{filepath.Join(source, "keys", "test-key"), filepath.Join(destination, "keys", "test-key")},
		{filepath.Join(source, "public-kid"), filepath.Join(destination, "public-kid")},
		{filepath.Join(source, "generated-token"), filepath.Join(destination, "generated-token")},
		{filepath.Join(source, "password-refresh-token"), filepath.Join(destination, "password-refresh-token")},
	} {
		data, err := os.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.destination, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type noPVCJournalState struct {
	Phase            string `json:"phase"`
	InstallGraph     bool   `json:"install_graph"`
	GraphHadOriginal bool   `json:"graph_had_original"`
}

func waitNoPVCJournalTracee(t *testing.T, ctx context.Context, pidFile string, stracePID int) int {
	t.Helper()
	for {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 1 && noPVCJournalTraceeIdentity(pid, stracePID) {
				return pid
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("tracee PID was not published and verified: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func noPVCJournalTraceeIdentity(pid, stracePID int) bool {
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || !strings.Contains(string(cmdline), "TestNoPVCAccountAndSigningKeyRecovery") {
		return false
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 4 {
		return false
	}
	parent, err := strconv.Atoi(fields[3])
	return err == nil && parent == stracePID
}

func waitNoPVCJournalPhase(t *testing.T, ctx context.Context, journal, want string) {
	t.Helper()
	for {
		if state, err := readNoPVCJournalStateErr(journal); err == nil && state.Phase == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("restore journal did not reach %q: %v", want, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func readNoPVCJournalState(t *testing.T, journal string) noPVCJournalState {
	t.Helper()
	state, err := readNoPVCJournalStateErr(journal)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func readNoPVCJournalStateErr(journal string) (noPVCJournalState, error) {
	data, err := os.ReadFile(journal)
	if err != nil {
		return noPVCJournalState{}, err
	}
	var state noPVCJournalState
	if err := json.Unmarshal(data, &state); err != nil {
		return noPVCJournalState{}, err
	}
	return state, nil
}

func assertNoPVCJournalLayout(t *testing.T, dataDir, phase string) {
	t.Helper()
	state := readNoPVCJournalState(t, filepath.Join(dataDir, "sqlite.db.restore-state.json"))
	if state.Phase != phase || !state.InstallGraph || !state.GraphHadOriginal {
		t.Fatalf("restore journal=%+v want phase=%q with original graph", state, phase)
	}
	db := filepath.Join(dataDir, "sqlite.db")
	dbBackup := db + ".restore-backup"
	graph := filepath.Join(dataDir, "latticedb")
	graphBackup := graph + ".restore-backup"
	for _, item := range []struct {
		path string
		want bool
	}{
		{db, phase != "sqlite-backed-up" && phase != "graph-installed"},
		{dbBackup, phase != "prepared"},
		{graph, true},
		{graphBackup, phase == "graph-installed" || phase == "sqlite-installed" || phase == "committed"},
	} {
		_, err := os.Stat(item.path)
		if item.want && err != nil {
			t.Fatalf("expected restore path %s: %v", item.path, err)
		}
		if !item.want && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected restore path %s: %v", item.path, err)
		}
	}
}

func waitNoPVCJournalTraceEvidence(t *testing.T, traceFile, journal, dataDir string, pid int) {
	t.Helper()
	data, err := os.ReadFile(traceFile)
	if err != nil {
		t.Fatal(err)
	}
	if !noPVCJournalTraceCutValid(strings.Split(string(data), "\n"), journal, dataDir, pid) {
		t.Fatalf("strace lacks journal rename/SIGKILL evidence for tracee %d", pid)
	}
}

// noPVCJournalTraceCutValid accepts the kernel-completed delayed journal rename
// only when the tracee dies before the following parent-directory fsync starts.
func noPVCJournalTraceCutValid(lines []string, journal, dataDir string, pid int) bool {
	killedAt := -1
	for index, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), strconv.Itoa(pid)+" ") && strings.Contains(line, "+++ killed by SIGKILL +++") {
			killedAt = index
			break
		}
	}
	if killedAt < 0 {
		return false
	}
	renameAt := -1
	for index := 0; index < killedAt; index++ {
		line := lines[index]
		if strings.Contains(line, journal) && strings.Contains(line, "= 0 (DELAYED)") {
			renameAt = index
		}
	}
	if renameAt < 0 {
		return false
	}
	for _, line := range lines[renameAt+1 : killedAt] {
		if strings.Contains(line, "fsync(") && strings.Contains(line, "<"+dataDir+">") {
			return false
		}
	}
	return true
}

func TestNoPVCJournalTraceCutEvidence(t *testing.T) {
	journal, dataDir, pid := "/data/sqlite.db.restore-state.json", "/data", 42
	for _, tc := range []struct {
		name  string
		lines []string
		want  bool
	}{
		{"allows earlier fsync and worker rename", []string{
			"17 fsync(3</data>) = 0", "17 renameat(4</data>, \".state\", 4</data>, \"/data/sqlite.db.restore-state.json\") = 0 (DELAYED)",
			"42 +++ killed by SIGKILL +++", "17 +++ killed by SIGKILL +++"}, true},
		{"rejects parent fsync after final journal rename", []string{
			"17 renameat(4</data>, \".state\", 4</data>, \"/data/sqlite.db.restore-state.json\") = 0 (DELAYED)", "17 fsync(3</data>) <unfinished ...>",
			"42 +++ killed by SIGKILL +++"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := noPVCJournalTraceCutValid(tc.lines, journal, dataDir, pid); got != tc.want {
				t.Fatalf("valid=%v want %v", got, tc.want)
			}
		})
	}
}

func noPVCJournalTraceDiagnostic(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("read strace stderr: %v", err)
	}
	return string(data)
}

func waitNoPVCJournalExited(t *testing.T, pid int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); errors.Is(err, os.ErrNotExist) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("tracee %d remained after SIGKILL", pid)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func assertNoPVCJournalFinalized(t *testing.T, dataDir string) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(dataDir, "sqlite.db.restore-state.json"),
		filepath.Join(dataDir, "sqlite.db.restore-backup"),
		filepath.Join(dataDir, "latticedb.restore-backup"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restore recovery left %s: %v", path, err)
		}
	}
}
