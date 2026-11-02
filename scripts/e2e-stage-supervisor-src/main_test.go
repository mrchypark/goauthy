//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real Go processes exercise group signal delivery without any SUT or browser.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--controller":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			os.Exit(run())
		case "--fixture", "--grandchild", "--orphan-parent":
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, syscall.SIGTERM)
			var child *exec.Cmd
			if os.Args[1] != "--grandchild" {
				child = exec.Command(os.Args[0], "--grandchild", os.Args[2])
				if err := child.Start(); err != nil {
					panic(err)
				}
			}
			path := filepath.Join(os.Args[2], strings.TrimPrefix(os.Args[1], "--"))
			if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				panic(err)
			}
			if os.Args[1] == "--orphan-parent" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(os.Args[2], "grandchild")); err == nil {
						status, _ := strconv.Atoi(os.Args[3])
						os.Exit(status)
					}
					if time.Now().After(deadline) {
						_ = child.Process.Kill()
						_ = child.Wait()
						os.Exit(99)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			<-signals
			if child != nil {
				_ = child.Wait()
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestTERMReapsGoChildAndGrandchild(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "--controller", os.Args[0], "--fixture", dir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var pids []int
	t.Cleanup(func() {
		// These exact fixture PIDs are recorded by our own test processes.
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		_ = cmd.Process.Kill()
	})
	for _, name := range []string{"fixture", "grandchild"} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err == nil {
				pid, err := strconv.Atoi(string(data))
				if err != nil || pid <= 1 {
					t.Fatalf("invalid owned fixture PID %q", data)
				}
				pids = append(pids, pid)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("fixture %s did not become ready: %v", name, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for _, pid := range pids {
		pgid, err := syscall.Getpgid(pid)
		if err != nil || pgid != pids[0] || pgid == syscall.Getpgrp() {
			t.Fatalf("fixture PID %d group=%d, want new owned group %d (%v)", pid, pgid, pids[0], err)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if status := exitStatus(err); status != 143 {
			t.Fatalf("controller exit=%d, want 143 (%v)", status, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not finish bounded cooperative cleanup")
	}
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			t.Fatalf("owned fixture PID %d remains: %v", pid, err)
		}
	}
	pids = nil
}

func TestStageExitStatus(t *testing.T) {
	for _, want := range []int{0, 37} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "--controller", "/bin/sh", "-c", "exit "+strconv.Itoa(want))
			if got := exitStatus(cmd.Run()); got != want {
				t.Fatalf("stage exit=%d, want %d", got, want)
			}
		})
	}
}

func TestOrphanCleanupPreservesStageStatus(t *testing.T) {
	for _, want := range []int{0, 37} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "--controller", os.Args[0], "--orphan-parent", dir, strconv.Itoa(want))
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			clean := false
			t.Cleanup(func() {
				if !clean {
					if data, err := os.ReadFile(filepath.Join(dir, "grandchild")); err == nil {
						if pid, err := strconv.Atoi(string(data)); err == nil && pid > 1 {
							_ = syscall.Kill(pid, syscall.SIGKILL)
						}
					}
				}
				_ = cmd.Process.Kill()
			})
			select {
			case err := <-done:
				if got := exitStatus(err); got != want {
					t.Fatalf("stage exit=%d, want %d", got, want)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("same-group orphan cleanup timed out")
			}
			data, err := os.ReadFile(filepath.Join(dir, "grandchild"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil || pid <= 1 {
				t.Fatalf("invalid orphan PID %q", data)
			}
			if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
				t.Fatalf("owned orphan PID %d remains: %v", pid, err)
			}
			clean = true
		})
	}
}
