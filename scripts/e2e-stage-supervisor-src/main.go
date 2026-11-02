//go:build darwin || linux

// e2e-stage-supervisor owns one newly created process group, including children
// left behind when a harness or the go command exits before its descendants.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e2e-stage-supervisor command [args...]")
		return 2
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start isolated stage:", err)
		return 1
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil || pgid <= 0 || pgid != cmd.Process.Pid || pgid == syscall.Getpgrp() {
		// Only the exact child PID is safe if group creation cannot be verified.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		fmt.Fprintln(os.Stderr, "could not verify new isolated stage process group")
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	status := 1
	select {
	case err := <-done:
		status = exitStatus(err)
		if groupAbsent(pgid) {
			return status
		}
		fmt.Fprintf(os.Stderr, "stage exited with remaining process group %d; cleaning owned descendants\n", pgid)
	case sig := <-signals:
		status = 128 + int(sig.(syscall.Signal))
	}
	// Registration has five sequential TERM/KILL waits of up to ten seconds.
	// Allow those plus scheduler margin before escalating the owned group.
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		fmt.Fprintln(os.Stderr, "signal owned stage group:", err)
		return 1
	}
	if waitAbsent(pgid, 75*time.Second) {
		return status
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		fmt.Fprintln(os.Stderr, "kill owned stage group:", err)
		return 1
	}
	if !waitAbsent(pgid, 5*time.Second) {
		fmt.Fprintf(os.Stderr, "owned stage process group remains: %d; preserve private fixture data\n", pgid)
		return 1
	}
	return status
}

func groupAbsent(pgid int) bool {
	return errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH)
}

func waitAbsent(pgid int, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for !groupAbsent(pgid) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return exit.ExitCode()
	}
	return 1
}
