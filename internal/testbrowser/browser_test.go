package testbrowser

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestStartupBudgetReservesActionsAndCleanup(t *testing.T) {
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		outer time.Time
		want  time.Duration
	}{
		{time.Time{}, 60 * time.Second}, {now.Add(2 * time.Minute), 60 * time.Second},
		{now.Add(time.Minute), 25 * time.Second}, {now.Add(30 * time.Second), -5 * time.Second},
	} {
		if got := startupBudget(now, tc.outer); got != tc.want {
			t.Fatalf("startup budget=%s want=%s", got, tc.want)
		}
	}
}

func TestStartupAllowsBoundedDelayAndKeepsLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan struct{})
	go func() { time.Sleep(20 * time.Millisecond); close(ready) }()
	err := startBounded(ctx, time.Second, cancel, func(ctx context.Context) error {
		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil || ctx.Err() != nil {
		t.Fatalf("successful startup canceled browser lifetime: %v", err)
	}
}

func TestStartupTimeoutReapsOwnedProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	child := exec.CommandContext(ctx, "/bin/sh", "-c", "exec sleep 30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	err := startBounded(ctx, 100*time.Millisecond, cancel, func(context.Context) error {
		return child.Wait() // The shell execs sleep, so no descendant is orphaned.
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup timeout hidden: %v", err)
	}
	if child.ProcessState == nil || child.ProcessState.ExitCode() == 0 {
		t.Fatal("owned startup process was not reaped after cancellation")
	}
}

func TestCanceledParentDoesNotStartBrowser(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	err := startBounded(ctx, time.Second, cancel, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled parent started browser: called=%v err=%v", called, err)
	}
}
