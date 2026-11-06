package apikey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSharedBootstrapCrashWaitObservesChildExit(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_marker", true: "marker_is_not_a_live_child"}[ready], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ready")
			if ready {
				if err := os.WriteFile(path, []byte("ready"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			exited := make(chan struct{})
			close(exited)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if err := waitForSharedBootstrapCrashMarker(ctx, path, exited); !errors.Is(err, errSharedBootstrapCrashChildExited) {
				t.Fatalf("child exit hidden by marker/deadline: %v", err)
			}
		})
	}
}

func TestSharedBootstrapCrashWaitTimeoutIsNotReady(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitForSharedBootstrapCrashMarker(ctx, filepath.Join(t.TempDir(), "missing"), make(chan struct{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation became readiness: %v", err)
	}
	ctx, stop := context.WithTimeout(t.Context(), time.Millisecond)
	defer stop()
	if err := waitForSharedBootstrapCrashMarker(ctx, filepath.Join(t.TempDir(), "missing"), make(chan struct{})); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout became readiness: %v", err)
	}
}

func TestSharedBootstrapCrashWaitRequiresMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(path, []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitForSharedBootstrapCrashMarker(t.Context(), path, make(chan struct{})); err != nil {
		t.Fatal(err)
	}
}

func TestSharedBootstrapCrashStartupBudgetPreservesRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name  string
		outer time.Time
		want  time.Time
	}{
		{"no outer deadline", time.Time{}, now.Add(2 * time.Minute)},
		{"long outer deadline", now.Add(10 * time.Minute), now.Add(2 * time.Minute)},
		{"recovery reserve", now.Add(120 * time.Second), now.Add(70 * time.Second)},
		{"insufficient budget", now.Add(40 * time.Second), now.Add(-10 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sharedBootstrapCrashStartupDeadline(now, tc.outer); !got.Equal(tc.want) {
				t.Fatalf("startup deadline=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSharedBootstrapCrashPhaseIsAllowlisted(t *testing.T) {
	root := t.TempDir()
	if got := sharedBootstrapCrashPhase(root); got != "unavailable" {
		t.Fatal("missing phase accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "phase"), []byte("arbitrary diagnostic contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := sharedBootstrapCrashPhase(root); got != "unavailable" {
		t.Fatal("arbitrary file content exposed")
	}
	writeSharedBootstrapCrashPhase(t, root, "migrate")
	if got := sharedBootstrapCrashPhase(root); got != "migrate" {
		t.Fatal("migration phase lost")
	}
}
