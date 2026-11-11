package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRhizaStartupTimeoutConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", want: 10 * time.Minute},
		{name: "override", value: "25m", want: 25 * time.Minute},
		{name: "minimum", value: "1s", want: time.Second},
		{name: "maximum", value: "1h", want: time.Hour},
		{name: "too short", value: "500ms", wantErr: true},
		{name: "too long", value: "2h", wantErr: true},
		{name: "malformed", value: "later", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rhizaStartupTimeoutFromEnv(func(string) string { return tc.value })
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "GOAUTHY_RHIZA_STARTUP_TIMEOUT") {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("timeout=%s err=%v, want %s", got, err, tc.want)
			}
		})
	}
}

func TestWaitForRhizaReadinessDeadline(t *testing.T) {
	started := time.Now()
	err := waitForRhizaReady(context.Background(), 20*time.Millisecond, func() bool { return false })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness deadline took %s", elapsed)
	}
}

func TestWaitForRhizaReadinessReturnsWhenReadyAndHonorsCancellation(t *testing.T) {
	if err := waitForRhizaReady(context.Background(), time.Second, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForRhizaReady(canceled, time.Second, func() bool { return false }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}
