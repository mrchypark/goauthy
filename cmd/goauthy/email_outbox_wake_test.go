package main

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/housekeeping"
	"github.com/mrchypark/goauthy/internal/recovery"
)

func TestEmailOutboxEnqueueWakesHousekeeping(t *testing.T) {
	t.Parallel()
	wake := make(chan struct{}, 1)
	delivered := make(chan string, 1)
	outbox, err := recovery.NewEmailOutbox(retirementCmdDB(t, true), func(_ context.Context, recipient, _, _, _ string) error {
		delivered <- recipient
		return nil
	}, recovery.WithEnvelopeKeyring(retirementCmdKeyring(t, "key-c")), recovery.WithWake(wake))
	if err != nil {
		t.Fatal(err)
	}

	jobs := buildHousekeepingJobs(outbox.DB, nil, nil, nil, outbox, wake, nil)
	var job housekeeping.Job
	for _, candidate := range jobs {
		if candidate.Name == "email-outbox" {
			job = candidate
			break
		}
	}
	if job.Step == nil {
		t.Fatal("email-outbox job is not wired")
	}
	started := make(chan struct{}, 1)
	step := job.Step
	job.Step = func(ctx context.Context) error {
		select {
		case started <- struct{}{}:
		default:
		}
		return step(ctx)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		housekeeping.New([]housekeeping.Job{job}, nil).Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("email-outbox job did not run at startup")
	}

	if err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", "<p>html</p>", "text"); err != nil {
		t.Fatal(err)
	}
	select {
	case recipient := <-delivered:
		if recipient != "user@example.test" {
			t.Fatalf("delivered to %q", recipient)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueue did not wake the housekeeping job")
	}
}
