package scim

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestScimConcurrentExpiredFinalClaimEmitsOneEvent(t *testing.T) {
	ctx := context.Background()
	resolve := func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }
	o := newOutboxTest(t, resolve, OutboxConfig{MaxAttempts: 1})
	o2 := NewOutbox(o.DB, resolve, OutboxConfig{MaxAttempts: 1})
	now := time.UnixMilli(1_800_000_000_000)
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.claim(ctx, now)
	if err != nil || !found || job.Attempts != 1 {
		t.Fatalf("claim found=%v attempts=%d err=%v", found, job.Attempts, err)
	}
	expired := now.Add(o.LeaseDuration)
	candidate, found, err := o.nextCandidate(ctx, expired)
	if err != nil || !found {
		t.Fatalf("candidate found=%v err=%v", found, err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for _, worker := range []*Outbox{o, o2} {
		workers.Go(func() {
			<-start
			_, err := worker.deadLetterExpired(ctx, candidate, expired)
			errs <- err
		})
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count := scimFailureEventCount(t, o); count != 1 {
		t.Fatalf("concurrent dead-letter events=%d", count)
	}
	if state := scimFailureRollbackState(t, o.DB, job.ID); state[0] != "dead" || state[1] != int64(1) || state[2] != nil || state[3] != nil || state[5] != expired.UnixMilli() {
		t.Fatalf("terminal state=%v", state)
	}
}

func TestScimFailureEventSurvivesJobCleanupAndSameClockRecreation(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, ErrRetryable }), nil
	}, OutboxConfig{MaxAttempts: 1, Retention: time.Millisecond})
	now := time.UnixMilli(1_800_000_000_000)
	var first Job
	for cycle := range 2 {
		job, err := o.EnqueueUser(ctx, "client-1", testUser(), now)
		if err != nil {
			t.Fatal(err)
		}
		if cycle == 0 {
			first = job
		} else if job.ID != first.ID || job.Revision != first.Revision || !job.CreatedAt.Equal(first.CreatedAt) {
			t.Fatal("fixture did not recreate the same job identity, revision and timestamp")
		}
		if err := o.Step(ctx, now); err != nil {
			t.Fatal(err)
		}
		if cycle == 0 {
			removed, err := o.Cleanup(ctx, now.Add(2*time.Millisecond), 1)
			if err != nil || removed != 1 {
				t.Fatalf("cleanup removed=%d err=%v", removed, err)
			}
		}
	}
	rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*),COUNT(DISTINCT id),MIN(data),MAX(data) FROM event_log WHERE typ='ScimTaskFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) || rows.Rows[0][1] != int64(2) || rows.Rows[0][2] != int64(1) || rows.Rows[0][3] != int64(1) {
		t.Fatalf("recreated job events=%#v err=%v", rows.Rows, err)
	}
}

func TestScimDeadLetterEventUsesStoredCountAboveCurrentLimit(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 3})
	now := time.UnixMilli(1_800_000_000_000)
	job, err := o.EnqueueUser(ctx, "client-1", testUser(), now)
	if err != nil {
		t.Fatal(err)
	}
	// A persisted job can outlive a higher configured attempt limit. The
	// emitted count is its seven real claims, not the new limit of three.
	_, err = storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-lowered-limit", SQL: `UPDATE scim_user_outbox SET attempts=7,status='processing',lease_token='expired',lease_until_unix_ms=? WHERE job_id=?`, Args: []any{now.UnixMilli(), job.ID}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, found, err := o.nextCandidate(ctx, now)
	if err != nil || !found {
		t.Fatalf("candidate found=%v err=%v", found, err)
	}
	if _, err := o.deadLetterExpired(ctx, candidate, now); err != nil {
		t.Fatal(err)
	}
	rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT data,text FROM event_log WHERE typ='ScimTaskFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(7) || rows.Rows[0][1] != `client-1 / UserCreateUpdate("ext-1")` {
		t.Fatalf("stored-count event=%#v err=%v", rows.Rows, err)
	}
}
