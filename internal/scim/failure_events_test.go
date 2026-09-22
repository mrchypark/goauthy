package scim

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func scimFailureEventCount(t *testing.T, o *Outbox) int64 {
	t.Helper()
	rows, err := o.DB.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("failure events=%#v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0].(int64)
}

func TestScimStepFailureEventOnlyAtRetryLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var o *Outbox
	var calls atomic.Int64
	o = newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { calls.Add(1); return Result{}, ErrRetryable }), nil
	}, OutboxConfig{MaxAttempts: 3, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 128))})
	now := time.UnixMilli(1_704_067_200_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if err := o.Step(ctx, now); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		want := int64(0)
		if attempt == 3 {
			want = 1
		}
		if got := scimFailureEventCount(t, o); got != want {
			t.Fatalf("attempt %d events=%d want=%d", attempt, got, want)
		}
		if attempt < 3 {
			job, found, err := o.Lookup(ctx, "client-1", "ext-1")
			if err != nil || !found {
				t.Fatalf("retry job=%+v found=%v err=%v", job, found, err)
			}
			now = job.NextAttemptAt
		}
	}
	rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ=?`, Args: []any{string(eventlog.ScimTaskFailed)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(eventlog.Critical.Rank()) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(3) || rows.Rows[0][4] != "client-1 / UserCreateUpdate(\"ext-1\")" {
		t.Fatalf("failure event=%#v err=%v", rows.Rows, err)
	}
	if err := o.Step(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := scimFailureEventCount(t, o); got != 1 || calls.Load() != 3 {
		t.Fatalf("terminal follow-up events=%d calls=%d", got, calls.Load())
	}
}

func TestScimStepSuccessAndPermanentFailureEmitNoFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, resolve := range map[string]ClientResolver{
		"success": func(context.Context, string) (Reconciler, error) {
			return fakeReconciler(func(context.Context, Request) (Result, error) {
				return Result{Action: ActionCreated, RemoteID: "remote-1"}, nil
			}), nil
		},
		"permanent": func(context.Context, string) (Reconciler, error) {
			return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, ErrInvalidUser }), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := newOutboxTest(t, resolve, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{5}, 128))})
			now := time.UnixMilli(1_704_067_201_000).UTC()
			if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
				t.Fatal(err)
			}
			if err := o.Step(ctx, now); err != nil {
				t.Fatal(err)
			}
			if got := scimFailureEventCount(t, o); got != 0 {
				t.Fatalf("events=%d", got)
			}
		})
	}
}

func TestScimStaleRevisionCompletionDoesNotEmitFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var o *Outbox
	o = newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-stale-revision-event", SQL: `UPDATE scim_user_outbox SET revision=revision+1 WHERE client_id=? AND status='processing'`, Args: []any{"client-1"}}); err != nil {
				t.Fatalf("revision update: %v", err)
			}
			return Result{}, ErrRetryable
		}), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 128))})
	now := time.UnixMilli(1_704_067_202_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil && !errors.Is(err, ErrOutboxLease) {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "pending" || job.Attempts != 0 {
		t.Fatalf("stale completion job=%+v found=%v err=%v", job, found, err)
	}
	if got := scimFailureEventCount(t, o); got != 0 {
		t.Fatalf("stale completion events=%d", got)
	}
}

func TestScimStaleLeaseCannotEmitFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 128))})
	now := time.UnixMilli(1_704_067_203_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.claim(ctx, now)
	if err != nil || !found {
		t.Fatalf("claim job=%+v found=%v err=%v", job, found, err)
	}
	job.leaseToken = "stale-lease"
	if err := o.finish(ctx, job, now, false, false, "stale"); !errors.Is(err, ErrOutboxLease) {
		t.Fatalf("stale lease err=%v", err)
	}
	if got := scimFailureEventCount(t, o); got != 0 {
		t.Fatalf("stale lease events=%d", got)
	}
}

func TestScimNewRevisionGetsDistinctFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, ErrRetryable }), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 256))})
	now := time.UnixMilli(1_704_067_204_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	updated := testUser()
	updated.UserName = "alice-updated"
	putOutboxProjection(t, o, updated, "phc", false, "password")
	if _, err := o.EnqueueUser(ctx, "client-1", updated, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	rows, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM event_log WHERE typ=? ORDER BY id`, Args: []any{string(eventlog.ScimTaskFailed)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 || rows.Rows[0][0] == rows.Rows[1][0] {
		t.Fatalf("revision events=%#v err=%v", rows.Rows, err)
	}
	if job, found, err := o.Lookup(ctx, "client-1", "ext-1"); err != nil || !found || job.Revision != 2 || job.Status != "dead" {
		t.Fatalf("revision job=%+v found=%v err=%v", job, found, err)
	}
}

func TestScimConcurrentFinalClaimEmitsOneFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var calls atomic.Int64
	resolve := func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { calls.Add(1); return Result{}, ErrRetryable }), nil
	}
	o := newOutboxTest(t, resolve, OutboxConfig{MaxAttempts: 3, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 512))})
	o2 := NewOutbox(o.DB, resolve, OutboxConfig{MaxAttempts: 3, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{10}, 512))})
	now := time.UnixMilli(1_704_067_205_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := o.Step(ctx, now); err != nil {
			t.Fatal(err)
		}
		job, found, err := o.Lookup(ctx, "client-1", "ext-1")
		if err != nil || !found {
			t.Fatal(err)
		}
		now = job.NextAttemptAt
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, worker := range []*Outbox{o, o2} {
		wg.Add(1)
		go func(worker *Outbox) { defer wg.Done(); <-start; errs <- worker.Step(ctx, now) }(worker)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := scimFailureEventCount(t, o); got != 1 || calls.Load() != 3 {
		t.Fatalf("concurrent final events=%d calls=%d", got, calls.Load())
	}
}

func TestScimCurrentIdentityMismatchDoesNotEmitFailureEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var calls atomic.Int64
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { calls.Add(1); return Result{}, ErrRetryable }), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{11}, 128))})
	now := time.UnixMilli(1_704_067_206_000).UTC()
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-current-identity-mismatch", SQL: `UPDATE identity_users SET username=? WHERE subject=?`, Args: []any{"alice-current", "ext-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || scimFailureEventCount(t, o) != 0 {
		t.Fatalf("identity mismatch calls=%d events=%d", calls.Load(), scimFailureEventCount(t, o))
	}
}
