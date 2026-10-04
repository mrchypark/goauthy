package backupschedule

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReportsFailureAndContinues(t *testing.T) {
	db := leaseTestDB(t)
	schedule, err := Parse("* * * * * * *")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	failure := errors.New("test backup failed")
	calls, reports := 0, 0
	var prior time.Time
	// Lease renewal and the production attempt deadline are exercised separately
	// in lease_test.go and TestRunDeadlineCancelsJobAndStops. Use a lease well
	// beyond the parent bound so no renewal fires here, and let the parent
	// bound the attempt. This isolates dispatch reporting from lease renewal
	// and a separate short attempt deadline.
	err = schedule.Run(ctx, db, "dispatch", time.UTC, 30*time.Second, 10*time.Second, func(context.Context) error {
		calls++
		if calls == 1 {
			return failure
		}
		return nil
	}, func(due time.Time, executed bool, err error) {
		reports++
		if !executed || !due.After(prior) || due.After(time.Now()) {
			t.Errorf("invalid dispatch due=%s executed=%t", due, executed)
		}
		prior = due
		if reports == 1 && !errors.Is(err, failure) {
			t.Errorf("lost failure: %v", err)
		}
		if reports == 2 {
			if err != nil {
				t.Errorf("second job: %v", err)
			}
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || calls != 2 || reports != 2 {
		t.Fatalf("calls=%d reports=%d err=%v", calls, reports, err)
	}
}

func TestRunDeadlineCancelsJobAndStops(t *testing.T) {
	db := leaseTestDB(t)
	schedule, err := Parse("* * * * * * *")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reports := 0
	// The first renewal is ten seconds after acquisition, beyond even the
	// parent deadline. Keep the two-second production attempt timeout while
	// isolating its cancellation from consensus-backed renewal failure.
	// Lease renewal and ownership loss are exercised separately in lease_test.go.
	err = schedule.Run(ctx, db, "deadline", time.UTC, 30*time.Second, 2*time.Second, func(jobCtx context.Context) error {
		deadline, ok := jobCtx.Deadline()
		parentDeadline, _ := ctx.Deadline()
		if !ok || !deadline.Before(parentDeadline) || time.Until(deadline) > 2*time.Second {
			return errors.New("job did not inherit the production attempt deadline")
		}
		<-jobCtx.Done()
		if ctx.Err() != nil {
			t.Errorf("parent expired before attempt cancellation: %v", ctx.Err())
		}
		return jobCtx.Err()
	}, func(_ time.Time, executed bool, err error) {
		reports++
		if !executed || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLeaseLost) {
			t.Errorf("executed=%t err=%v", executed, err)
		}
		cancel()
	})
	if !errors.Is(err, context.Canceled) || reports != 1 {
		t.Fatalf("reports=%d err=%v", reports, err)
	}
}

func TestRunCancellationDuringFutureWait(t *testing.T) {
	db := leaseTestDB(t)
	schedule, err := Parse("0 0 0 1 1 * 2100")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- schedule.Run(ctx, db, "waiting", time.UTC, time.Second, time.Second, func(context.Context) error { return nil }, func(time.Time, bool, error) { t.Error("dispatched future slot") })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher did not stop")
	}
}
