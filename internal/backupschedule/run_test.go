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
	err = schedule.Run(ctx, db, "dispatch", time.UTC, time.Second, 2*time.Second, func(context.Context) error {
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
	// Attempt timeout must leave headroom for consensus-backed lease
	// acquisition (CAS budget ttl/3); a tighter budget flakes under loaded
	// -race CI while proving nothing about deadline cancellation.
	err = schedule.Run(ctx, db, "deadline", time.UTC, time.Second, 2*time.Second, func(jobCtx context.Context) error {
		<-jobCtx.Done()
		return jobCtx.Err()
	}, func(_ time.Time, executed bool, err error) {
		reports++
		if !executed || !errors.Is(err, context.DeadlineExceeded) {
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
