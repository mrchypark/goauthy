package backupschedule

import (
	"context"
	"errors"
	"github.com/mrchypark/rhiza"
	"time"
)

// Run dispatches future slots serially, with durable completion suppression and
// a per-attempt deadline. Failed attempts are reported; the next future slot is
// then selected. Missed slots are not replayed in a catch-up burst. Report must
// not log credentials from provider errors and must return promptly.
func (s *Schedule) Run(ctx context.Context, db *rhiza.DB, scope string, location *time.Location, lease, timeout time.Duration, job func(context.Context) error, report func(time.Time, bool, error)) error {
	if s == nil || db == nil || scope == "" || len(scope) > 4096 || location == nil || lease < time.Second || lease > time.Hour || timeout <= 0 || job == nil || report == nil {
		return errors.New("invalid backup dispatcher configuration")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		due, err := s.Next(ctx, time.Now().In(location))
		if err != nil {
			return err
		}
		if due.IsZero() {
			return nil
		}
		for {
			delay := time.Until(due)
			if delay <= 0 {
				break
			}
			// Recheck civil time during long waits so clock corrections do not cause
			// early dispatch or hold a past slot behind a years-long monotonic timer.
			if delay > time.Minute {
				delay = time.Minute
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		executed, err := RunSlot(attempt, db, scope, due, lease, job)
		cancel()
		report(due, executed, err)
	}
}
