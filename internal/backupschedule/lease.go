package backupschedule

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/rhiza"
)

var (
	ErrLeaseLost    = errors.New("backup job lease lost")
	ErrLeaseAcquire = errors.New("backup lease acquisition failed")
)

// WithLease runs job only after a replicated TTL CAS is won. Renewals use the
// exact random holder token; any failed/ambiguous renewal cancels job. Callers
// must honor that context. This is cooperative ownership, not an external-write
// fence: a paused old process can still publish an immutable duplicate backup.
func WithLease(ctx context.Context, db *rhiza.DB, scope string, ttl time.Duration, job func(context.Context) error) (acquired bool, err error) {
	if db == nil || scope == "" || len(scope) > 4096 || ttl < time.Second || ttl > time.Hour || job == nil {
		return false, errors.New("invalid backup lease configuration")
	}
	key := fmt.Sprintf("goauthy/backup-lease/%x", sha256.Sum256([]byte(scope)))
	token := []byte(rand.Text())
	mutate := func(parent context.Context, expected bool, duration time.Duration) (bool, error) {
		call, cancel := context.WithTimeout(parent, ttl/3)
		defer cancel()
		started := time.Now()
		req := rhiza.KVMutationRequest{RequestID: rand.Text(), Key: key, Value: token, ExpectedExists: expected, TTLMS: duration.Milliseconds()}
		if expected {
			req.Expected = token
		}
		receipt, err := db.KVCAS(call, req)
		if err != nil {
			return false, err
		}
		if receipt.Status != rhiza.MutationCommitted {
			return false, errors.New("backup lease mutation was not committed")
		}
		// Do not start/continue work on a receipt whose lease window may have elapsed
		// while the mutation waited for consensus or object-store durability.
		if duration == ttl && time.Since(started) >= ttl/3 {
			return false, ErrLeaseLost
		}
		return receipt.Applied, nil
	}
	acquired, err = mutate(ctx, false, ttl)
	if err != nil {
		return false, errors.Join(ErrLeaseAcquire, err)
	}
	if !acquired {
		return false, nil
	}
	work, cancel := context.WithCancelCause(ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(ttl / 3)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				ok, err := mutate(work, true, ttl)
				if err != nil || !ok {
					cancel(errors.Join(ErrLeaseLost, err))
					return
				}
			}
		}
	}()
	defer func() {
		// This also stops renewal if job panics; no goroutine retains ownership.
		cause := context.Cause(work)
		cancel(context.Canceled)
		<-stopped
		if errors.Is(context.Cause(work), ErrLeaseLost) {
			cause = context.Cause(work)
		}
		releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), ttl/3)
		defer releaseCancel()
		// Conditional expiry cannot remove a successor. Never KVDelete here.
		released, releaseErr := mutate(releaseCtx, true, time.Millisecond)
		if releaseErr == nil && !released {
			releaseErr = ErrLeaseLost
		}
		err = errors.Join(err, cause, releaseErr)
	}()
	if err := work.Err(); err != nil {
		return true, err
	}
	return true, job(work)
}
