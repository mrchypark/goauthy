package backupschedule

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mrchypark/rhiza"
)

var ErrCompletionRead = errors.New("backup completion read failed")

// RunSlot executes a due job under WithLease unless this scope already completed
// that slot or a later one. The durable watermark advances only after success.
// Executed reports whether job was called, not whether remote writes succeeded.
// A crash between job and watermark can produce a duplicate on retry.
func RunSlot(ctx context.Context, db *rhiza.DB, scope string, due time.Time, ttl time.Duration, job func(context.Context) error) (executed bool, err error) {
	if job == nil || due.Unix() <= 0 || due.Nanosecond() != 0 || due.UTC().Year() > 2100 || due.After(time.Now()) {
		return false, errors.New("invalid backup schedule slot")
	}
	key := fmt.Sprintf("goauthy/backup-completed/%x", sha256.Sum256([]byte(scope)))
	_, err = WithLease(ctx, db, scope, ttl, func(work context.Context) error {
		previous, err := db.KVGet(work, rhiza.KVGetRequest{Key: key, Consistency: "linearizable"})
		if err != nil {
			return errors.Join(ErrCompletionRead, err)
		}
		if previous.Found {
			last, parseErr := strconv.ParseInt(string(previous.Value), 10, 64)
			if parseErr != nil || last <= 0 || strconv.FormatInt(last, 10) != string(previous.Value) || time.Unix(last, 0).UTC().Year() > 2100 || time.Unix(last, 0).After(time.Now()) {
				return errors.New("invalid backup completion watermark")
			}
			if last >= due.Unix() {
				return nil
			}
		}
		if err := work.Err(); err != nil {
			return err
		}
		executed = true
		if err := job(work); err != nil {
			return err
		}
		if err := work.Err(); err != nil {
			return err
		}
		// No unconditional put: an old holder cannot overwrite a successor's marker.
		receipt, err := db.KVCAS(work, rhiza.KVMutationRequest{RequestID: rand.Text(), Key: key, Value: []byte(strconv.FormatInt(due.Unix(), 10)), ExpectedExists: previous.Found, Expected: previous.Value})
		if err != nil {
			return err
		}
		if receipt.Status != rhiza.MutationCommitted || !receipt.Applied {
			return errors.New("backup completion watermark changed")
		}
		return nil
	})
	return executed, err
}
