package credential

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

// Events contain only synthetic IDs and public work costs, never credential data.
// Times mark Go call boundaries, not atomic semaphore or Argon2 allocation state.
type passwordWorkEvent struct {
	ID        uint64
	Kind      string
	MemoryKiB uint32
	Stage     string
	At        time.Time
	Outcome   string
}
type passwordWork struct {
	h      *Hasher
	id     uint64
	kind   string
	memory uint32
}

func (h *Hasher) work(kind string, memory uint32) passwordWork {
	w := passwordWork{h: h, kind: kind, memory: memory}
	if h.observer != nil {
		w.id = h.sequence.Add(1)
		w.emit("classified", nil)
	}
	return w
}
func (w passwordWork) emit(stage string, err error) {
	if w.h.observer == nil {
		return
	}
	outcome := "ok"
	switch {
	case errors.Is(err, context.Canceled):
		outcome = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		outcome = "deadline"
	case errors.Is(err, ErrWorkLimit):
		outcome = "limit"
	case err != nil:
		outcome = "error"
	}
	w.h.observer(passwordWorkEvent{w.id, w.kind, w.memory, stage, time.Now(), outcome})
}
func (w passwordWork) derive(ctx context.Context, password, salt []byte, p parameters, keyLen uint32) ([]byte, error) {
	// The observer runs before the last cancellation check, including for Hash
	// after salt generation. A canceled start event is paired with a failed finish
	// and does not represent an executed KDF. No cancellation watcher owns release.
	w.emit("start", nil)
	if err := ctx.Err(); err != nil {
		w.emit("finish", err)
		return nil, err
	}
	key := argon2.IDKey(password, salt, p.time, p.memory, p.parallelism, keyLen)
	w.emit("finish", nil)
	return key, nil
}

func (h *Hasher) tryAcquire(ctx context.Context, w passwordWork) (func(), error) {
	admission := ctx
	cancel := func() {}
	if h.policy.WaitTimeout > 0 {
		admission, cancel = context.WithTimeout(ctx, h.policy.WaitTimeout)
	}
	defer cancel()
	failure := func(stage string) (func(), error) {
		// Parent cancellation wins when both parent and local expiry are observed.
		err := ctx.Err()
		if err == nil {
			err = ErrWorkLimit
		}
		w.emit(stage, err)
		return nil, err
	}
	if ctx.Err() != nil {
		return failure("reject-slot")
	}
	w.emit("slot-wait", nil)
	if h.policy.WaitTimeout == 0 {
		select {
		case h.slots <- struct{}{}:
		default:
			return failure("reject-slot")
		}
	} else {
		select {
		case h.slots <- struct{}{}:
		case <-admission.Done():
			return failure("reject-slot")
		}
	}
	w.emit("slot", nil)
	// Release events mark the call boundary before making capacity reusable;
	// observers must not double-count a successor before seeing this release.
	releaseSlot := func() { w.emit("slot-release", nil); <-h.slots }
	if admission.Err() != nil {
		releaseSlot()
		return failure("reject-slot")
	}
	w.emit("memory-wait", nil)
	if h.memory != nil {
		var acquired bool
		if h.policy.WaitTimeout == 0 {
			acquired = h.memory.TryAcquire(int64(w.memory))
		} else {
			acquired = h.memory.Acquire(admission, int64(w.memory)) == nil
		}
		if !acquired {
			releaseSlot()
			return failure("reject-memory")
		}
	}
	w.emit("memory", nil)
	release := func() {
		w.emit("memory-release", nil)
		if h.memory != nil {
			h.memory.Release(int64(w.memory))
		}
		releaseSlot()
		w.emit("release", nil)
	}
	if admission.Err() != nil {
		release()
		return failure("reject-memory")
	}
	return release, nil
}
