package backupschedule

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func slotKey(scope string) string {
	return fmt.Sprintf("goauthy/backup-completed/%x", sha256.Sum256([]byte(scope)))
}

func waitSlotLease(t *testing.T, db *rhiza.DB, scope string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		value, err := db.KVGet(ctx, rhiza.KVGetRequest{Key: leaseKey(scope), Consistency: "linearizable"})
		if err != nil {
			t.Fatal(err)
		}
		if !value.Found {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestRunSlotSkipsCompletedAndOlder(t *testing.T) {
	db := leaseTestDB(t)
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	job := func(context.Context) error { calls++; return nil }
	for i, slot := range []time.Time{due, due, due.Add(-time.Second), due.Add(time.Second)} {
		waitSlotLease(t, db, "slots")
		executed, err := RunSlot(t.Context(), db, "slots", slot, time.Second, job)
		want := i == 0 || i == 3
		if err != nil || executed != want {
			t.Fatalf("slot%d executed=%t err=%v", i, executed, err)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestRunSlotFailureRemainsRetryable(t *testing.T) {
	db := leaseTestDB(t)
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	failure := errors.New("export failed")
	executed, err := RunSlot(t.Context(), db, "retry", due, time.Second, func(context.Context) error { return failure })
	if !executed || !errors.Is(err, failure) {
		t.Fatalf("%t %v", executed, err)
	}
	marker, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: slotKey("retry"), Consistency: "linearizable"})
	if err != nil || marker.Found {
		t.Fatalf("failure marked completed: %v", err)
	}
	waitSlotLease(t, db, "retry")
	executed, err = RunSlot(t.Context(), db, "retry", due, time.Second, func(context.Context) error { return nil })
	if !executed || err != nil {
		t.Fatalf("retry %t %v", executed, err)
	}
}

func TestRunSlotNeverRegressesConcurrentCompletion(t *testing.T) {
	db := leaseTestDB(t)
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	later := []byte(strconv.FormatInt(due.Add(time.Hour).Unix(), 10))
	executed, err := RunSlot(t.Context(), db, "successor", due, time.Second, func(ctx context.Context) error {
		_, err := db.KVPut(ctx, rhiza.KVMutationRequest{RequestID: rand.Text(), Key: slotKey("successor"), Value: later})
		return err
	})
	if !executed || err == nil {
		t.Fatalf("accepted stale completion %t %v", executed, err)
	}
	marker, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: slotKey("successor"), Consistency: "linearizable"})
	if err != nil || string(marker.Value) != string(later) {
		t.Fatalf("overwrote successor: %v", err)
	}
}

func TestRunSlotLostHolderCannotCompleteOrDeleteSuccessorLease(t *testing.T) {
	db := leaseTestDB(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const scope = "lost-holder-slot"
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	resumed := make(chan struct{})
	result := make(chan struct {
		executed bool
		err      error
	}, 1)
	go func() {
		executed, err := RunSlot(ctx, db, scope, due, time.Second, func(work context.Context) error {
			close(started)
			<-work.Done()
			close(resumed)
			// A paused callback can resume and claim success despite cancellation.
			return nil
		})
		result <- struct {
			executed bool
			err      error
		}{executed, err}
	}()
	waitLease(t, started)

	successor := []byte("successor-owner")
	receipt, err := db.KVPut(ctx, rhiza.KVMutationRequest{
		RequestID: rand.Text(), Key: leaseKey(scope), Value: successor, TTLMS: 60_000,
	})
	if err != nil || receipt.Status != rhiza.MutationCommitted {
		t.Fatalf("replace lease receipt=%+v err=%v", receipt, err)
	}
	waitLease(t, resumed)
	var got struct {
		executed bool
		err      error
	}
	select {
	case got = <-result:
	case <-ctx.Done():
		t.Fatal("lost holder did not return")
	}
	if !got.executed || !errors.Is(got.err, ErrLeaseLost) {
		t.Fatalf("executed=%t err=%v", got.executed, got.err)
	}
	marker, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: slotKey(scope), Consistency: "linearizable"})
	if err != nil || marker.Found {
		t.Fatalf("lost holder marked completion found=%t err=%v", marker.Found, err)
	}
	lease, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: leaseKey(scope), Consistency: "linearizable"})
	if err != nil || !lease.Found || string(lease.Value) != string(successor) {
		t.Fatalf("successor lease found=%t value=%q err=%v", lease.Found, lease.Value, err)
	}
}

func TestRunSlotRejectsCorruptMarkerAndCancellation(t *testing.T) {
	db := leaseTestDB(t)
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := db.KVPut(t.Context(), rhiza.KVMutationRequest{RequestID: rand.Text(), Key: slotKey("corrupt"), Value: []byte("+123")})
	if err != nil {
		t.Fatal(err)
	}
	executed, err := RunSlot(t.Context(), db, "corrupt", due, time.Second, func(context.Context) error { t.Fatal("ran past corrupt marker"); return nil })
	if executed || err == nil {
		t.Fatalf("%t %v", executed, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	executed, err = RunSlot(ctx, db, "canceled", due, time.Second, func(context.Context) error { cancel(); return nil })
	if !executed || !errors.Is(err, context.Canceled) {
		t.Fatalf("%t %v", executed, err)
	}
	marker, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: slotKey("canceled"), Consistency: "linearizable"})
	if err != nil || marker.Found {
		t.Fatalf("canceled job marked completed: %v", err)
	}
}

func TestRunSlotRejectsFutureState(t *testing.T) {
	db := leaseTestDB(t)
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	job := func(context.Context) error { t.Fatal("ran future state"); return nil }
	if executed, err := RunSlot(t.Context(), db, "future", future, time.Second, job); err == nil || executed {
		t.Fatalf("future slot %t %v", executed, err)
	}
	_, err := db.KVPut(t.Context(), rhiza.KVMutationRequest{RequestID: rand.Text(), Key: slotKey("future"), Value: []byte(strconv.FormatInt(future.Unix(), 10))})
	if err != nil {
		t.Fatal(err)
	}
	if executed, err := RunSlot(t.Context(), db, "future", future.Add(-2*time.Hour), time.Second, job); err == nil || executed {
		t.Fatalf("future watermark %t %v", executed, err)
	}
}

func TestRunSlotCompletionSurvivesReopen(t *testing.T) {
	config := rhiza.Config{NodeID: "backup-slot-reopen", DataDir: t.TempDir()}
	db, err := rhiza.Open(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	due := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if executed, err := RunSlot(t.Context(), db, "reopen", due, time.Second, func(context.Context) error { return nil }); err != nil || !executed {
		t.Fatalf("%t %v", executed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = rhiza.Open(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := db.KVGet(t.Context(), rhiza.KVGetRequest{Key: slotKey("reopen"), Consistency: "linearizable"})
	if err != nil || !marker.Found || string(marker.Value) != strconv.FormatInt(due.Unix(), 10) {
		t.Fatalf("lost completion: %v", err)
	}
	waitSlotLease(t, db, "reopen")
	if executed, err := RunSlot(t.Context(), db, "reopen", due, time.Second, func(context.Context) error { t.Fatal("replayed completed job"); return nil }); err != nil || executed {
		t.Fatalf("%t %v", executed, err)
	}
}
