package backchannel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func failureEventCount(t *testing.T, db *rhiza.DB) int64 {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("failure event rows=%#v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0].(int64)
}

func TestStepEmitsBackchannelFailureOnlyAtRetryLimit(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	w, db := newTestWorker(t)
	now := time.UnixMilli(1_704_067_200_000).UTC()
	insertDelivery(t, db, "step-failure-event", "client-step", "sid-step", server.URL, true, true, now)
	for attempt := 1; attempt <= 3; attempt++ {
		if err := w.Step(context.Background(), now); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		wantEvents := int64(0)
		if attempt == 3 {
			wantEvents = 1
		}
		if got := failureEventCount(t, db); got != wantEvents {
			t.Fatalf("attempt %d failure events=%d want=%d", attempt, got, wantEvents)
		}
		if attempt < 3 {
			_, _, _, next := deliveryState(t, db, "step-failure-event", "client-step")
			now = next
		}
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(3) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(3) || rows.Rows[0][4] != "client-step / " {
		t.Fatalf("failure event=%#v err=%v", rows.Rows, err)
	}
	if err := w.Step(context.Background(), now.Add(time.Hour)); err != nil {
		t.Fatalf("terminal follow-up: %v", err)
	}
	if got := failureEventCount(t, db); got != 1 || calls.Load() != 3 {
		t.Fatalf("terminal follow-up events=%d calls=%d", got, calls.Load())
	}
}

func TestStepConcurrentFinalAttemptEmitsOneFailureEvent(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	first, db := newTestWorker(t)
	second := first
	second.WorkerID = "worker-second"
	now := time.UnixMilli(1_704_067_210_000).UTC()
	insertDelivery(t, db, "step-concurrent-event", "client-step", "sid-concurrent", server.URL, true, true, now)
	for range 2 {
		if err := first.Step(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		_, _, _, next := deliveryState(t, db, "step-concurrent-event", "client-step")
		now = next
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, worker := range []Worker{first, second} {
		wg.Add(1)
		go func(worker Worker) {
			defer wg.Done()
			<-start
			errs <- worker.Step(context.Background(), now)
		}(worker)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent final step: %v", err)
		}
	}
	if got := failureEventCount(t, db); got != 1 || calls.Load() != 3 {
		t.Fatalf("concurrent final events=%d calls=%d", got, calls.Load())
	}
	attempts, _, failed, _ := deliveryState(t, db, "step-concurrent-event", "client-step")
	if attempts != 3 || !failed {
		t.Fatalf("terminal state attempts=%d failed=%t", attempts, failed)
	}
}
