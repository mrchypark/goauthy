package notify

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

type countingFactory struct {
	n    atomic.Int32
	fail bool
}

func (f *countingFactory) Sender(Target) (Sender, error) { return countingSender{f}, nil }

type countingSender struct{ f *countingFactory }

func (s countingSender) Send(context.Context, eventlog.Event) error {
	s.f.n.Add(1)
	if s.f.fail {
		return context.Canceled
	}
	return nil
}

func TestNotificationRuntimeStep(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://runtime.example")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("runtime-info", "", now))
	f := &countingFactory{}
	r := Runtime{Queue: q, Factory: f}
	if err := r.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 1 {
		t.Fatalf("test event sends=%d", f.n.Load())
	}
	putEvent(t, db, eventlog.IPBlacklisted("runtime-warning", "192.0.2.1", 0, now))
	if err := r.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 2 {
		t.Fatalf("warning sends=%d", f.n.Load())
	}
	putEvent(t, db, eventlog.Creation("runtime-filtered", "user@example.test", "", true, now))
	if err := r.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 2 {
		t.Fatal("below-threshold event was sent")
	}
	if rows, err := q.Claim(ctx, id, now.Add(time.Minute), 1, time.Minute); err != nil || len(rows) != 0 {
		t.Fatal("filtered event remained pending")
	}
}
func TestNotificationRuntimeCompetingAndCancel(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://runtime2.example")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("runtime-one", "", now))
	f := &countingFactory{}
	r1 := Runtime{Queue: q, Factory: f}
	q2 := &RhizaQueue{DB: db, allowed: map[string]bool{id: true}}
	r2 := Runtime{Queue: q2, Factory: f}
	start, results := make(chan struct{}), make(chan error, 2)
	for _, runtime := range []*Runtime{&r1, &r2} {
		go func() { <-start; results <- runtime.Step(ctx, now) }()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if f.n.Load() != 1 {
		t.Fatalf("competing sends=%d", f.n.Load())
	}
	putEvent(t, db, eventlog.TestEvent("runtime-cancel", "", now))
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := r1.Step(cctx, now); err == nil {
		t.Fatal("cancel accepted")
	}
	if f.n.Load() != 1 {
		t.Fatal("cancelled runtime sent event")
	}
}

func TestNotificationRuntimeRetryBoundary(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://retry.example.test")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("retry-runtime", "", now))
	f := &countingFactory{fail: true}
	r := Runtime{Queue: q, Factory: f}
	if err := r.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 1 {
		t.Fatal("initial attempt missing")
	}
	f.fail = false
	if err := r.Step(ctx, now.Add(time.Second-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 1 {
		t.Fatal("retry occurred before due boundary")
	}
	if err := r.Step(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 2 {
		t.Fatal("retry missing at equality")
	}
	if err := r.Step(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 2 {
		t.Fatal("acknowledged event was sent again")
	}
}

// TestNotificationMaintenanceBudgetDoesNotBlockDelivery covers GA66-NOTIFY-002:
// one maintenance turn spends a fixed cleanup batch, and a warning queued after
// cleanup started is delivered before the backlog it shares a goroutine with is
// exhausted.
func TestNotificationMaintenanceBudgetDoesNotBlockDelivery(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://maintenance-budget.example.test")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Hour)
	backlog := 2*cleanupBatchSize + 1
	seedCleanupBacklog(t, ctx, db, id, now, backlog)

	f := &countingFactory{}
	r := Runtime{Queue: q, Factory: f}
	more, err := r.Maintain(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	remaining := deliveryCount(t, ctx, db, id)
	if !more || remaining != backlog-cleanupBatchSize {
		t.Fatalf("maintenance turn removed %d rows and reported more=%v, want one batch of %d", backlog-remaining, more, cleanupBatchSize)
	}
	putEvent(t, db, eventlog.IPBlacklisted("maintenance-warning", "192.0.2.1", 0, at))
	if err := r.Step(ctx, at); err != nil {
		t.Fatal(err)
	}
	if f.n.Load() != 1 {
		t.Fatalf("warning sends=%d, want delivery before the cleanup backlog drained", f.n.Load())
	}
	if got := deliveryCount(t, ctx, db, id); got != remaining+1 {
		t.Fatalf("deliveries after step=%d want=%d", got, remaining+1)
	}
	if more, err = r.Maintain(ctx, at); err != nil || !more {
		t.Fatalf("resumed maintenance more=%v err=%v, want the backlog resumed", more, err)
	}
	if more, err = r.Maintain(ctx, at); err != nil || more {
		t.Fatalf("drained maintenance more=%v err=%v", more, err)
	}
	if got := deliveryCount(t, ctx, db, id); got != 1 {
		t.Fatalf("deliveries after drain=%d want only the delivered warning", got)
	}
}
