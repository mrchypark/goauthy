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
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}})
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
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}})
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
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}})
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
