package housekeeping

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestJobsRunAtExpectedIntervals(t *testing.T) {
	var count atomic.Int32
	j := Job{Name: "tick", Interval: 10 * time.Millisecond, Step: func(ctx context.Context) error {
		count.Add(1)
		return nil
	}}
	s := New([]Job{j}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
	got := int(count.Load())
	if got < 5 || got > 15 {
		t.Fatalf("expected ~8 ticks, got %d", got)
	}
}

func TestContextCancellationStopsAllJobs(t *testing.T) {
	var a, b atomic.Bool
	j1 := Job{Name: "a", Interval: time.Hour, Step: func(ctx context.Context) error {
		a.Store(true)
		return nil
	}}
	j2 := Job{Name: "b", Interval: time.Hour, Step: func(ctx context.Context) error {
		b.Store(true)
		return nil
	}}
	s := New([]Job{j1, j2}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(5 * time.Millisecond)
	if !a.Load() || !b.Load() {
		t.Fatal("both jobs should have executed at least once")
	}
	cancel()
	<-done
}

func TestErrorCallbackInvocation(t *testing.T) {
	sentinel := errors.New("boom")
	var called atomic.Bool
	var gotName atomic.Value
	s := New([]Job{{
		Name:     "fail",
		Interval: time.Hour,
		Step:     func(ctx context.Context) error { return sentinel },
	}}, func(job string, err error) {
		if errors.Is(err, sentinel) {
			called.Store(true)
			gotName.Store(job)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
	if !called.Load() {
		t.Fatal("error callback was not invoked")
	}
	if gotName.Load().(string) != "fail" {
		t.Fatalf("expected job name %q, got %q", "fail", gotName.Load().(string))
	}
}

func TestMultipleJobsRunConcurrently(t *testing.T) {
	var seq1, seq2 atomic.Int32
	barrier := make(chan struct{})
	j1 := Job{Name: "slow", Interval: time.Hour, Step: func(ctx context.Context) error {
		seq1.Add(1)
		<-barrier
		return nil
	}}
	j2 := Job{Name: "fast", Interval: time.Hour, Step: func(ctx context.Context) error {
		seq2.Add(1)
		return nil
	}}
	s := New([]Job{j1, j2}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(5 * time.Millisecond)
	close(barrier)
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	if seq1.Load() == 0 || seq2.Load() == 0 {
		t.Fatal("both jobs should have executed")
	}
}

func TestWakeChannelTriggersImmediateExecution(t *testing.T) {
	var count atomic.Int32
	wake := make(chan struct{})
	j := Job{Name: "waked", Interval: time.Hour, Step: func(ctx context.Context) error {
		count.Add(1)
		return nil
	}, Wake: wake}
	s := New([]Job{j}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(5 * time.Millisecond)
	if count.Load() != 1 {
		t.Fatal("expected initial execution")
	}
	wake <- struct{}{}
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	if count.Load() != 2 {
		t.Fatalf("expected 2 executions after wake, got %d", count.Load())
	}
}

func TestNilOnError(t *testing.T) {
	s := New([]Job{{
		Name:     "nil-cb",
		Interval: time.Hour,
		Step:     func(ctx context.Context) error { return errors.New("fail") },
	}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
}

func TestPreCanceledContext(t *testing.T) {
	var count atomic.Int32
	s := New([]Job{{
		Name:     "noop",
		Interval: time.Millisecond,
		Step: func(ctx context.Context) error {
			count.Add(1)
			return nil
		},
	}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-done
	if count.Load() != 0 {
		t.Fatalf("expected 0 executions, got %d", count.Load())
	}
}
