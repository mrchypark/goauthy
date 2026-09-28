package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func budgetHasher(t *testing.T, wait time.Duration) *Hasher {
	t.Helper()
	p := DefaultPolicy()
	p.MemoryBudgetKiB = maxMemoryKiB
	p.WaitTimeout = wait
	h, err := NewHasher(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func assertAdmissionEmpty(t *testing.T, h *Hasher) {
	t.Helper()
	if len(h.slots) != 0 {
		t.Fatalf("leaked slots=%d", len(h.slots))
	}
	if h.memory != nil {
		if !h.memory.TryAcquire(int64(h.policy.MemoryBudgetKiB)) {
			t.Fatal("leaked memory reservation")
		}
		h.memory.Release(int64(h.policy.MemoryBudgetKiB))
	}
}
func TestPasswordMemoryBudgetValidation(t *testing.T) {
	for _, n := range []uint32{0, 1, maxMemoryKiB - 1, maxMemoryKiB, 192 * 1024, ^uint32(0)} {
		p := DefaultPolicy()
		p.MemoryBudgetKiB = n
		h, err := NewHasher(p)
		valid := n == 0 || n >= maxMemoryKiB
		if (err == nil) != valid {
			t.Fatalf("budget=%d err=%v", n, err)
		}
		if valid && (h.memory == nil) != (n == 0) {
			t.Fatalf("budget=%d wrong gate", n)
		}
	}
	if DefaultPolicy().MemoryBudgetKiB != 0 {
		t.Fatal("memory gate default enabled")
	}
}
func TestPasswordMemoryPartialRollbackAndCancellation(t *testing.T) {
	for _, wait := range []time.Duration{0, 10 * time.Millisecond, -1} {
		t.Run(wait.String(), func(t *testing.T) {
			h := budgetHasher(t, wait)
			waiting := make(chan struct{}, 1)
			h.observer = func(e passwordWorkEvent) {
				if e.Kind == "waiter" && e.Stage == "memory-wait" {
					waiting <- struct{}{}
				}
			}
			release, err := h.tryAcquire(t.Context(), h.work("holder", maxMemoryKiB))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				r, err := h.tryAcquire(ctx, h.work("waiter", 19*1024))
				if err == nil {
					r()
				}
				result <- err
			}()
			<-waiting
			want := ErrWorkLimit
			if wait < 0 {
				cancel()
				want = context.Canceled
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatalf("wait=%s err=%v", wait, err)
			}
			if len(h.slots) != 1 {
				t.Fatalf("partial rollback slots=%d", len(h.slots))
			}
			if h.memory.TryAcquire(1) {
				t.Fatal("failed acquisition released holder's memory")
			}
			release()
			assertAdmissionEmpty(t, h)
		})
	}
}
func TestPasswordOneAdmissionDeadline(t *testing.T) {
	h := budgetHasher(t, 10*time.Millisecond)
	memoryStage := false
	h.observer = func(e passwordWorkEvent) {
		if e.Stage == "slot" {
			time.Sleep(30 * time.Millisecond)
		}
		if e.Stage == "memory-wait" {
			memoryStage = true
		}
	}
	_, err := h.tryAcquire(t.Context(), h.work("test", 19*1024))
	if !errors.Is(err, ErrWorkLimit) || memoryStage {
		t.Fatalf("expired slot admission restarted at memory: err=%v memory=%v", err, memoryStage)
	}
	assertAdmissionEmpty(t, h)
}
func TestPasswordAdmissionCancellationBoundaries(t *testing.T) {
	for _, stage := range []string{"slot-wait", "slot", "memory"} {
		t.Run(stage, func(t *testing.T) {
			h := budgetHasher(t, 10*time.Millisecond)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h.observer = func(e passwordWorkEvent) {
				if e.Stage == stage {
					cancel()
					if stage == "slot" {
						time.Sleep(20 * time.Millisecond)
					}
				}
			}
			_, err := h.tryAcquire(ctx, h.work("test", 19*1024))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("parent precedence: %v", err)
			}
			assertAdmissionEmpty(t, h)
		})
	}
}
func TestPasswordCostClassificationAndFinalCancel(t *testing.T) {
	valid := func(memory uint32) string {
		return encode(parameters{memory: memory, time: 2, parallelism: 1}, make([]byte, 16), make([]byte, 32))
	}
	for _, tc := range []struct {
		name, phc, password, kind string
		memory                    uint32
	}{
		{"stored-small", valid(8 * 1024), "password", "verify", 8 * 1024},
		{"stored-max", valid(maxMemoryKiB), "password", "verify", maxMemoryKiB},
		{"missing", "", "password", "dummy", 19 * 1024},
		{"huge-malformed", strings.Replace(valid(maxMemoryKiB), "m=131072", "m=4294967295", 1), "password", "dummy", 19 * 1024},
		{"invalid-password", valid(maxMemoryKiB), "", "dummy", 19 * 1024},
		{"long-password", valid(maxMemoryKiB), strings.Repeat("x", 1025), "dummy", 19 * 1024},
		{"hash", "", "password", "hash", 19 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := budgetHasher(t, -1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var classified, start, finished bool
			h.observer = func(e passwordWorkEvent) {
				if e.Stage == "classified" {
					classified = true
					if e.Kind != tc.kind || e.MemoryKiB != tc.memory {
						t.Errorf("classification=%+v", e)
					}
				}
				if e.Stage == "start" {
					start = true
					cancel()
				} // For Hash this is AFTER salt generation.
				if e.Stage == "finish" {
					finished = true
					if e.Outcome != "canceled" {
						t.Error("KDF executed past final cancellation check")
					}
				}
			}
			var err error
			if tc.kind == "hash" {
				_, err = h.Hash(ctx, []byte(tc.password))
			} else {
				_, _, err = h.VerifyOrDummy(ctx, []byte(tc.password), tc.phc)
			}
			if !errors.Is(err, context.Canceled) || !classified || !start || !finished {
				t.Fatalf("err=%v events=%v/%v/%v", err, classified, start, finished)
			}
			assertAdmissionEmpty(t, h)
		})
	}
}
func TestPasswordBudgetDoesNotExposeMalformedPHC(t *testing.T) {
	h := budgetHasher(t, 0)
	for _, phc := range []string{"", "not a PHC", strings.Repeat("x", maxPHCBytes+1)} {
		valid, upgrade, err := h.VerifyOrDummy(t.Context(), []byte("password"), phc)
		if valid || upgrade || err != nil {
			t.Fatalf("dummy result=%v %v %v", valid, upgrade, err)
		}
	}
	if _, _, err := Verify([]byte("password"), "not a PHC"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("package Verify hid parse error")
	}
}
func TestPasswordRealWeightedLifetime(t *testing.T) {
	h := budgetHasher(t, 0)
	fixturePolicy := DefaultPolicy()
	fixturePolicy.MemoryKiB = maxMemoryKiB
	fixture, _ := NewHasher(fixturePolicy)
	phc, err := fixture.Hash(t.Context(), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	completed, finish := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// The barrier is after actual synchronous IDKey completion but before its
	// return/release. It must still own BOTH permits, even after cancellation.
	h.observer = func(e passwordWorkEvent) {
		if e.Stage == "finish" {
			close(completed)
			<-finish
		}
	}
	result := make(chan error, 1)
	go func() { _, _, err := h.VerifyOrDummy(ctx, []byte("password"), phc); result <- err }()
	<-completed
	cancel()
	if len(h.slots) != 1 || h.memory.TryAcquire(1) {
		t.Error("cancellation/completion released capacity before return")
	}
	// A different operation can get a slot but cannot get the memory reservation.
	if _, err := h.tryAcquire(t.Context(), h.work("probe", 19*1024)); !errors.Is(err, ErrWorkLimit) {
		t.Errorf("probe=%v", err)
	}
	close(finish)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	assertAdmissionEmpty(t, h)
}

func TestPasswordCompatibilityVerifyChargesParsedCost(t *testing.T) {
	h := budgetHasher(t, 0)
	previous := defaultHasher
	defaultHasher = h
	defer func() { defaultHasher = previous }()
	var charges []uint32
	h.observer = func(e passwordWorkEvent) {
		if e.Stage == "classified" && e.Kind == "verify" {
			charges = append(charges, e.MemoryKiB)
		}
	}
	release, err := h.tryAcquire(t.Context(), h.work("holder", maxMemoryKiB))
	if err != nil {
		t.Fatal(err)
	}
	phc := encode(parameters{memory: maxMemoryKiB, time: 2, parallelism: 1}, make([]byte, 16), make([]byte, 32))
	if _, _, err := Verify([]byte("password"), phc); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("compatibility memory gate=%v", err)
	}
	if _, _, err := Verify([]byte("password"), "malformed"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("parse error=%v", err)
	}
	if len(charges) != 1 || charges[0] != maxMemoryKiB {
		t.Fatalf("charges=%v", charges)
	}
	release()
	assertAdmissionEmpty(t, h)
}

func TestPasswordMemoryBudgetSnapshotAndDisabledObserver(t *testing.T) {
	p := DefaultPolicy()
	p.MemoryBudgetKiB = maxMemoryKiB
	h, err := NewHasher(p)
	if err != nil {
		t.Fatal(err)
	}
	p.MemoryBudgetKiB = 0
	if _, err := h.Hash(t.Context(), []byte("password")); err != nil {
		t.Fatal(err)
	}
	if h.policy.MemoryBudgetKiB != maxMemoryKiB || h.sequence.Load() != 0 {
		t.Fatal("policy mutated or nil observer generated IDs")
	}
	assertAdmissionEmpty(t, h)
}

func TestPasswordBudgetOwnersAndSequentialLeases(t *testing.T) {
	first, second := budgetHasher(t, 0), budgetHasher(t, 0)
	hold, err := first.tryAcquire(t.Context(), first.work("holder", maxMemoryKiB))
	if err != nil {
		t.Fatal(err)
	}
	other, err := second.tryAcquire(t.Context(), second.work("other", maxMemoryKiB))
	if err != nil {
		t.Fatal("independent owner was blocked")
	}
	other()
	hold()
	assertAdmissionEmpty(t, first)
	assertAdmissionEmpty(t, second)
	first = budgetHasher(t, 0)
	// This is the same sequential contract used by identity verification followed
	// by bestEffortRehash: verification returns/relinquishes before Hash starts.
	p := parameters{memory: 8 * 1024, time: 1, parallelism: 1}
	fixture := encode(p, make([]byte, 16), make([]byte, 32))
	var events []passwordWorkEvent
	first.observer = func(e passwordWorkEvent) { events = append(events, e) }
	if _, _, err := first.VerifyOrDummy(t.Context(), []byte("password"), fixture); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Hash(t.Context(), []byte("password")); err != nil {
		t.Fatal(err)
	}
	releaseIndex, hashIndex := -1, -1
	for i, e := range events {
		if e.Kind == "verify" && e.Stage == "release" {
			releaseIndex = i
		}
		if e.Kind == "hash" && e.Stage == "classified" {
			hashIndex = i
		}
	}
	if releaseIndex < 0 || hashIndex <= releaseIndex {
		t.Fatal("sequential operations shared or overlapped leases")
	}
	assertAdmissionEmpty(t, first)
}
