//go:build darwin || linux

package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Explicit opt-in; each case runs in a fresh process. All experiment settings
// are bounded independently of the public policy/configuration surface.
func TestPasswordContentionMeasurement(t *testing.T) {
	mix := os.Getenv("GOAUTHY_MEASURE_MIX")
	if mix == "" {
		t.Skip("set GOAUTHY_MEASURE_MIX=small|large|mixed")
	}
	if mix != "small" && mix != "large" && mix != "mixed" {
		t.Fatal("invalid mix")
	}
	setting := func(name string, fallback int, allowed ...int) int {
		raw := os.Getenv(name)
		if raw == "" {
			return fallback
		}
		n, err := strconv.Atoi(raw)
		if err != nil || !slices.Contains(allowed, n) {
			t.Fatalf("invalid %s", name)
		}
		return n
	}
	workers := setting("GOAUTHY_MEASURE_CONCURRENCY", 8, 1, 4, 8)
	calls := setting("GOAUTHY_MEASURE_CALLS", 128, 128, 256)
	slots := setting("GOAUTHY_MEASURE_SLOTS", 4, 1, 2, 4)
	budget := setting("GOAUTHY_MEASURE_BUDGET_MIB", 0, 0, 128, 192, 256, 512)
	rate := setting("GOAUTHY_MEASURE_RATE", 0, 0, 20)
	password := []byte("measurement-password")
	costs := []uint32{19 * 1024}
	if mix == "large" {
		costs = []uint32{maxMemoryKiB}
	} else if mix == "mixed" {
		costs = append(costs, maxMemoryKiB)
	}
	phcs := make(map[uint32]string)
	for _, cost := range costs {
		p := DefaultPolicy()
		p.MemoryKiB = cost
		fixture, err := NewHasher(p)
		if err != nil {
			t.Fatal(err)
		}
		phc, err := fixture.Hash(t.Context(), password)
		if err != nil {
			t.Fatal(err)
		}
		phcs[cost] = phc
	}
	policy := DefaultPolicy()
	policy.MaxConcurrency = slots
	policy.MemoryBudgetKiB = uint32(budget) * 1024
	h, err := NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	observer := newPasswordMeasurementObserver()
	h.observer = observer.observe
	debug.FreeOSMemory()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var cpuBefore syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore); err != nil {
		t.Fatal(err)
	}
	var peakHeap, peakInuse, peakHeapSys uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peakHeap = max(peakHeap, m.HeapAlloc)
			peakInuse = max(peakInuse, m.HeapInuse)
			peakHeapSys = max(peakHeapSys, m.HeapSys)
		}
	}()
	records := make([]passwordMeasurementCall, calls)
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				cost := costs[i%len(costs)]
				begin := time.Now()
				valid, _, err := h.VerifyOrDummy(t.Context(), password, phcs[cost])
				elapsed := time.Since(begin)
				outcome := "success"
				if errors.Is(err, ErrWorkLimit) {
					outcome = "rejected"
				} else if err != nil || !valid {
					t.Errorf("valid=%v err=%v", valid, err)
					outcome = "error"
				}
				records[i] = passwordMeasurementCall{cost, outcome, float64(elapsed) / float64(time.Millisecond)}
			}
		})
	}
	var maxGeneratorLag time.Duration
	for i := range calls {
		if rate == 0 {
			jobs <- i
			continue
		}
		target := started.Add(time.Duration(i) * time.Second / time.Duration(rate))
		time.Sleep(time.Until(target))
		maxGeneratorLag = max(maxGeneratorLag, time.Since(target))
		select {
		case jobs <- i:
		default:
			records[i] = passwordMeasurementCall{costs[i%len(costs)], "generator-drop", 0}
		}
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(started)
	close(stop)
	<-sampled
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	var cpuAfter syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter); err != nil {
		t.Fatal(err)
	}
	rss := cpuAfter.Maxrss
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	spans := observer.results()
	distributions := map[string]passwordLatency{}
	for _, cost := range costs {
		for _, outcome := range []string{"success", "rejected", "generator-drop"} {
			var values []float64
			for _, r := range records {
				if r.MemoryKiB == cost && r.Outcome == outcome {
					values = append(values, r.Milliseconds)
				}
			}
			distributions[fmt.Sprintf("%dKiB/%s", cost, outcome)] = passwordQuantiles(values)
		}
	}
	report := map[string]any{
		"Mix": mix, "Workers": workers, "Calls": calls, "Slots": slots, "MemoryBudgetMiB": budget, "Rate": rate, "WaitMS": 100,
		"GoVersion": runtime.Version(), "OS": runtime.GOOS, "Arch": runtime.GOARCH, "GOMAXPROCS": runtime.GOMAXPROCS(0),
		"WallSeconds": elapsed.Seconds(), "UserSeconds": usageSeconds(cpuAfter.Utime) - usageSeconds(cpuBefore.Utime), "SystemSeconds": usageSeconds(cpuAfter.Stime) - usageSeconds(cpuBefore.Stime),
		"MaxGeneratorLagMS": float64(maxGeneratorLag) / float64(time.Millisecond),
		"PeakReservedSlots": observer.PeakSlots, "PeakSlotWaiters": observer.PeakSlotWaiters, "PeakMemoryWaiters": observer.PeakMemoryWaiters, "PeakComputing": observer.PeakComputing,
		"PeakReservedKiB": observer.PeakReservedKiB, "PeakComputingKiB": observer.PeakComputingKiB,
		"BaselineHeapBytes": before.HeapAlloc, "PeakHeapBytes": peakHeap, "PeakHeapInuseBytes": peakInuse, "PeakHeapSysBytes": peakHeapSys, "EndHeapBytes": after.HeapAlloc, "AllocatedBytes": after.TotalAlloc - before.TotalAlloc,
		"GCCycles": after.NumGC - before.NumGC, "ProcessMaxRSSBytes": rss, "Distributions": distributions, "Records": records, "Spans": spans,
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PASSWORD_MEASUREMENT %s\n", encoded)
	if observer.slots != 0 || observer.slotWaiters != 0 || observer.memoryWaiters != 0 || observer.computing != 0 || observer.reservedKiB != 0 || observer.computingKiB != 0 {
		t.Fatal("observer accounting did not drain")
	}
	if observer.PeakSlots > slots || observer.PeakComputing > slots {
		t.Fatal("concurrency bound exceeded")
	}
	if budget > 0 && observer.PeakReservedKiB > uint64(budget)*1024 {
		t.Fatal("memory reservation bound exceeded")
	}
	if len(h.slots) != 0 {
		t.Fatal("work slots leaked")
	}
	if h.memory != nil {
		if !h.memory.TryAcquire(int64(policy.MemoryBudgetKiB)) {
			t.Fatal("memory leaked")
		}
		h.memory.Release(int64(policy.MemoryBudgetKiB))
	}
}

type passwordMeasurementCall struct {
	MemoryKiB    uint32
	Outcome      string
	Milliseconds float64
}
type passwordLatency struct {
	N                          int
	P50MS, P95MS, P99MS, MaxMS float64
}

func passwordQuantiles(values []float64) passwordLatency {
	if len(values) == 0 {
		return passwordLatency{}
	}
	slices.Sort(values)
	at := func(q float64) float64 { return values[int(math.Ceil(q*float64(len(values))))-1] }
	return passwordLatency{len(values), at(.5), at(.95), at(.99), values[len(values)-1]}
}

func TestPasswordMeasurementQuantiles(t *testing.T) {
	if got := passwordQuantiles(nil); got != (passwordLatency{}) {
		t.Fatalf("empty distribution=%+v", got)
	}
	values := make([]float64, 100)
	for i := range values {
		values[i] = float64(100 - i)
	}
	if got := passwordQuantiles(values); got != (passwordLatency{100, 50, 95, 99, 100}) {
		t.Fatalf("nearest-rank distribution=%+v", got)
	}
}
func usageSeconds(v syscall.Timeval) float64 { return float64(v.Sec) + float64(v.Usec)/1e6 }

// Real KDFs finish before cancellation, with their operations held before lease
// release. This measures queued deadlines and post-IDKey lease lifetime, not
// cancellation during IDKey or proof of entry from slot occupancy.
func TestPasswordRealKDFCancellationMeasurement(t *testing.T) {
	if os.Getenv("GOAUTHY_MEASURE_CANCEL") == "" {
		t.Skip("set GOAUTHY_MEASURE_CANCEL=1 for real KDF cancellation checks")
	}
	policy := DefaultPolicy()
	policy.MemoryKiB = 128 * 1024
	policy.Iterations = 5
	h, err := NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("measurement-password")
	phc, err := h.Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	// Install the observer on a fresh hasher before use, separate from fixtures.
	h, err = NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan struct{}, cap(h.slots))
	finish := make(chan struct{})
	h.observer = func(e passwordWorkEvent) {
		if e.ID <= uint64(cap(h.slots)) && e.Stage == "finish" && e.Outcome == "ok" {
			completed <- struct{}{}
			<-finish
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	start := make(chan struct{})
	workerErrors := make(chan error, cap(h.slots))
	var wg sync.WaitGroup
	for range cap(h.slots) {
		wg.Go(func() {
			<-start
			if valid, _, err := h.VerifyOrDummy(ctx, password, phc); err != nil || !valid {
				workerErrors <- fmt.Errorf("started KDF: valid=%v err=%v", valid, err)
			}
		})
	}
	defer func() {
		cancel()
		close(finish)
		wg.Wait()
		if len(h.slots) != 0 {
			t.Error("cleanup leaked slots")
		}
	}()
	close(start)
	barrierTimeout := time.NewTimer(30 * time.Second)
	defer barrierTimeout.Stop()
	for range cap(h.slots) {
		select {
		case <-completed:
		case err := <-workerErrors:
			t.Fatal(err)
		case <-barrierTimeout.C:
			t.Fatal("timed out waiting for real KDF finish barriers")
		}
	}
	cancel()
	held := len(h.slots)
	if held != cap(h.slots) {
		t.Fatal("cancellation released admitted work before observation")
	}
	begin := time.Now()
	queued, cancelQueued := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelQueued()
	_, _, err = h.VerifyOrDummy(queued, []byte("password"), "")
	cancelWait := time.Since(begin)
	callerOutcome := err
	if !errors.Is(queued.Err(), context.DeadlineExceeded) ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued cancellation=%v context=%v elapsed=%s", err, queued.Err(), cancelWait)
	}
	begin = time.Now()
	_, _, err = h.VerifyOrDummy(t.Context(), []byte("password"), "")
	rejectWait := time.Since(begin)
	if !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("100ms rejection=%v", err)
	}
	t.Logf("held after IDKey and cancellation=%d caller-budget return=%s outcome=%v admission rejection=%s", held, cancelWait, callerOutcome, rejectWait)
	// Release the barrier without closing it twice in deferred cleanup.
	for range cap(h.slots) {
		finish <- struct{}{}
	}
	wg.Wait()
	select {
	case err := <-workerErrors:
		t.Fatal(err)
	default:
	}
	if len(h.slots) != 0 {
		t.Fatal("slots did not release after KDF return")
	}
	if _, _, err := h.VerifyOrDummy(t.Context(), []byte("password"), ""); err != nil {
		t.Fatalf("post-KDF admission: %v", err)
	}
}
