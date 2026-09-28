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

// Explicit opt-in: ordinary tests must not run a load experiment. Invoke this
// test binary once per case so RSS and GC history are not shared between cases.
func TestPasswordContentionMeasurement(t *testing.T) {
	mix := os.Getenv("GOAUTHY_MEASURE_MIX")
	if mix == "" {
		t.Skip("set GOAUTHY_MEASURE_MIX=small|large|mixed for bounded measurement")
	}
	if mix != "small" && mix != "large" && mix != "mixed" {
		t.Fatal("invalid mix")
	}
	workers, err := strconv.Atoi(os.Getenv("GOAUTHY_MEASURE_CONCURRENCY"))
	if err != nil || (workers != 1 && workers != 4 && workers != 8) {
		t.Fatal("concurrency must be 1, 4 or 8")
	}
	const calls = 128
	password := []byte("measurement-password")
	phcs := make(map[uint32]string)
	costs := []uint32{19 * 1024}
	if mix == "large" {
		costs = []uint32{128 * 1024}
	} else if mix == "mixed" {
		costs = append(costs, 128*1024)
	}
	for _, cost := range costs {
		policy := DefaultPolicy()
		policy.MemoryKiB = cost
		fixture, err := NewHasher(policy)
		if err != nil {
			t.Fatal(err)
		}
		phc, err := fixture.Hash(t.Context(), password)
		if err != nil {
			t.Fatal(err)
		}
		phcs[cost] = phc
	}
	h, err := NewHasher(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// Discard fixture KDF garbage before measurement, never force GC in the loop.
	debug.FreeOSMemory()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var cpuBefore syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	running := make(map[int]uint32) // calls, including queueing, NOT KDF admission
	records := make([]passwordMeasurementCall, calls)
	peakSlots, peakWaiting := 0, 0
	var peakLower, peakUpper, peakHeap, peakInuse, peakHeapSys uint64
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
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			mu.Lock()
			slots := len(h.slots)
			activeCosts := make([]uint32, 0, len(running))
			for _, cost := range running {
				activeCosts = append(activeCosts, cost)
			}
			slices.Sort(activeCosts)
			// Holding mu stabilizes call registration. A slot can still be released
			// concurrently; these are sampled occupancy estimates, not exact KDF bytes.
			k := min(slots, len(activeCosts))
			var lower, upper uint64
			for i := 0; i < k; i++ {
				lower += uint64(activeCosts[i]) * 1024
				upper += uint64(activeCosts[len(activeCosts)-1-i]) * 1024
			}
			peakSlots = max(peakSlots, slots)
			peakWaiting = max(peakWaiting, len(running)-slots)
			peakLower = max(peakLower, lower)
			peakUpper = max(peakUpper, upper)
			peakHeap = max(peakHeap, mem.HeapAlloc)
			peakInuse = max(peakInuse, mem.HeapInuse)
			peakHeapSys = max(peakHeapSys, mem.HeapSys)
			mu.Unlock()
		}
	}()
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				cost := costs[i%len(costs)]
				mu.Lock()
				running[i] = cost
				mu.Unlock()
				begin := time.Now()
				valid, _, err := h.VerifyOrDummy(t.Context(), password, phcs[cost])
				elapsed := time.Since(begin)
				outcome := "success"
				if errors.Is(err, ErrWorkLimit) {
					outcome = "rejected"
				} else if err != nil || !valid {
					t.Errorf("unexpected verification valid=%v err=%v", valid, err)
					outcome = "error"
				}
				mu.Lock()
				delete(running, i)
				records[i] = passwordMeasurementCall{cost, outcome, float64(elapsed) / float64(time.Millisecond)}
				mu.Unlock()
			}
		})
	}
	for i := range calls {
		jobs <- i
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
	distributions := map[string]passwordLatency{}
	for _, cost := range costs {
		for _, outcome := range []string{"success", "rejected"} {
			var values []float64
			for _, r := range records {
				if r.MemoryKiB == cost && r.Outcome == outcome {
					values = append(values, r.Milliseconds)
				}
			}
			distributions[fmt.Sprintf("%dKiB/%s", cost, outcome)] = passwordQuantiles(values)
		}
	}
	report := struct {
		Mix                                                                                                  string
		Workers, Calls, Slots                                                                                int
		WaitMS                                                                                               int
		GoVersion, OS, Arch                                                                                  string
		GOMAXPROCS                                                                                           int
		WallSeconds, UserSeconds, SystemSeconds                                                              float64
		PeakOccupiedSlots, PeakWaitingCalls                                                                  int
		SampledLogicalLowerBytes, SampledLogicalUpperBytes                                                   uint64
		BaselineHeapBytes, PeakHeapBytes, PeakHeapInuseBytes, PeakHeapSysBytes, EndHeapBytes, AllocatedBytes uint64
		GCCycles                                                                                             uint32
		ProcessMaxRSSBytes                                                                                   int64
		Distributions                                                                                        map[string]passwordLatency
		Records                                                                                              []passwordMeasurementCall
	}{mix, workers, calls, cap(h.slots), 100, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), elapsed.Seconds(), usageSeconds(cpuAfter.Utime) - usageSeconds(cpuBefore.Utime), usageSeconds(cpuAfter.Stime) - usageSeconds(cpuBefore.Stime), peakSlots, peakWaiting, peakLower, peakUpper, before.HeapAlloc, peakHeap, peakInuse, peakHeapSys, after.HeapAlloc, after.TotalAlloc - before.TotalAlloc, after.NumGC - before.NumGC, rss, distributions, records}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PASSWORD_MEASUREMENT %s\n", encoded)
	if len(h.slots) != 0 {
		t.Fatal("work slots leaked")
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

// Real KDFs occupy every slot while queued requests exercise the production
// 100ms timeout and caller cancellation. Cancellation after admission must not
// make a slot available before the synchronous KDF returns.
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range cap(h.slots) {
		wg.Go(func() {
			<-start
			if valid, _, err := h.VerifyOrDummy(ctx, password, phc); err != nil || !valid {
				t.Errorf("started KDF: valid=%v err=%v", valid, err)
			}
		})
	}
	defer wg.Wait()
	close(start)
	until := time.Now().Add(time.Second)
	for len(h.slots) != cap(h.slots) {
		if time.Now().After(until) {
			t.Fatal("KDFs did not occupy slots")
		}
		runtime.Gosched()
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
	// Under scheduling delay both select cases may be ready. The existing
	// admission code does not prioritize caller cancellation over its timer.
	callerOutcome := err
	if !errors.Is(queued.Err(), context.DeadlineExceeded) ||
		(!errors.Is(err, context.DeadlineExceeded) && !(errors.Is(err, ErrWorkLimit) && cancelWait >= policy.WaitTimeout)) {
		t.Fatalf("queued cancellation=%v context=%v elapsed=%s", err, queued.Err(), cancelWait)
	}
	begin = time.Now()
	_, _, err = h.VerifyOrDummy(t.Context(), []byte("password"), "")
	rejectWait := time.Since(begin)
	if !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("100ms rejection=%v", err)
	}
	t.Logf("occupied after cancel=%d caller-budget return=%s outcome=%v admission rejection=%s", held, cancelWait, callerOutcome, rejectWait)
	wg.Wait()
	if len(h.slots) != 0 {
		t.Fatal("slots did not release after KDF return")
	}
	if _, _, err := h.VerifyOrDummy(t.Context(), []byte("password"), ""); err != nil {
		t.Fatalf("post-KDF admission: %v", err)
	}
}
