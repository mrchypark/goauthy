# Argon2 admission measurement, issue #109

Measurement-only on base `7e48bde15c4b5423eb918c3c0da5548ab471e6c7`,
2026-09-28. No production policy, parser, dummy behavior, configuration, or
budget default changed. No candidate weighted limiter is implemented or modeled.

## Conditions and method

Apple M1 Macmini9,1, 8 logical CPUs, 16 GiB RAM; Go 1.27.0 darwin/arm64.
Desktop workload remained active (load averages approximately 2.5–3.3); this
was not an isolated performance machine. No deployment or paid environment
was used. In particular, this is not the 512 MiB/500m qualification deployment.

Each of the nine mix/concurrency combinations ran in two fresh processes:
128 calls/process, 2,304 retained calls total. Fixed process settings:
`GOMAXPROCS=4 GOGC=100 GOMEMLIMIT=1GiB`. This is an experimental soft Go memory
target, **not a hard RSS cap or a proposed production admission budget**.
Four production slots bound simultaneous KDF reservations to at most 512 MiB
for the selected PHCs. The largest observed process RSS was about 1.17 GiB;
no OOM was induced. Each process has a 90-second watchdog and fixed call count.
The retained workload windows total about 127 seconds.

Each process creates valid PHCs outside the measured interval, discards fixture
KDF garbage with `debug.FreeOSMemory`, then calls the real shared
`Hasher.VerifyOrDummy`. Costs are 19/128 MiB, two iterations, one lane. Production
`DefaultPolicy` provides four slots and the actual 100 ms admission timeout.
The mixed input alternates costs equally. A fixed number of workers pulls jobs
from an unbuffered channel: this is **closed-loop offered concurrency**, not a
fixed arrival rate. There are no application retries. Rejections reduce completed
KDF work and change the successful mix; shorter elapsed time is not necessarily
higher useful throughput. Initial small-case runs overlapping a short validation
run were discarded and rerun after the matrix without another test workload.

The process TSV retains CPU, wall time, heap, GC and RSS measurements for every
fresh process. The local task evidence packet also retains all individual call
records in `argon2-109-measurements.jsonl`. Percentiles below are nearest-rank
percentiles of individual calls pooled across the two processes, never of batch
means. Small tail counts (particularly after rejection) do not qualify production
P99 or establish confidence intervals.

## Results

All times are milliseconds; memory columns are MiB. Heap/RSS are the maximum
across the two processes, not averages. CPU and wall seconds are summed across
both processes. CPU seconds include user plus system time during the workload.
Success percentiles exclude rejected calls; each row offered 256 calls.

| Mix | Workers | Success / reject | Success P95 / P99 | Peak occupied slots | Sampled logical peak interval | Peak heap / RSS | Wall / CPU seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 19 MiB | 1 | 256 / 0 | 25.5 / 61.7 | 1 | 19–19 | 38.2 / 45.9 | 6.2 / 6.3 |
| 19 MiB | 4 | 256 / 0 | 79.9 / 89.4 | 4 | 76–76 | 152.2 / 160.4 | 2.8 / 9.7 |
| 19 MiB | 8 | 256 / 0 | 69.6 / 82.2 | 4 | 76–76 | 152.2 / 160.6 | 2.0 / 7.6 |
| 128 MiB | 1 | 256 / 0 | 331.9 / 428.5 | 1 | 128–128 | 256.2 / 391.9 | 49.9 / 48.8 |
| 128 MiB | 4 | 256 / 0 | 494.3 / 577.6 | 4 | 512–512 | 1024.2 / 1032.2 | 17.1 / 62.9 |
| 128 MiB | 8 | 99 / 157 | 336.8 / 350.9 | 4 | 512–512 | 1024.2 / 1161.1 | 5.7 / 22.3 |
| 50:50 | 1 | 256 / 0 | 197.6 / 412.9 | 1 | 128–128 | 275.2 / 282.9 | 28.3 / 27.6 |
| 50:50 | 4 | 256 / 0 | 352.0 / 456.7 | 4 | 512–512 | 1100.2 / 1109.2 | 9.3 / 34.3 |
| 50:50 | 8 | 168 / 88 | 350.5 / 493.7 | 4 | 512–512 | 1100.2 / 1199.5 | 6.0 / 22.6 |

Conditional mixed-cost distributions show the different populations hidden by a
single aggregate percentile. At concurrency 1 and 4, each cost had 128 successes.

| Workers | Cost | Outcome | N | P50 | P95 | P99 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 1 | 19 MiB | success | 128 | 23.2 | 37.3 | 60.3 |
| 1 | 128 MiB | success | 128 | 179.4 | 337.4 | 415.0 |
| 4 | 19 MiB | success | 128 | 28.8 | 42.1 | 82.2 |
| 4 | 128 MiB | success | 128 | 229.1 | 401.3 | 459.2 |
| 8 | 19 MiB | success | 81 | 109.0 | 154.6 | 184.8 |
| 8 | 19 MiB | rejected | 47 | 106.2 | 118.1 | 127.6 |
| 8 | 128 MiB | success | 87 | 310.2 | 451.8 | 494.0 |
| 8 | 128 MiB | rejected | 41 | 105.8 | 118.9 | 129.2 |

The 100 ms admission timer is not a wall-clock upper bound on the caller's return:
CPU scheduling and GC can delay observing it. No timeout was raised to obtain
these results. An alternating mix can still accumulate four high-cost operations
because those operations occupy slots longer.

## What each instrument does and does not establish

- A 5 ms sampler reads `len(h.slots)` and the costs of calls in progress. Occupied
  slots include parsing and a small amount of surrounding work, not exclusively
  `argon2.IDKey` execution. For k occupied slots, summing the k smallest/largest
  costs among in-progress calls yields a sampled logical reservation interval.
  It is **not an exact trace of running mixed-cost KDF bytes**; unsampled peaks
  are possible. Each endpoint in the table is the maximum of sampled endpoints.
- `PeakWaitingCalls` in JSON is a **proxy**: in-progress calls minus observed
  occupied slots. It includes entry/exit bookkeeping, so even concurrency one
  can briefly report one. Concurrency eight reached four such calls. There is no
  hook to distinguish exact queue entry, admission and KDF start. Successful
  queue-wait percentiles are therefore **not measured**. Reported latencies cover
  the entire `VerifyOrDummy` call. Rejection latency measures the failed call,
  not an inferred KDF duration.
- HeapAlloc/HeapInuse/HeapSys are sampled Go runtime values; allocation totals
  include harness/sampler overhead. The sampler itself can perturb scheduling.
  EndHeapBytes is before any post-workload forced GC. Unreachable KDF arrays may
  remain until collection, and released memory need not leave RSS immediately.
- `getrusage` CPU deltas exclude fixture creation. Maximum RSS covers the whole
  fresh process, including fixture creation; Darwin bytes and Linux KiB are
  normalized to bytes. RSS also contains runtime, stacks and other resident
  pages. Neither RSS nor heap is the logical admission charge.

## Cancellation check and remaining hook limitation

A separate opt-in check uses four real 128 MiB, five-iteration verifications to
maintain overlap. It observes all four slots occupied, cancels their caller,
then issues a 20 ms caller-budget verification and a default 100 ms admission
attempt. Both reject while started work retains its slots. After the KDFs return,
slots drain and another operation succeeds. These are overlap/correctness checks,
not performance samples for the two-iteration matrix. Caller-budget latency is
measured from before context creation so a scheduling pause cannot be omitted.

The initial race check incorrectly required the caller deadline to win over the
admission timer. One run returned `ErrWorkLimit` after scheduling delay made both
select cases ready. The check now records the outcome and accepts that existing
behavior only if the caller deadline has expired and, for `ErrWorkLimit`, the
full admission duration has elapsed. This corrects a measurement assumption;
production error precedence and deadlines are unchanged. Both results must reject
without starting another KDF. Race timing is not included in the matrix above.

Without a production event hook, the check observes admission, not the exact CPU
instruction at which KDF computation starts. The measurement slice adds no such
hook. If Pro requires exact admitted-cost and successful queue/KDF decomposition,
the next proposal is narrowly scoped instrumentation at admission, KDF start and
KDF return carrying the validated cost. That requires separate approval; no
observer abstraction or production timing hooks are introduced here.

## Options supported by this evidence

Cost-aware admission alongside concurrency is worth evaluating: fixed slots allow
76 or 512 MiB of logical work, and even balanced arrivals can reach the latter.
Lowering concurrency alone also bounds high-cost work, but would constrain small
work unnecessarily; compare both against this baseline before choosing. Neither
approach is an RSS cap. GC retention and the rest of GoAuthy's live workload need
headroom that these isolated credential measurements cannot determine.

No memory budget default is selected. Deployment CPU throttling, whole-service
memory, paced arrivals, other accepted iteration/lane costs, longer tail samples,
and candidate-policy comparisons
remain outstanding. Pro design review precedes production implementation.

Validation: ordinary credential package race tests passed; the real cancellation
check passed three race repetitions (53.513 seconds total); the mixed/eight-worker
measurement harness also passed under race instrumentation, separately from the
performance data. The cancellation checks observed four retained slots, caller
returns of 20.48, 20.72 and 162.23 ms, and admission rejection returns of 104.46,
104.13 and 102.37 ms. `go vet ./internal/credential` passed.

## Reproduction

Run on a development machine with sufficient spare memory, with other test loads
stopped. Do not run the matrix under the race detector for performance numbers.

```sh
go test -c -o /tmp/goauthy-109-measure.test ./internal/credential
mkdir -p /tmp/goauthy-109-measurements
for run in 1 2; do
  for mix in small large mixed; do
    for concurrency in 1 4 8; do
      GOAUTHY_MEASURE_MIX="$mix" GOAUTHY_MEASURE_CONCURRENCY="$concurrency" \
        GOMAXPROCS=4 GOMEMLIMIT=1GiB GOGC=100 \
        /tmp/goauthy-109-measure.test \
        -test.run '^TestPasswordContentionMeasurement$' -test.timeout=90s \
        > "/tmp/goauthy-109-measurements/$mix-$concurrency-$run.log" 2>&1 || exit 1
    done
  done
done
GOAUTHY_MEASURE_CANCEL=1 GOMAXPROCS=4 GOMEMLIMIT=1GiB GOGC=100 \
  go test -race ./internal/credential \
  -run '^TestPasswordRealKDFCancellationMeasurement$' -count=3 -v -timeout=90s
```

Ordinary package tests skip the explicitly opted-in workloads. The existing
single-operation benchmarks and admission-bookkeeping benchmark remain intact.
