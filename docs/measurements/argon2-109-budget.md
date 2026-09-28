# Opt-in Argon2 memory admission: #109

The memory gate defaults to **off**. These measurements demonstrate logical
reservation bounds and contention tradeoffs. They do not select a production
budget or qualify a 512 MiB / 500m deployment. Independent and Pro implementation
review remain required; issue #109 is not claimed complete.

## Contract and source

Policy.MemoryBudgetKiB is immutable per constructed Hasher. Zero disables the
weighted gate; positive values must be at least the shared maximum accepted PHC
cost, 131072 KiB. GOAUTHY_ARGON2_MEMORY_BUDGET_KIB uses canonical unsigned decimal
uint32 syntax. Invalid syntax, overflow or a positive value below the floor fails
startup and config check before opening storage. No dependency version changed.

The runtime constructs one active Hasher injected into the identity store.
Package compatibility helpers have a separate default Hasher. Independently
constructed Hashers have independent limits, not a process or cluster budget.
Defaults remain 19 MiB, two iterations, one lane, four slots, 100 ms admission.

Valid PHCs are parsed once before admission and charged their stored memory cost.
Missing/malformed credentials and invalid passwords in VerifyOrDummy use the
configured dummy cost and hide parse errors. Package Verify preserves parse
errors. Real and dummy cost classes need not have identical latency or admission
outcomes. Parser limits, cryptographic costs and upgrade rules are unchanged.

Admission takes a slot before weighted memory using one admission context.
Zero wait is nonblocking; negative wait uses the caller context. Local expiry
returns ErrWorkLimit, with observed parent cancellation taking precedence.
Failure rolls back acquired capacity. The final cancellation check immediately
precedes synchronous IDKey, after Hash salt generation. Cancellation cannot
interrupt IDKey or release leases early. Verification and subsequent best-effort
upgrade acquire separate leases.

See [password.go](../../internal/credential/password.go),
[admission](../../internal/credential/password_admission.go) and
[runtime](../../cmd/goauthy/main.go). The private observer is installed before use.
When nil it performs no timestamps, ID increments or event construction; nil
checks remain. Events contain synthetic IDs, public costs, stages, timestamps
and fixed outcomes, never credential material.

## Conditions and protocol

Measured 2026-09-28 on Apple M1, 8 logical CPUs, 16 GiB, macOS arm64,
Go **go1.27.0**. Each process used GOMAXPROCS=4, GOGC=100, GOMEMLIMIT=1GiB
(a soft Go target, not a hard RSS limit). No deployment or paid environment
was used and no intentional OOM experiment was performed.

48 fresh processes: two repetitions of six policies, each with all-small,
all-large and alternating 50:50 closed-loop traffic plus paced 50:50 traffic.
Each process offered 256 operations through at most eight callers with the real
100 ms admission deadline. Both PHCs use t=2,p=1; memory is 19456 or 131072 KiB.
The optional 512 MiB control was not run. Each child had a 90 second timeout.
Fixtures were generated before measurement, followed by FreeOSMemory.

**The host was contended, not isolated.** Chrome was active from the beginning;
other agents' Go tests/builds ran during the matrix. Observed load rose from
about 2.69 to 7.18 and memory compression was active. The generator parent was
paused after 32 log files existed, allowing its current child to finish;
correctness checks ran during that pause. External workloads returned after
resumption. No measurement child or other agent's process was paused or killed.
All samples are retained. Timing/resource comparisons cannot establish a causal
policy ranking.

Paced traffic targets 20 offered operations/second. If all eight callers are busy,
the generator records a drop instead of queueing. Late generation catches up to
its schedule and can burst; worst generator lag was 257.5 ms. This bounded probe
is not a faithful steady open-loop simulation. Closed-loop traffic also has
coordinated omission.

## Results

All 48 processes passed reservation and cleanup assertions. Of 12288 offers,
5670 succeeded, 6608 were admission rejections, and 10 were generator drops.
No other operation errors were reported. This matrix does not inject caller
cancellation; separate correctness tests cover cancellation.

Each row combines two processes (512 offers). The last three columns are maximum
per-process peaks in MiB, not sums. Off disables only memory admission.

| Slots / budget | Traffic | Success | Reject | Drop | Reserved | Heap | RSS |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 / off | large closed | 35 | 477 | 0 | 128 | 256 | 392 |
| 1 / off | mixed closed | 57 | 455 | 0 | 128 | 370 | 412 |
| 1 / off | mixed 20/s | 183 | 328 | 1 | 128 | 294 | 411 |
| 1 / off | small closed | 272 | 240 | 0 | 19 | 38 | 65 |
| 2 / off | large closed | 77 | 435 | 0 | 256 | 512 | 521 |
| 2 / off | mixed closed | 115 | 397 | 0 | 256 | 569 | 686 |
| 2 / off | mixed 20/s | 277 | 234 | 1 | 256 | 588 | 687 |
| 2 / off | small closed | 290 | 222 | 0 | 38 | 76 | 84 |
| 4 / off | large closed | 184 | 328 | 0 | 512 | 1152 | 1161 |
| 4 / off | mixed closed | 297 | 215 | 0 | 512 | 1100 | 1308 |
| 4 / off | mixed 20/s | 486 | 24 | 2 | 512 | 1100 | 1217 |
| 4 / off | small closed | 512 | 0 | 0 | 76 | 152 | 179 |
| 4 / 128 | large closed | 36 | 476 | 0 | 128 | 256 | 392 |
| 4 / 128 | mixed closed | 51 | 461 | 0 | 128 | 294 | 411 |
| 4 / 128 | mixed 20/s | 163 | 348 | 1 | 128 | 275 | 410 |
| 4 / 128 | small closed | 511 | 1 | 0 | 76 | 152 | 180 |
| 4 / 192 | large closed | 38 | 474 | 0 | 128 | 256 | 392 |
| 4 / 192 | mixed closed | 260 | 252 | 0 | 185 | 427 | 544 |
| 4 / 192 | mixed 20/s | 324 | 185 | 3 | 185 | 446 | 492 |
| 4 / 192 | small closed | 504 | 8 | 0 | 76 | 190 | 198 |
| 4 / 256 | large closed | 68 | 444 | 0 | 256 | 512 | 521 |
| 4 / 256 | mixed closed | 131 | 381 | 0 | 256 | 588 | 705 |
| 4 / 256 | mixed 20/s | 291 | 219 | 2 | 256 | 550 | 687 |
| 4 / 256 | small closed | 508 | 4 | 0 | 76 | 152 | 179 |

[Per-process results](argon2-109-budget-processes.tsv) retain both repetitions
with per-cost successful sample counts, operation P95/P99, successful queue P95,
service P95/P99, CPU seconds, wall time, heap/RSS, reservation/computing and queue
peaks. Process fields repeat on the two cost rows; do not sum duplicates.
Percentiles use nearest rank over individual calls, never batch means. With few
successful large calls, P99 is often the maximum: descriptive samples, not reliable
production tails. Raw traces retain rejected latencies/failure stages, per-call
queue/service durations, GC and allocation fields.

Reservations count admitted PHC KiB until release. Computing intervals surround
synchronous IDKey. Observer events mark Go call boundaries, not atomic allocator
or semaphore state: release is observed just before capacity becomes reusable;
start just before the final cancellation check. A canceled start followed by a
failed finish is not an executed KDF. All matrix starts completed actual KDF work.
Slot holders include memory waiters. Memory-wait is also emitted with the gate
off; then it measures fast-path/instrumentation overhead, not weighted blocking.
The short mutex observer itself perturbs timing.

Heap sampling every 5 ms can miss brief peaks. CPU is process user+system time
delta, not quota or utilization. RSS is the process high-water mark including
fixture generation; it is not a workload delta. Heap retention and GC mean active
logical memory cannot bound heap/RSS. Peak RSS was 1307.97 MiB despite the 1 GiB
soft target.

## Supported options and remaining limits

- Four slots / 128 MiB permits four small jobs but only one large job. It differs
  from one slot / off for small work. A large weighted waiter can block smaller
  work behind it while holding a slot; mixed traffic has no latency or maximum
  utilization guarantee.
- Four slots / 192 MiB permits one large plus three small jobs (185 MiB), an
  observed logical peak. It cannot admit two large jobs.
- Four slots / 256 MiB permits two large or four small jobs. Two slots / off also
  permits two large jobs, but restricts small concurrency to two.
- Four slots / off reached 512 MiB logical reservation. A weighted cap reduces
  that bound; neither the mechanism nor measurements establish RSS safety.

No performance winner or default is selected. Deployment qualification still
needs isolated 512 MiB / 500m runs with realistic application baseline,
GC/headroom, accepted higher iteration/lane PHCs, arrival distributions,
successful/rejected tails, cancellation and overload recovery. This laptop
matrix has too few successful tail samples and too much uncontrolled load.

## Verification and reproduction

Passed: credential race tests (three repetitions); focused runtime/config race
tests; identity legacy/upgrade/rehash/history race regressions; both password CLI
packages; go vet for credential/runtime; observer-enabled mixed 192 MiB race
probe. Race timings are excluded from the matrix. Tests cover rollback, one
deadline, parent priority, cost classification, malformed/dummy behavior,
independent owners and separate leases. A real 128 MiB KDF test cancels while
held after IDKey returns but before lease release, proving capacity retention
until the synchronous operation returns. Source has no cancellation release
goroutine. Full repository CI was not run here.

Compile with: go test -c ./internal/credential -o /tmp/goauthy-109-budget-measure.test

For each slots/budget pair (4/0, 1/0, 2/0, 4/128, 4/192, 4/256), run two
repetitions of small, large, mixed at RATE=0, and mixed at RATE=20, each as a fresh
binary process. Set GOAUTHY_MEASURE_MIX, GOAUTHY_MEASURE_SLOTS,
GOAUTHY_MEASURE_BUDGET_MIB, GOAUTHY_MEASURE_RATE, GOAUTHY_MEASURE_CONCURRENCY=8,
GOAUTHY_MEASURE_CALLS=256, GOMAXPROCS=4, GOMEMLIMIT=1GiB, GOGC=100.
Binary arguments: -test.run '^TestPasswordContentionMeasurement$' -test.timeout=90s.
Harness source is in internal/credential/password_measurement_test.go and
password_measurement_observer_test.go.

Raw local evidence:
/Users/cypark/.codex/task-state/goauthy-issue-loop/argon2-109-budget-measurements.jsonl

SHA256: 3c742d19fddb12be32d9a5267f5e5e6b2e0003604f43eefa1f936c147f313676

Original child logs: /tmp/goauthy-109-budget-matrix.
The [earlier measurement-only baseline](argon2-109.md) remains historical;
its instrumentation and conditions differ.
