# Goauthy 성능 구현 현황과 측정 결과

## 범위

This document separates implemented runtime behavior from standalone
experiments and reports measurements with their limits. It does not define
capacity targets or a production SLO.

## 구현 상태

### Standalone in-memory cache package

`internal/cache` contains a sharded TTL/LRU cache implementation, tests, and
microbenchmarks. Production Go packages do not import it. It is not wired into
authentication, browser sessions, identities, profiles, RBAC, or API-key
lookups. No production hot path currently receives cache hits from this
package.

The TTL and capacity values previously listed for session, user, profile,
principal, and API-key caches were not implemented and have been removed.

### Argon2 admission policy

The default maximum concurrency is 4. Admission can wait up to 250 ms for the
combined slot and optional memory budget, and respects context cancellation.
Requests that cannot acquire capacity return the work-limit error.

## 이전 마이크로벤치마크의 범위

The former cache and Argon2 microbenchmark figures were not OAuth endpoint
measurements and did not support estimated database timings, cache-hit latency
reductions, or traffic thresholds. The runtime HTTP campaign below reports
measured request distributions and failures for one local synthetic setup; it
is not a capacity target or deployment SLO.

## DB/cache metric instrumentation status

The Prometheus registry declares DB-query duration and cache hit/miss/eviction
collectors, and `internal/metrics` has methods to update them. Repository search
found no production call sites for those methods. These series therefore do
not provide live DB/cache measurements, and no PromQL dashboard or alert is
listed here as operational guidance.

## 설정

### 환경 변수

```bash
# Argon2 동시성 (기본: 4)
GOAUTHY_ARGON2_MAX_CONCURRENCY=4

# Optional memory admission gate in KiB; off by default.
GOAUTHY_ARGON2_MEMORY_BUDGET_KIB=0
```

The total slot-plus-memory admission timeout is 250 ms in the runtime policy;
there is no wait-time environment variable. Positive memory budgets must be at
least 131072 KiB. This bounds nominal reservations, not process RSS. See the
[measurement report](measurements/argon2-109-budget.md) before opting in.

## 실제 HTTP 런타임 측정

`internal/oauth/review_http_measurement_test.go` is an opt-in, bounded
measurement using a real loopback TCP `httptest.Server` and `http.Client` with
the production token and UserInfo handlers. Each volume uses a private migrated
database seeded with 0 or 1,000 unrelated synthetic users. It records 200
samples per case at concurrency 1 and 8 for authorization-code token exchange,
UserInfo validation, and rotating refresh grant. A separate direct Argon2 verify
case reports KDF latency, throughput, and work-limit errors at each concurrency.
It does not measure browser login/session-cookie validation, remote network
latency, multi-node replication, expired-token cleanup backlog, or live-user data.

Authorization codes and synthetic fixtures are prepared outside each timed
sample; authorization itself is not the measured HTTP stage. The resolver uses
the current linearizable identity-profile query and production-equivalent OIDC
field projection. Per-cell counters assert two profile resolver calls for each
baseline authorization-code/refresh request and one for each fixed request;
UserInfo asserts one. Invalid UserInfo and authorization-code controls are
recorded outside latency samples. Non-200 responses remain in the sample count
and are reported as errors. The 1,000-row volume is unrelated identity users
only. These are local loopback measurements on the stated host. `GOMAXPROCS=2`
configures Go scheduling, not a CPU quota; cores and memory are not isolated and
the run has no OS resource limit. Other local activity can affect results.

Run the exact same harness source against the archived v0.3.8 tree and the fixed
tree, as three serial baseline/fixed pairs with fresh output directories. The
test emits nearest-rank P50/P95/P99, throughput, HTTP status/error counts, and request/authorization/
response byte totals to `results.json`; `manifest.json` records runtime and
fixture provenance. It also logs a `SNAPSHOT112 http_runtime` JSON line. Report
median and minimum–maximum range across the three paired runs; with 200 samples per cell, tail percentiles
are noisy and do not support significance claims. The 10-minute test context and
11-minute Go timeout are harness bounds, not SLOs.

```sh
set -e
WORKTREE=/Users/cypark/.codex/worktrees/login-browser-fixes/goauthy
BASELINE=/Users/cypark/.codex/task-state/goauthy-v038-review-fixes-20261024/baseline-source
RESULTS=/Users/cypark/.codex/task-state/goauthy-v038-review-fixes-20261024/http-runtime
mkdir -p "$RESULTS"
cp "$WORKTREE/internal/oauth/review_http_measurement_test.go" "$BASELINE/internal/oauth/"
for REP in 1 2 3; do
  (
    cd "$BASELINE"
    GOMAXPROCS=2 GOAUTHY_HTTP_MEASURE=1 GOAUTHY_HTTP_LABEL="baseline-$REP" \
      GOAUTHY_HTTP_HARDWARE='Macmini9,1 M1 8CPU 16GiB' GOAUTHY_HTTP_OUTPUT="$RESULTS/baseline-$REP" \
      go test -mod=readonly -tags=integration -count=1 -run '^TestReviewHTTPRuntimeMeasurement$' -timeout=11m -v ./internal/oauth
  )
  (
    cd "$WORKTREE"
    GOMAXPROCS=2 GOAUTHY_HTTP_MEASURE=1 GOAUTHY_HTTP_LABEL="fixed-$REP" \
      GOAUTHY_HTTP_HARDWARE='Macmini9,1 M1 8CPU 16GiB' GOAUTHY_HTTP_OUTPUT="$RESULTS/fixed-$REP" \
      go test -mod=readonly -tags=integration -count=1 -run '^TestReviewHTTPRuntimeMeasurement$' -timeout=11m -v ./internal/oauth
  )
done
```

The comparison is only meaningful when both runs complete with matching sample
counts, status/error profiles, Go version, architecture, GOMAXPROCS, matrix, and
fixture source. Keep the raw JSON with any summary; do not turn a single-host
result into a performance guarantee.

## Measured baselines (issue #65)

Historical recorded run: 8 CPU, macOS, go1.27.0 darwin/arm64; representative run of
`go test -bench . -benchtime 3x -run '^$' ./internal/ipblacklist/ ./internal/oauth/`.
Measurements only; no behavior changed.

| item | benchmark | 1000 rows | 10000 rows |
|------|-----------|-----------|------------|
| GA-PERF-002 Check hit /32 | `BenchmarkCheckAtCeiling` `hit32` | 0.86 ms | 9.1 ms |
| GA-PERF-002 Check miss | `BenchmarkCheckAtCeiling` `miss` | 0.84 ms | 8.8 ms |
| GA-PERF-002 Check longest prefix | `BenchmarkCheckAtCeiling` `longestPrefix` | 1.14 ms | 9.1 ms |
| GA-PERF-001 issuance + cleanup | `BenchmarkCreateAccessTokenSessionWithCleanup` | 9.8 ms | 16.6 ms |

GA-PERF-002 (`internal/ipblacklist/bench_test.go`): one linearizable SELECT of
every row, then longest-prefix matching in Go; cost is linear in table size,
bounded by `DefaultMaxEntries = 10000` which `Add` enforces with a `COUNT(*)`
precondition. `TestAddCeilingDeterministic` (`internal/ipblacklist/store_test.go`)
already proves that ceiling deterministically, so it is not duplicated.

GA-PERF-001 (`internal/oauth/bench_test.go`): the storage-layer cycle
`Store.CreateAccessTokenSession` on a migrated database, where both cleanup
DELETEs batch with the token INSERT in one replicated Execute (the full fosite
HTTP token-endpoint path is not driven). Cleanup runs on every issuance, and the
orphan-row DELETE anti-joins `oauth_token_requests` against
`oauth_access_tokens`, so its cost tracks the live token count.

The completed v0.3.8 comparison, including sanitized raw results, host-load
caveats, aggregation, and hashes, is recorded in
[`docs/measurements/v038-review-http/`](measurements/v038-review-http/README.md).
The load-average snapshot was taken immediately after the six-run campaign, not per run. Latency
and throughput are descriptive only and cannot establish a causal change.
