# #113 standalone SaaS/IAM isolation measurement

This is a bounded measurement-only tranche, not a production SLO or admission
change. The frozen source/manifest commit is
`1eb345e85b431b3705205b76a7a2149234703e75`, on base
`510b94d547e9112152d4f50272e71899f5734d9d`. See [protocol](protocol.md) and
[manifest](manifest.json). No normal-build source, schema, dependency or service
configuration changed. **#113 remains open.** Exact-three is blocked by the
previously established absence of a permitted shared conditional-write object
store; no infrastructure search/deployment was repeated.

## Scope and source validation

The opt-in Darwin harness is
[`TestSaaSIsolation113Measurement`](../../../cmd/goauthy/saas_isolation_measurement_darwin_test.go),
with a tagged [SaaS fixture](../../../internal/saas/isolation_fixture_integration.go).
Both require `goauthy_integration`; measurement additionally requires its env
opt-in. Production login/RBAC handlers, real password verification, cookie
rotation/CSRF, managed OAuth bearer authorization and both registered SaaS store
owners share one real Rhiza DB. Synthetic provider traffic uses the actual
restricted transport with hostname-verified private TLS roots. Only DNS and raw
TCP routing are injected; unmapped destinations fail locally in both owners.
There is no fixture authorization bypass on measured routes.

Locally verified source boundaries:

- [`http_pool.go`](../../../internal/saas/http_pool.go): four leases per
  provider/revision/origin entry, 32 entries per owner including retirement,
  15s request budget, 30s idle sockets. `roundTrip` performs current binding
  authority inside its validation gate. Lease count is not workflow admission
  or a count of waiters. The fixture observes existing state under its mutex.
- [`refresh.go`](../../../internal/saas/refresh.go): load, durable claim,
  exchange, guarded completion; errors attempt uncertainty marking with a
  detached five-second context. Generator reservations remain held through the
  outer handler return. Cancellation alone does not release them.
- [`api_key_call.go`](../../../internal/saas/api_key_call.go): authority and
  binding checks precede dispatch and successful result release;
  [`api_key_request.go`](../../../internal/saas/api_key_request.go) bounds the
  response at 64 KiB. Refresh and invocation use the actual
  [refresh](../../../internal/rbac/account_connection_oauth2_refresh.go) and
  [invoke](../../../internal/rbac/connection_invoke_http.go) handlers.
- Pinned Rhiza v0.12.3 `pkg/node/node.go` rejects filesystem-backed multi-member
  startup and requires shared storage. Three independent standalone databases
  would not meet exact-three acceptance.

The composition deliberately omits unrelated runtime startup workers and some
outer middleware; it is not an actual `run()` process test. The signing-key
loader uses a generated fixed test signing key. Setup seeds credentials using
an actual subject-existence guard outside timing; measured authorization uses
production checks. Four fixed test peers enter through the runtime peer-IP
middleware. No test-peer header is trusted by normal binaries.

## Frozen workload and measurement meaning

Apple M1 / 16 GiB / Darwin arm64, Go 1.27.0, GOMAXPROCS=4. One excluded pilot,
then three sequential fresh non-race/non-coverage executable processes. Each
process has 16s all-healthy baseline, 16s identical scheduled mixed traffic,
and 50s natural recovery (12s healthy probes, 38s drain). One IAM flow/s and one
call/s on each of six provider routes. Recovery uses IAM and the two healthy
routes only. Each process offers 260 workflows: 44 IAM and 216 SaaS.

The generator caps are 12 OAuth fault +12 API fault +4 OAuth healthy +4 API
healthy, plus four IAM. These caps are experiment controls, not production
budgets. There is no pending queue, catch-up burst or retry. Distinct inventory
contains 222 bindings including controls; recovery bindings are untouched.
Expected old refresh version is always 1. Uncertain credentials are never
reset. Faults cover identity headers after token acceptance, partial API body,
real TCP refusal and cancellation after token POST acceptance.

Latency is individual client-flow elapsed time. IAM includes real GET/form
processing/POST and records constituent GET/POST times; it excludes the later
measurement-only session proof query. The reservation still covers that query
and actual handler completion. SaaS timers include the actual handler's final
authority/status work before its response. Handler entry/exit is recorded
separately. `HandlerNS` in an attempt is an absolute workflow completion offset,
not a duration; raw `handlers` contain actual entry/exit offsets. Dispatch delay
is actual launch minus scheduled time for launched work. Dropped/missed entries
would remain in outcome denominators, not latency distributions.

JSON evidence encoding and final durable inspection are outside phase timers.
Counter locks, timer reads, parsing and 100ms resource sampling remain in the
measured process. Server, generator and TLS provider are colocated: CPU/heap/RSS
are totals, not isolated GoAuthy cost. RSS is Darwin process historical
high-water; heap/goroutine/socket peaks are sampled, not guaranteed maxima.
`TCP` counts successful raw dials; `TLS` counts server ClientHello callbacks,
not verified completed handshakes; `DNS` counts injected resolver calls, not
packets. Cumulative counters include setup controls. Pool snapshots are per
owner aggregates over the fixed three origins, not per-entry waiter or idle
counts. No GC forcing or pool close precedes recovery observations.

Success-only percentiles must be read with all-outcome counts. Nearest-rank
P95/P99 at n=16 baseline/mixed and n=12 recovery are both the maximum. These
are extreme samples, not stable tail estimates. The experimental thresholds
are applied offline by [summarize.jq](summarize.jq); a passing Go test means its
correctness/resource oracles passed, not that every latency threshold passed.

## Primary results and decision

All three primary processes passed the harness correctness/resource checks.
**Performance acceptance is inconclusive:** run 2 mixed healthy API exceeded
both frozen thresholds; runs 1 and 3 did not. No run was dropped or repeated.
No admission candidate is proposed from this evidence. The isolated breach
cannot distinguish server interference from colocated provider/generator or
other host scheduling activity.

Protected-route P95 = P99 = maximum, in milliseconds (baseline/mixed n=16,
recovery n=12 for each route in each process):

| Run | Route | Baseline | Mixed | Recovery | Mixed threshold result |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | IAM login | 222.22 | 218.52 | 192.65 | pass |
| 1 | OAuth healthy | 120.69 | 97.75 | 67.61 | pass |
| 1 | API healthy | 56.66 | 67.38 | 58.53 | pass |
| 2 | IAM login | 635.40 | 329.24 | 174.60 | pass |
| 2 | OAuth healthy | 212.61 | 183.87 | 72.17 | pass |
| 2 | API healthy | 107.11 | 164.61 | 32.69 | **P95/P99 breach** |
| 3 | IAM login | 265.22 | 218.51 | 179.33 | pass |
| 3 | OAuth healthy | 157.95 | 108.62 | 55.19 | pass |
| 3 | API healthy | 52.69 | 71.73 | 40.94 | pass |

All recovery comparisons passed. Run 2's failed API sample was
`mixed-api-healthy-010`: 164.605708ms, versus P95 limit 133.8825525ms and P99
limit 160.659063ms; scheduling delay was 1.980208ms. This does not identify its
internal delay source. Baseline IAM varied substantially too. Full unrounded
per-process distributions, P50s, scheduling delays and comparison limits are
in [results.json](results.json); individual samples are in the raw archive.

Each primary process retained the following complete outcome denominator:

| Phase / route class | Offered | Outcomes |
| --- | ---: | --- |
| Baseline, all seven routes | 112 | 112 success |
| Mixed, IAM + two healthy routes | 48 | 48 success |
| Mixed, OAuth identity headers | 16 | 16 client-error |
| Mixed, OAuth accepted-POST cancel | 16 | 16 client-error |
| Mixed, API body stall | 16 | 16 client-error |
| Mixed, API TCP refusal | 16 | 16 HTTP 502 |
| Recovery, IAM + two healthy routes | 36 | 36 success |

No generator drop, missed arrival or protected policy rejection occurred.
The raw error classification is intentionally coarse: `client-error` does not
encode the exact Go error. Fault routes distinguish the configured cancellation
from deadline-driven stalls; this is not an independently measured error-type
breakdown or an overload rate. All 16 accepted-POST cancellations per run
recorded client completion with the handler still active. Header/body stalls
also recorded that overlap. Actual handler exit and permit release follow.

Each run had 108 accepted primary token POSTs on 108 distinct old-version-1
bindings, maximum one each; controls add two accepted mutations. Final mixed
OAuth durable outcomes were 16 `ready` version 2 and 32 `uncertain` version 1.
No `refreshing` row remained in these runs, but the oracle allows that safe
non-replayable outcome rather than resetting it. All 222 inventory rows were
retained in durable evidence: 112 ready/v1, 78 ready/v2, 32 uncertain/v1,
including controls. Mixed TCP-refusal origin received zero provider requests.
No capacity rejection before useful provider dispatch was observed at this
load; this does not prove such post-claim damage impossible.

| Run | Sampled RSS high-water bytes | Sampled heap peak bytes | Sampled goroutine peak | Campaign CPU user/system ms |
| --- | ---: | ---: | ---: | ---: |
| 1 | 176734208 | 83240144 | 233 | 5952.946 / 1270.978 |
| 2 | 159072256 | 64619640 | 192 | 4768.422 / 1081.592 |
| 3 | 151339008 | 83088480 | 184 | 5814.584 / 1289.070 |

The frozen abort ceilings were 314474496 RSS bytes, 124526000 heap bytes and
390 goroutines. There were 793/794/793 resource samples. Exact generator
high-water counts were 5 OAuth fault, 5 API fault, 1 OAuth healthy, 1 API
healthy, 1 IAM in every run; this did not approach the experiment's caps.
Sampled active HTTP handler peaks were 11/12/11. Raw TotalAlloc observations
are cumulative and permit phase deltas, not live memory estimates.

After natural recovery every owner had zero leases, dials, tracked connections
and retiring entries, with three reusable entries retained. Final sampled
workflow/handler counts were zero. No forced GC or pool closure produced this
result. Historical RSS cannot demonstrate return to an instantaneous memory
baseline. `/usr/bin/time -l` records whole-process peaks/costs separately from
the timed campaign. Pilot plus all primary process wall times total **377.97s**
(95.28 +94.17 +95.09 +93.43), below the 600s limit. Correctness-only checks and
compilation are separately logged, not additional load samples.

## Correctness checks and retained limitations

The final tagged `check` mode runs invalid CSRF/password/bearer controls,
positive authenticated login/refresh/invoke, grant revocation preventing
provider dispatch, old-version replay rejection and same-binding concurrent
single-winner mutation. `TestIsolation113ReservationSurvivesClientCancellation`
uses channel barriers to hold an actual handler after cancellation; a replacement
reservation must fail until handler return. It does not delay production cleanup
with a new hook. Primary cancellation observations exercise real detached cleanup.

The accompanying focused existing SaaS suite covers:

- `TestCallAPIKeyEncryptedStoreToTLSProvider`: projected result, policy mismatch,
  revoke/rotation/current-authority changes before result release. These store
  tests use their existing controlled TLS client and authority callback; they
  are separate from the campaign's real RBAC/restricted-transport composition.
- `TestRefreshCredential*`: commit before publication, uncertainty no-retry,
  revoke/current authority/expiry and identity mismatch.
- `TestCredentialCollectionProviderRemovalCannotResurrect`: collection removal.
- `TestSaaSPoolRegistered*`, `TestSaaSPoolRefreshFailureRemainsUncertain`,
  `TestSaaSPoolProviderOriginAndOwnerIsolation`: registered provenance,
  invalidation, uncertainty and owner separation.

The campaign itself checks successful SaaS HTTP status and durable credential
outcomes; it does not separately parse/assert each successful SaaS response
projection. Existing focused tests cover projection. Concurrent revocation is
covered by those focused tests, not repeated during the timed workload. Pool
snapshots aggregate the fixed origins by owner; no queue length, validation-gate
waiters, per-entry latency or instantaneous idle count was measured.

This tranche does not qualify mass-refresh capacity, 32-entry saturation,
five-minute reuse age, nonregistered adapters, full runtime worker contention,
production IAM tails, cluster-wide budgets or exact-three. The existing transport
limits do not supply a global workflow/queue budget or a unified overload policy.
No production SLO/default is chosen. Review should treat this as partial
standalone evidence with one retained performance breach, not closure of #113.

## Reproduction and evidence

Build once, outside measurements:

```sh
GOMAXPROCS=4 go test -tags goauthy_integration -c -o /tmp/goauthy113.test ./cmd/goauthy
```

Each primary uses a fresh process and fresh temporary storage; N is 1, 2 or 3:

```sh
/usr/bin/time -l env GOMAXPROCS=4 GOAUTHY_ISOLATION113=primary \
  GOAUTHY_ISOLATION113_MANIFEST="$PWD/docs/measurements/saas-isolation-113/manifest.json" \
  GOAUTHY_ISOLATION113_OUTPUT="/tmp/runN.json" \
  /tmp/goauthy113.test -test.run '^TestSaaSIsolation113Measurement$' -test.v -test.timeout=125s
jq -f docs/measurements/saas-isolation-113/summarize.jq /tmp/runN.json
```

[raw-evidence.tar.gz](raw-evidence.tar.gz) contains all four raw run JSON files,
logs/time records, source/binary hashes, provenance and focused check logs.
The archive has an internal `SHA256SUMS`; adjacent [SHA256SUMS](SHA256SUMS)
checks the archive, manifest, protocol, report, summary program and results.
No binaries, credential bodies, keys, cookies or database dumps are published.
The initial failed correctness preflight (explicit API endpoint ports rejected)
is retained; it was corrected before the single pilot. The pilot is excluded
and its source differences are documented in the protocol/provenance.

Final verification commands (all passed, run after primary sampling):

```sh
GOMAXPROCS=4 GOAUTHY_ISOLATION113=check go test -race -tags goauthy_integration ./cmd/goauthy -run '^(TestSaaSIsolation113Measurement|TestIsolation113ReservationSurvivesClientCancellation)$' -count=1 -timeout=120s
GOMAXPROCS=4 go test -race ./internal/saas -run '^(TestCallAPIKeyEncryptedStoreToTLSProvider|TestRefreshCredential.*|TestCredentialCollectionProviderRemovalCannotResurrect|TestSaaSPoolRegistered.*|TestSaaSPoolRefreshFailureRemainsUncertain|TestSaaSPoolProviderOriginAndOwnerIsolation)$' -count=1 -timeout=180s
GOMAXPROCS=4 go vet -tags goauthy_integration ./cmd/goauthy ./internal/saas
git diff --check
```

Tagged check race: 35.833s; focused SaaS race: 20.784s. Earlier accounting-only
race repetition (`-count=3`) also passed. `go list` confirmed the new harness
and fixture are ignored without the tag. Post-primary hashes match the frozen
binary, both Go source files and manifest exactly. No code changed during the
primary campaign. [pool-peaks.json](pool-peaks.json) supplements the raw samples
with observed owner resource peaks and TotalAlloc deltas between first and last
sample; those deltas exclude the unsampled edges, not a precise phase-wide
allocation counter bracket.

Across all three runs, sampled owner connection peaks were four each, API lease
peak four and OAuth lease peak three. Sampled in-progress dials were zero even
though cumulative successful TCP counters increased: the 100ms sampler missed
short dials, so zero is not evidence of no dialing. Between-sample TotalAlloc
deltas were 1,013,832,752 / 1,013,216,944 / 1,013,184,080 bytes; these are cumulative
allocation churn across colocated components, not resident/live memory.

Sanitized raw evidence occupies 1,852 KiB on disk before compression; the archive
is 143,136 bytes. The entire report directory is below 256 MiB. No primary run
failed a correctness/resource oracle; the excluded initial fixture check and
run 2's performance breach remain visible rather than being replaced.
