# #65 expiry backlog: bounded measurement protocol and evidence

Base: `5769e91f366fc4e047b4f666efa18711b5580fa0`. Measurement-only;
no production, schema, dependency, cleanup-policy or limit changes. This is
partial #65 evidence, not a cleanup-worker proposal or issue-closure claim.

**Acceptance is incomplete.** The one primary campaign executed all 45 cases,
but the post-run audit found a vacuous interaction-sentinel hash comparison and
an unaligned SQLite background checkpoint loop. The original samples and their
source are retained unchanged. The oracle is fixed in the current test source;
there was **no replacement campaign**. See the result qualifications below.

## Frozen protocol

`internal/oauth/expiry_backlog_measurement_darwin_test.go` contains an opt-in
`integration`-tagged Darwin harness. Five operations × empty/live/expired ×
three fresh-process, independently migrated database repetitions = **45 cases,
90 timed operations maximum**. Each nonempty case has 1,000 bundles. A separate
two-bundle correctness test is not part of the primary samples.

| Operation | Timed production boundary | Seeded bundle (rows per 1,000 bundles) |
| --- | --- | --- |
| session | `browser.Store.CreateUpstreamSession`, including confirmation | 1,000 sessions + 1,000 upstream bindings |
| interaction | `browser.Store.CreateAuthorizationInteraction` | 1,000 interactions, bound to the same live initialization parent |
| code | `Server.WriteAuthorization`, configured explicit-code/PKCE callbacks and Commit | 1,000 code + 1,000 PKCE rows |
| redemption | configured `TokenHandler` with authorization_code + S256 + offline_access | 1,000 access + 1,000 linked request snapshots + 1,000 linked refresh rows |
| client_credentials | configured `TokenHandler`, guarded bootstrap machine policy | 1,000 access + 1,000 linked request snapshots |

OAuth timings use in-process HTTP handlers and recorders, not network endpoint
latency. Browser timings use public Store operations, not full login/UI paths.
The CC variant is **unmapped machine**, `ClientCredentialsMapSub=false`, with
persisted custom-claims policy revision 1. End-user validation uses the identity
Store; the synthetic no-membership principal resolver reads current active-user
and principal-revision state linearly from the same DB. It is not a measurement
of the complete RBAC membership resolver or a permissive success callback.

All cases first create identical live sentinel artifacts, current authority,
and BOTH valid operation inputs. Redemption inputs are two distinct already
issued codes. Only then is the backlog seeded. Empty means zero backlog, not
zero database rows. Session binding and access/request/refresh keys are linked.
Code and PKCE projections come independently from actual production issuance,
and their retained forms must differ. Synthetic seed projections adjust request
IDs, creation/request times and expiry together; they are not issued credentials.
The initialization parent's creation time is aged during setup so it predates
expired children, while its last-seen time and absolute expiry remain live.
Setup uses <=64-KiB encoded ExecuteRequests, ten bundles per batch; it is not
measured issuance or atomic across all batches.

Live and expired timestamps are one hour into the future/past. The frozen
60-second case budget cannot reach those margins. This is not an OAuth exact
cutoff-equality experiment; browser equality semantics retain existing tests.
Both successful outputs and their access/refresh linkage, PKCE bindings and
consumption markers are independently checked. Live seed rows and sentinels
must retain exact full-row hashes. Eligible seed keys must all disappear;
per-table totals also account for each new artifact and consumed PKCE removal.

Sequence: setup/seed/verify → first operation → read-only validation → distinct
follow-up → read-only validation → consumption/replay controls → pre-close
observations → close → post-close observations. The follow-up is explicitly
**post-validation**, not an independent repetition or cold-cache counterfactual.
The validation queries can warm pages and incur read barriers. They are outside
timers and outside each immediately bracketed object-counter window.

## Resource and checkpoint policy

The parent starts accounting before evidence-directory creation. Its 600-second
aggregate cap includes child setup, validation, controls, close, fixture removal
and raw evidence/hash handling. Child execution stops at 595 seconds aggregate,
reserving five seconds for final evidence handling; each child also has a
60-second process limit and a 55-second operation context. Compilation and
separately reported correctness/race/vet checks are outside primary accounting.

Active fixtures plus retained/temporary evidence have a 256-MiB file-length
budget. A serial parent samples them every 50 ms and stops at 240 MiB, preserving
16 MiB headroom; it also checks after each child and removes only successful
disposable case databases. This is sampled enforcement, not an OS disk quota.
A cap or oracle failure stops the campaign and retains the failure; no replacement
samples or silent matrix reduction. Compiler caches/executable are tooling,
not fixture/evidence bytes. No backup/archive materialization is performed.

Every case opens an empty data/object directory, migrates afresh, and uses one
local node, filesystem object storage and `before_ack` durability. Checkpoint
interval is explicitly one hour, tail threshold 512 MiB, object GC interval zero
(disabled). With case duration <=60 seconds and disk <256 MiB, neither checkpoint
trigger can be reached before close; there is no inherited checkpoint history.
Initial file inventories record that starting state. Close may checkpoint and
is reported separately. Defaults for archive sync/batch delay are unchanged.

This policy excludes **Rhiza archive checkpoints only**. Post-run source audit
found `pkg/materializer/materializer.go:922` also starts an unconditional
one-second `PRAGMA wal_checkpoint(PASSIVE)` loop. Foreground autocheckpointing
is disabled (`writerDSN`, line 181), but the background loop is not exposed by
public Config. Its phase/history was not aligned across this campaign's
different seed histories. Thus a requirement to exclude *all* periodic
checkpoint overlap is **not satisfied**. Process CPU, wall and WAL-length
observations include this uncontrolled component; no isolated cleanup or
checkpoint cost is claimed. No production hook or policy change was added.

The Pro design's references to a `policy.UserID` CC preparatory path and an
every-20-operations snapshot checkpoint policy do not match this pinned source.
The actual CC split is in `grant_storage.go:1272`; `rhiza.Config` exposes
time/tail checkpoint controls, and the existing snapshot harness sets one hour.
Rhiza v0.12.3 `pkg/checkpoint/auto.go` checks elapsed time/tail at its ticker;
`pkg/node/node.go` starts object GC only with a positive interval.

## Measurement definitions

- Each timer contains only the complete production call. No diagnostic JSON,
  counters, queries, output, explicit GC, profiler or race instrumentation is
  inside a primary timer. Request/recorder/input construction precedes seeding.
- Monotonic wall time and process `RUSAGE_SELF` user/system CPU are bracketed;
  MemStats snapshots outside the wall/CPU bracket yield TotalAlloc/Mallocs.
  These include concurrent Rhiza/runtime work, not isolated DELETE CPU. Go heap
  allocation is not RSS or native allocation. Empty brackets are retained,
  never subtracted. Parent disk sampling can affect colocated I/O/wall time.
- Logical text bytes sum UTF-8 byte lengths of all string-valued cells in the
  eight observed tables. They exclude numeric cells, indexes, SQLite headers,
  receipts and other tables: **not total SQLite storage bytes**.
- Relative file inventories contain lengths for database, sidecars, qlog and
  filesystem objects. Length reduction is not allocated-block reclamation.
  Inventories and atomic bucket counters are separate observations, not a
  transactionally atomic filesystem snapshot.
- Object counters become unavailable after `DB.Close`; post-close observations
  retain file lengths and an explicit unavailable/null counter value, not zero.
  The last pre-close inventory precedes a final read-only table audit, so its
  difference from post-close files is not an isolated close-only byte cost.
- Rhiza v0.12.3 `internal/objstore/metrics.go`: operation counters count calls;
  upload/download byte counters count bytes read through wrappers, including
  unsuccessful attempts. They are not necessarily accepted durable bytes.
  Failures and conflict/dedup counters remain visible. Uploaded bytes and
  retained object inventory are **not additive**. No filesystem observation is
  a proxy for peer wire traffic, quorum cost or remote object-service CPU.
- Execute/statement structure is source-backed, not instrumented per-operation
  runtime counts. No synthetic command-size estimate is substituted for qlog or
  wire bytes. Untimed rotation inspection uses the real staging callbacks,
  discards them without commit, then separately verifies real HTTP rotation.

## Safety controls and scope

New small controls verify a late SQL abort rolls session/binding cleanup back;
a missing conditional session INSERT returns an error after cleanup commits;
stale CC policy permits its separate cleanup but no new token; and a pre-existing
orphan snapshot is removed. The primary matrix has no orphan-only size axis.
The rotation staging sequence is old-access deletion → orphan scan → expired
access deletion → another orphan scan → expired refresh deletion. Rotation is
untimed. Real code/interaction replay checks run only after both timers.

Reuse existing interaction precondition/constraint rollback, wrong-verifier,
client binding, concurrent single-use, principal-revision and cleanup-masking
regressions. Browser confirmation errors are not treated as rollback; OAuth
post-commit proof failures likewise cannot undo committed commands.

Unmeasured: actual peer wire traffic, exact-three topology, deployment SLOs,
large/adversarial backlogs, concurrent issuance contention, isolated cleanup CPU,
GC/recovery costs, mapped-subject CC, full browser login, password/device/exchange
grant timings, optimal cleanup cadence and any cleanup-worker benefit.

## Results and checks

One primary campaign: **45 cases / 90 timed operations**, all runtime checks
returned PASS, **204.05 seconds** as reported by the campaign test driver.
The historical outcome's precise **204,041,125,209 ns** counter was captured
after setup, validation, controls, close, fixture removal and CSV/summary
reduction, but **before raw hashing and final deadline checking**. It is not
an inclusive finalization-time certificate. Sampled peak active
fixture plus retained raw evidence file length: **29,870,196 bytes** (256-MiB
cap, 240-MiB stop threshold). No cap was hit and no primary case was replaced.
The generated `raw/outcome.json` records runtime completion, **not acceptance
of the subsequently audited oracle**.

Go 1.27.0, darwin/arm64, GOMAXPROCS=4, eight logical CPUs. At launch the host
reported load averages **14.39 / 15.80 / 15.95**. These are busy-laptop, warm-OS-
cache observations, not controlled-idle or deployment qualification. Case order
was fixed, not randomized. No race/coverage/profiler or other verification job
ran concurrently with the primary campaign.

| Operation | First wall median, empty/live/expired (ms) | First process CPU median, live/expired (ms) |
| --- | --- | --- |
| session | 15.652 / 18.514 / 27.971 | 3.227 / 14.525 |
| interaction | 16.739 / 14.918 / 19.847 | 3.381 / 6.917 |
| code | 17.931 / 18.536 / 37.408 | 4.118 / 18.502 |
| redemption | 23.594 / 23.069 / 52.561 | 8.496 / 27.337 |
| client_credentials | 33.526 / 36.284 / 50.259 | 8.148 / 20.194 |

Each cell summarizes three observations. [Full ranges, allocations and separate
follow-ups](raw/summary.md) and [all 90 samples](raw/samples.csv) are retained.
For example, expired redemption first wall time ranged **34.638–64.204 ms**;
its post-validation follow-up ranged **17.588–32.235 ms**. These are whole-flow
intervals with the stated confounds, not DELETE latency or tail percentiles.
Do not infer a worker saving from their difference.

Observed first-operation qlog length deltas stayed within 3,466–23,009 bytes
across the matrix. The filesystem bucket counted two upload calls per operation,
except guarded CC's four; this is consistent with its separate cleanup/issuance
mutations but is not a measured Execute count. First-operation uploaded-read
bytes ranged 2,006–10,393. Bucket failure deltas were zero. These do not scale
as a transmission of every deleted row and say nothing about actual peer wire.
SQLite main-file length deltas were zero in these intervals; WAL-length deltas
ranged 0–1,058,840 bytes, affected by reuse/background checkpointing. Raw files
retain exact logical text bytes, per-table counts and separate object inventories;
none is a reclaimed-space or object-service-cost estimate.

### Post-run oracle failure and stop

The measured helper hashed the encoded interaction token string, while
`browser.CanonicalTokenDigest` hashes its decoded 32 bytes. As a result the
interaction sentinel query returned zero rows and its hash was SHA256(`null`)
in **all 45** initial case records. The comparison stayed vacuously equal.
Other sentinel hashes were nonempty; exact live-seed hashes, deletion sets,
table counts, new artifacts and consumption controls remain recorded, but the
interaction sentinel's exact field preservation cannot be recovered from these
raw observations. Successful fixture DBs had already been removed.

Current source uses the public canonical helper and requires **exactly one row
for every sentinel lookup**. A valid Go overlay restoring the old digest
calculation fails before timing with `sentinel lookup
browser_authorization_interactions returned 0 rows, want exactly one` (exit 1,
not a compile/SQL error). Only two-bundle correctness checks were rerun after
the correction. The original campaign's evidence was not rewritten or replaced.

[Measured source](measured-harness.go.txt) has SHA256
`c114ead923e1ba73975c2dc8e5b0ac68789b55b240872a47b04912fe490c51d2`, matching
`raw/manifest.json`; current harness source intentionally differs by the oracle
correction and the subsequent untimed finalization/metadata corrections below.
The reducer SHA256 is
`f81d7c28898a6a2375165396f0a54f8796211c9d03f2443c04b3777a32c4c85d`.
All 49 original [raw hashes](raw/SHA256SUMS) verified. No keys, cookies, token
values or database dumps are published; inventories contain relative storage
filenames/lengths and hashes only.

The current harness now writes explicit pending/failed finalization status
until evidence hashing, pending-status publication and deadline gates succeed.
Its mutable `outcome.json` is excluded
from the new checksum inventory; missing, unreadable, pending or failed status
cannot certify completion. The new elapsed counter is post-hash but before
pending-status publication, which has its own deadline check. The final status
write reports that gate result and does not certify its own elapsed time.
Isolated filesystem tests force checksum-write failure and deadline crossings
before and after pending-status publication, with successful and prior-failure
controls; they open no database.
Current checkpoint metadata separately identifies excluded Rhiza archive
checkpoints and uncontrolled default one-second SQLite PASSIVE checkpoints.
The current manifest also hashes the separate finalization helper source.
These are current-source corrections, not new measurements. Historical raw
logs, outcome, hashes, manifest and measured source remain unchanged. Neither
review finding demonstrates historical finalization failure or a production bug.

**Stop decision:** retain these qualified observations and the corrected harness
for independent/Pro review. The sentinel evidence gap and unaligned SQLite
checkpoint component prevent full acceptance of the planned controlled tranche.
No production cleanup change, worker, new infrastructure, or replacement
measurement is authorized by these results. #65 remains open.

Primary invocation (working directory `internal/oauth`, after compilation):

```sh
GOMAXPROCS=4 go test -c -tags=integration -o /tmp/goauthy-expiry65.test ./internal/oauth
# From internal/oauth; OUTPUT must not exist. One campaign only.
GOMAXPROCS=4 GOAUTHY_EXPIRY65_OUTPUT=/absolute/new/evidence-directory \
  /tmp/goauthy-expiry65.test -test.run='^TestExpiry65Campaign$' -test.v -test.timeout=610s
```

Correctness checks outside the primary budget:

```sh
GOMAXPROCS=4 go test -tags=integration ./internal/oauth \
  -run '^TestExpiry65(FixtureShapes|TransactionBoundaries)$' -count=1 -v -timeout=90s
GOMAXPROCS=4 go test -race -tags=integration ./internal/oauth \
  -run '^TestExpiry65(FixtureShapes|TransactionBoundaries)$' -count=1 -v -timeout=150s
GOMAXPROCS=4 go vet -tags=integration ./internal/oauth ./internal/browser
```

Pre-campaign normal checks: PASS, 19.495s. Focused race: PASS, 77.238s.
Vet: PASS. An earlier two-bundle control found reused fixture request IDs;
the IDs now include operation/state. The first race check found that post-close
object counters are unavailable; the observer now records that explicitly.
These development checks preceded the frozen primary campaign and are not
replacement primary samples.

The following existing regressions passed under race in the earlier combined
run (the combined command failed only because of the then-unfixed post-close
measurement assertion):

```sh
GOMAXPROCS=4 go test -race -tags=integration ./internal/oauth ./internal/browser \
  -run '^Test(Expiry65(FixtureShapes|TransactionBoundaries)|AuthorizationCodePKCEAndRefreshRotation|AuthorizationCodeIsSingleUseUnderConcurrency|AuthorizationCodeClientBinding|AuthorizationRejectsMissingLoginAndRedirectMismatch|AuthorizationIssueRemovesExpiredState|TokenIssueRemovesExpiredState|ClientCredentialsCleanupDoesNotMaskGuardFailure|OIDCPrincipalRevisionGuardRejectsCodeAndRefreshWithoutArtifacts|ConfirmationCreateCleanup|ConfirmationAuthorityLossRollsBackCleanup|ConfirmationConstraintFailureIsNotAbsence)$' \
  -count=1 -v -timeout=240s
```

Browser package PASS, 139.826s. Existing OAuth selected tests all PASS; the
combined OAuth package result was FAIL, 88.449s, for the explained harness
assertion. The corrected new tests were rerun separately, as listed above.

Post-campaign canonical-sentinel correction: focused race PASS, 71.723s.
Final normal/vet and mutation evidence are recorded in `checks.txt`.
