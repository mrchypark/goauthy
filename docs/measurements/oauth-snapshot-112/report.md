# OAuth snapshot baseline (#112)

Measurement-only, 2026-09-28. Base `64f3503b5e06d3b43c32e879ee5de4c2f5063ae3`,
Go **go1.27.0 darwin/arm64**, Apple M1, GOMAXPROCS=4; pinned Rhiza v0.12.3 and
Fosite v0.49.0. Production, schema, encoding, dependencies and defaults unchanged.
No optimization is selected and no issue-closure claim is made.

## What ran and what it means

`internal/oauth/snapshot_measurement_test.go` contains actual `encodeRequest` and
`decodeRequest` benchmarks, JSON-only decode, base64 codec microbenchmarks, and
an opt-in real storage/browser/backup workload. Codec numbers are medians of
**five benchmark averages**, not operation latency percentiles. The JSON-only
case creates a fresh `requestRecord`; full decode creates a fresh session. The
static client returns from the Store's configured client, without a managed
client database lookup. Separate medium managed and ephemeral cases exercise
the real authority/reconstruction paths. No decode result is cached by the test.

The three storage shapes have 2/8/32 synthetic requested and granted scopes,
256/2048/16384 claim-value bytes, and 256/2048/8192 retained form-value bytes.
These **storage-stress** requests are not claimed valid HTTP scope requests.
Their forms go through Fosite's distinct code and PKCE allowlists: code retains
redirect_uri, PKCE retains challenge/method. Both retain the default form fields.
The unsanitized helper microbenchmark has both bindings and is therefore larger
than either actual persisted request. It must not be multiplied by two to
estimate the stored pair.

Each of nine fresh compiled-test processes (three per shape) performs exactly
100 iterations: code+PKCE issue through production transaction methods, both
production getters, interaction create/load plus cross-session rejection, and
50 code/PKCE consumptions plus 50 interaction consumptions. There are 100 code,
50 surviving PKCE and 100 interaction rows at the logical measurement boundary.
This is 100 scenario iterations, not 100 SQL statements or commits. Every
iteration checks nonidentical form bindings. The code-consumption measurements
exercise the real invalidation transaction but do not mint tokens.

Each process then runs one separate **HTTP-valid** flow using existing
`issueCode`/`postToken`: seed user, authorize, wrong verifier rejection, successful
redemption. That combined interval was 50.54–64.92 ms (nine individual samples,
not a tail estimate). It is outside the logical/physical workload deltas. The
focused race checks also cover concurrent redemption and refresh rotation.

Interaction payloads rotate URL, continuation JSON and opaque storage bytes,
with repeated and deterministic varied text, at 256/4096/65536 bytes. These
exercise actual browser methods but are not full login/logout handler benchmarks.
Codec-only base64 benchmarks use repeated bytes. No real credentials or user data
were used; no secrets are printed. Independent sentinel fixtures cover password,
client secret/assertions, exchange tokens, code/verifier, device/refresh tokens,
request objects and id_token_hint; retained bindings and input nonmutation are
asserted. The existing cross-grant persisted-row filtering tests are retained.

## Results

Microbenchmarks, median ns/op and allocated bytes/op (all five samples are in
`bench.tsv` and the raw evidence):

| Shape | Helper JSON bytes | Encode ns / B | JSON-only decode ns / B | Full static decode ns / B |
|---|---:|---:|---:|---:|
| small | 1,028 | 3,063 / 3,713 | 4,679 / 3,296 | 4,701 / 4,289 |
| medium | 4,864 | 7,129 / 11,334 | 12,149 / 11,217 | 12,921 / 12,595 |
| large | 26,352 | 27,309 / 56,969 | 49,998 / 56,789 | 50,535 / 59,708 |

Encode allocs/op: 25 throughout. JSON decode: 31/46/98; full static: 41/60/116.
Medium managed decode: 100,431 ns/op, 20,198 B/op, 256 allocs/op, 5,168 JSON bytes.
Medium ephemeral decode: 15,124 ns/op, 14,324 B/op, 80 allocs/op, 5,053 JSON bytes.
Managed sample means ranged 76,097–147,220 ns/op: authority work and host load
matter; this is not an isolated JSON comparison.

Base64 encode median ns/op: 265.8 / 3,799 / 47,811; allocated B/op:
704 / 12,288 / 180,224 (two allocations). Decode: 176.5 / 2,524 / 37,370 ns/op,
256 / 4096 / 65536 B/op (one allocation). Actual TEXT lengths are
342 / 5462 / 87382 bytes. Those are representation lengths, **not disk ratios**.

Logical bytes at the workload boundary, identical in all three repetitions:

| Shape | Code bytes (100) | PKCE bytes (50 retained) | Interaction bytes (100) | Issue request JSON bytes (100 commands) |
|---|---:|---:|---:|---:|
| small | 92,600 | 48,950 | 34,200 | 256,100 |
| medium | 476,200 | 240,750 | 546,200 | 1,028,100 |
| large | 2,625,000 | 1,315,150 | 8,738,200 | 5,344,900 |

Per-row code/PKCE bytes are 926/979, 4762/4815, 26250/26303. The request JSON
counter serializes the actual staged issuance ExecuteRequest, including cleanup
SQL. For these string/integer arguments the pinned Rhiza SQLCommand has the same
JSON fields and its argument encoder changes only byte slices; the migration
field is absent. This source correspondence supports its per-command encoded
length here, **not** batching, consensus framing or wire transmission totals.
It does not count consumption/browser commands. Actual qlog lengths are measured
separately. No multiplication by replica count is justified.

Physical deltas against each process's migrated/server-initialized/two-session
control (not an empty database), decimal MB ranges:

| Shape | SQLite main | SQLite sidecars | qlog | Retained object bytes | Cumulative uploaded bytes |
|---|---:|---:|---:|---:|---:|
| small | 0.221–0.287 | 1.347–4.124 | 1.519–1.520 | 0.776 | 0.816 |
| medium | 1.425–1.495 | 3.494–6.654 | 4.516 | 2.060 | 2.100 |
| large | 11.297–11.448 | 6.938–25.783 | 33.703 | 14.569 | 14.609 |

Full per-file inventories and cumulative `DB.ObjectStoreStats()` values are in
the raw logs. There were 600 additional object uploads per workload. Upload byte
counters measure traffic at the bucket boundary; retained inventories measure
files presently stored. Indexes, receipts, SQLite page allocation and WAL reuse
are included; deltas are not per-column physical attribution. Inventories are
observations after completed calls, not atomic filesystem snapshots. The source
is single-node filesystem storage with before-ACK durability and a one-hour
checkpoint interval. Close creates a checkpoint and changes qlog/archive
retention: post-close inventories are separately recorded and never substituted
for live workload deltas.

Whole-workload TotalAlloc deltas: 77.14–77.38 MB small, 131.52–132.03 MB medium,
650.88–652.85 MB large. These include GoAuthy, Rhiza/background work, fixture
construction, validation and readback—not just snapshot serialization or live
heap. Whole-process CPU and peak RSS (compiled binary, excluding compilation):
small 2.26–2.58 CPU seconds / 76.58–82.13 MB RSS; medium 2.23–2.40 seconds /
82.31–85.54 MB; large 3.21–3.39 seconds / 156.22–167.33 MB. Process real times were
7.58–9.24 seconds including setup, and recovery where enabled. See `process.tsv`.
These are not per-operation CPU or a deployment capacity qualification.

`storage.tsv` retains per-process nearest-rank P50/P95/P99 for **100 instrumented
storage-scenario issue intervals and 50 individual consume calls**. Issue P50:
14.76–17.07 ms; P99: 24.90–33.55 ms. The issue intervals include real transaction
work and storage waits, plus measurement-only `json.Marshal` of the staged
`rhiza.ExecuteRequest` and command-byte accounting before Commit. They are not
uninstrumented issuance or endpoint latency; the historical values are retained
without subtracting instrumentation costs. Consume excludes the subsequent
browser consume. They are not benchmark
batch means relabeled as tails; at n=50 P99 is the maximum. No pooled tail claim.

A separate fixed-10,000-iteration CPU/allocation profiling pass covers six
encode/JSON-decode cases. CPU sampling observed 170 ms cumulatively in
`encodeRequest` and 330 ms in the JSON-only benchmark decode stack, out of
1,830 ms total sampled process CPU. Setup, database/background and runtime work
are also profiled. Do not divide these sampled totals into precise per-shape
CPU estimates. Go 1.27's stdlib profile includes encoding/json/v2 internals;
this task did not replace the application's JSON library.

## Recovery and compatibility boundary

Small and large each completed **three** export/extract/restore/cold-open runs,
with the source stopped and its single-node identity preserved. Export uses the
existing tar+age path without a compression stage. Fresh target object prefixes
and fresh local data directories are used. A live and a consumed code, PKCE row
presence/absence, and a live/consumed browser interaction are checked after open.
The binding checks include request IDs and original session-token association.

| Shape | Backup bytes | Export ms | Extract ms | Restore publication ms | Cold open ms |
|---|---:|---:|---:|---:|---:|
| small | 1,576,008–1,580,104 | 42.16–70.38 | 4.43–13.81 | 34.44–65.08 | 327.73–363.64 |
| large | 14,170,184 | 106.74–187.79 | 36.24–53.64 | 90.36–102.55 | 370.88–440.92 |

Three values per size are reported as ranges, not recovery tails. Raw manifest
mode is empty (the legacy checkpoint-mode representation), not archive-only.
Object download counters after restored open are recorded. Export/restore use
a separate filesystem bucket, so their own per-operation download/upload
counters are **not** included in the restored DB counter. Per-phase recovery CPU
and allocations were not separately isolated; whole-process resource costs above
include them. The archive includes schema, receipts and the separate HTTP flow;
its length is not attributable only to the measured payload columns.

The initial pilot changed NodeID for restored open and failed with
`restore checkpoint recovery base: invalid checkpoint recovery base`. Its log is
retained; it is not a success or a proven production defect. A subsequent pilot
and all six final recoveries retained the source identity and passed. No Rhiza
source/config-default change or retry loop was introduced.

New legacy-shaped JSON and malformed-record checks plus existing managed
metadata-change, CIMD snapshot, default-audience and sensitive-form tests retain
compatibility coverage. **This does not validate an actual old-binary cold
upgrade**, all historic snapshot formats, archive-only recovery, crash/WAL-only
recovery, cross-version restore, or unresolved-commit recovery. Those remain
required gates before any future encoding/schema change. Existing consume and
recovery code is untouched. Multi-node wire replication is explicitly
**unmeasured**, not inferred from command/qlog/object bytes.

## Budget, provenance and reproduction

Fixed limits: 100 scenario iterations/process, nine serial storage processes;
90-second test context and 120-second external test timeout; file inventories
reject a measured root over 256 MiB; backup limits 4096 files, 64 MiB/file,
128 MiB captured data. Limits are test bounds/checks, not OS disk quotas. The
largest measured process RSS was 167.33 MB. No external deployment or paid
service was used. Codecs used 5 x 1-second benchmark targets per case (75 codec
samples + 10 authority samples); fixed profiling added 60,000 timed iterations.
No Cartesian size/client/recovery matrix expansion. The two exploratory pilots
are separate from the nine final processes. Other host processes were active;
the codec run overlapped pilots, while the final nine storage processes ran
serially without another agent-launched benchmark. Raw load/provenance retained.

Build once, then run each process fresh:

```sh
GOMAXPROCS=4 go test -c -o /tmp/oauth112.test ./internal/oauth
GOMAXPROCS=4 /tmp/oauth112.test -test.run '^$' \
  -test.bench '^BenchmarkSnapshot112$' -test.benchmem -test.benchtime=1s -test.count=5
GOMAXPROCS=4 /tmp/oauth112.test -test.run '^$' \
  -test.bench '^BenchmarkSnapshot112Authority$' -test.benchmem -test.benchtime=1s -test.count=5
# Repeat three fresh invocations for each small/medium/large shape.
# RECOVERY=1 for small/large, 0 for medium; retain stdout and /usr/bin/time -l stderr.
GOMAXPROCS=4 GOAUTHY_SNAPSHOT112_SHAPE=small GOAUTHY_SNAPSHOT112_RECOVERY=1 \
  /usr/bin/time -l /tmp/oauth112.test -test.run '^TestSnapshot112Storage$' \
  -test.count=1 -test.timeout=120s -test.v
```

Raw evidence includes logs, all operation samples, per-file inventories, time
outputs, CPU/allocation profiles, dependency versions and the measured test-source
SHA-256. `SHA256SUMS` identifies the committed evidence archive and summaries.
The initial codec binary predates the additive authority/legacy/payload-fixture
helpers; its benchmark bodies are unchanged in the measured final source. The
final nine processes and profile pass use the source hash in `source.sha256`.

## Interpretation for the next design review

The data establishes allocation/representation scaling and materially different
current-authority decode cost. It does **not** demonstrate an optimization's
benefit. Preserving only PKCE's challenge/method would also remove client and
session reconstruction behavior; it cannot be justified from duplicate JSON
bytes alone. Reusing an encoding is not automatically valid because forms differ.
The smaller scope to investigate next is a test-only candidate comparison that
preserves exact bindings and authority checks; Pro should choose that design
before any production change. No JSON library, schema or encoding change is
recommended from this baseline alone.

## Validation executed

- New sentinel/legacy/storage checks plus existing code+PKCE retry, concurrent
  single-use and form nonmutation tests: **race PASS, 35.556s** (small recovery
  enabled, 100 iterations). No race report.
- Existing persisted-row filtering across grants, managed metadata-change,
  CIMD snapshot and default-audience compatibility: **race PASS, 15.353s**.
- `GOMAXPROCS=4 go vet ./internal/oauth`: PASS.
- `git diff --check`: PASS. Full repository suite and CI were not run for this
  test-only measurement slice; parent independent measurement review and Pro
  optimization design remain outstanding.
