# #112 remaining measurement: clean restore complete, wire blocked

Production formats remain unchanged; the access/refresh reuse candidate remains
rejected. This is a measurement-only continuation of local `71c811e2c5b637373d4ff2bd58d9ce9b7a6d6972`.
**#112 remains open because actual peer wire traffic is unmeasured.** No size,
replication, deployment, or optimization benefit is inferred from these results.

## One wire feasibility check

On 2026-09-28 the existing Docker CLI successfully returned an empty running
container inventory (`docker ps --format '{{.Names}} {{.Image}} {{.Ports}}'`).
The existing TCP listener inventory showed desktop services including doryd on
80/443/8443 and localhost:8080, relaker:8081, and development applications, but
established no permitted conditional-write object-store fixture. Targeted local
backup/OAuth test and CI searches found no MinIO/localstack/ObjStoreEndpoint
fixture. No existing permitted shared service or bucket credentials were supplied.
This establishes an unavailable prerequisite for this bounded experiment, not a
claim that every process or possible service on the host was exhaustively audited.
No service was started, installed, deployed, or probed with credentials.

Pinned Rhiza v0.12.3 `pkg/node/node.go:61-70` rejects filesystem (including an
implicit directory) for multiple members, and `:203-204` requires archive CAS.
Its public `rhiza.Config` has no transport injection hook. `/usr/sbin/tcpdump`
exists; tshark is absent. Capture permission, peer filter/direction, loss,
loopback duplication and offload accounting were **not validated** after the
object-store blocker. The wire branch stopped before a three-voter harness or
packet capture. No qlog, object-store or JSON multiplier stands in for wire bytes.

## Clean restore method

Host: Apple M1, go1.27.0 darwin/arm64, GOMAXPROCS=4. Initial host load averages
4.22/3.43/3.52; this is a shared laptop, not an isolated deployment. Nine primary
fresh executable processes ran sequentially, three per existing small/medium/large
tier. No race, coverage, forced GC or profiling in primary runs. The single small
pilot is separate and excluded. Race checks occurred afterward.

One prebuilt synthetic age bundle per tier used the existing actual storage
fixture: 100 code/PKCE/interaction scenarios, 50 consumes, plus one genuine HTTP
wrong-verifier/correct-verifier flow. Code and PKCE forms remain nonidentical.
Fixture creation and Export were outside all primary timers. Existing scopes,
claims and form sizes were unchanged. Source Close produces the checkpoint;
these are clean checkpoint backups, not crash or archive-only restores. Bundle
format is the existing uncompressed tar inside age. No expiry timestamp rewrites.

Each process opens its prebuilt input and creates a fresh target filesystem
bucket outside timers. Separate brackets execute real Extract, Restore, and
rhiza.Open. Pinned single-node `pkg/node/node.go:421-422` sets local readiness
before Open returns; the harness asserts Ready afterward. This is not quorum
readiness. CPU is process RUSAGE_SELF user/system deltas, not whole-command CPU;
Go cumulative TotalAlloc/Mallocs deltas are reported separately. ReadMemStats
surrounds the wall/CPU bracket; CPU reads surround monotonic wall measurement.
Thus brackets have slightly different boundaries and include normal runtime
activity in this process. They are not isolated function CPU profiles.

An empty bracket per process uses the same counter path. Its wall range was
0.0015–0.011416 ms, CPU 0.005–0.016 ms, allocations zero; overhead is reported,
not subtracted. No correctness query, counter output or instrumentation
serialization occurs inside operations. OS cache is not flushed: **fresh process
is not cold OS cache**. Filesystem backend CPU is in process; no external object
service CPU or network service is measured.

Budgets: exactly three preparations and nine primary restores, 120-second
preparation process deadline and 45-second restore process deadline (30-second
restore context), sequential execution. Backup limits: 4,096 files, 64 MiB/file,
128 MiB total; existing preparation inventory rejects observed totals over
256 MiB (a post-operation guard, not a disk quota). Preparation took
7.77/7.90/8.02 seconds; all primary child tests completed successfully. No larger
matrix or repeated baseline was run; generation was solely to prebuild inputs.

| Tier | Bundle bytes | SHA-256 |
|---|---:|---|
| small | 1,576,008 | b0bf78cbe2f5d5102d12a17be9ebf5a7d7f01de23609e0e930ff54a1efdf4a08 |
| medium | 2,731,352 | cd6e9db59d45ef295df2753d4deb2ba80b45d62d3f20aedc0914f37333c6c5f7 |
| large | 14,170,184 | 8a9f2eab48b6f6b2ed0f34da88dda4f3c864b3416abdeb3292fa36e9fbb65661 |

Bundles and their synthetic private decryption keys remain local temporary
fixtures; they are not published. Raw logs, source/binary hashes, and parsed
samples are retained. Reproduction generates new random encrypted bundles,
therefore new hashes. Fixture construction and original timing source are the
committed tests; the ordinary invalidated-code regression was appended after
primary measurement and does not execute in the measurement selection.

## Results

Ranges across **three individual samples** per cell, not percentiles or confidence
intervals. CPU below is user+system; raw JSON retains each component and Mallocs.

| Tier | Phase | Wall ms | CPU ms | TotalAlloc bytes |
|---|---|---:|---:|---:|
| small | Extract | 6.00–11.17 | 8.09–12.05 | 1,788,928–1,789,024 |
| small | Restore | 34.49–48.63 | 13.11–22.92 | 421,584–429,944 |
| small | Open→ready | 327.56–344.96 | 70.86–76.54 | 5,731,400–5,735,248 |
| medium | Extract | 9.17–19.33 | 9.57–12.96 | 2,894,288–2,903,120 |
| medium | Restore | 36.60–59.28 | 16.98–29.91 | 422,936–424,032 |
| medium | Open→ready | 299.43–497.77 | 51.78–68.13 | 5,739,344–5,740,528 |
| large | Extract | 40.02–61.71 | 37.72–50.95 | 14,371,952–14,371,968 |
| large | Restore | 85.34–160.77 | 43.15–74.00 | 423,872–428,856 |
| large | Open→ready | 388.13–519.58 | 86.36–137.92 | 5,735,456–5,743,776 |

No errors in pilot, preparations or nine primary restores. Extract allocation
increases with bundle size in these fixtures. These small noisy samples do not
justify an encoding change or deployment latency prediction.

## Actual assertion map

Paths below are relative to `internal/oauth/`; names identify exact assertions,
not claims of exhaustive coverage.

| Contract | Test / assertion |
|---|---|
| Filtering and ownership | `grant_storage_persistence_test.go:TestEncodeRequestDropsTransientFormFieldsWithoutMutatingRequest`: retained form equality, independent password/client-secret sentinels, input form comparison. `snapshot_reuse_measurement_test.go:TestSnapshotReuseSensitiveSet` enumerates 20 fields independently; `TestSnapshotReusePairOwnership` changes caller-owned inputs. |
| Durable grant filtering | `TestPersistedRequestRowsDropTransientFormsAcrossGrantPaths`: queries actual code, PKCE, access, refresh, device and exchange request rows for unsafe transient fields. |
| Concurrent consume | `grant_test.go:TestAuthorizationCodeIsSingleUseUnderConcurrency`: two concurrent HTTP redemptions, exactly one success, durable access count at most one (replay can revoke it). |
| Wrong verifier / retry | `TestAuthorizationCodePKCEAndRefreshRotation`: wrong verifier rejected, reconstructed server can redeem same code correctly; rotated refresh replay rejected and grant revoked. |
| Error plus requester | NEW `snapshot_measurement_test.go:TestSnapshot112InvalidatedCodeRetainsRequest`: production invalidation/commit then getter must return ErrInvalidatedAuthorizeCode AND original request ID/client/redirect. The restore oracle checks the same contract after recovery. |
| Verified DPoP extra | `dpop_test.go:TestDecodeRequestPreservesOnlyVerifiedDPoPCNF`: verified JKT survives hydration, stored Extra restored, unrelated transient Extra discarded. This is the hydration contract, not a new end-to-end DPoP matrix. |
| Current managed authority | `managed_clients_test.go:TestManagedClientIssuanceGuardsRevisionAndGeneration`: positive issue, revision mutation before commit causes rejection and zero stale code/access rows. Despite its title, this test's concrete mutation is revision. `managed_client_http_test.go:TestManagedClientHTTPCodeRefreshSurviveMetadataChange`: benign rename survives, per-request client identity stable, disable/re-enable cannot revive old refresh generation. |
| Issue-time ephemeral snapshot | `cimd_test.go:TestCIMDResolvesOnlyAtAuthorizationAndPersistsSnapshot`: mutable resolver metadata changes; redemption retains stored metadata, resolver call counts unchanged, access load does not consult mutable cache. |
| Final MFA fence | `device_mfa_test.go:TestDeviceMFAChangedAfterClaimCannotCommit`: force_mfa changed without revision bump after claim; response issuance fails with no token artifacts. |
| Compatibility / recovery | `TestSnapshot112LegacyRecord` decodes legacy descriptor-free JSON and rejects malformed records. NEW Darwin `TestSnapshot112IsolatedRestore` checks consumed code error+original identity, consumed PKCE absence, pending PKCE challenge/method, pending interaction exact payload/request ID, consumed interaction error and cross-session denial after real Extract/Restore/Open. No binary-version upgrade claim. |

The ordinary exact error/request binding assertion was the small missing gate;
other existing gates were reused, not duplicated. A temporary Go overlay changing
`return request, fosite.ErrInvalidatedAuthorizeCode` to `return nil, ...` must fail
that new test; the production file is never changed. Raw validation logs record
this expected failure separately from passing checks.

## Reproduction and limits

Build `GOMAXPROCS=4 go test -c -o /tmp/oauth112.test ./internal/oauth`.
For each shape, run that executable with `GOAUTHY_SNAPSHOT112_SHAPE=small` (or
medium/large), `GOAUTHY_SNAPSHOT112_RECOVERY=1`, and
`GOAUTHY_SNAPSHOT112_BUNDLE=/tmp/<shape>`; select only
`-test.run '^TestSnapshot112Storage$' -test.v -test.timeout=120s`.
Then invoke a fresh executable three times with
`GOAUTHY_SNAPSHOT112_RESTORE_BUNDLE=/tmp/<shape>` and
`-test.run '^TestSnapshot112IsolatedRestore$' -test.v -test.timeout=45s`, always
GOMAXPROCS=4. Do not run the primary measurements with race/coverage.
Use `jq -s -f summarize.jq samples.jsonl` for the summary.

Remaining: actual peer UDP/wire bytes, multi-voter replication, crash/partition
recovery, archive-only replay, external object-service CPU, cold OS caches, and
cross-version binary upgrade are unmeasured. Earlier baseline reports still own
logical/physical/qlog/object statistics; this slice does not reinterpret them as
wire data. Retain-format/reject-candidate decision is final for this bounded
experiment; no optimization search was restarted.

Additional existing DPoP gate: `TestDPoPAuthorizationCodeRefreshAndUserInfo`
checks signed/stored JKT agreement, no persisted proof/nonce, rejects missing or
wrong refresh proof, then permits the correct key; resource nonce/replay checks
also run. It passed separately under race. No new DPoP implementation was added.

Validation: focused OAuth race selection passed (15.320s); isolated restore race
passed separately (not part of primary data); the DPoP HTTP race test passed;
`go vet ./internal/oauth` and `git diff --check` passed. The nil-request mutation
failed specifically with `request=<nil> error=Authorization code has ben
invalidated`, as intended (not a build failure). Primary runs used the prebuilt
non-race executable whose hash is recorded in provenance. Final harness changes
only add a deferred Close-error assertion and simplify a comment after primary
sampling; they do not alter timed operations. Final race checks exercise that
cleanup assertion. The harness is Darwin-only because it uses Darwin Rusage;
the ordinary error/request regression runs on all supported test platforms.
