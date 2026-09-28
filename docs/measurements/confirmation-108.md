# Confirmation-read proof (#108)

Baseline: a4515ac517affedf55f073d625d91c9a3d4b17cc, Rhiza v0.12.3,
Fosite v0.49.0. This slice changes only interaction creation and the shared
Execute helper's rejected-receipt recovery. No dependency upgrade, other read
removal, authority-read batching, or new production hook/API.

## Contract and prerequisite

CreateAuthorizationInteraction succeeds when its exact replicated request
inserts one interaction under the existing session/user predicates at its
position in the mutation order, with the configured ACK durability satisfied.
This is intentionally **not schedule-equivalent** to the former later existence
snapshot. Deletion ordered after insertion may complete before the creator
returns; returning the created token still records successful creation. The
receipt does not promise the row exists after a whole batched SQLite apply,
remains unconsumed, or retains current authority.

Only the INSERT has ExpectedRowsAffected=1. The preceding expiry cleanup has no
expectation. A zero INSERT rejects and rolls back that command's cleanup, unlike
the baseline. No compensating cleanup is added. A preceding LoadSession touch
can already have committed; a rejection also records receipt/replication state.
Do not describe rollback as “no durable writes.”

The creator retains its sampled SQL cutoff. Advancing wall time after capture
does not add apply-time expiry checks. Authority-loss tests change persisted
deadlines or revoke/disable before execution; a separate test preserves the
fixed-cutoff behavior and checks later loading rejects expiry.

Pinned Rhiza evidence:

- internal/types/value.go:44–99: bounded MutationReceipt, per-statement expected
  affected/returned rows, and statement results.
- pkg/materializer/materializer.go:1080–1113: command savepoint rollback,
  precondition-failed receipt, aggregate row-count sum, and retained result rules.
- Same file:1615–1627: exact non-row-returning statement count check.
- pkg/network/server.go:729–763: exact fingerprint check and cached receipt
  durability wait on Execute replay.
- Same file:917–943: RequestStatus is only an ID-based local receipt lookup.
- Same file:1133–1150: linearizable query invokes ReadIndex, optional catch-up,
  then applyDecisions. pkg/quepaxa/core.go:312 returns the local tip for one node.

GoAuthy's internal/storage/migrate.go Execute now treats recovered committed and
rejected states alike: require a receipt, replay the unchanged request once,
join the original ErrCommitUnknown with a replay error, then validate the
replayed receipt only if Execute returned nil error. No new retry loop.
The creator vetoes ErrCommitUnknown/ErrRequestConflict even with a populated
receipt, then maps only rejected/precondition_failed to ErrNotFound. Other
errors remain errors, never creation success. Aggregate RowsAffected,
LastInsertID and SQL receipt Applied are not success proofs.

Replay means the same mutation ID, SQL, arguments and expectations within the
slot-bounded receipt horizon. The public creator generates a new token and
mutation ID on each call; its logical requestID is a separate stored field.
No new public-method retry guarantee is implied.

## Caller and read inventory

Counts are successful-path application Query invocations within the named
method, before caller-specific earlier reads. Each linearizable Query invokes
one ReadIndex/apply barrier sequence; invocation is not an apply commit,
consensus write, network round-trip count, or object-store write.
Errors can stop a sequence early.

| Path (repository source) | Count / purpose | Decision |
|---|---|---|
| browser/store.go createSessionWithParent | One postwrite loadSession: stored capped expiry, current user/session validity, result fields. Reauthentication adds one parent read in reauthentication.go. | Retain; INSERT count lacks current capped result. |
| loadSessionAndTouch | One loadSession; optional guarded touch; one more loadSession when touch RowsAffected=0. Peer check retained. | Retain current authority and ambiguous-touch reread. Same-ID replay of a successful touch is not the zero-row branch. |
| LoadSessionReadOnly / ForPeer / reauthentication parent | One loadSession. | Retain current expiry, revocation, account validity and peer binding. |
| RevokeSessionID | One digest-existence lookup before revoke; UPDATE result also requires one row. | Retain existing absence semantics; outside selected postwrite removal. |
| CreateAuthorizationInteraction | Baseline 2 Queries (3 with zero-row touch); candidate 1 (2 with zero-row touch). Initial LoadSession retained; only digest-exists postread removed. | Exact INSERT expectation provides insertion-time proof. |
| loadAuthorizationInteractionReadOnlyAuth | **Two sequential reads**: loadSession, then separate interaction payload/expiry/consumption read. Authentication-mode mismatch can stop after first. | Retain both; this is not the joined consume query. |
| consumeAuthorizationInteractionGuarded | One joined postwrite result/attempt/current-authority read; unsuccessful result adds one consumeError diagnostic read. Reauthentication adds parent lookup. | Retain winning attempt, payload and live authority. |
| oauth captureManagedSnapshot | One request_json read; managed record adds GetClient cost C. Called by code invalidation and refresh rotation. | Retain current client incarnation/revision snapshot for commit fence. |
| GetAuthorizeCodeSession | One request_json + invalidated read, then decodeRequest cost C+F. Called by Fosite request validation and response production, and GoAuthy token-principal preparation (server.go:824). | Retain current code state, payload and client/MFA authority; preserve DPoP data handling. |
| GetPKCERequestSession | One request_json read then C+F. Called by Fosite PKCE validation. | Retain verification input. DeletePKCERequestSession intentionally defers deletion to guarded code consumption. |
| GetAccessTokenSession | One request_json read, followed by C+F. Used by token exchange, resource authorization, userinfo, forward auth and Fosite storage consumers. | Retain request result and authority. |
| accessTokenExpiry | One separate expiry read where invoked by callers. | Retain current token-expiry result; not an implicit read inside GetAccessTokenSession. |
| GetRefreshTokenSession | One request_json + active read then C+F. Used by Fosite refresh flow; RotateRefreshToken separately captures managed snapshot. | Retain active/reuse decision and authority. |
| Commit: password | One verifyPasswordIssue Query with counts for target access token, request and expected refresh binding. | Retain all-artifact proof. |
| Commit: exchange | One Query containing both target access and request counts. | Retain both-artifact proof. |
| Commit: guarded issue | One authorize-code existence Query when SID/principal/client/managed/account guards apply. | Retain; no code/PKCE statement expectations added in this slice. |
| Commit: device | One claim-digest-specific consumed-state Query, despite an exact UPDATE expectation. | Retain claim-specific issuance proof. |
| Commit: code / refresh | One Query matching this used_attempt / rotated_attempt. | Retain this transaction's ownership proof; another request's consumption is insufficient. |
| Commit: other / unguarded issue | No postread in this method. | Unchanged. |

C is GetClient's path-dependent cost, not a constant “one client read.”
oauth/server.go:1853 checks a request-local managed snapshot first (zero).
A static bootstrap client is zero plus any configured custom-scope callback.
A managed lookup performs Owns then GetClient (two queries) when uncached.
A dynamic fallback may first pay the managed Owns query, then registration and
secret reads (two), plus each configured custom-scope lookup. CIMD fallback
has its own lookup behavior; no fixed network/SQL count is asserted here.
decodeRequest can reconstruct a persisted ephemeral client without GetClient.
F is one additional device-MFA evidence query when forceMFA applies, otherwise
zero. These authority/callback costs must be counted for the selected HTTP
fixture rather than hidden in a universal endpoint total.

Final commit fences remain: principal revision and enabled/expiry predicates,
password/authentication generations and account locks, client-policy revision,
managed-client revision/generation, claims catalog, DPoP policy, exact profile
snapshot, session guards, code/refresh attempt and device claim. Relevant sources:
oauth/grant_storage.go BeginTX, principalGuard, managedGuard, Commit;
oauth/profile_revalidation.go profileGuard; oauth/password_transaction.go
verifyPasswordIssue. No snapshot sharing or fence removal is introduced.

All production creator call sites were inspected:

| Caller | Returned token use and subsequent authority |
|---|---|
| login/handler.go:414 ordinary login | Render form/cookie; submission loads interaction before credentials and consumes through continuation paths. |
| login/handler.go:710 FedCM landing | Render landing interaction; submission consumes via handler.go:809. |
| login/device.go:193 createLoginInteraction | Shared by device login (:63), connection-handoff login (:259), account login (account_login.go:47), and reauthentication continuation (continuation.go:135). Render a purpose-bound login form/cookie. Device submission loads at :105 and enters shared loginPassword; shared continuation load/consume and reauthentication parent guards remain. |
| login/profile_continuation.go:76 | Redirect to profile form; GET/POST load authenticated-session interaction (:98/:205), completion consumes (:327). |
| logout/http.go:241 | Render confirmation; POST consumes (:264), checks request prefix, payload and current subject before logout. |

None treats creation as a credential grant or bypasses later load/consume
validation. A stale form/token can be returned under overlapping deletion or
revocation, but cannot make the downstream authority checks succeed.

The profile creator is reached both from existing-session authorization
(handler.go:373) and post-authentication continuation (:1290/:1292). The extra
OAuth code lookup at server.go:824 is specifically grantedTokenScopes, called
before claim preflight (:606), not an optional cache fill. A successful ordinary
code redemption therefore includes both Fosite code loads plus that scope
projection load, the PKCE load when its handler applies, managed snapshot
capture during invalidation, and the final attempt proof. Add each row's C/F
cost at its actual invocation; request-local client snapshots can change C
between calls. No endpoint-wide constant is asserted across these configurations.

## Tests and reproduction

Ordinary tests exercise the real creator and pinned DB: init/authenticated
success with 0/1/3 expired rows; payload ownership, expiry and persisted binding;
revoke/delete/hard-expiry/idle-expiry/disabled-user/account-expiry between load
and creator cutoff; exactly one cleanup row rolls back on zero INSERT; genuine
uniqueness failure remains execution failure. Existing winner-only consumption
tests remain unchanged.

The opt-in overlay suite captures the actual creator ExecuteRequest, intercepts
errors at the real call boundary, and invokes pinned storage/DB execution.
It tests historical committed/rejected replay, changed-payload conflicts,
overlapping delete/revoke, fixed cutoff, both postapply durability failures,
populated receipts with errors, restoration and restart within retention.
Synthetic receipt/error combinations are explicitly error-mapping tests;
durability tests use the real filesystem before-ACK failure path.

No overlay changes persisted production or module-cache sources. Run:

    scripts/test-confirmation-proof.sh ./internal/browser -run '^TestConfirmation' -count=1 -timeout=180s
    CONFIRMATION_RECOVERY_OVERLAY=1 scripts/test-confirmation-proof.sh ./internal/storage -run '^TestConfirmationRecoveryRechecksFingerprint$' -count=1 -timeout=90s

Recovery-overlay mode is for the storage package alone. Normal go test includes
the ordinary tests; tagged overlay tests require this script. The parent owns
independent review and Pro re-review; this note makes no issue-closure claim.

## Measured result

Go go1.27.0, darwin/arm64, Apple M1 laptop, GOMAXPROCS=4, single node,
default local test database profile. Two fresh processes/databases per variant
and scenario, 40 individual calls each, concurrency one: 640 total successful
creator calls, zero operation errors. Setup is outside timed regions.
All runs use the same atomic coverage instrumentation on pinned Rhiza network
and materializer packages. This adds overhead; absolute latency is descriptive.
No own correctness-test workload ran during the completed comparison; the
shared desktop is not an isolated performance environment.

Zero-row touch is forced with a distinct competing request and a later stored
last-seen value. Same-ID replay executes the identical touch first. Injection
duration is subtracted from individual latency, but its effects/receipt history
and all its underlying calls remain in whole-process coverage. These are
controlled paths, not a throughput or contention benchmark. Creator cleanup
starts empty for every timed call. Separate tests cover 0/1/3 cleanup rows and
preservation of one expired row after rejected creation.

| Scenario | Query/call before → after | Execute/call before → after | Whole-process ReadIndex before → after | applyDecisions before → after | SQL statement ExecContext (both) | Network Execute (both) |
|---|---:|---:|---:|---:|---:|---:|
| Fresh | 2 → 1 | 1 → 1 | 195 → 155 | 387 → 347 | 607 | 192 |
| Touch due | 2 → 1 | 2 → 2 | 195 → 155 | 427 → 387 | 647 | 232 |
| Identical touch replay | 2 → 1 | 2 → 2 | 195 → 155 | 427 → 387 | 647 | 272 |
| Distinct losing touch | 3 → 2 | 2 → 2 | 235 → 195 | 507 → 467 | 687 | 272 |

Coverage totals include migrations, fixture setup and competing touches; matched
runs have equivalent setup and each contains 40 measured calls. Both repetitions
produced the same counts. Counter locations in the pinned module:
network/server.go:1138 (ReadIndex), :1407 (applyDecisions entry), :700 (Execute
entry), materializer/materializer.go:1615 (non-row-returning statement ExecContext).
The last count excludes internal receipt SQL and row-returning/query statements.
Query calls and ReadIndex separately account for removed query work.
None of these counters counts durable commits or S3 writes.

Latency ranges across the two independent runs, milliseconds:

| Scenario | Baseline P50 / P95 / P99 | Candidate P50 / P95 / P99 |
|---|---|---|
| Fresh | 10.68–11.86 / 14.54–16.37 / 20.46–22.89 | 10.14–11.96 / 14.79–15.15 / 21.13–23.67 |
| Touch due | 23.82–23.90 / 35.59–37.89 / 40.28–46.26 | 24.67–26.25 / 34.11–38.86 / 38.18–40.48 |
| Identical touch replay | 10.69–11.76 / 13.46–24.07 / 21.06–26.81 | 12.10–12.26 / 14.50–15.01 / 15.26–22.11 |
| Distinct losing touch | 23.29–25.43 / 34.22–38.21 / 35.37–45.78 | 20.46–22.55 / 29.24–32.38 / 38.43–56.87 |

These are nearest-rank percentiles of individual calls. N=40 makes P99 the
maximum; no statistical performance-win claim follows. The supported result is
one fewer Query/ReadIndex/apply invocation per success, unchanged successful
mutation invocation counts. Single-node ReadIndex has no quorum exchange.
There is no measured quorum-latency or S3-write saving.

[Per-process table](confirmation-108-processes.tsv) preserves both repetitions.
Raw JSON is retained locally at
/Users/cypark/.codex/task-state/goauthy-issue-loop/confirmation-108-measurements.jsonl;
logs and coverage profiles are in /tmp/goauthy-108-measure.

Reproduce each scenario (fresh, due, replay, loser), baseline flag (1, 0), twice:

    CONFIRMATION_BASELINE=1 GOAUTHY_CONFIRMATION_MEASURE=fresh GOMAXPROCS=4 scripts/test-confirmation-proof.sh ./internal/browser -run '^TestConfirmationMeasurement$' -count=1 -timeout=90s -covermode=atomic -coverpkg=github.com/mrchypark/rhiza/pkg/network,github.com/mrchypark/rhiza/pkg/materializer -coverprofile=/tmp/confirmation.cover -v

The baseline store is read from the pinned Git object into a temporary overlay;
no checkout reset, other repository edit, or dependency source modification occurs.
The helper remains the candidate helper in this comparison; its only production
change is the ErrCommitUnknown recovery branch, which these measurement cases
do not enter. Recovery behavior is compared separately by the baseline-helper
negative control and real durability tests, not inferred from these latencies.

## Negative controls

Two temporary source overlays were tested without altering the worktree:

1. Baseline storage/migrate.go restored from a4515ac. The rejected branch of
   TestExecuteRecoveryRequiresDurableExactReceipt failed in 1.84s: a locally
   rejected/precondition_failed receipt returned an ordinary rejection error
   instead of retaining ErrCommitUnknown while the before-ACK store was broken.
2. Creator mutant removed the INSERT expectation and accepted aggregate
   RowsAffected == 1. TestConfirmationAuthorityLossRollsBackCleanup/revoke
   failed in 9.54s: the one expired-row cleanup supplied the count, and the
   creator returned a token with nil error despite zero inserted rows.

The corrected implementation passed both original regression tests. Negative
logs and overlays are retained in /tmp/goauthy-108-negative. These are deliberate
expected failures, not failures of the candidate. Raw measurement JSON SHA256:
4e2ed176af36ee4d0e53c1e560d0c3fff332b9f645ecef27173b1dd85e4a2b0c.

A separate rejected-creation probe used the same 40-call/two-process-per-variant
protocol (160 total calls), with exactly one expired interaction seeded per call
and a deterministic revoke after the initial session read. All 160 outcomes were
not_found, no other error classes occurred. Baseline cleanup population went
1→0; candidate went 1→1. Setup restored authority for each new request.
The revoke injection was excluded from latency, as for competing touches above.

These four processes ran while the full correctness suite was active, so their
latencies are **contended-host observations**, not comparable performance rankings
against the earlier successful workload. P50/P95/P99 ranges in milliseconds:
baseline 18.95–41.72 / 42.19–72.83 / 54.28–96.14;
candidate 24.56–33.78 / 48.00–62.61 / 57.04–90.14.
Each P99 is again the per-process maximum.

The rejected path measured Query/call 2→1, Execute/call 1→1. Whole-process
ReadIndex 235→195 and applyDecisions 507→467; non-returning statement ExecContext
727 and network Execute 272 were unchanged. The extra setup/revoke/population
checks are included in these totals. Rolling back domain cleanup does not erase
the replicated rejection receipt or imply that a durable write was avoided.

Raw rejected samples:
/Users/cypark/.codex/task-state/goauthy-issue-loop/confirmation-108-rejections.jsonl
SHA256 ceac61153aab1cd47bff89a81b18227ccd565955bec1b83f728c6a524da3c5f6.
Reproduce with GOAUTHY_CONFIRMATION_MEASURE=rejected and the same command above.
The per-process table includes these rows; their latency population is rejection,
not successful requests.

## Validation record

All checks used Go go1.27.0 darwin/arm64. Focused race checks passed for:

- Ordinary creation cleanup, six authority-loss cases, genuine constraint
  failure, existing authorization-interaction and consumption-winner regressions.
- Overlay actual-request replay, populated receipt/error mapping (including
  Rhiza's quorum error), overlapping removal, both actual-request durability
  outcomes/restart, and captured-cutoff behavior.
- Shared storage receipt recovery, retained statement results, rejected receipt
  validation, envelope guards and exact-request fingerprint recovery.
- OAuth client-credentials cleanup guard and browser-session issuance/revocation
  races. Those reads and fences were not modified.

Representative commands:

    GOMAXPROCS=4 go test -race ./internal/browser -run '^TestConfirmationCreateCleanup$' -count=1 -timeout=180s
    GOMAXPROCS=4 go test -race ./internal/browser -run '^TestConfirmationAuthorityLossRollsBackCleanup$' -count=1 -timeout=180s
    GOMAXPROCS=4 go test -race ./internal/storage -run '^TestExecuteRecoveryRequiresDurableExactReceipt$' -count=1 -timeout=90s
    GOMAXPROCS=4 CONFIRMATION_RECOVERY_OVERLAY=1 scripts/test-confirmation-proof.sh -race ./internal/storage -run '^TestConfirmationRecoveryRechecksFingerprint$' -count=1 -timeout=90s

Run browser overlay race groups separately, each with -count=1 -timeout=180s:
TestConfirmationActualRequestReplay, TestConfirmationPopulatedReceiptErrors,
TestConfirmationOverlappingRemoval, TestConfirmationActualRequestDurabilityAndRestart,
TestConfirmationCapturedCutoff. All passed. The final quorum-sentinel case was
also checked separately after replacing the initial synthetic quorum error.

Two earlier combined race commands exhausted aggregate package budgets (240s
and 300s), during migration setup and a just-started consumption case respectively.
No assertion failure preceded those timeouts. They are retained in
/tmp/goauthy-108-overlay-race.log and /tmp/goauthy-108-focused-race.log.
Splitting groups preserved all assertions and individual bounded checks; it did
not alter production deadlines or skip the remaining tests. The latter log also
contains passing storage (23.374s) and OAuth (24.670s) package results.

Final split logs: /tmp/goauthy-108-race-*.log.
Final storage lifetime/recovery race: /tmp/goauthy-108-storage-final-race.log
(5.044s); fingerprint overlay: /tmp/goauthy-108-recovery-overlay-race-final.log
(2.937s). go vet -p 2 ./... and tagged browser/storage vet passed.
Formatting and git diff --check passed. Full-suite outcome is recorded below.

Full regression command completed successfully:

    GOMAXPROCS=4 go test -p 2 ./... -timeout=600s

All 74 listed packages completed without failure (storage 217.152s, browser
247.971s, login 74.880s, logout 19.456s, OAuth 74.742s). Log:
/tmp/goauthy-108-full.log. Environment-dependent E2E packages ran under their
normal local skip/configuration rules; no external cluster was provisioned.
Independent implementation review and Pro re-review remain pending.
