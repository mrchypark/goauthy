# PR123 backup deadline CI diagnosis

Target: `634339cf257873fd6f557d24a3a47ad1f5d24c93`; Unit run
36401050786, job 108858738090. No CI rerun or cancellation was requested.
The original log remains at
`/Users/cypark/.codex/task-state/goauthy-issue-loop/pr123-unit.log`, SHA-256
`01d9213432b645a040240deb316f3cb77da89638e3b5cd7a636e1710a5e5f9aa`.

## Finding

The exact failure is reproducible without the #108 SQL helper. This is a
pre-existing test scheduling assumption plus a pinned Rhiza diagnostic defect,
not evidence of a random request-ID collision or a confirmation-read regression.
The CI log alone cannot establish which underlying lookup error occurred there;
the controlled reproduction establishes a deadline-expiry mechanism yielding
exactly the same error chain.

`Schedule.Run` (`internal/backupschedule/run.go`) gives an attempt two seconds in
`TestRunDeadlineCancelsJobAndStops`. `RunSlot` enters `WithLease`, reads the
completion watermark, and calls the job. The test grants a one-second lease.
`WithLease` renews every ttl/3 and independently limits each CAS to ttl/3 (333 ms).
If renewal loses confirmation before the attempt deadline, it correctly cancels
the job with `ErrLeaseLost`. The job returns `context.Canceled`. The test requires
`context.DeadlineExceeded`, assuming renewal always succeeds until the attempt
expires. Its acquisition-headroom comment does not account for renewal.

Every acquisition, renewal, conditional expiry, and completion-watermark mutation
creates a fresh `crypto/rand.Text()` request ID. The holder token is reused for
ownership comparison, not as a request ID. Conditional expiry cannot delete a
successor. Failed jobs never advance the completion watermark.

Pinned Rhiza v0.12.3 `rhiza.go:447` forwards KVCAS directly to its network server.
`pkg/network/server.go:1118-1119` maps **either** a post-submit
`KVRequestMatches` error **or** an actual fingerprint mismatch to
`ErrRequestConflict`. `pkg/materializer/materializer.go:574-591` uses
`QueryRowContext` and returns its error; an expired context therefore becomes a
misleading conflict. The KV fingerprint excludes observed/expiry timestamps
(`internal/types/value.go:305-313`); changing server admission time is not a
fingerprint conflict.

The sole production scheduler caller is `scheduledBackupRuntime.Run` in
`cmd/goauthy/backup.go:212`. It reports a failed attempt and preserves cooperative
ownership cancellation. The backup CLI's scheduler use is in a test. No lease
path calls `storage.Execute`; #108 changed that SQL helper and browser creation,
not these KV operations, the scheduler, or the dependency version. The scheduler
and go.mod/go.sum diff from a4515ac is empty.

## Deterministic experiment

Go 1.27.0 darwin/arm64, Apple M1, GOMAXPROCS=4. A temporary copy of the pinned
module and a temporary modfile/Go overlay were used; neither the module cache,
other repositories, nor repository dependencies were edited. Go disallows
module-cache overlays directly, hence the copy. Immediately after successful KV
submit, before the post-submit matches lookup, the overlay inserts:

```go
if req.ExpectedExists && req.TTLMS == 1000 { <-ctx.Done() }
```

This affects the one-second renewal only, not acquisition or one-millisecond
release. It deterministically models descheduling across the renewal deadline;
there is no sleep or retry. Diagnostic output inside the existing error branch
prints the lookup error and context error. The original test and assertions run
unchanged. The ordinary reproduction failed in 1.56 seconds with:

```
executed=true err=context canceled
backup job lease lost
request ID conflict
```

Temporary reproduction inputs/logs: `/tmp/goauthy-pr123-lease-proof/`.
Commands use `go test -modfile=.../proof.mod -overlay=.../overlay.json
./internal/backupschedule -run '^TestRunDeadlineCancelsJobAndStops$' -count=1
-timeout=40s`, and the same command with `-race -count=3 -timeout=60s`.

## Scope and unresolved repair

No production or assertion change is justified by this evidence. Continuing a
job after ambiguous renewal would violate ownership. Joining a renewal deadline
into the result merely to satisfy the attempt-deadline assertion would conceal
which timer fired. A longer TTL or accepting lease loss would hide the scheduling
assumption rather than deterministically test attempt expiry.

A proper follow-up should isolate the dispatcher's attempt-deadline test from
real consensus renewal scheduling while retaining real lease-loss/renewal tests;
that requires an explicit, small test seam or a separately agreed integration
test contract. The pinned dependency's masked lookup error is an upstream defect,
but fixing its diagnostic alone would not guarantee renewal succeeds under load.
No dependency patch/upgrade or speculative GoAuthy production fix is included.
This diagnosis does not turn the failed CI run green or claim PR123 acceptance.

## Completed checks

- Unmodified `GOMAXPROCS=4 go test -race ./internal/backupschedule -count=3
  -timeout=180s`: PASS, 57.801s; all existing package tests, no race report.
- Controlled post-apply deadline overlay with `-race -count=3`: expected FAIL
  in all three repetitions, 4.067s total. Each prints
  `matches=false lookup=context deadline exceeded context=context deadline exceeded`
  with a distinct random request ID, then the exact CI error chain. This is a
  negative-control result, not a passing regression test.
- No CI rerun, race-job cancellation, production edit, dependency change, or
  timeout/assertion relaxation. The original CI failure remains unresolved.
