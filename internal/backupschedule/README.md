# backupschedule

## Overview
`internal/backupschedule` provides cron-like schedule parsing, next-run calculation, distributed KV lease acquisition, and idempotent slot execution for automated backups backed by `*rhiza.DB`.

## Interface
- `[parse.go:Schedule]`, `[parse.go:Parse]`: Parses cron schedule expressions into a `Schedule`.
- `[next.go:Schedule.Next]`: Computes the next scheduled execution time after a given timestamp.
- `[lease.go:WithLease]`: Acquires a scoped distributed KV lease in `*rhiza.DB` with TTL `ttl` and runs `job` while holding the lease, returning whether the lease was acquired.
- `[slot.go:ErrCompletionRead]`, `[slot.go:RunSlot]`: Executes a due `job` under `WithLease` only if the durable completion watermark for `scope` has not already reached `due`, advancing the watermark via `db.KVCAS` after success.
- `[run.go:Schedule.Run]`: Runs the scheduling loop for `scope` in `location`, invoking `job` via `RunSlot` and reporting outcomes to `report`.

## Invariants
- Monotonic compare-and-swap watermark: `[slot.go:RunSlot]` never issues an unconditional KV put; it advances `goauthy/backup-completed/<sha256(scope)>` via `db.KVCAS` so a stale lease holder cannot overwrite a successor's completion marker.
- Slot time bounds: `[slot.go:RunSlot]` rejects `nil` jobs, non-positive/sub-second/future `due` timestamps, or years beyond `2100`.
- Lease-guarded execution: `job` is only invoked when `WithLease` succeeds and `work.Err()` is nil.

## Side Effects
- Reads and writes lease and completion-watermark keys in `*rhiza.DB` KV storage.
- Runs timers/sleeps in `[run.go:Schedule.Run]`.

## Verification
- Run: `go test ./internal/backupschedule`
