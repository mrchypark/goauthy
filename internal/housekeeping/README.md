# housekeeping

## Overview
`housekeeping` provides a lightweight goroutine scheduler for periodic and wake-triggered background maintenance jobs.

## Interface
- `Job`, `Scheduler`, `New`, and `Scheduler.Run` in [housekeeping.go](file:///Users/cypark/Documents/project/goauthy/internal/housekeeping/housekeeping.go#L9-L38).

## Invariants
- Each `Job` runs immediately once on `Scheduler.Run` (unless `ctx` is already canceled) and thereafter on `job.Interval` ticks or `job.Wake` signals ([housekeeping.go:runJob](file:///Users/cypark/Documents/project/goauthy/internal/housekeeping/housekeeping.go#L40-L62)).
- `Scheduler.Run` blocks until `ctx` is canceled and all spawned job goroutines exit; errors returned while `ctx.Err() == nil` are forwarded to `onError` ([housekeeping.go:Run](file:///Users/cypark/Documents/project/goauthy/internal/housekeeping/housekeeping.go#L29-L45)).

## Side Effects
- Spawns one goroutine per `Job` with a `time.Ticker` and invokes `job.Step(ctx)` and `onError`.

## Verification
- Run: `go test ./internal/housekeeping`
