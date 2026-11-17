# e2e-stage-supervisor-src

## Overview
Standalone Go module (`goauthy.local/e2e-stage-supervisor`, Go 1.25.0) implementing `e2e-stage-supervisor`, a process-group supervisor for `darwin` and `linux` E2E test stages. Built on demand by [`../e2e-stage-supervisor.sh`](../e2e-stage-supervisor.sh) to ensure child and descendant processes (such as `go test` subprocesses) are terminated cleanly when a stage exits or receives a signal.

## Interface
- `main.go` (`//go:build darwin || linux`):
  - CLI: `e2e-stage-supervisor command [args...]` (prints usage to stderr and exits `2` if fewer than 2 args are provided).
  - Spawns `command` with `SysProcAttr{Setpgid: true}`, inheriting `Stdin`, `Stdout`, and `Stderr`.
  - Signals handled: `SIGTERM`, `SIGINT`, `SIGHUP` (returns `128 + signal`).
  - `groupAbsent(pgid int) bool`, `waitAbsent(pgid int, limit time.Duration) bool`, `exitStatus(err error) int`.
- `go.mod` — Standalone module definition (`module goauthy.local/e2e-stage-supervisor`, `go 1.25.0`).
- `main_test.go` — Unit tests for supervisor process-group isolation and cleanup.

## Invariants
- The spawned child's process group ID must equal `cmd.Process.Pid` and differ from the supervisor's own `Getpgrp()`; if group creation cannot be verified, the child PID is killed immediately and the supervisor exits `1`.
- On child exit with surviving group members or on `SIGTERM`/`SIGINT`/`SIGHUP`, `SIGTERM` is sent to `-pgid` with a `75s` wait window before escalating to `SIGKILL` for `5s`.
- If processes still remain after `SIGKILL`, exits `1` and preserves private fixture diagnostics rather than returning `0`.

## Side Effects
- Creates a new OS process group (`Setpgid: true`) and sends `SIGTERM`/`SIGKILL` to `-pgid`.
- Writes diagnostic messages to `stderr`.

## Verification
- Run: `cd scripts/e2e-stage-supervisor-src && go test ./...`
