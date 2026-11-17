# goauthy-password-calibrate

## Overview
Benchmarking CLI that measures bounded Argon2id parameter candidates (`iterations` 5 down to 2) against a target duration without modifying any configuration (`[main.go:main]`).

## Interface
- CLI flags (`[main.go:run]`):
  - `-target`: Target Argon2id duration (`500ms..10s`, default `500ms`)
  - `-memory-kib`: Argon2id memory in KiB (`32768..131072`, default `32768`)
  - `-parallelism`: Argon2id parallelism (`2..8`, default `min(runtime.NumCPU(), 8)`)
  - `-samples`: Odd measurement sample count (`1`, `3`, or `5`, default `3`)
- Output (`[main.go:recommendation]`):
  - Writes a JSON array of `{iterations, memory_kib, parallelism, median_ms, within_target}` objects to `os.Stdout`.

## Invariants
- Positional arguments are rejected `[main.go:run]`.
- Flag bounds are strictly enforced: `minTarget` (`500ms`)..`maxTarget` (`10s`), `minMemoryKiB` (`32768`)..`maxMemoryKiB` (`131072`), `minParallelism` (`2`)..`maxParallelism` (`8`), and `samples` in `{1, 3, 5}` `[main.go:run]`.
- Uses fixed synthetic calibration input and salt strings (`argon2.IDKey`) `[main.go:measure]`.

## Side Effects
- Performs CPU/memory-intensive Argon2id hashing and writes JSON results to `os.Stdout` (or errors to `os.Stderr`) `[main.go:main]`, `[main.go:measure]`.

## Verification
- Run: `go test ./...`
