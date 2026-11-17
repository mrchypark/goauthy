# goauthy-checkpoint-fault

## Overview
Test-only HTTP reverse proxy and control server used by the Kind disaster-recovery (DR) test (`[main.go:main]`). It intercepts S3/VersityGW checkpoint downloads, stalls after the first `32 KiB` (`stallBytes`) until released or cancelled, and allows tests to inspect partial writes and release the fault.

## Interface
- CLI subcommands (`[main.go:run]`):
  - No arguments: Runs the proxy and control HTTP servers.
  - `status`: Queries `GET http://<CONTROL_LISTEN>/status` and prints JSON (`blocked`, `partial_written`, `cancelled`, `released`) to stdout `[main.go:controlCommand]`, `[main.go:faultStatus]`.
  - `release`: Sends `POST http://<CONTROL_LISTEN>/release` to unblock the stalled response `[main.go:controlCommand]`.
- Environment variables (`[main.go:loadConfig]`):
  - `UPSTREAM`: Upstream HTTP/HTTPS URL (default `http://versity.goauthy.svc.cluster.local:9000`).
  - `LISTEN`: Proxy listen address (default `127.0.0.1:9001`, must be loopback).
  - `CONTROL_LISTEN`: Control listen address (default `127.0.0.1:9002`, must be loopback).
  - `DATA_DIR`: Absolute path to the data directory containing `.rhiza-checkpoint-restore-*` `[main.go:loadConfig]`.
  - `BLOCK_PATH`: URL path starting with `/` (no `?` or `#`) to fault on `GET` `[main.go:loadConfig]`.

## Invariants
- Both `LISTEN` and `CONTROL_LISTEN` must be loopback IP addresses `[main.go:loadConfig]`, `[main.go:isLoopbackAddress]`.
- Preserves original `r.Host` on proxied requests so SigV4 signatures remain valid `[main.go:newProxy]`.
- Faults at most once per run, only on `2xx` `GET` responses to `BLOCK_PATH` when a `.rhiza-checkpoint-restore-*` directory exists under `DATA_DIR` `[main.go:fault.shouldFault]`, `[main.go:newProxy]`.
- Error output on `os.Stderr` is a static string to avoid disclosing S3 credentials `[main.go:main]`.

## Side Effects
- Binds two loopback TCP listeners (`LISTEN` and `CONTROL_LISTEN`) and proxies HTTP traffic to `UPSTREAM` `[main.go:run]`.
- Reads `DATA_DIR/.rhiza-checkpoint-restore-*/sqlite.db` prefixes to verify partial write state `[main.go:restorePrefixMatches]`.

## Verification
- Run: `go test ./...`
