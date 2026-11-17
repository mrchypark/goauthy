# e2e-saas-isolation-fixture

## Overview
Bounded local HTTPS SaaS provider fixture used only by the opt-in `#113` topology measurement (`[main.go:main]`). It simulates healthy, slow-headers, slow-body, and failing upstream SaaS endpoints while tracking per-route concurrency and completion metrics.

## Interface
- CLI binary (`package main`, `[main.go:main]`):
  - `-addr`: HTTPS listen address (default `:443`) `[main.go:parseOptions]`
  - `-cert`: TLS certificate file path (required) `[main.go:parseOptions]`
  - `-key`: TLS private key file path (required) `[main.go:parseOptions]`
  - `-token-file`: Optional private file containing the expected synthetic bearer token; without it only `/metrics` is accessible `[main.go:parseOptions]`
- HTTP routes (`[main.go:fixture.ServeHTTP]`):
  - `GET /metrics`: Returns JSON `started`, `active`, and `completed` atomic counters per route.
  - `GET /healthy`, `GET /slow-headers`, `GET /slow-body`, `GET /fail`: Bearer-authenticated synthetic SaaS endpoints.

## Invariants
- Positional CLI arguments are rejected; `-cert` and `-key` are mandatory `[main.go:parseOptions]`.
- `-token-file` must be a regular file with `0077` permission bits unset (no group/other permissions), max 4096 bytes (`[main.go:maxTokenFileBytes]`), and contain a single non-empty token without whitespace `[main.go:readTokenFile]`.
- Bearer token verification uses SHA-256 + `subtle.ConstantTimeCompare` `[main.go:fixture.authorized]`.
- Routes reject non-GET methods (`405`), query strings (`404`), and unknown paths (`404`) `[main.go:fixture.ServeHTTP]`.
- `slow-headers` and `slow-body` are bounded by `slowLimit` (`20s`) or client request cancellation `[main.go:waitForCancellationOrLimit]`.
- TLS enforces `MinVersion: tls.VersionTLS12` and HTTP/1.1 only (`NextProtos: []string{"http/1.1"}`) `[main.go:run]`.

## Side Effects
- Reads the TLS cert/key files and optional token file from disk `[main.go:run]`.
- Binds a TCP/TLS listener on `-addr` and handles `SIGINT`/`SIGTERM` for graceful shutdown `[main.go:run]`.
- Mutates in-memory `atomic.Int64` route counters per request `[main.go:routeCounts]`.

## Verification
- Run: `go test ./...`
