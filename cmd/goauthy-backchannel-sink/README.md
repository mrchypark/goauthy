# goauthy-backchannel-sink

## Overview
Test-only Relying Party (RP) back-channel logout endpoint (`[main.go:main]`) for verifying OpenID Connect Back-Channel Logout deliveries. It keeps bounded observations in memory and never logs request data that may contain signed logout tokens.

## Interface
- Environment variables:
  - `LISTEN_ADDR`: HTTP/HTTPS listen address (default `:8081`) `[main.go:run]`
  - `FAIL_FIRST`: Non-negative integer controlling how many valid requests fail with `503` before succeeding (default `1`) `[main.go:failFirstFromEnv]`
  - `TLS_CERT_FILE`, `TLS_KEY_FILE`: Optional TLS certificate and key pair (must be set together) `[main.go:tlsFilesFromEnv]`
- HTTP routes (`[main.go:sink.handler]`):
  - `POST /backchannel`: Accepts `application/x-www-form-urlencoded` body (max `8 KiB`, `[main.go:maxRequestBody]`) with exactly one non-empty `logout_token` parameter and no query string `[main.go:sink.backchannel]`.
  - `POST /control`: Accepts JSON (`maxControlBody` = `1 KiB`) with `fail_first`, `delay_first_ms`, and `success_status` (`200` or `204`) to reconfigure and reset observations `[main.go:sink.control]`.
  - `GET /events`: Returns recorded observations as JSON `[main.go:sink.events]`.
  - `GET /livez`: Liveness probe returning `204 No Content` `[main.go:sink.livez]`.

## Invariants
- In-memory observations are capped at `maxEvents` (`128`), evicting oldest entries `[main.go:sink.record]`, `[main.go:sink.recordValid]`.
- Request data (including `logout_token`) is never written to logs (`ErrorLog: log.New(io.Discard, "", 0)`) `[main.go:run]`.
- Delayed `503` responses abort and mark `Status = 0` if the client disconnects before `delay_first_ms` elapses `[main.go:sink.backchannel]`, `[main.go:sink.cancel]`.
- TLS enforces `MinVersion: tls.VersionTLS12` and HTTP/1.1 (`NextProtos: []string{"http/1.1"}`) `[main.go:run]`.

## Side Effects
- Binds a TCP (or TLS) HTTP server on `LISTEN_ADDR` and handles `SIGINT`/`SIGTERM` for graceful shutdown `[main.go:run]`.
- Reads optional TLS cert/key files from disk `[main.go:tlsFilesFromEnv]`.
- Mutates mutex-protected in-memory `sink` state (`observations`, `attempts`, `valid`, `config`) `[main.go:sink]`.

## Verification
- Run: `go test ./...`
