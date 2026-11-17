# goauthy-cimd-fixture

## Overview
Local HTTPS Client ID Metadata Document (CIMD) fixture server and loopback admin API for end-to-end CIMD tests (`[main.go:main]`). It serves deterministic valid, path-bound, malformed, and redirect-to-private-IP client metadata documents; it is not an identity provider.

## Interface
- Environment variables (`[main.go:configFromEnv]`):
  - `CIMD_FIXTURE_ADDR`: Public TLS listen address (default `:8443`).
  - `CIMD_FIXTURE_ADMIN_ADDR`: Loopback HTTP admin listen address (default `127.0.0.1:8082`).
  - `CIMD_FIXTURE_TLS_CERT_FILE`, `CIMD_FIXTURE_TLS_KEY_FILE`: Required TLS cert and key paths.
  - `CIMD_FIXTURE_CLIENT_ID`, `CIMD_FIXTURE_REDIRECT_URI`: Required exact HTTPS URLs sharing the same origin.
  - `CIMD_FIXTURE_PRIVATE_REDIRECT_URL`: Private/loopback HTTP(S) URL for redirect testing (default `https://127.0.0.1/sentinel`).
- Public HTTPS routes (`[main.go:state.documentHandler]`):
  - `GET/HEAD /good`, `/allow`, `/deny`, `/recovery`, `/mismatch`, `/invalid`, `/redirect-private`, `/sentinel`.
- Admin HTTP routes (`[main.go:state.adminHandler]`):
  - `GET /admin/state`: Returns request counts, document version, mode, and negative counters.
  - `POST /admin/document`: Sets mode (`"valid"` or `"invalid"`) and increments `document_version`.
  - `POST /admin/reset`: Resets counters and mode to defaults.

## Invariants
- `CIMD_FIXTURE_ADMIN_ADDR` must bind a loopback address `[main.go:loopbackAddr]`.
- `CIMD_FIXTURE_CLIENT_ID` and `CIMD_FIXTURE_REDIRECT_URI` must be exact HTTPS URLs sharing the same hostname and effective port `[main.go:exactHTTPSURL]`, `[main.go:sameOrigin]`.
- `CIMD_FIXTURE_PRIVATE_REDIRECT_URL` must resolve to a loopback, private, link-local, or unspecified IP address `[main.go:privateHTTPURL]`.
- Public TLS server enforces `MinVersion: tls.VersionTLS12` `[main.go:run]`.

## Side Effects
- Reads TLS certificate and key files from disk `[main.go:run]`.
- Binds two TCP listeners (public TLS and loopback admin HTTP) and handles `SIGINT`/`SIGTERM` for graceful shutdown `[main.go:run]`.
- Mutates mutex-protected in-memory `state` (`mode`, `version`, `requests`, `negative` counters) `[main.go:state]`.

## Verification
- Run: `go test ./...`
