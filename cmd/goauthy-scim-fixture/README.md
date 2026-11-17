# goauthy-scim-fixture

## Overview
Deterministic, test-only SCIM 2.0 user and group provisioning provider with a loopback admin control plane (`[main.go:main]`). Supports simulating success, temporary `503`, permanent `400`, and connection-drop failure modes.

## Interface
- Environment variables (`[main.go:configFromEnv]`):
  - `SCIM_FIXTURE_ADDR`: Public HTTPS listen address (default `:8444`)
  - `SCIM_FIXTURE_ADMIN_ADDR`: Loopback HTTP admin listen address (default `127.0.0.1:8083`)
  - `SCIM_FIXTURE_TLS_CERT_FILE`, `SCIM_FIXTURE_TLS_KEY_FILE`: Required TLS cert and key paths
  - `SCIM_FIXTURE_BEARER_TOKEN`: Required bearer token (1..1024 non-whitespace-padded bytes)
- Public SCIM routes (`[main.go:state.serveSCIM]`):
  - `/scim/v2/Users` (`GET`, `POST`) and `/scim/v2/Users/{id}` (`GET`, `PUT`, `PATCH`, `DELETE`)
  - `/scim/v2/Groups` (`GET`, `POST`) and `/scim/v2/Groups/{id}` (`GET`, `PUT`, `DELETE`)
- Loopback admin routes (`[main.go:state.adminHandler]`):
  - `POST /admin/reset`, `POST /admin/mode` (`success`, `temporary`, `permanent`, `drop`), `GET /admin/state`, `GET /admin/calls`, `GET /admin/count`.

## Invariants
- `SCIM_FIXTURE_ADMIN_ADDR` must bind a loopback IP `[main.go:loopbackAddr]`.
- Public SCIM requests require `Authorization: Bearer <SCIM_FIXTURE_BEARER_TOKEN>` `[main.go:state.serveSCIM]`.
- In-memory storage is bounded (`maxUsers` = `1024`, `maxGroups` = `1024`, `maxCalls` = `1024`, `maxBody` = `8 KiB`) `[main.go:validTarget]`.
- Public TLS enforces `MinVersion: tls.VersionTLS12` and HTTP/1.1 (`NextProtos: []string{"http/1.1"}`) `[main.go:run]`.

## Side Effects
- Reads TLS cert/key files from disk and binds public TLS and loopback admin HTTP listeners `[main.go:run]`.
- Mutates mutex-protected in-memory `users`, `groups`, `calls`, and `mode` state `[main.go:state]`.

## Verification
- Run: `go test ./...`
