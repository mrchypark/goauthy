# backchannel

## Overview
`internal/backchannel` implements the OpenID Connect Back-Channel Logout delivery worker and dynamic root CA reloader. It claims durable logout notifications from `*rhiza.DB`, signs logout tokens, and delivers them over HTTP/HTTPS with DNS-rebinding protection.

## Interface
- `[ca.go:RootCAReloader]`, `[ca.go:NewRootCAReloader]`, `[ca.go:RootCAReloader.Reload]`, `[ca.go:RootCAReloader.Pool]`, `[ca.go:LoadRootCAs]`: Reloadable PEM trust-bundle loader that retains the last known-good `*x509.CertPool` if a projected Secret is temporarily incomplete or invalid.
- `[worker.go:Worker]`: Configurable delivery worker (`DB`, `Issuer`, `LoadSigningKey`, `WorkerID`, `TickInterval`, `RetryBase`, `LeaseDuration`, `RequestTimeout`, `MaxAttempts`, `TokenLifetime`, `RootCAs`, `RootCAReloader`, `AllowPrivate`, `AllowHTTP`, `OnError`).
- `[worker.go:ValidateEndpoint]`: Validates administratively configured backchannel logout URIs (scheme, host, port, and IP policy) without resolving hostnames upfront.
- `[worker.go:Worker.Run]`, `[worker.go:Worker.Step]`: Reconciles pending backchannel logout deliveries on a ticker or single step.

## Invariants
- DNS-rebinding & SSRF protection: `[worker.go:ValidateEndpoint]` checks literal IPs against `AllowPrivate`, and `[worker.go:Worker]` re-resolves and pins the target IP immediately before each delivery, respecting runtime `AllowPrivate` and `AllowHTTP` policy ceilings.
- Immutable runtime config: `[worker.go:Worker]` fields must not be mutated after `Run` begins.
- Bounded responses: HTTP responses from logout endpoints are capped at `responseBodyLimit` (`64 << 10`).

## Side Effects
- Acquires leases and updates delivery attempts/status in `*rhiza.DB` (and records events via `internal/eventlog`).
- Reads PEM CA bundle files from disk via `RootCAReloader`.
- Makes outbound HTTP(S) POST requests to client `backchannel_logout_uri` endpoints.

## Verification
- Run: `go test ./internal/backchannel`
