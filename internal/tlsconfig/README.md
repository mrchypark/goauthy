# TLS Certificate Reloader (`internal/tlsconfig`)

## Overview
Loads and atomically hot-reloads X.509 server TLS certificates from disk for `tls.Config.GetCertificate`.

## Interface
- `[reloader.go:ErrNoCertificate]` — Sentinel error returned when no certificate is currently loaded.
- `[reloader.go:Reloader]` — Holds certificate/key paths and an `atomic.Pointer[tls.Certificate]`.
- `[reloader.go:New]` — Constructs a `Reloader` and performs an initial `Reload()`, returning an error if loading fails.
- `[reloader.go:Reloader.Reload]` — Reads and validates the PEM keypair via `tls.LoadX509KeyPair` and atomically stores it.
- `[reloader.go:Reloader.GetCertificate]` — Implements `tls.Config.GetCertificate`, returning the active certificate or `ErrNoCertificate`.

## Invariants
- The active certificate pointer is only replaced after `tls.LoadX509KeyPair` succeeds, preserving the previous valid certificate if a reload fails.
- Concurrent reads via `GetCertificate` and updates via `Reload` are lock-free via `atomic.Pointer`.

## Side Effects
- Reads certificate and private key PEM files from disk during `New` and `Reload`.

## Verification
- Run: `go test ./internal/tlsconfig`
