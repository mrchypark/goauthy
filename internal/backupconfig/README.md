# backupconfig

## Overview
`internal/backupconfig` reads and validates local `age` recipient files, Ed25519 catalog signing/trust keys, and destination object-store configurations shared by the backup CLI and the in-process backup scheduler.

## Interface
- `[config.go:ReadRecipients]`: Reads a bounded (<= 1 MiB), regular `age` recipient file and requires at least one recipient.
- `[config.go:ReadCatalogKey]`: Reads either a single PKCS#8 Ed25519 private signing key or a single PKIX public trust key from PEM.
- `[config.go:ReadCatalogTrustKeys]`: Reads an operator-pinned PEM bundle of Ed25519 public trust keys (never keys from a remote catalog).
- `[config.go:DestinationConfig]`: Builds a destination `rhiza.Config` from environment lookup (`getenv`) and the source `rhiza.Config`.

## Invariants
- Strict regular-file & size bounds: `[config.go:ReadRecipients]`, `[config.go:ReadCatalogKey]`, and `[config.go:ReadCatalogTrustKeys]` reject non-regular files (e.g., directories/devices) and enforce size caps (`1 << 20` for recipients).
- Single-key & Ed25519-only enforcement: `[config.go:ReadCatalogKey]` requires a single `PRIVATE KEY` PKCS#8 PEM block containing an `ed25519.PrivateKey` when `private=true`, or a single native PEM public key when `private=false`.
- Operator-pinned trust: Trust keys are loaded strictly from local operator-supplied files, never from untrusted catalog metadata.

## Side Effects
- Opens and reads key/recipient files from the local filesystem.
- Reads environment variables via the supplied `getenv` function.

## Verification
- Run: `go test ./internal/backupconfig`
