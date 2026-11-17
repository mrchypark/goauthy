# goauthy-password

## Overview
CLI utility that reads a plaintext password from stdin and prints an Argon2id PHC credential string to stdout (`[main.go:main]`).

## Interface
- CLI flags (`[main.go:policyFromArgs]`):
  - `-memory-kib`: Argon2 memory in KiB (default from `credential.DefaultPolicy()`)
  - `-iterations`: Argon2 iterations (default from `credential.DefaultPolicy()`)
  - `-parallelism`: Argon2 parallelism (default from `credential.DefaultPolicy()`)
- Stdin/Stdout (`[main.go:run]`):
  - Reads a single-line password from `os.Stdin` and prints the PHC hash to `os.Stdout`.

## Invariants
- Accepts no positional CLI arguments `[main.go:policyFromArgs]`.
- Numeric flags must be strict unsigned decimal integers (no signs, leading zeros, or non-digits) and pass `credential.NewHasher(policy)` validation `[main.go:flagUint]`, `[main.go:policyFromArgs]`.
- Password input must be non-empty, single-line (optional trailing `\r\n` or `\n`), and at most `maxPasswordBytes` (`1024`) bytes `[main.go:readPassword]`.

## Side Effects
- Reads password bytes from `os.Stdin`, computes Argon2id hash via `internal/credential`, and writes the PHC string to `os.Stdout` (or errors to `os.Stderr`) `[main.go:main]`, `[main.go:run]`.

## Verification
- Run: `go test ./...`
