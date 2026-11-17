# goauthy-bootstrap-secrets

## Overview
CLI utility to explicitly retrieve or purge an encrypted generated-secret bootstrap artifact (`[main.go:main]`). Retrieval writes decrypted secrets to stdout as JSON so secrets are never emitted to application logs.

## Interface
- CLI binary (`package main`, `[main.go:main]`):
  - `-file`: Path to the encrypted generated-secret artifact (required) `[main.go:run]`
  - `-key-dir`: Path to the master-key directory (required) `[main.go:run]`
  - `-purge-expired`: Boolean flag (default `false`); when true, removes only an authenticated expired artifact and outputs `{"removed": <bool>}` `[main.go:run]`

## Invariants
- Both `-file` and `-key-dir` are required and positional arguments are rejected `[main.go:run]`.
- Delegates artifact decryption and expiration-checked purging to `apikey.ReadGeneratedBootstrapSecrets` and `apikey.PurgeGeneratedBootstrapSecrets` `[main.go:run]`.
- Errors are written to `os.Stderr` and exit with status `1` `[main.go:main]`.

## Side Effects
- Reads encrypted bootstrap artifact and master keys from disk via `internal/apikey` `[main.go:run]`.
- With `-purge-expired`, deletes the expired artifact file on disk `[main.go:run]`.
- Writes decrypted bootstrap secrets (or purge status JSON) to `os.Stdout` `[main.go:run]`.

## Verification
- Run: `go test ./...`
