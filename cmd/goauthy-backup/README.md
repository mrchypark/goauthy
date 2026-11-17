# goauthy-backup

## Overview
Offline backup and restore CLI for Rhiza object-store snapshots using `age` encryption and Ed25519-signed immutable backup catalogs (`[main.go:main]`).

## Interface
- Subcommands (`[main.go:run]`, `[catalog.go:runCatalog]`, `[create.go:runCreate]`):
  - `export`: Exports an `age`-encrypted snapshot to `-file` and prints its SHA-256 hex digest. Flags: `-file`, `-key-file`, `-work-dir`, `-timeout`, `-max-files`, `-max-file-bytes`, `-max-total-bytes` `[main.go:run]`.
  - `restore`: Verifies `-sha256` against `-file`, decrypts with `-key-file`, and restores to object storage. Flags: same as `export` plus `-sha256` `[main.go:run]`.
  - `create`: Exports and publishes a signed backup catalog entry. Flags: `-recipient-file`, `-signing-key-file`, `-catalog-prefix`, `-work-dir`, `-timeout`, `-max-files`, `-max-file-bytes`, `-max-total-bytes` `[create.go:runCreate]`.
  - `publish`, `list`, `fetch`, `prune`: Manage signed completion records in `-catalog-prefix` (`-key-file`, `-file`, `-id`, `-work-dir`, `-max-bytes`, `-keep-days`, `-retention-policy`, `-apply`, `-max-entries`, `-timeout`) `[catalog.go:runCatalog]`.
- Environment variables: Storage and destination object-store settings via `storage.RhizaConfigFromEnv` and `backupconfig.DestinationConfig` `[main.go:run]`, `[create.go:backupDestinationConfig]`.

## Invariants
- Does not support the Rhiza `Local` archive format/profile `[main.go:run]`, `[catalog.go:runCatalog]`, `[create.go:runCreate]`.
- `export` and `fetch` publish artifacts via `os.Link` + directory `Sync` and never overwrite an existing `-file` `[main.go:run]`, `[catalog.go:runCatalog]`.
- `restore` requires a lowercase SHA-256 digest (`-sha256`), owner-only private key permissions (`0077` unset), and copies the artifact to `-work-dir` while hashing so extraction consumes only verified bytes `[main.go:run]`.
- Provider errors are sanitized via `backup.FailureMessage` before printing to `os.Stderr` to avoid leaking credential-bearing URLs `[main.go:main]`, `[main.go:backupFailureMessage]`.

## Side Effects
- Reads `age` keys, Ed25519 catalog keys, and backup artifacts from disk; creates temporary staging files in `-work-dir` and destination directories `[main.go:run]`, `[catalog.go:runCatalog]`, `[create.go:runCreate]`.
- Connects to, reads from, and writes/deletes objects in Rhiza/destination object stores `[main.go:run]`, `[catalog.go:runCatalog]`, `[create.go:runCreate]`.

## Verification
- Run: `go test ./...`
