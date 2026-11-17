# goauthy-rhiza-init

## Overview
Pre-start initialization binary that opens and closes Rhiza Local storage to perform crash recovery before the main `goauthy` application starts (`[main.go:main]`).

## Interface
- Environment variables (`[main.go:main]`):
  - `GOAUTHY_RHIZA_PROFILE`: Must equal `storage.RhizaProfileStandaloneLocal` (`"standalone-local"`).
  - Storage configuration environment variables consumed by `storage.RhizaConfigFromEnv`.

## Invariants
- Accepts no positional CLI arguments `[main.go:main]`.
- Requires `GOAUTHY_RHIZA_PROFILE=standalone-local` `[main.go:main]`.
- Requires `config.Local == true` and `config.ObjStoreDurability == rhiza.ObjectStoreDurabilityBeforeAck` `[main.go:run]`.
- Bounded by a 2-minute timeout context and `SIGINT`/`SIGTERM` signal cancellation `[main.go:main]`.

## Side Effects
- Opens and immediately closes the Rhiza database (`rhiza.Open` / `db.Close`), replaying/recovering local storage state on disk/object store `[main.go:run]`.

## Verification
- Run: `go test ./...`
