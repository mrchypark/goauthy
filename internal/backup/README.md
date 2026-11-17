# backup

## Overview
`internal/backup` implements encrypted, signed snapshot export, publication, catalog management, verification, restore, export, and retention pruning for Rhiza object-store backups using `age` encryption and Ed25519-signed catalog entries.

## Interface
- `[bundle.go:Limits]`, `[bundle.go:Entry]`, `[bundle.go:Inventory]`, `[bundle.go:Extracted]`, `[bundle.go:Write]`, `[bundle.go:Extract]`: Age-encrypted tar/bundle writer and bounded extractor.
- `[catalog.go:CatalogEntry]`, `[catalog.go:MaxCatalogTrustKeys]`, `[catalog.go:ValidateCatalogLocation]`, `[catalog.go:Publish]`, `[catalog.go:ListCompleted]`, `[catalog.go:FetchCompleted]`: Signed backup catalog publication, verification, listing, and retrieval.
- `[create.go:Create]`: Exports a fresh encrypted snapshot (with bounded retry on Rhiza moving-head/maintenance errors) and publishes its signed catalog entry to the destination bucket.
- `[export.go:Export]`, `[restore.go:Restore]`: Snapshot export from and restore to `objstore.Bucket`.
- `[manifest.go:SnapshotManifest]`, `[manifest.go:ManifestObject]`, `[manifest.go:MarshalManifest]`, `[manifest.go:ReadManifest]`: Snapshot manifest serialization and verification against extracted inventory.
- `[retention.go:RetentionPolicy]`, `[retention.go:Prune]`, `[retention.go:PruneWithPolicy]`, `[trim.go:TrimCatalog]`, `[trim.go:RetentionTarget]`: Age/count-based catalog and artifact retention pruning.
- `[errors.go:FailureMessage]`: Redacted/normalized failure message helper.

## Invariants
- Fail-closed publication & verification: `[create.go:Create]` retries only native Rhiza snapshot-acquisition errors before publication; any error (including cleanup errors after remote publication) fails closed. `[catalog.go:ListCompleted]` and `[catalog.go:FetchCompleted]` verify Ed25519 signatures against operator-pinned trust keys (`MaxCatalogTrustKeys = 32`).
- Private temporary staging: Local staging uses private temp files/directories under `workParent` and cleans them up on exit.
- Distinct catalog/source prefixes: `[catalog.go:ValidateCatalogLocation]` enforces valid, non-colliding catalog and source prefixes.

## Side Effects
- Reads and writes objects in `objstore.Bucket` (snapshots, manifests, and signed catalog entries).
- Creates and removes temporary files/directories under `workParent` on local disk.

## Verification
- Run: `go test ./internal/backup`
