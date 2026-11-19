# Storage & Rhiza Persistence (`internal/storage`)

## Overview
Owns embedded Rhiza database configuration, schema migrations (`schemaVersion = 116`), object-store opening (S3/GCS), master-key retirement fencing/barrier state machine, envelope writer admission, DCR software-statement trust fencing, and passkey cookie retention watermarks.

## Interface
- `[config.go:RhizaConfigFromEnv]` — Builds `rhiza.Config` for supported profiles (`RhizaProfileStandalone`, `RhizaProfileStandaloneLocal`, `RhizaProfileDev`, `RhizaProfileCluster`).
- `[migrate.go:Migrate]`, `[migrate.go:Execute]`, `[migrate.go:Ready]` — Idempotent schema migration runner, linearizable/replicated statement execution wrapper, and readiness probe.
- `[object_store.go:OpenObjectStore]` — Opens S3 or GCS `objstore.Bucket` from `rhiza.Config` without opening a database.
- `[envelope.go:CheckEnvelopeWriterAllowed]`, `[envelope.go:ExecuteEnvelope]` — Admission check and transactional fence ensuring fenced or retired master-key writers cannot persist new ciphertext references.
- `[master_key_retirement.go:MasterKeyRetirement]` & lifecycle types/functions — `MasterKeyRetirementAuthorization`, `MasterKeyRetirementPrepareRequest`, `MasterKeyRetirementStatus`, `MasterKeyRetirementAttestationRequest`, `MasterKeyRetirementAttestation`, `PrepareMasterKeyRetirement`, `PrepareMasterKeyRetirementGuarded`, `AttestMasterKeyRetirement`, `AttestMasterKeyRetirementGuarded`, `FenceMasterKeyRetirement`, `FenceMasterKeyRetirementGuarded`, `ReadyMasterKeyRetirement`, `ReadyMasterKeyRetirementGuarded`, `AbortMasterKeyRetirement`, `AbortMasterKeyRetirementGuarded`, `LoadMasterKeyRetirement`, `LoadMasterKeyRetirementGuarded`, `AcknowledgeMasterKeyRetirementArchival`, `MarkMasterKeyRetirementGenerationRemoved`, `LoadMasterKeyRetirementGenerations`, `MasterKeyRetirementProhibitsWriter`.
- `[software_statement.go:EnsureDCRSoftwareStatementTrust]`, `[software_statement.go:CheckDCRSoftwareStatementTrust]`, `[software_statement.go:DCRTopologyDigest]`, `[software_statement.go:ErrDCRSoftwareStatementTrustMismatch]` — Fences static DCR software-statement trust policy against the replicated DB.
- `[passkey_cookie_retention.go:RegisterPasswordlessCookieKeyTTL]`, `[passkey_cookie_retention.go:PasswordlessCookieKeyTTL]` — Monotonic per-key lifetime high-water mark in `passkey_cookie_key_retention`.

## Invariants
- `[envelope.go:ExecuteEnvelope]` appends an atomic barrier check (`UPDATE master_key_retirement_barrier SET epoch=-1 WHERE ...`) in the same replicated transaction so fenced or retired writers roll back all preceding statements.
- `[master_key_retirement.go]` enforces monotonic epochs and state transitions (`prepared` -> `fenced` -> `ready`, or `aborted`) and records retired keys permanently in `master_key_retirement_generations`.
- `[config.go:RhizaConfigFromEnv]` rejects cluster/object-store env vars under `RhizaProfileDev` and S3-only env vars under GCS.
- `[passkey_cookie_retention.go:RegisterPasswordlessCookieKeyTTL]` only increases `max_ttl_ns` monotonically.

## Side Effects
- Executes DDL/DML against `*rhiza.DB` (creating/migrating tables and updating retirement/trust/retention state).
- Reads `GOAUTHY_RHIZA_*` environment variables and opens external S3/GCS buckets.

## Verification
- Run: `go test ./internal/storage`
