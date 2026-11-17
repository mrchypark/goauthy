# apikey

## Overview
`internal/apikey` implements narrowly scoped API keys (`API-Key <name>$<secret>`), their RBAC group/right authorization, idempotent/guarded SQL mutations, bootstrap loading (including master-key-encrypted and generated-secret modes), and the browser-admin HTTP management surface.

## Interface
- `[store.go:Right]`, `[store.go:Read]`, `[store.go:Create]`, `[store.go:Update]`, `[store.go:Delete]`: Access-right enum and constants.
- `[store.go:GroupAPIKeys]`: Group name constant (`"ApiKeys"`).
- `[store.go:ErrUnauthorized]`, `[store.go:ErrForbidden]`, `[store.go:ErrInvalid]`, `[store.go:ErrNotFound]`: Store error sentinels.
- `[store.go:Access]`, `[store.go:Key]`, `[store.go:Request]`, `[store.go:Principal]`: Domain models for key grants, metadata, mutation requests, and authenticated principals.
- `[store.go:Store]`, `[store.go:NewStore]`: Store backed by `*rhiza.DB`.
- `[store.go:Store.Authenticate]`, `[store.go:Store.Authorize]`, `[store.go:Store.AuthorizationGuard]`, `[store.go:Store.AuthorizationSnapshot]`, `[store.go:Store.AuthorizationSnapshotAt]`: Authentication and SQL authorization guard helpers.
- `[store.go:Store.Create]`, `[store.go:Store.List]`, `[store.go:Store.Get]`, `[store.go:Store.Update]`, `[store.go:Store.Delete]`, `[store.go:Store.Rotate]`, `[store.go:Store.ListAuditEvents]`: Key CRUD, secret rotation, and guarded audit-event listing.
- `[store.go:GuardExistsSQL]`, `[store.go:Store.RunMutation]`, `[store.go:Store.RunDelegatedMutation]`, `[store.go:Store.RunEnvelopeMutation]`: Replicated mutation runners that attach authorization guards and audit/idempotency fences.
- `[bootstrap.go:ErrUnsupportedSecret]`, `[bootstrap.go:ValidateBootstrapFile]`, `[bootstrap.go:Store.Bootstrap]`, `[bootstrap.go:Store.BootstrapWithMasterKeyDir]`, `[bootstrap.go:Store.BootstrapWithGeneratedSecrets]`: Atomic bootstrap loaders for declarative API-key provisioning.
- `[bootstrap_secret.go:ErrGeneratedBootstrapExpired]`, `[bootstrap_secret.go:BootstrapSecretEntry]`, `[bootstrap_secret.go:WriteGeneratedBootstrapSecrets]`, `[bootstrap_secret.go:ReadGeneratedBootstrapSecrets]`, `[bootstrap_secret.go:PurgeGeneratedBootstrapSecrets]`, `[bootstrap_shared.go]`: Master-key envelope decryption and generated-secret bootstrap artifact helpers.
- `[http.go:Handler]`, `[http.go:NewHandler]`, `[http.go:Handler.Keys]`, `[http.go:Handler.Key]`, `[http.go:Handler.Secret]`, `[http.go:Authorization]`, `[http.go:HasAuthorization]`: HTTP handlers for `/auth/v1/api_keys` and bearer/header extraction.

## Invariants
- Constant-time digest verification: `[store.go:Store.Authenticate]` validates key name/secret syntax and compares SHA-256 digests with `subtle.ConstantTimeCompare` on linearizable reads.
- Browser-admin-only key management: `[http.go:Handler]` permits API keys only for self-test (`GET` on their own key); creating, updating, rotating, or deleting keys requires `browserAdmin`.
- Plaintext secret isolation: Bootstrap and store paths never persist or log raw secrets; only SHA-256 digests are passed to Rhiza SQL statements, and master keys are wiped after use.
- Bounded bootstrap batches: `[bootstrap.go]` enforces `maxBootstrapFileBytes` (1 MiB) and `maxBootstrapStatements` (64) per atomic Rhiza transaction.

## Side Effects
- Queries and mutates `api_keys`, `api_key_access`, and `audit_events` tables in `*rhiza.DB`.
- Reads bootstrap JSON files and master-key directories from disk, and may write generated-secret artifacts.
- Invokes `OnAuthFailure` callback on invalid/expired secret attempts.

## Verification
- Run: `go test ./internal/apikey`
