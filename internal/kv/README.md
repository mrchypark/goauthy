# kv

## Overview
`kv` implements namespace-scoped JSON key-value storage in Rhiza with optional per-row envelope encryption, namespace-scoped Bearer credentials, keyset pagination, and an HTTP admin/runtime API under `/auth/v1/kv`.

## Interface
- Store and models: `ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`, `ErrBadRequest`, `ErrConflict`, `ErrCorrupt`, `Namespace`, `Access`, `Value`, `Store`, and `NewStore` in [store.go](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L21-L65).
- Namespace, access, and value operations: `Store.ListNamespaces`, `Store.Namespace`, `Store.PutNamespace`, `Store.DeleteNamespace`, `Store.Accesses`, `Store.CreateAccess`, `Store.UpdateAccess`, `Store.DeleteAccess`, `Store.RotateAccess`, `Store.Authenticate`, `Store.Set`, `Store.Get`, `Store.PublicGet`, `Store.Delete`, `Store.Keys`, and `Store.Values` in [store.go](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L158-L667).
- Master-key envelope maintenance: `EnvelopeReferences`, `RewrapResult`, `Store.InspectEnvelopeReferences`, and `Store.RewrapBatch` in [envelope.go](file:///Users/cypark/Documents/project/goauthy/internal/kv/envelope.go#L15-L219).
- HTTP handler: `Handler`, `NewHandler`, and `Handler.Routes` in [http.go](file:///Users/cypark/Documents/project/goauthy/internal/kv/http.go#L16-L75).

## Invariants
- Values must be valid JSON up to 64 KiB; encrypted values and access secrets are sealed/opened via `oidc.Keyring` using purpose-bound AAD (`kv/access/<id>` and `kv/value/<digest(identity, key)>`), keeping encrypted values valid across namespace renames via immutable `identity` ([store.go:PutNamespace](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L219-L239), [store.go:Set](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L421-L440)).
- Bearer writes and reads re-validate the `Access` credential inside the SQL query/mutation (`accessGuard`), and `PublicGet` checks `public` and reads the value in one linearizable query ([store.go:accessGuard](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L415-L420), [store.go:PublicGet](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L482-L510)).
- `Store.Values` enforces a per-page byte budget (`kvValuePageByteBudget = 8 MiB`) alongside keyset cursors (`e1.<kind>.<pos>`) ([store.go:valueRows](file:///Users/cypark/Documents/project/goauthy/internal/kv/store.go#L538-L590)).

## Side Effects
- Executes linearizable queries and envelope-guarded replicated mutations (`storage.ExecuteEnvelope`) against `kv_namespaces`, `kv_access`, and `kv_values`.
- `Handler.Routes` registers admin, public, and Bearer-authenticated endpoints on `/auth/v1/kv/*` with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Verification
- Run: `go test ./internal/kv`
