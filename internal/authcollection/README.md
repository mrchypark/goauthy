# authcollection

## Overview
`internal/authcollection` stores administrator-defined authentication metadata schemas (`Definition`) and user-owned draft connection metadata (`Connection`) in `*rhiza.DB`. It deliberately stores no credentials.

## Interface
- `[store.go:ErrInvalid]`, `[store.go:ErrConflict]`, `[store.go:ErrUnauthorized]`, `[store.go:ErrNotFound]`: Store error sentinels.
- `[store.go:Field]`, `[store.go:Definition]`, `[store.go:DefinitionInput]`, `[store.go:Connection]`: JSON-serializable domain types for collection schemas and user connections.
- `[store.go:Store]`, `[store.go:NewStore]`: Store backed by `*rhiza.DB`.
- `[store.go:Store.CreateDefinition]`, `[store.go:Store.UpdateDefinition]`, `[store.go:Store.DeleteDefinition]`, `[store.go:Store.GetDefinition]`, `[store.go:Store.ListDefinitions]`: Authority-guarded CRUD for collection definitions with optimistic revision checks.
- `[store.go:Store.CreateConnection]`, `[store.go:Store.UpdateConnection]`, `[store.go:Store.DeleteConnection]`, `[store.go:Store.GetConnection]`, `[store.go:Store.ListConnections]`: Authority-guarded CRUD for user-owned connections bound to a definition revision.

## Invariants
- Caller-supplied SQL authority guard: Every read and write requires an `authority func() (string, []any)` predicate; a nil or empty guard fails closed (`"0"`).
- Bounded list & byte-budgeted keyset pagination: `[store.go:listRows]` caps results at `maxList = 1000` (returning `ErrConflict` if exceeded) and paginates within `maxListPageBytes = 8 << 20` per linearizable query to stay under Rhiza's 16 MiB response limit.
- Credential-free metadata: Only schema definitions and non-secret connection metadata are persisted.
- Identifier validation: IDs, field names, and provider IDs are validated against strict regular expressions (`idPattern`, `connectionIDPattern`, `fieldPattern`, `providerIDPattern`).

## Side Effects
- Reads and mutates `auth_collections` and `auth_collection_connections` tables in `*rhiza.DB`.

## Verification
- Run: `go test ./internal/authcollection`
