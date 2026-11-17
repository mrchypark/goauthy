# clients

## Overview
`internal/clients` stores dynamically managed OAuth 2.0 / OIDC clients (`managed_oauth_clients`) and per-client connection policies in `*rhiza.DB`, implementing `fosite.Client` and authority-guarded CRUD with encrypted client secrets.

## Interface
- `[store.go:TableName]`: Constant `"managed_oauth_clients"`.
- `[store.go:NewRequest]`, `[store.go:UpdateRequest]`, `[store.go:Client]`: Request and client models; `*Client` implements `fosite.Client` (`GetID`, `GetHashedSecret`, `GetRedirectURIs`, `GetGrantTypes`, `GetResponseTypes`, `GetScopes`, `GetAudience`, `GetDefaultAudience`, `GetBackchannelLogoutURI`, `IsPublic`).
- `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:Store.EnsureBootstrap]`, `[store.go:Store.Owns]`, `[store.go:Store.GetClient]`: Store constructor, bootstrap registration, ownership check, and `fosite.Client` lookup.
- `[store.go:Store.CreateWithGuard]`, `[store.go:Store.UpdateWithGuard]`, `[store.go:Store.DeleteWithGuard]`, `[store.go:Store.RotateSecretWithGuard]`, `[store.go:Store.ReadSecretWithGuard]`, `[store.go:Store.ReadSecretWithRevisionWithGuard]`, `[store.go:Store.ListWithGuard]`, `[store.go:Store.GetWithGuard]`: Authority-guarded client lifecycle and secret-rotation methods.
- `[connection_policy.go:ConnectionPolicy]`, `[connection_policy.go:BootstrapConnectionConfig]`, `[connection_policy.go:Store.CheckBootstrapConnectionsInactive]`, `[connection_policy.go:Store.PinBootstrapConnections]`, `[connection_policy.go:Store.GetConnectionPolicyWithGuard]`: Per-client and bootstrap connection policy pinning and lookup.

## Invariants
- Caller-supplied SQL authority guard: All `*WithGuard` methods gate reads/writes through the caller-provided `authority func() (string, []any)` predicate.
- Optimistic revision concurrency: Updates, deletes, secret rotations, and revisioned secret reads check `rev` against the persisted row revision.
- Keyring-encrypted secrets: Confidential client secrets are encrypted using `*oidc.Keyring` when stored and hashed for `fosite.Client` verification.
- Reserved IDs: `NewStore` accepts `reservedIDs` that cannot be created or claimed as managed clients.

## Side Effects
- Reads and mutates `managed_oauth_clients` and connection policy tables in `*rhiza.DB`.

## Verification
- Run: `go test ./internal/clients`
