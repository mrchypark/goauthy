# claims

## Overview
`internal/claims` manages custom user attributes, custom OAuth/OIDC scopes, user attribute values, per-client scope policies, `client_credentials` claims, and claim resolution for issued tokens, exposed over browser-admin and API-key HTTP endpoints.

## Interface
- `[model.go:ErrInvalid]`, `[model.go:ErrNotFound]`, `[model.go:ErrConflict]`, `[model.go:ErrReserved]`, `[model.go:ErrUnauthorized]`, `[model.go:ErrInactiveSubject]`: Error sentinels.
- `[model.go:Attribute]`, `[model.go:Scope]`, `[model.go:ClientScopes]`, `[model.go:ClientCredentialsClaims]`, `[model.go:Resolved]`: Domain models for attributes, scopes, client policies, and resolved token claims.
- `[store.go:Store]`, `[store.go:NewStore]`: Persistence and resolution store backed by `*rhiza.DB` (plus `EditableAttribute` and `Store` methods for attributes, scopes, user values, bootstrap client scopes, and client-credentials claims).
- `[store.go:Store.GetUserValues]`, `[store.go:Store.GetUserValuesAPIKey]`, `[store.go:Store.EditableUserAttributes]`, `[store.go:Store.ScopeExists]`, `[store.go:Store.PutSelfUserValues]`, `[store.go:Store.PutUserValues]`, `[store.go:Store.PutUserValuesAPIKey]`: User attribute value management.
- `[store.go:Store.GetBootstrapClientScopes]`, `[store.go:Store.GetBootstrapClientScopesAPIKey]`, `[store.go:Store.BootstrapClientScopes]`, `[store.go:Store.UpdateBootstrapClientScopes]`, `[store.go:Store.UpdateBootstrapClientScopesAPIKey]`, `[store.go:Store.GetBootstrapClientCredentialsClaims]`, `[store.go:Store.GetBootstrapClientCredentialsClaimsAPIKey]`, `[store.go:Store.BootstrapClientCredentialsClaims]`: Bootstrap client scope and `client_credentials` claim management.
- `[http.go:Handler]`, `[http.go:NewHandler]`, `[http.go:Handler.Scopes]`, `[http.go:Handler.Scope]`, and sibling HTTP handlers: Browser-admin and API-key-authorized HTTP endpoints (`/auth/v1/scopes`, attributes, user values, client scopes).

## Invariants
- Reserved OIDC scopes: Standard OIDC scopes (`address`, `email`, `groups`, `openid`, `phone`, `profile`) cannot be overwritten as custom scopes (`ErrReserved`).
- Optimistic revision concurrency: Updates and deletes require the expected `revision` and return `ErrConflict` on mismatch.
- Bounded HTTP payloads: `[http.go]` caps request bodies at `requestLimit` (`8 << 10`).

## Side Effects
- Reads and mutates custom attribute, scope, user value, and client claim tables in `*rhiza.DB`.
- Writes HTTP responses.

## Verification
- Run: `go test ./internal/claims`
