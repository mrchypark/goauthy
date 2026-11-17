# dcr

## Overview
`internal/dcr` implements RFC 7591 Dynamic Client Registration (`/oidc/register`) and RFC 7592 client configuration management, supporting global bearer tokens, software statements, optional anonymous rate-limited registration, idempotency keys, and expired anonymous-client cleanup in `*rhiza.DB`.

## Interface
- `[store.go:CreateRequest]`, `[store.go:Registration]`, `[store.go:Config]`, `[store.go:RateLimitError]`, `[store.go:EnvelopeKeyring]`, `[store.go:ScopePolicy]`, `[store.go:NewScopePolicy]`, `[store.go:Store]`, `[store.go:NewStore]`: DCR persistence store, request/response models, scope policy, and rate-limit error.
- `[store.go:Store.ScopePolicy]`, `[store.go:Store.Create]`, `[store.go:Store.CreateIdempotent]`, `[store.go:Store.CreateAnonymousIdempotent]`, `[store.go:Store.RewrapIdempotencyBatch]`, `[store.go:Store.GetClient]`, `[store.go:Store.DefaultScopes]`, `[store.go:Store.Update]`, `[store.go:Store.DeleteRegistration]`, `[store.go:Store.GetRegistration]`, `[store.go:Store.ForceMFA]`, `[store.go:Store.DPoPBoundAccessTokens]`: Client registration CRUD, `fosite.Client` resolution, and idempotency-envelope rewrapping.
- `[http.go:LoadRegistrationToken]`, `[http.go:Handler]`, `[http.go:HandlerConfig]`, `[http.go:NewHandler]`, `[http.go:Handler.ServeHTTP]`: HTTP endpoint (`/oidc/register`) returning `404` when neither `globalBearer` nor `Anonymous` is configured.
- `[redirect.go:Store.HasExactRedirectURI]`: Exact redirect URI lookup across registered clients.
- `[software_statement.go:SoftwareStatementIssuer]`, `[software_statement.go:SoftwareStatementConfig]`, `[software_statement.go:LoadSoftwareStatementConfig]`, `[software_statement.go:SoftwareStatementConfig.CanonicalDigest]`: Trusted software-statement issuer configuration loader and digest computation.
- `[cleanup.go:DefaultAnonymousCleanupLimit]`, `[cleanup.go:AnonymousCleanupConfig]`, `[cleanup.go:CleanupAnonymousClients]`: Bounded cleanup of expired anonymous DCR clients.

## Invariants
- Registration token hygiene: `[http.go:LoadRegistrationToken]` enforces length `[32, 256]` with no whitespace and never leaks the token in error messages.
- Bounded HTTP payloads: `[http.go]` limits request bodies to `registrationBodyLimit = 16 << 10`.
- Per-IP anonymous rate limiting & idempotency: `[store.go:Store.CreateAnonymousIdempotent]` enforces per-IP rate windows and digest-checked idempotency keys; idempotency payloads are envelope-encrypted via `EnvelopeKeyring`.

## Side Effects
- Reads and mutates DCR client, idempotency, and rate-limit tables in `*rhiza.DB`.
- Reads registration token and software-statement config files from disk.

## Verification
- Run: `go test ./internal/dcr`
