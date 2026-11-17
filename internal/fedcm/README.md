# fedcm

## Overview
`fedcm` implements the opt-in HTTP surface for the browser Federated Credential Management (FedCM) API. It does not own account or session storage; callers inject account, client-origin, metadata, and signing-key resolvers at the trust boundary.

## Interface
- Path constants: `ManifestPath`, `ConfigPath`, `AccountsPath`, `ClientMetadataPath`, `AssertionPath`, `StatusPath` in [fedcm.go](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L33-L40).
- Models and config: `Account`, `ClientMetadata`, `ManifestDocument`, `ProviderConfig`, `AccountsResponse`, `AssertionResponse`, `Config`, and `IdentityAssertionRequest` in [fedcm.go](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L46-L105).
- HTTP handler and endpoints: `NewHandler`, `Handler.ServeHTTP`, `Handler.Manifest`, `Handler.Config`, `Handler.Accounts`, `Handler.ClientMetadata`, `Handler.Assertion`, `Handler.Status`, `Handler.Disconnect`, and `Handler.Onboarding` in [fedcm.go](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L127-L421).

## Invariants
- Zero `Config` has `Enabled: false` and fails closed with `404`; `NewHandler` requires a normalized issuer (`oidc.NormalizeIssuer`), a relative `LoginURL`, and exactly one complete client-binding mode (static `ClientID`+`ClientOrigin`, `ClientOrigins` map, or `ResolveClientOrigin` hook) ([fedcm.go:NewHandler](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L127-L196)).
- Every active endpoint enforces `Sec-Fetch-Dest: webidentity`, exact HTTP method, `Cache-Control: no-store` / `Pragma: no-cache`, and `Origin` presence/absence rules; `ClientMetadata` and `Assertion` validate exact HTTPS `Origin` matching against the resolved client origin before setting CORS headers ([fedcm.go:guard](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L437-L462), [fedcm.go:allowClientOrigin](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L554-L573)).
- `Handler.Assertion` re-verifies the live session via `ResolveCurrent`, binds `Issuer`, `Audience`, `Subject`, `Nonce`, and `AuthTime` (omitting `AuthTime` if ahead of `Now`), and signs a 5-minute EdDSA ID token via `oidc.SignIDToken` ([fedcm.go:Assertion](file:///Users/cypark/Documents/project/goauthy/internal/fedcm/fedcm.go#L326-L385)).

## Side Effects
- Writes HTTP responses with `Set-Login` (`logged-in` / `logged-out`) and `Access-Control-Allow-Origin` headers where applicable, and invokes caller-provided resolver/signing hooks.

## Verification
- Run: `go test ./internal/fedcm`
