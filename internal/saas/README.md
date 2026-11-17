# SaaS Connections, Credentials & Use Grants (`internal/saas`)

## Overview
Manages third-party SaaS provider configurations (OAuth 2.0, GitHub, and API-key connectors), encrypted per-owner connection credentials, authorization proofs, use-grants and handoff reviews, and SSRF-restricted outbound HTTP calls.

## Interface
- `[provider_store.go:ProviderStore]`, `[provider_store.go:NewProviderStore]`, `[provider_store.go:Provider]`, `[provider_store.go:ProviderInput]` — CRUD and OAuth2 loader (`Create`, `Update`, `Delete`, `Get`, `GetMany`, `List`, `LoadOAuth2`, `CloseConnections`) for SaaS providers with `OnPolicyChange` invalidation callback.
- `[credential_store.go:CredentialStore]`, `[credential_store.go:NewCredentialStore]` — Encrypted SaaS credential lifecycle (`Install`, `Load`, `Revoke`, `ClaimRefresh`, `CompleteRefresh`, `MarkRefreshUncertain`, `InvalidateProviderConnections`, `CloseConnections`).
- `[oauth2_connection.go]` / `[oauth2_refresh.go]` / `[oauth2_delivery.go]`: `BeginOAuth2`, `CompleteOAuth2`, `OAuth2Status`, `PrepareOAuth2Reconnect`, `RefreshOAuth2`, `RefreshOAuth2UseGrant`, `RejectOAuth2`, `RevokeOAuth2`, `DeliverOAuth2`, `OAuth2ConnectionStatus`, `OAuth2Delivery`, `OAuth2Start`, `OAuth2Status`.
- `[api_key_store.go]` / `[api_key_call.go]` / `[api_key_connector.go]` / `[credential_delivery.go]`: `PutAPIKey`, `PutBoundAPIKey`, `APIKeyStatus`, `RevokeAPIKey`, `DeliverAPIKey`, `APIKeyDelivery`, `APIKeyConnector`, `NewAPIKeyConnector`, `APIKeyConnectorInfo`, `APIKeyOperationConfig`, `APIKeyOperationInfo`, `CallAPIKey`.
- `[use_grant.go]` / `[use_handoff.go]`: `CreateUseGrant`, `AuthorizeUseGrant`, `GetUseGrantStatus`, `ListUseGrants`, `RevokeUseGrant`, `OAuth2UseGrantStatus`, `CreateUseHandoff`, `ReviewUseHandoff`, `CompleteUseHandoff`, `UseGrant`, `UseGrantInput`, `UseGrantStatus`, `UseHandoffInput`, `UseHandoffReview`.
- `[authorization_store.go]`: `CreateAuthorization`, `ConsumeAuthorization`, `CompleteAuthorization`.
- `[oauth2.go]` & `[github.go]`: `OAuth2`, `NewOAuth2`, `OAuth2Config`, `GitHub`, `NewGitHub`, `GitHubUser`.
- `[isolation_fixture_integration.go]` & `[runtime_fixture_integration.go]`: `IntegrationIsolation`, `IntegrationIsolationTLS`, `IsolationFixture`, `IsolationRoutes`, `IsolationPoolSample`, `IntegrationRegisteredRefresh`.
- `[provider_envelope.go]`, `[credential_envelope.go]`, `[authorization_verifier.go]`: `InspectProviderEnvelopeReferences`, `RewrapProviderEnvelopeBatch`, `InspectCredentialEnvelopeReferences`, `RewrapCredentialEnvelopeBatch`, `InspectAuthorizationEnvelopeReferences`, `RewrapAuthorizationEnvelopeBatch`.
- Sentinels: `ErrAuthorizationNotFound`, `ErrCredentialNotFound`, `ErrProviderInvalid`, `ErrProviderNotFound`, `ErrProviderConflict`, `ErrProviderUnauthorized`, `ErrProviderInUse`, `ErrUseGrantInvalid`, `ErrAPIKeyConnectorConfig`, `ErrAPIKeyRequest`, `ErrInvalidAPIKey`, `ErrOAuth2Config`, `ErrOAuth2Exchange`, `ErrOAuth2Identity`.

## Invariants
- `[http.go:restrictedTransport]` and `[http.go:allowedOutboundIP]` block all non-global-unicast, IPv4-mapped IPv6, and special-use/private IP ranges (loopback, RFC 1918, link-local, CGNAT, etc.) and disable HTTP redirects (`CheckRedirect`) to prevent SSRF.
- All provider secrets, SaaS credentials, and authorization records are sealed with `*oidc.Keyring` GAOP envelopes and audited/migrated via the `Inspect*` / `Rewrap*` functions.
- Store mutations require an explicit `authority func() (string, []any)` predicate and execute atomically against `*rhiza.DB`.

## Side Effects
- Reads and mutates SaaS provider, credential, authorization, and use-grant tables in `*rhiza.DB`.
- Makes outbound HTTPS requests to external SaaS OAuth2/API endpoints through `restrictedTransport` and maintains pooled connections (`http_pool.go`).

## Verification
- Run: `go test ./internal/saas`
