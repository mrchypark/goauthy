# Upstream Identity Providers (`internal/upstreamprovider`)

## Overview
Implements upstream OAuth 2.0 / OIDC / GitHub federated login, account linking, back-channel logout, JWKS ID-token verification, claim mapping, and the persisted upstream-provider registry with encrypted client secrets.

## Interface
- `[http.go:Handler]`, `[http.go:NewHandler]`, `[http.go:NewLinkHandler]`, `[http.go:NewLocalLoginHandler]`, `[http.go:NewLocalLoginAndLinkHandler]` — HTTP handlers (`StartHandler`, `CallbackHandler`, `LocalStartHandler`, `LocalCallbackHandler`, `LinkStartHandler`, `LinkCallbackHandler`, `CombinedCallbackHandler`, `BackchannelLogoutHandler`) wiring `[http.go:LocalLoginHooks]`, `[http.go:LinkHooks]`, `[http.go:LinkSession]`, `[http.go:TokenExchangeResult]`, and `[subject.go:LinkDecision]`.
- `[auth.go:GenerateAuthorizationURL]`, `[callback.go:ValidateCallback]` — Core PKCE/state/nonce transaction creation and callback validation (`AuthorizationParams`, `AuthorizationResult`, `CallbackParams`, `CallbackResult`, `SubjectResult`, `VerifiedIdentity`, `OIDCSession`).
- `[jwks_verifier.go:JWKSVerifier]`, `[jwks_verifier.go:NewJWKSVerifier]`, `[callback.go:ValidateIDToken]`, `[oauth2_exchanger.go:OAuth2TokenExchanger]`, `[oauth2_exchanger.go:NewOAuth2TokenExchanger]` — Upstream token exchange (`TokenExchanger`) and OIDC ID-token / logout-token signature and claim verification (`TokenVerifier`, `IDTokenClaims`, `LogoutTokenClaims`).
- `[config.go:Config]`, `[config.go:ProviderKind]`, `[config.go:ProviderProtocol]`, `[provider_document.go:AuthProviderType]`, `[provider_document.go:ProviderRequest]`, `[provider_document.go:ProviderResponse]`, `[provider_document.go:ProviderLookupRequest]`, `[provider_document.go:ProviderLookupResponse]`, `[provider_document.go:ProviderLinkedUserResponse]`, `[provider_document.go:ProviderDocument]`, `[provider_document.go:ProviderPersistedFieldCount]`, `[provider_registry_http.go:ProviderMinimalResponse]` — Provider configuration, persistence, and HTTP DTOs (`Config.AllowPrivate` gates private/loopback/CGNAT targets for `netsec.NewSafeHTTPClient` per provider/issuer, defaulting to `false`).
- `[provider_registry.go:RegistryStore]`, `[provider_registry.go:NewRegistryStore]`, `[provider_registry_http.go:RegistryHandler]`, `[provider_registry_http.go:NewRegistryHandler]` — Persisted `auth_providers` registry (`Get`, `List`, `GetRuntime`, `RuntimeConfig`, `SecretCleartext`, `LinkedUsers`, `CreateAuthorized`, `UpdateAuthorized`, `DeleteAuthorized`) and admin HTTP endpoints (`GetProvidersMinimal`, `PostProviders`, `CreateProvider`, `UpdateProvider`, `DeleteProvider`, `GetProviderDeleteSafe`).
- `[rhiza_store.go:RhizaStore]`, `[rhiza_store.go:NewRhizaStore]`, `[rhiza_store.go:EnvelopeKeyring]` — Rhiza-backed one-use `[transaction.go:Transaction]` store (`Save`, `Consume`, `RewrapTransactionBatch`).
- `[provider_registry_rewrap.go]` & helpers: `InspectAuthProviderSecretReferences`, `RewrapAuthProviderSecretBatch`, `ProviderSecretPurpose`, `EvaluateClaimMapping`, `ComputeNamespace`, `DigestSHA256`, `GenerateProviderID`, `NormalizeProviderID`, `ValidateLocalOAuthBinding`, `DefaultCryptoProvider`.
- Sentinels: `ErrInvalidConfig`, `ErrProviderNotFound`, `ErrProviderExists`, `ErrIDTokenVerification`, `ErrLogoutTokenVerification`.

## Invariants
- `[provider_registry.go:ProviderSecretPurpose]` binds each encrypted client secret envelope to `"upstream-provider-secret/v1/<id>"` so envelopes cannot be replayed across providers.
- `[rhiza_store.go:RhizaStore.Consume]` enforces one-use transaction consumption bound to `stateDigest`, `browserBindingDigest`, and `providerID`, using `__Host-goauthy_upstream_state` and `__Host-goauthy_upstream_browser` cookies.
- `[http.go:OIDCSession]` stores only upstream-scoped claims verified against the consumed transaction; its `SessionID` is never a local browser session identifier.

## Side Effects
- Reads and writes `auth_providers`, upstream transactions, and linked-user records in `*rhiza.DB`.
- Makes outbound HTTPS requests to upstream authorization, token, userinfo, and JWKS endpoints.
- Sets `__Host-goauthy_upstream_state` and `__Host-goauthy_upstream_browser` HTTP cookies.

## Verification
- Run: `go test ./internal/upstreamprovider`
