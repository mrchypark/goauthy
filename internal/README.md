# internal

## Overview
Core GoAuthy domain, protocol, security, persistence, and UI packages under `internal/`. All packages are internal to the GoAuthy module (`github.com/mrchypark/goauthy`) and back the binaries in `../cmd/README.md`.

## Subdirectories & Boundaries
- `account`: [./account/README.md](./account/README.md) - Authenticated self-service account-management endpoints, embedded dashboard UI, passkey/password/external-link flows, and workspace routing.
- `admin`: [./admin/README.md](./admin/README.md) - Browser-only administrator landing page and embedded single-page admin dashboard UI with modular JS/CSS assets.
- `apidocs`: [./apidocs/README.md](./apidocs/README.md) - Generates and validates the OpenAPI 3.0.3 deployment specification and serves a read-only Swagger UI at `/auth/v1/docs/`.
- `apikey`: [./apikey/README.md](./apikey/README.md) - Narrowly scoped API keys (`API-Key name$secret`), RBAC authorization guards, guarded SQL mutations, bootstrap loaders, and admin HTTP management.
- `audit`: [./audit/README.md](./audit/README.md) - Durable, append-only security-event store and HMAC-SHA256 pseudonymization helpers backed by `*rhiza.DB`.
- `authcollection`: [./authcollection/README.md](./authcollection/README.md) - Stores administrator-defined authentication metadata schemas and credential-free user draft connections in `*rhiza.DB`.
- `backchannel`: [./backchannel/README.md](./backchannel/README.md) - OIDC Back-Channel Logout delivery worker with lease-based reconciliation, DNS-rebinding protection, and reloadable root CAs.
- `backup`: [./backup/README.md](./backup/README.md) - Age-encrypted, Ed25519-signed object-store snapshot export, publication, catalog verification, restore, and retention pruning.
- `backupconfig`: [./backupconfig/README.md](./backupconfig/README.md) - Reads and validates local age recipient files, Ed25519 catalog keys/trust bundles, and destination object-store configs.
- `backupschedule`: [./backupschedule/README.md](./backupschedule/README.md) - Cron schedule parsing, distributed KV lease acquisition, and CAS-watermark-guarded backup slot execution in `*rhiza.DB`.
- `branding`: [./branding/README.md](./branding/README.md) - Global and per-client/provider themes, CSS generation, sanitized SVG/raster logos, favicons, brand resolution, and branded error middleware (embeds [./branding/assets/README.md](./branding/assets/README.md)).
- `browser`: [./browser/README.md](./browser/README.md) - Peer-bound browser sessions, init/reauthentication flows, authorization interactions, issuer-scoped cookies, and session-bound CSRF tokens.
- `captcha`: [./captcha/README.md](./captcha/README.md) - Pluggable CAPTCHA verifier supporting Cloudflare Turnstile, hCaptcha, and an unconfigured no-op fallback.
- `cimd`: [./cimd/README.md](./cimd/README.md) - Validates, fetches, and caches OAuth Client ID Metadata Documents (CIMD) in `*rhiza.DB` with SSRF and policy-digest isolation.
- `claims`: [./claims/README.md](./claims/README.md) - Manages custom user attributes, custom OIDC scopes, user attribute values, per-client scope policies, and token claim resolution.
- `clients`: [./clients/README.md](./clients/README.md) - Stores dynamically managed OAuth 2.0/OIDC clients and connection policies in `*rhiza.DB` with keyring-encrypted secrets and `fosite.Client` support.
- `credential`: [./credential/README.md](./credential/README.md) - Argon2id password hashing/verification with bounded concurrency and memory gates, PHC validation, and password strength rules.
- `dcr`: [./dcr/README.md](./dcr/README.md) - RFC 7591/7592 Dynamic Client Registration (`/oidc/register`) with global bearer, software statements, anonymous rate-limited mode, and cleanup.
- `device`: [./device/README.md](./device/README.md) - RFC 8628 Device Authorization Grant (`/oidc/device` and `/oidc/device/verify`) with client/resource bindings, rate limits, and session-guarded UI.
- `dpop`: [./dpop/README.md](./dpop/README.md) - RFC 9449 DPoP JWT proof validation at the HTTP boundary and Rhiza-backed single-use nonce and JTI replay tracking.
- `eventlog`: [./eventlog/README.md](./eventlog/README.md) - Public lifecycle/security event constructors, hash-chained integrity verification, guarded keyset/stream queries, and bounded retention cleanup in Rhiza.
- `fedcm`: [./fedcm/README.md](./fedcm/README.md) - Opt-in HTTP endpoints for the browser FedCM API with caller-injected account, origin, metadata, and EdDSA signing-key hooks.
- `geoblock`: [./geoblock/README.md](./geoblock/README.md) - Country-based HTTP admission middleware (Whitelist/Blacklist) and IP-to-country/location lookup via trusted proxy headers and MaxMind MMDB.
- `housekeeping`: [./housekeeping/README.md](./housekeeping/README.md) - Lightweight goroutine scheduler for periodic and wake-triggered background maintenance jobs.
- `i18n`: [./i18n/README.md](./i18n/README.md) - Embedded UI message catalogs (`en`, `ko`) and bounded `Accept-Language`/cookie resolution for UI pages and account/email locales.
- `identity`: [./identity/README.md](./identity/README.md) - Local user accounts, password/passkey authentication, password history/expiry/reset, external/federated links, login locations, profile values, and SCIM projections in Rhiza.
- `ipblacklist`: [./ipblacklist/README.md](./ipblacklist/README.md) - Replicated manual and automatic IP/CIDR blacklist store, fail-closed HTTP middleware, and authenticated `/auth/v1/blacklist` admin handler.
- `kv`: [./kv/README.md](./kv/README.md) - Namespace-scoped JSON KV store in Rhiza with optional purpose-bound envelope encryption, Bearer credentials, keyset pagination, and `/auth/v1/kv` HTTP API.
- `login`: [./login/README.md](./login/README.md) - Browser-facing authentication UI and HTTP handlers for OAuth/OIDC authorization, account/device/handoff login, FedCM landing, passkeys, email OTP, and upstream providers.
- `loginpolicy`: [./loginpolicy/README.md](./loginpolicy/README.md) - Replicated brute-force protection, distributed credential-stuffing detection, system lockdown store/admin API, and trusted-proxy IP extraction.
- `logout`: [./logout/README.md](./logout/README.md) - OIDC RP-initiated logout request planner and HTTP handler for session revocation, cookie clearing, and confirmation UI.
- `masterkeyretirement`: [./masterkeyretirement/README.md](./masterkeyretirement/README.md) - API-key-authenticated HTTP operator surface (`/auth/v1/master_key_retirement`) for inspecting and advancing the master-key retirement barrier.
- `metrics`: [./metrics/README.md](./metrics/README.md) - Isolated Prometheus `Registry`, bounded-cardinality HTTP instrumentation, Bearer-authenticated `/metrics` handler, and typed security/DB/cache collectors.
- `notify`: [./notify/README.md](./notify/README.md) - Reliable outbound event delivery runtime to Slack, Matrix, and SMTP targets backed by a generation-gated Rhiza lease queue.
- `oauth`: [./oauth/README.md](./oauth/README.md) - Fosite-backed OAuth 2.0 / OIDC authorization server and transactional Rhiza grant/session store supporting Auth Code + PKCE, Refresh, Client Credentials, Device, Password, Token Exchange, DPoP, ForwardAuth, and UserInfo.
- `oidc`: [./oidc/README.md](./oidc/README.md) - AES-256-GCM master `Keyring` and envelope encryption, Ed25519 signing-key lifecycle/rotation, EdDSA JWT sign/verify, OAuth/OIDC discovery/JWKS handlers, and master-key reference inspection/rewrap.
- `passkey`: [./passkey/README.md](./passkey/README.md) - WebAuthn registration, login, MFA, and modification-proof ceremony lifecycle, encrypted credential/ceremony persistence via Rhiza, passwordless cookies, and master-key envelope inspection/rewrapping.
- `rbac`: [./rbac/README.md](./rbac/README.md) - Persists roles, groups, subject memberships, and bootstrap client login restrictions in Rhiza, and exposes browser-admin and account-management HTTP endpoints.
- `recovery`: [./recovery/README.md](./recovery/README.md) - Manages password-reset flows, PoW-gated reset requests, open and passkey-only registration, email OTP, login-revoke links, and a durable encrypted email outbox over SMTP.
- `redirecturi`: [./redirecturi/README.md](./redirecturi/README.md) - Shared narrow RFC 8252 loopback redirect URI matching policy and Dynamic Client Registration loopback template validation.
- `saas`: [./saas/README.md](./saas/README.md) - Manages third-party SaaS provider configurations, encrypted per-owner credentials, authorization proofs, use-grants/handoffs, and SSRF-restricted outbound HTTP calls.
- `scim`: [./scim/README.md](./scim/README.md) - Stateless bounded outbound SCIM 2.0 client for Users and Groups, Rhiza-backed durable outbox, encrypted SCIM client config store, and immutable user mapping store.
- `security`: [./security/README.md](./security/README.md) - HTTP security header middleware (OWASP/NIST), CORS middleware, Fetch Metadata/Origin CSRF protection middleware, and header text validation.
- `smtptransport`: [./smtptransport/README.md](./smtptransport/README.md) - Context-bound SMTP dialer and custom authentication selector for `go-mail` supporting implicit TLS and channel-bound SCRAM.
- `storage`: [./storage/README.md](./storage/README.md) - Embedded Rhiza database configuration, schema migrations (`v115`), S3/GCS object-store opening, master-key retirement fencing, envelope writer admission, DCR trust fencing, and passkey cookie retention watermarks.
- `testbrowser`: [./testbrowser/README.md](./testbrowser/README.md) - Bounded headless Chrome lifecycle helper for UI and end-to-end browser regression tests via `chromedp`.
- `tlsconfig`: [./tlsconfig/README.md](./tlsconfig/README.md) - Loads and atomically hot-reloads X.509 server TLS certificates from disk for `tls.Config.GetCertificate`.
- `tracing`: [./tracing/README.md](./tracing/README.md) - Configures OpenTelemetry OTLP/HTTP tracing, HTTP request tracing middleware without path credential leakage, and allowlisted auth-stage spans.
- `ui`: [./ui/README.md](./ui/README.md) - Integrates `ely-htmx` embedded UI templates and CSS/font assets with GoAuthy's issuer-prefixed asset path and `brand.css`.
- `upstreamprovider`: [./upstreamprovider/README.md](./upstreamprovider/README.md) - Upstream OAuth 2.0 / OIDC / GitHub federated login, account linking, back-channel logout, JWKS verification, claim mapping, and encrypted provider registry.
- `webid`: [./webid/README.md](./webid/README.md) - Serves bounded public Solid/FOAF WebID profile documents in `text/turtle` format for active accounts.
