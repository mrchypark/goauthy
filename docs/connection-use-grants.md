# Connection Use Grants

- **Status**: Implemented (Async-Delegation Extension & Co-Requisite Fixes; Automatic OAuth refresh orchestration remains Experimental per [capabilities.md](capabilities.md#external-user-owned-connections))
- **Scope**: `internal/authcollection`, `internal/saas`, `internal/rbac`, `internal/oauth`, `internal/dpop`, `internal/clients`, `internal/claims`, `internal/netsec`, `internal/storage`, `cmd/goauthy`

---

## Problem Statement

GoAuthy stores third-party SaaS credentials (API keys and OAuth 2.0 tokens) encrypted under **auth collections** (global admin-defined metadata schemas) and global **providers** (admin-registered OAuth 2.0 or API-key SaaS definitions, each carrying `provider_id`, `provider_revision`, and—for API keys—one or more named **connectors** with `GET` operations and `response_fields` projections). In GoAuthy's embedded Raft-replicated SQLite engine (Rhiza `v0.27.3`, with single-node synthetic filesystem qualification limited as described in [no-pvc-dr.md](no-pvc-dr.md#qualification-boundary)):
- `auth_collection_connections` (`internal/authcollection`) stores per-owner credential-free connection metadata and a reconnect counter `generation`.
- `saas_connection_credentials` (`internal/saas`) stores AEAD-encrypted credentials bound to `(owner_subject, collection_id, connection_id, provider_id, generation, token_version)`.

External consumers—such as **Handoff Requesters** (e.g., Backoffice, initiating one-use owner consent handoffs) and **Execution Consumers** (e.g., Conductor, executing connectors)—need scoped, revocable, owner-consented access without receiving long-lived refresh tokens or admin-level session authority.

Consumer endpoints under `/auth/v1/connection-grants/{grant_id}/*` accept both live non-DPoP human Bearer tokens and [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) (`token-exchange`) [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) (`DPoP`, Demonstrating Proof-of-Possession)-bound delegation tokens scoped to `goauthy.connections.use` and [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) `GOAUTHY_CONNECTIONS_RESOURCE`. Queued/asynchronous Execution Consumers exchange a single-hop human `subject_token` at `POST /oidc/token` for a DPoP-bound delegation token without persisting raw user Bearer tokens in durable write-ahead logs (WALs), while bounding synchronous Raft writes on single-node Rhiza `v0.27.3` via `jti` replay protection (`MarkReplay`).

---

## Goals & Non-Goals

### Goals

- **Scoped Grants**: Issue immutable grants bound to `(owner_subject, collection_id, connection_id, consumer_client_id, mode, resource)` with `expires_at_unix_ms` (<= 30 days), descriptive `purpose`, and `allow_refresh` (multiple concurrent active grants per tuple permitted). List/revoke endpoints address `(collection_id, connection_id)` or `(collection_id, connection_id, grant_id)` under authenticated owner context.
- **Zero-Secret Consumer Execution**:
  - `proxy`: Executes configured `GET` API-key operations server-side without revealing credentials.
  - `credential_delivery`: Exports current API keys or OAuth 2.0 access tokens (never refresh tokens or provider `client_secret`) to confidential consumers.
- **Explicit Consumer Refresh**: Allow `POST .../refresh` only for OAuth 2.0 `credential_delivery` grants with `allow_refresh=true`, using fail-closed claim semantics.
- **Linearizable Authority & Fencing**: Verify `connection_generation` (connection `generation`), `consumer_generation`, `provider_revision`, `connector_digest`, and active user/client/session authority on every call.
- **Async-Delegation Extension**: Enable confidential Execution Consumers to exchange a single-hop human `subject_token` at `POST /oidc/token` (`RFC 8693` + `RFC 9449` DPoP + `RFC 8707` `resource`) for a DPoP-bound `goauthy.connections.use` token, and accept `Authorization: DPoP` on `/auth/v1/connection-grants/{grant_id}/*` without custom tenant headers.

### Non-Goals

- **Unattended M2M Grants**: `client_credentials` tokens remain permanently rejected for connection use (`subject_token` must always represent a live human owner).
- **Generic Upstream HTTP Proxy**: Arbitrary HTTP methods, paths, or custom headers outside configured API-key connector operations are rejected.
- **Scope Subsetting on Delivery**: `purpose` is descriptive only; OAuth 2.0 delivery exports all upstream-granted scopes on the connection.
- **Background Refresh Daemons**: GoAuthy performs no background OAuth 2.0 refresh scheduling; `/credential` and `/credential-status` never initiate upstream token refreshes.
- **Service-Specific Delegation Headers**: Rejects custom `X-Workspace-Id` / `X-Actor-*` / tenant flags on consumer credential endpoints.

---

## References

- Repository overview: [`README.md`](../README.md); Rhiza `v0.27.3` qualification boundary: [`no-pvc-dr.md`](no-pvc-dr.md#qualification-boundary)
- One-use consent handoffs & bootstrap policy pinning: [`connection-use-handoffs.md`](connection-use-handoffs.md#request-and-approval), [`connection-use-handoffs.md`](connection-use-handoffs.md#bootstrap-client-policy)
- Consumer HTTP contract & schema `v74`: [`external-credential-consumer-contract.md`](external-credential-consumer-contract.md#사용자-oauth-연결-runtime-schema-v74) (Korean reference)
- Maturity matrix (`Preview` vs `Experimental`): [`capabilities.md`](capabilities.md#external-user-owned-connections)
- Qualification ledger (`2026-09-17`, schema `v102` baseline; `status.md` header notes `v116`, runtime is at `schemaVersion = 116`): [`status.md`](status.md#current-qualification-ledger-verified-2026-09-17)
- Package docs: [`internal/authcollection`](../internal/authcollection/README.md), [`internal/saas`](../internal/saas/README.md), [`internal/rbac`](../internal/rbac/README.md), [`internal/oauth`](../internal/oauth/README.md), [`internal/dpop`](../internal/dpop/README.md), [`internal/clients`](../internal/clients/README.md), [`internal/claims`](../internal/claims/README.md), [`internal/netsec`](../internal/netsec/README.md), [`internal/storage`](../internal/storage/README.md), [`cmd/goauthy`](../cmd/goauthy/README.md)

---

## Architecture & Current Wire Contract

### 1. Component Layout, Actors & Fencing Bindings

```text
[Owner Browser] ──(Session + CSRF)──────────────────────────┐
[Read Client]   ──(Bearer: goauthy.connections.read)────────┼──▶ [internal/rbac HTTP Endpoints]
                                                            │       │                    │
[Execution Consumer] ──(Bearer / Planned: DPoP: ...use)─────┘       │ (Injected AuthZ)   ▼
        │                                                           │         [internal/saas + internal/authcollection]
        │                                                           ▼             │                  │
        └──(Planned: RFC 8693 + DPoP POST /oidc/token)──▶ [internal/oauth/dpop]   │ (Rhiza SQL)      │ (HTTPS, internal/netsec)
                                                                    │             ▼                  ▼
                                                                    └────▶ [*rhiza.DB]    [Outbound Proxy / Refresh] ──▶ [External SaaS]
```

- **Three-Layer Gatekeeper Split**: Requests on `/auth/v1/connection-grants/{grant_id}/*` pass sequentially through (1) `internal/rbac` HTTP boundary checks, (2) `internal/oauth` token/DPoP/active-authority verification injected in `cmd/goauthy`, and (3) `internal/saas` grant, generation, revision, digest, and credential-state enforcement in Rhiza.
- **Startup Policy Pinning**: First startup with `GOAUTHY_CONNECTIONS_RESOURCE` (the single RFC 8707 resource URI identifying connection-use endpoints) pins the public connections policy cluster-wide ([`connection-use-handoffs.md`](connection-use-handoffs.md#bootstrap-client-policy)).
- **Client Classes**: **Bootstrap** (built-in consumer in `bootstrap_connection_policy` + `managed_oauth_client_bootstrap`) and **Managed** (`managed_oauth_clients`) clients are persistent first-party clients. Only they appear in the `connection_client_policies` SQL `UNION ALL` view (`internal/storage/bootstrap_connection_policy.go:19-30`). **Dynamic** clients (**DCR**, Dynamic Client Registration in `dynamic_oauth_clients`; **CIMD**, Client ID Metadata Document in `cimd_client_documents`) are excluded from `connection_client_policies`.
- **Actors & Client Eligibility**:
  - **Owner**: Browser-authenticated user owning the connection.
  - **Handoff Requester**: Initiates one-use consent handoffs (`POST /auth/v1/connection-handoffs`) with `goauthy.connections.write` ([`connection-use-handoffs.md`](connection-use-handoffs.md#request-and-approval)).
  - **Read Client**: Reads grant status via `GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}` (`goauthy.connections.read`) via `AuthorizeUserResource` (DCR clients are admitted only if `GOAUTHY_DCR_ALLOWED_SCOPES` explicitly includes `goauthy.connections.read`, omitted by default).
  - **Execution Consumer**: Must be a bootstrap or managed client in `connection_client_policies` holding a live human-delegated token (`Authorization Code + PKCE`, `Refresh Token`, `Device Authorization Grant`, or `Password`; `client_credentials` and `token-exchange` currently rejected) with `scope=goauthy.connections.use`, `aud=GOAUTHY_CONNECTIONS_RESOURCE`, active user/client/**client group policy** (`RestrictGroupPrefix` restricting allowed user group prefixes), and—for interactive grants carrying `goauthy_oidc_session_id`—a live browser session (`Device` and `Password` grants lack a browser session and omit this check). `proxy` supports public or confidential clients; `credential_delivery` requires confidential clients.
- **Four-Dimension Fencing & Version Naming**:
  1. **Connection Generation (`connection_generation` / grant `generation`)**: Rotates only on `POST .../oauth2/reconnect` completion (`auth_collection_connections.generation`). Existing grants fail `404` on reconnect.
  2. **Consumer Generation (`consumer_generation`)**:
     - Managed clients rotate `generation` on `Secret`, `Confidential`, `Enabled -> false`, or `Delete`. Non-rotating edits (`Scopes`, `RestrictGroupPrefix`, `enabled=1`) are re-checked per call: `AuthorizeConnectionUse` checks `RestrictGroupPrefix`, and `AuthorizeUseGrant` checks scopes/enabled via `usePolicyWithoutState` (the shared SaaS SQL predicate that omits `saas_connection_credentials` alias `x.state='ready'`; note `managed_oauth_clients.revision`—the client's optimistic-concurrency counter—is not pinned in `usePolicyWithoutState`, and `ForceMFA` enforcement is added in `Co-Requisite Fixes`).
     - Bootstrap `consumer_generation` in `connection_client_policies` appends `:scopes:<revision>` from `bootstrap_client_claim_scopes.revision` (custom scope assignment table), invalidating grants on scope edits.
  3. **Provider Revision (`provider_revision`)**: Providers referenced by non-deleted collections are immutable (`409 Conflict`). Grants pin `provider_revision` so edits made to a provider before a collection attaches it invalidate older provider definitions. Removing a provider is rejected (`409 Conflict`) while a `ready`, `refreshing`, or `uncertain` SaaS credential still references it.
  4. **Connector Digest & Credential Version**:
     - API-key grants pin `connector_digest`—a 43-character unpadded `base64.RawURLEncoding` SHA-256 digest of canonical connector JSON (`version`, `purpose`, `id`, canonicalized `header` `"Authorization"|"X-API-Key"`, `prefix` `""|"Bearer "|"Token "`, sorted `GET` operations).
     - Rotating an API key or refreshing OAuth 2.0 increments DB column `token_version` (exposed as `credential_version` on `/credential`/`/refresh`, and `version` on `/oauth2/refresh`/`/oauth2/reconnect`/`/credential-status`), keeping grants valid only when `connector_digest` is unchanged.

### 2. HTTP Boundary & Security Rules

- **Delivery, Refresh & Status Routes** (`/credential`, `/refresh`, `/credential-status`): Check `https://` configured OIDC issuer and dependency wiring (`503 Service Unavailable`) *before* `405 Method Not Allowed`; reject `Cookie`, `Origin`, `Sec-Fetch-Site`, `RawQuery`/`ForceQuery` (trailing `?` via Go `net/url`), or invalid `Authorization` (`401 Unauthorized` with RFC 9449 `WWW-Authenticate: DPoP algs="ES256" error="invalid_token" | "invalid_dpop_proof"` for DPoP errors); reject `If-Match`, `X-CSRF-Token`, or non-empty body (`400 Bad Request`, except `POST .../refresh`); propagate Rhiza/context unavailability as `503`.
- **`POST .../invoke` Route**: Shares the unified `authorizeConnectionUseBoundary` preamble: checks `https://` OIDC issuer and dependency wiring (`503`) *before* `405` -> `RawQuery`/`ForceQuery` (`401`) -> `h.crossSite` (CSRF origin check; rejects `Sec-Fetch-Site: cross-site` with `401`; allows `same-origin` or omitted) -> `Cookie`/multiple `Authorization` (`401`) -> `AuthorizeConnectionUseHTTP` -> JSON body `{"operation": "<op_id>"}` (`400`).
- **Read Endpoint** (`GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}`): Requires `goauthy.connections.read` + `GOAUTHY_CONNECTIONS_RESOURCE` (`401` on `RawQuery`, `Cookie`, `Origin`, `Sec-Fetch-Site`, or invalid Bearer; `400` on `If-Match`, non-empty body, or missing path segments; `503` if unconfigured or storage unavailable; `404` on missing target). Returns `{grant, connection_generation}` including revoked/expired grants.
- **Response Headers**: All endpoints emit `Cache-Control: no-store` and security headers.

### 3. Owner Browser-Session Grant Management

- **Browser Boundary**: Authenticated via owner browser session + `X-CSRF-Token` + same-origin check (`400` on invalid CSRF/body). Owner routes under `/auth/v1/account/connections/{collection_id}/{connection_id}/...` include `PUT/DELETE .../api-key` (`200`/`204`), `POST .../oauth2/refresh`, `POST .../oauth2/reconnect` (`200 OK` `OAuth2Status`), and `DELETE .../oauth2` (takes JSON `{"version": <int64>}`, returns `204 No Content`). Owner refresh returns `200`; `400` for invalid input, `401` for authentication failure, `404` for missing credentials, `409` for a stale version or concurrent claim, `502` for `ErrRefreshUncertain`, and `503` for storage unavailability. `OAuth2Status` contains `{connected, state, version, provider_id, account_id, scopes}`.
- **Use-Grant JSON Fields (`UseGrant`)**: `id`, `owner_subject`, `collection_id`, `connection_id`, `consumer_client_id`, `mode`, `resource`, `purpose`, `generation` (serializes `connection_generation`), `consumer_generation`, `provider_id`, `provider_revision`, `connector_digest` (`""` for OAuth 2.0), `expires_at_unix_ms`, `revoked` (`bool`), `revision`, and `allow_refresh` (`omitempty`, omitted when `false`).

| Endpoint | Request / Parameters | Behavior & Status Codes |
| --- | --- | --- |
| `GET /auth/v1/account/connections/{collection_id}/{connection_id}/grants` | Empty body, no `If-Match` | Lists grants ordered by `expires_at_unix_ms DESC, id LIMIT 256` (includes revoked/expired). `200 OK` array; `400` on `If-Match`/body; `401` on `RawQuery`/cross-site; `404` if connection missing; `503` on storage failure. |
| `POST /auth/v1/account/connections/{collection_id}/{connection_id}/grants` | `consumer_client_id`, `mode` (`proxy` \| `credential_delivery`), `purpose`, `expires_at_unix_ms` (<= 30 days), optional `allow_refresh` (`bool`), optional `connector_digest` (43-char base64url), optional `credential_version` (`int64`) | Auto-binds `resource` to `GOAUTHY_CONNECTIONS_RESOURCE`. Enforces `connection_client_policies` (confidential required for `credential_delivery`; rejects `allow_refresh=true` on API-key/proxy; rejects `connector_digest` on OAuth 2.0; rejects `mode=proxy` on OAuth 2.0). `201 Created` `UseGrant`; `400` on invalid input/legacy empty-provider API key; `404` on missing/non-ready target; `409` on digest/version mismatch, `>= 32` active grants, or conflict; `503` if unconfigured/unavailable. |
| `DELETE /auth/v1/account/connections/{collection_id}/{connection_id}/grants/{grant_id}` | `If-Match` revision required, empty body | Soft-revokes grant (`revoked=1, revision=revision+1`). `204 No Content`; `428` if `If-Match` missing; `404` if missing or revoked; `409` on revision conflict; `503` on storage failure. |

### 4. Consumer Execution Endpoints (`/invoke` & `/credential`)

- **API-Key Proxy (`POST /auth/v1/connection-grants/{grant_id}/invoke`)**:
  - Request JSON: `{"operation": "<op_id>"}` (unknown fields return `400`).
  - Executes the preconfigured HTTPS `GET` operation via `internal/netsec` (SSRF blocking, disabled redirects, `64 KiB` body cap) and projects configured scalar `response_fields`. Re-verifies `credential_version` after dispatch (`409` on mid-dispatch rotation).
  - **Status Codes**: `200 OK` flat `map[string]json.RawMessage`; `400` invalid JSON/legacy empty-provider key; `401` invalid token/DPoP/cross-site; `404` missing/revoked/expired grant, `mode != "proxy"`, OAuth 2.0 connection, `state != "ready"`, or pre-call generation/revision/digest mismatch; `409` mid-dispatch `credential_version` race; `500` internal `ErrCredentialUnauthorized`/`ErrCredentialCorrupted`; `502` upstream error/timeout/non-scalar response; `503` storage unavailability.
- **Credential Delivery (`POST /auth/v1/connection-grants/{grant_id}/credential`)**:
  - Empty body `POST`, confidential `connection_client_policies` client, `mode="credential_delivery"`.
  - **API Key Response (`200 OK`)**: `{kind: "api_key", api_key, grant_id, provider_id, connection_generation, credential_version, connector_digest, header, prefix, consent_expires_at_unix_ms}` (`header` is `"Authorization"` or `"X-API-Key"`; `prefix` is `"" | "Bearer " | "Token "`).
  - **OAuth 2.0 Response (`200 OK`)**: `{kind: "oauth2", access_token, token_type: "Bearer", grant_id, provider_id, connection_generation, credential_version, account_id, scopes, token_expires_at_unix_ms, consent_expires_at_unix_ms}` (requires non-empty `access_token` with `token_expires_at_unix_ms > now`).
  - **Status Codes**: `200 OK`; `400` `If-Match`/`X-CSRF-Token`/non-empty body; `401` invalid Bearer/DPoP token or proof; `404` non-confidential client (via `usePolicyWithoutState`), missing/revoked/expired grant, `mode != "credential_delivery"`, `state != "ready"`, expired upstream `access_token`, or pre-call generation/revision/digest mismatch; `409` mid-delivery concurrent rotation race; `500` internal `ErrCredentialUnauthorized`/`ErrCredentialCorrupted`; `503` storage/issuer/dependency unavailability.

### 5. Explicit OAuth 2.0 Refresh & Interrupted Recovery

- **Refresh (`POST /auth/v1/connection-grants/{grant_id}/refresh`)**:
  - Request JSON: `{"credential_version": <int64>}` (`> 0`, `< MaxInt64`). Requires `mode="credential_delivery"`, `allow_refresh=true`, OAuth 2.0 `state='ready'`, and non-expired `refresh_token`.
  - **Fail-Closed State Machine**: `ready -> refreshing` (CAS claim via `refresh_claim` column) -> upstream provider refresh via `internal/netsec` -> `ready` (increments `token_version`) | `uncertain` (on upstream error/timeout/stored-vs-upstream `account_id` mismatch/commit ambiguity such as `ErrCommitUnknown`). Owner `DELETE .../oauth2` transitions `ready | refreshing | uncertain -> revoked`.
  - **Status Codes**: `200 OK` `OAuth2Status`; `400` invalid JSON/version; `401` unauthorized; `404` missing/revoked/expired grant, `allow_refresh=false`, API-key, `state` in `uncertain`/`revoked`, or pre-claim expired `refresh_token` (`ErrCredentialNotFound`); `409` stale `credential_version` or concurrent `refreshing` claim (`ErrUseGrantConflict`); `500` `ErrCredentialUnauthorized`/`ErrCredentialCorrupted`; `502` `ErrRefreshUncertain` (the durable state becomes `uncertain` only when the uncertainty marker commit succeeds); `503` storage unavailability.
- **Status Probe (`GET /auth/v1/connection-grants/{grant_id}/credential-status`)**:
  - Empty-body `GET` for `mode="credential_delivery"` OAuth 2.0 grants.
  - **Status Codes**: `200 OK` `OAuth2Status` (returned for **credential** states `ready`, `refreshing`, `uncertain`, `revoked`, omitting internal `refresh_claim`; `connected` is `true` only when `state == "ready"`). Returns `404 Not Found` on missing/expired/**revoked use-grants**, API-key grants, `proxy` grants, or stale generation/revision.
- **Consumer Expired-Token Recovery**: When `POST .../credential` returns `404`, an Execution Consumer probes `GET .../credential-status` once:
  - `state == "refreshing"` -> retryable backoff (`>= 5s` interval, capped at `<= 1m` total wait).
  - `state == "ready"` -> retry `POST .../credential` **once** (in case another worker refreshed concurrently); if still `404` and `allow_refresh=true`, call `POST .../refresh` once with `{"credential_version": status.version}` (if `404`/`502`, treat as terminal `auth_expired`; if `409`, treat as `refreshing`).
  - `state == "uncertain"` / `"revoked"` / `404` -> terminal failure (if credential is `uncertain`, owner must revoke via `DELETE .../oauth2` and reconnect).

---

## Async-Delegation Extension & Co-Requisite Fixes

To support asynchronous/queued confidential Execution Consumers without storing raw user Bearer tokens in WALs or introducing custom tenant headers, GoAuthy implements the **Async-Delegation Extension** alongside the **Co-Requisite Fixes** below (applied in `schemaVersion = 116`).

### 1. End-to-End Standard Protocol Flow (`RFC 8693` + `RFC 9449` + `RFC 8707`)

```text
[Caller / Edge] ──(Bearer <subject_token>, scope=goauthy.connections.use)──▶ [Execution Consumer]
                                                                                   │
   1. POST /oidc/token (Confidential Auth + DPoP proof, no nonce) ◀────────────────┤
      grant_type=token-exchange, scope=goauthy.connections.use,                    │
      resource=GOAUTHY_CONNECTIONS_RESOURCE, subject_token=<token>                 │
   ◀── 400 use_dpop_nonce (DPoP-Nonce: N1) ────────────────────────────────────────┤
   2. Retry POST /oidc/token (DPoP proof with nonce=N1, fresh jti) ────────────────┤
   ◀── 200 OK {access_token: <delegation_token>, token_type: DPoP, expires_in} ────┘
         │  (Persist <delegation_token> + consumer DPoP key in WAL; discard <subject_token>)
         ▼
   3. Async Worker wakes ──▶ POST /auth/v1/connection-grants/{grant_id}/credential
      Authorization: DPoP <delegation_token> + DPoP proof (ath, htm, htu, fresh jti, 1m MaxAge)
   ◀── 200 OK {kind: "oauth2"|"api_key", ...}
```

### 2. Async-Delegation Extension (`internal/oauth`, `internal/rbac`)

- **Metadata-Driven Connection-Use Exchange (`POST /oidc/token`)**:
  - Enforce `clientGroupPolicy` (`RestrictGroupPrefix`) and preserve `goauthy_oidc_session_id`, `goauthy_oidc_auth_method` (tracks login authentication method such as `"mfa"`), and `goauthy_oidc_auth_time` uniformly for all non-machine user token exchanges (`TokenExchangeGrantType && !machine`, where `machineTokenSubject` identifies machine-only tokens lacking a human subject—distinct from `client_credentials` which is rejected on `/auth/v1/connection-grants/*`).
  - When a confidential bootstrap/managed client requests `scope=goauthy.connections.use` or `resource=GOAUTHY_CONNECTIONS_RESOURCE`:
    - Reject unset `GOAUTHY_CONNECTIONS_RESOURCE` (`503`), reject public/dynamic clients (`400 unauthorized_client`), require the exchanging client's own `Scopes` to include `goauthy.connections.use` (`400 invalid_scope`), and reject the `audience` query/form alias (`400 invalid_target`).
    - Require `scope=goauthy.connections.use` and `resource=GOAUTHY_CONNECTIONS_RESOURCE` explicitly (`400 invalid_scope` / `400 invalid_target` if omitted or mismatched; never fall back to copying all scopes or `h.defaultAudiences`).
    - Require a single-hop non-DPoP human `subject_token` already holding `goauthy.connections.use` and `GOAUTHY_CONNECTIONS_RESOURCE` (reject `machineTokenSubject`, `grant_type=token-exchange`, `act`, or `actor_token` with `400 invalid_grant`).
    - Enforce `clientGroupPolicy` and `ForceMFA` *before* `verifyDPoPTokenRequest` (avoiding wasted nonce/replay writes on `403`): check `oidcAMR(goauthy_oidc_auth_method) == "mfa"` (admitting `"mfa"` and `"webauthn"`) and, when `deviceOIDCExtra` is present, verify `mfa_verified` (stored in `session.Extra` on initial device grant issuance so refreshed device tokens retain it without relying on `oauth_device_grants.token_request_id` matching the new `request_id`, falling back to `oauth_device_grants.mfa_verified == 1` for pre-existing initial tokens); return `403 access_denied` on mismatch and propagate MFA status into the exchanged `session.Extra`. Then require DPoP (`400 invalid_request`/`invalid_dpop_proof` when `DPoP` header missing; `400 use_dpop_nonce` + `DPoP-Nonce` when `DPoP` header lacks a valid nonce), bind `cnf.jkt`, and bound `expires_in` by `min(client_lifespan, subject_token.remaining)`.
  - At exchange commit (`grant_storage.go`), enforce `browser_sessions` liveness (`revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ?`, matching `authorizeResource` without idle timeout) via conditional `INSERT ... SELECT ... WHERE EXISTS(...)` with `ExpectedRowsAffected=1` when `goauthy_oidc_session_id != ""`, and map `rhiza.MutationErrorCodePreconditionFailed` -> `fosite.ErrSerializationFailure` -> `400 invalid_grant`.
  - Propagate Rhiza/context unavailability (`ErrNotReady`, `ErrQuorumUnavailable`, `ErrDurabilityUnavailable`, `ErrCommitUnknown`, `DeadlineExceeded`, `Canceled`) through `token_exchange.go` (`exchangePrincipal`, `accessTokenExpiry`, `validateTokenAccounts`, `PopulateTokenEndpointResponse` / `BeginTokenExchangeTX` / `IssueAccessToken` / `Commit`), `TokenHandler`, `dpop.go`, and `writeTokenError` as `503 Service Unavailable`.
- **DPoP Resource Auth & Direct `internal/oauth` Boundary**:
  - Extend `AuthorizeConnectionUse` via a dedicated `MarkReplay`-only DPoP branch in `internal/oauth/dpop.go` (isolating `UserInfoHandler` so it retains `ConsumeNonce` enforcement) to accept `Authorization: Bearer` (`cnf.jkt == ""`, non-exchange human tokens) and `Authorization: DPoP` (`cnf.jkt != ""`, `TokenExchangeGrantType` tokens with `ath`, `htm`, `htu`, `MaxAge: 1m` / `FutureSkew: 10s`, and `dpop.Store.MarkReplay` `jti` replay protection—skipping per-call resource `DPoP-Nonce` round-trips so `N` resource calls after 1 exchange incur `N + 4` Raft writes instead of `3N + 4`), rejecting `TokenExchangeGrantType` Bearer tokens.
  - Define exact RFC 9449 DPoP resource error separation: missing/Bearer scheme for DPoP-bound token -> `WWW-Authenticate: DPoP algs="ES256" error="invalid_token"` (`401`); malformed proof, `jkt`/`ath`/`htm`/`htu` mismatch, or `dpop.ErrReplay` -> `WWW-Authenticate: DPoP algs="ES256" error="invalid_dpop_proof"` (`401`); Rhiza failures in `MarkReplay` -> `503`.
  - Replace `connectionUseAuthorizer` across `/invoke`, `/credential`, `/refresh`, and `/credential-status` with GoAuthy's standard `(http.ResponseWriter, *http.Request) -> (owner, consumer, authority, ok bool)` callback pattern; ensure `h.securityHeaders` / `Cache-Control: no-store` run before the auth callback, and unify the duplicated `internal/rbac` boundary preamble (adding the `https://` issuer `503` check before `405` on `/invoke`, while preserving `h.crossSite` for same-origin `proxy` callers).

### 3. Co-Requisite Fixes (`internal/oauth`, `internal/dpop`, `internal/saas`, `internal/rbac`, `internal/authcollection`, `cmd/goauthy`)

- **ForceMFA, Concurrent Refresh `409` & Boundary Mapping**: Enforce `ForceMFA` (`oidcAMR(goauthy_oidc_auth_method) == "mfa"`, admitting `"mfa"` and `"webauthn"`, plus `mfa_verified` in `session.Extra` / `oauth_device_grants.mfa_verified == 1` when `deviceOIDCExtra` is present; `managed_oauth_clients.revision` already rotates on updates so `authorizeResource` SQL `policySQL` fences TOCTOU drift) across all human grant types at `AuthorizeConnectionUse`; update `authorizeUseRefresh` (`use_grant_refresh.go`) to return `ErrUseGrantConflict` (`409`) when `x.state == 'refreshing'` (and `404` for `uncertain`/`revoked`); fix `ResolvePrincipal` in `cmd/goauthy/main.go` to map `rbac.ErrInactiveSubject` -> `identity.ErrInactiveSubject` (`401`, not `503`).
- **DPoP Store, Provider Integrity & RBAC Delivery Fixes**: Fix `dpop.Store.MarkReplay` exact-second expiry (reject only when `expiresAt.Before(now)` matching `dpop.Validate`) and stop masking Rhiza query errors as `ErrInvalid` in `dpop/store.go`; deduplicate double `AuthorizeUseGrant` calls in `DeliverConnectionCredential` (reducing linearizable queries and AEAD decrypts from `8 -> 5` queries / `2 -> 1` decrypt on `DeliverAPIKey`, and `9 -> 6` queries / `3 -> 2` decrypts on `DeliverOAuth2` unless merged); map `ErrCredentialUnauthorized` to `500` (internal wiring bug) and split unexported `errCredential` into exported `internal/saas` sentinels (`ErrCredentialNotFound` for expired `refresh_token` -> `404`, `ErrCredentialCorrupted` for ciphertext corruption -> `500`, never `503`); reject `mode=proxy` on OAuth 2.0 connections in `createUseGrant`; harden `authcollection.Store.UpdateDefinition` to reject removing providers still referenced in `saas_connection_credentials` with `state IN ('ready', 'refreshing', 'uncertain')` (excluding `'revoked'`).
- **Refresh Claim Lease (`30s`)**: Schema migration `schemaVersion = 116` (`migrateRefreshClaimLease`) persists `refresh_claimed_at_unix_ms` alongside `refresh_claim` in `saas_connection_credentials` (treating `refresh_claimed_at_unix_ms IS NULL` on pre-upgrade `refreshing` rows as expired), bounds the combined `exchange` context deadline in `refreshOAuth2`/`refreshCredential` (covering sequential `newSaaSHTTPClient` `Refresh` + `Identity` calls in `internal/saas/http.go`) to `<= 20s` total (leaving Raft commit headroom under the `30s` lease), fences `CompleteRefresh` with `refresh_claimed_at_unix_ms + 30000 > ?` (preventing late `ready` commits after `30s`), and enforces fail-closed OAuth 2.0 refresh semantics: `ClaimRefresh` does not recover expired `refreshing` rows (only owner `Revoke` via `DELETE .../oauth2` transitions expired `refreshing` rows -> `revoked`), while `OAuth2Status`, `OAuth2UseGrantStatus` (`GET .../credential-status`), and `DeliverOAuth2` project expired `refreshing` claims as `uncertain` read-only.

---

## Alternatives Considered

| Option | Decision | Trade-Off & Rationale |
| --- | --- | --- |
| M2M `client_credentials` + `X-Actor-*` / `X-Workspace-*` headers | **Rejected** | Breaks OAuth 2.0 user-delegated accountability and introduces confused-deputy risk if an edge proxy or worker header is spoofed. |
| Stateless JWTs with offline validation | **Rejected** | Cannot synchronously fence `connection_generation`, `consumer_generation`, `provider_revision`, user disablement, or `clientGroupPolicy`. |
| OAuth 2.0 `source_signature` cascade index on `oauth_access_tokens` (storing source token hash for `/oidc/revoke` cascade) | **Rejected** | Adds write amplification and index maintenance to every token issuance; mitigated instead by bounding exchanged token TTL by `subject_token.remaining` and preserving `goauthy_oidc_session_id` for Relying Party (RP) logout. |
| Transparent auto-refresh inside `POST .../credential` | **Rejected** | Violates GoAuthy's explicit fail-closed refresh boundary ([`external-credential-consumer-contract.md`](external-credential-consumer-contract.md)); keeping `POST .../refresh` explicit lets consumers retry `/credential` once and refresh once on `404` (`allow_refresh=true`). |
| Per-call `401 use_dpop_nonce` challenge on `/auth/v1/connection-grants/*` | **Rejected** | Costs `3N + 4` Raft writes (`IssueNonce` + `ConsumeNonce` + `MarkReplay` per call) and `2` RTTs per call on single-node Rhiza; `jti` replay (`MarkReplay`, `1` write/call) + `1m` proof `MaxAge` + `ath` binds WAL tokens with `N + 4` total writes and `0` extra resource RTTs. |
| Cross-package `oauth <-> rbac` error-outcome bridge struct | **Rejected** | Duplicates protocol types across 3 packages (`oauth`, `cmd/goauthy`, `rbac`); `(w, r) -> (..., ok bool)` lets `internal/oauth` own RFC 9449 headers directly. |

---

## Risks & Mitigations

1. **`ListUseGrants` `LIMIT 256` History Truncation**: `ListUseGrants` filters only `(owner_subject, collection_id, connection_id)` without `revoked=0`. Over 256 historical revoked/future-dated grants can hide shorter-TTL active grants.
   - *Mitigation*: Reuse existing active grants across tasks instead of minting per-execution grants, and avoid near-30-day TTLs when frequent revocation is expected; tracked for follow-up hardening to filter `revoked=0` and expired rows.
2. **Stale `refreshing` Wedge**: Pre-claim expired `refresh_token` values return `404 ErrCredentialNotFound`; crashed pods can still leave `state='refreshing'` wedged.
   - *Mitigation*: Consumers must cap `refreshing` retries to `<= 1/5s` for `<= 1m`; the `30s` `refresh_claimed_at_unix_ms` lease requires owner `DELETE .../oauth2` recovery rather than unsafe automatic `ClaimRefresh` re-claim.
3. **Unbounded OAuth 2.0 Scope Export**: `credential_delivery` exports all upstream scopes on the connection; `purpose` is non-enforcing.
   - *Mitigation*: `POST .../grants` enforces confidential-client eligibility for `credential_delivery` and owners explicitly approve scope exposure per connection during consent handoff.
4. **Orphaned Provider References on `authcollection.Store.UpdateDefinition`**: Resolved. `UpdateDefinition` rejects removing a provider referenced by a `saas_connection_credentials` row in `ready`, `refreshing`, or `uncertain` state.
5. **Non-Browser Grant Partial Revocation Cascade**: `Device` and `Password` grants lack `goauthy_oidc_session_id`, and `POST /oidc/revoke` on a `subject_token` does not cascade to derived exchanged tokens.
   - *Mitigation*: Keep `subject_token` TTLs short (`expires_in` of exchanged tokens is bounded by `subject_token.remaining`); enforce `ForceMFA` and active authority per call in Rhiza.
6. **Synchronous Raft Write & Cleanup Cost (`N + 4` Writes)**: Where `N` is the number of resource calls per exchanged delegation token, `1` un-nonced `POST /oidc/token` + retry adds `4` Raft writes (`IssueNonce` + `ConsumeNonce` + `MarkReplay` + `Commit`), and each resource call adds `1` Raft write (`MarkReplay`) = `N + 4` writes (`N + 2` RTTs; e.g., `20` writes / `18` RTTs at `N=16`), each running `expiredCleanup` (`DELETE ... LIMIT 128` on `dpop_replays`), alongside 5 (`DeliverAPIKey`) or 6 (`DeliverOAuth2`) queries and 2 AEAD decrypts per `/credential`.
   - *Mitigation*: Benchmark `N + 4` writes against single-node Rhiza `v0.27.3` (with `before-ack` object-store publication disabled or tuned per deployment per [`README.md`](../README.md#L126)) and gate production rollout on target sustained QPS and p99 latency SLOs.

---

## Verification

### Current Regression Baseline

Qualification in [`status.md`](status.md#current-qualification-ledger-verified-2026-09-17) verified schema `v102` on `2026-09-17` (runtime is now at `schemaVersion = 116` on Rhiza `v0.27.3`). Run package tests covering `Scope` (`internal/storage` uses `-p=2` per ledger):

```sh
go test -count=1 -p=3 -timeout=60m ./internal/authcollection ./internal/clients ./internal/claims ./internal/dpop ./internal/netsec ./internal/saas ./internal/rbac ./internal/oauth ./cmd/goauthy
go test -count=1 -p=2 -timeout=45m ./internal/storage
go test -race -p=3 -timeout=60m ./internal/authcollection ./internal/clients ./internal/claims ./internal/dpop ./internal/netsec ./internal/saas ./internal/rbac ./internal/oauth ./internal/storage ./cmd/goauthy
```

### Async-Delegation Acceptance Checklist

1. **General RFC 8693 Isolation**: `TestTokenExchangeMachineSubjectMapping` and cross-client machine exchanges continue passing without DPoP or `goauthy.connections.use` restrictions.
2. **Connection-Use Exchange Gate**: `POST /oidc/token` with `scope=goauthy.connections.use` or `resource=GOAUTHY_CONNECTIONS_RESOURCE` rejects unset `GOAUTHY_CONNECTIONS_RESOURCE` (`503`), dynamic/public clients (`400 unauthorized_client`), missing client scope (`400 invalid_scope`), `audience` query/form alias (`400 invalid_target`), missing `subject_token` scope/audience or machine/exchanged/`act`/`actor_token` subject tokens (`400 invalid_grant`), `ForceMFA` mismatches including `Device` `mfa_verified` checks (`403 access_denied` before `verifyDPoPTokenRequest`), `clientGroupPolicy` denials (`403` before `verifyDPoPTokenRequest`), and missing `DPoP` headers (`400 invalid_request`/`invalid_dpop_proof`); issues `400 use_dpop_nonce` + retry, enforces exact `scope=goauthy.connections.use` and `aud=[GOAUTHY_CONNECTIONS_RESOURCE]`, enforces `browser_sessions` + `ExpectedRowsAffected=1` (`400 invalid_grant` on precondition failure), copies `goauthy_oidc_session_id`/`goauthy_oidc_auth_method` uniformly, and returns `503` on Rhiza unavailability.
3. **DPoP Resource Auth, Direct Boundary & Co-Requisite Fixes**: `/auth/v1/connection-grants/{grant_id}/*` accept DPoP-bound `TokenExchangeGrantType` tokens (`Authorization: DPoP` + `ath` + `MarkReplay`), enforce `401` (`WWW-Authenticate: DPoP algs="ES256" error="invalid_dpop_proof"` / `"invalid_token"`) directly from `internal/oauth`, reject `TokenExchangeGrantType` Bearer tokens, enforce `ForceMFA` on human grants, return `409` on concurrent `refreshing` claims in `POST .../refresh`, map `ErrInactiveSubject` -> `401`, map `ErrCredentialUnauthorized` -> `500`, `ErrCredentialCorrupted` -> `500`, and `ErrCredentialNotFound` -> `404`, keep expired `refreshing` claims fail-closed (`ClaimRefresh` rejects them; only owner `DELETE .../oauth2` transitions to `revoked`), enforce `UpdateDefinition` reference checks, and propagate Rhiza unavailability as `503`.
4. **Consumer Wire Contract Parity**: Verify 43-char `base64.RawURLEncoding` `connector_digest`, canonical `header`/`prefix` (`"" | "Bearer " | "Token "`), and `POST .../credential` (`404`) -> `GET .../credential-status` (`ready` retry `/credential` once, else `POST .../refresh` when `allow_refresh=true`) parity against [`external-credential-consumer-contract.md`](external-credential-consumer-contract.md#사용자-oauth-연결-runtime-schema-v74).
