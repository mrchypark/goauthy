# Connection Use Grants (`docs/connection-use-grants.md`)

## Problem Statement & Goals

GoAuthy allows connection owners to store third-party SaaS credentials (API keys or OAuth 2.0 tokens) inside named **auth collections** (`collection` → `connection` → `provider` in `internal/authcollection` and `internal/saas`). External consumer applications (such as **Backoffice** or **Conductor** BFFs and execution workers) need scoped, revocable, owner-consented access to those credentials without receiving long-lived refresh tokens or admin-level session authority.

- **Goals**:
  - Enable owners to grant, list, and revoke consumer access per `(owner, collection_id, connection_id)` via browser-authenticated endpoints, binding grants to `connection_generation`, `consumer_generation`, `provider_revision`, and (for API keys) `connector_digest`.
  - Support two consumer access modes: **`proxy`** (server-side fixed `GET` operation invocation with scalar JSON projection for registered API-key providers) and **`credential_delivery`** (delivering the raw API key or OAuth2 `access_token` to confidential human-delegated consumers).
  - Enforce fail-closed OAuth2 token refresh (`POST .../refresh`) and linearizable Rhiza authority/version rechecks before every outbound call or credential export.
- **Non-Goals**:
  - `proxy` mode for OAuth2 connections (OAuth2 grants support `credential_delivery` only).
  - Per-operation OAuth2 scope attenuation (all upstream granted scopes are delivered; `purpose` is descriptive only).
  - Background refresh scheduling, automatic upstream RFC 7009 revocation, or recalling already-delivered plaintext credentials.

Related contracts: [one-use handoffs](connection-use-handoffs.md), [external credential consumer contract](external-credential-consumer-contract.md), [capability matrix](capabilities.md), [execution ledger](status.md), [`internal/saas/README.md`](../internal/saas/README.md), and [`internal/rbac/README.md`](../internal/rbac/README.md).

---

## Alternatives Considered

| Option | Decision | Trade-off / Rejection Rationale |
| --- | --- | --- |
| **Self-contained attenuated capability JWTs** | Rejected | Cannot synchronously fence against mid-flight `connection_generation`, `provider_revision`, or owner revocation without a linearizable Rhiza SQL guard (`AuthorizeUseGrant`). |
| **Background refresh daemon** | Rejected | Risks silent refresh-token consumption races across HA pods; explicit consumer/owner refresh with a durable pre-send `refresh_claim` keeps refresh ownership deterministic. |
| **OAuth2 `proxy` mode** | Deferred | Arbitrary upstream HTTP methods/paths require a general-purpose HTTP policy proxy; currently `proxy` is limited to fixed `GET` scalar-JSON API-key operations. |

---

## Proposed Architecture

### 1. Participants, Collections & Generation Fencing

- **Collection & Connection**: An `authcollection` defines user-owned connection slots; each `connection` holds an encrypted API key or OAuth2 credential under a configured `provider` (`internal/saas`).
- **Actors**: **Owner** (browser-authenticated user owning the connection), **Managed / Execution Consumer** (confidential OAuth client holding a human-delegated Bearer token with `goauthy.connections.use` and `GOAUTHY_CONNECTIONS_RESOURCE` audience, obtained via Authorization Code + PKCE), and **Handoff Requester** (application initiating a [one-use handoff](connection-use-handoffs.md)).
- **Generation & Revision Bindings**:
  - `connection_generation`: Incremented/replaced when the owner revokes and reconnects a connection; invalidates all existing grants on that connection.
  - `consumer_generation`: Current consumer client generation bound at grant creation.
  - `provider_revision`: Incremented on provider config updates; invalidates grants whose bound `provider_revision` or `connector_digest` no longer matches.
  - `credential_version`: Incremented on API-key rotation or OAuth2 refresh.

### 2. Shared Consumer Bearer Security Contract

All consumer Bearer endpoints (`/auth/v1/connection-grants/{grant_id}/*`) enforce:
- Confidential human-delegated Bearer token (`Authorization: Bearer ...`) with scope `goauthy.connections.use`, `GOAUTHY_CONNECTIONS_RESOURCE` audience, and non-expired grant/authority verified in **Rhiza** (`*rhiza.DB`).
- HTTPS-only (unless explicitly allowed in local test configs), no query parameters, no cookies, and rejection of `Origin` and `Sec-Fetch-*` Fetch Metadata headers.

### 3. Owner Grant Management (`/auth/v1/account/connections/{collection_id}/{connection_id}/grants`)

Requires an owner browser session; `POST` and `DELETE` also require the session-bound CSRF header (`X-CSRF-Token`).

| Endpoint | Behavior & Constraints |
| --- | --- |
| `GET .../grants` | Lists up to `256` grants (`ORDER BY expires_at_unix_ms DESC, id LIMIT 256`). |
| `POST .../grants` | Creates a grant (`consumer_client_id`, `mode`: `proxy` \| `credential_delivery`, `purpose`, `expires_in_seconds`, optional `allow_refresh`, `connector_digest`, and `credential_version` for OAuth2). Caps active grants at `32` per connection; `allow_refresh` applies only to OAuth2 `credential_delivery`. |
| `DELETE .../grants/{grant_id}` | Revokes the grant locally in Rhiza (`404` if missing). |
| `GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}` | Owner-side Bearer status check (e.g., for Backoffice BFF verifying consent targeting Conductor) via one linearizable Rhiza query (`404` on unknown/cross-owner/mismatched grant). |

### 4. API-Key Connector & Proxy Invocation (`proxy` Mode)

- **Connector inspection & key setup**: Owners/admins inspect connector definitions via `GET /auth/v1/account/connections/{collection_id}/{connection_id}/api-key/connector` and store keys via `PUT /auth/v1/account/connections/{collection_id}/{connection_id}/api-key` (supported for registered providers and empty-provider legacy keys; `connector_digest` is computed from canonicalized provider operation metadata).
- **`POST /auth/v1/connection-grants/{grant_id}/invoke`**: Requires `mode=proxy` and a `connector_digest`-bound grant (`operation` id). Revalidates authority, grant, `provider_revision`, `connector_digest`, and `credential_version` via `AuthorizeUseGrant` SQL guard before and after dispatching the registered `GET` request through `restrictedTransport` (no redirects, scalar JSON projection).

### 5. Credential Delivery (`credential_delivery` Mode)

- **`POST /auth/v1/connection-grants/{grant_id}/credential`**:
  - **API-key (`kind=api_key`)**: Returns decrypted key material, `credential_version`, `provider_revision`, and `connector_digest`. Consumers must inject keys only against approved provider destinations, disable HTTP redirects, and avoid logging secrets.
  - **OAuth2 (`kind=oauth2`)**: Returns decrypted `access_token`, `token_type`, `expires_at_unix_ms`, `scope` (all upstream granted scopes), `credential_version`, `connection_generation`, and `provider_revision` (no `refresh_token` or destination URL is exported).

### 6. Explicit OAuth2 Refresh & Interrupted Recovery

- **Owner refresh**: `POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh` (takes `{"version": ...}`).
- **Consumer refresh**: `POST /auth/v1/connection-grants/{grant_id}/refresh` (requires `allow_refresh=true` on OAuth2 `credential_delivery`, takes `{"credential_version": ...}`).
- **State machine (`ready` → `refreshing` → `ready` | `uncertain` | `revoked`)**:
  1. `ClaimRefresh` durably records a pre-send `refresh_claim` (`state: "refreshing"`) in Rhiza before any outbound token-endpoint call.
  2. Single-attempt upstream refresh runs without automatic retries.
  3. On local commit/transport ambiguity (`MarkRefreshUncertain`), the connection enters `uncertain`; on success, `CompleteRefresh` advances `credential_version` and returns `ready`.
  4. `GET /auth/v1/connection-grants/{grant_id}/credential-status` (handler implemented in `internal/rbac/connection_credential_status_http.go`; top-level router wiring tracked in [docs/status.md](status.md)) reports `state` and `connected` without `claim_started_at`. Consumers observing `refreshing` may poll conservatively (for example every 5s up to 1m); `refreshing` or `uncertain` failures require the owner to revoke the connection version, reconnect/re-authorize at the provider, and issue fresh consumer consent.

---

## Risks & Mitigations

1. **`ListUseGrants` `LIMIT 256` truncation without active filtering**:
   - *Risk*: `internal/saas/use_grant.go` queries `LIMIT 256` ordered by `expires_at_unix_ms DESC, id` without filtering `revoked=0` or expired rows and has no pagination/GC. 256 revoked grants with long expirations can hide newly created shorter-lived active grants from `GET .../grants`.
   - *Mitigation*: Track as a code fix to filter active grants (`revoked=0 AND expires_at_unix_ms > now`) or add keyset pagination and expired-grant pruning.
2. **Sticky `refreshing` / `uncertain` DoS & multi-consumer blast radius**:
   - *Risk*: A crash or timeout between `ClaimRefresh` and `CompleteRefresh` leaves the connection wedged until manual owner revoke + reconnect, which bumps `connection_generation` and invalidates *all* consumers' grants on that connection. `credential-status` lacks server-side rate limiting and `claim_started_at`.
   - *Mitigation*: Enforce client-side polling caps and document owner revoke/reconnect recovery.
3. **OAuth2 full-scope delivery & lack of upstream revocation**:
   - *Risk*: `credential_delivery` exports all upstream-granted scopes (`purpose` is descriptive only), cannot revoke delivered tokens upstream, and relies on consumers to enforce destination allowlists and disable HTTP redirects.
   - *Mitigation*: Restrict `credential_delivery` to trusted confidential consumers and prefer `proxy` mode for API-key integrations.
4. **Optional `connector_digest` / `credential_version` on direct `POST .../grants`**:
   - *Risk*: Omitting `connector_digest` or `credential_version` on the direct owner `POST` route preserves API compatibility without recording a review commitment (unlike [one-use handoffs](connection-use-handoffs.md)).
   - *Mitigation*: Prefer the handoff approval flow for interactive user consent and supply explicit digests/versions in automated clients.
5. **Runtime allocation note**:
   - `validUseCredential` (`internal/saas/use_grant.go`) constructs `NewAPIKeyConnector` (including `restrictedTransport`) during `AuthorizeUseGrant` digest checks; extract a pure digest helper when optimizing hot paths.

---

## Verification

```sh
go test ./internal/saas ./internal/rbac ./internal/oauth
```

Dated local TLS / standalone E2E runs and remaining integration wiring (`credential-status` router wiring, Backoffice consumer validation) are tracked in [docs/status.md](status.md) and [docs/capabilities.md](capabilities.md).
