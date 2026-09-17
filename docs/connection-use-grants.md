# Connection use grants — partial implementation

Owner browser session is required; POST/DELETE also require the existing CSRF
header. These routes do not accept consumer Bearer tokens and never return secrets.

Base: `/auth/v1/account/connections/{collection_id}/{connection_id}/grants`

| Request | Contract |
| --- | --- |
| POST base | Strict JSON `consumer_client_id`, `mode`, `purpose`, `expires_at_unix_ms`; optional non-null boolean `allow_refresh` (default `false`); 201 metadata with ETag |
| GET base | Empty body; 200 metadata array, at most 256 entries |
| DELETE base `/{grant_id}` | Empty body and quoted `If-Match` revision; 204; missing revision 428, stale revision 409 |

Modes are `proxy` and `credential_delivery`. Proxy grants can now authorize the
registered API-key invocation route below. Separate credential-delivery consent
can authorize the registered API-key or OAuth access-token retrieval route below.
Purpose is descriptive, not an enforceable operation policy.
Expiry must be future and at most 30 days; at most 32 active grants per connection.
Creation requires configured `GOAUTHY_CONNECTIONS_RESOURCE` (otherwise 503), an
active managed consumer with that exact audience and `goauthy.connections.use`.
Credential-delivery consent additionally requires a confidential consumer. `allow_refresh`
is an explicit user-approved OAuth2 `credential_delivery` capability; it is false by
default and has no effect for API-key or proxy grants. Legacy omitted values remain false.

POST also accepts optional `connector_digest`, the API-key settings digest reviewed
by the owner. When supplied it must match the currently authenticated API-key
binding (malformed/null or OAuth use: 400; valid but mismatched: 409). Existing
provider revision and credential-version commit guards still apply. Omission
preserves the existing API contract; it does not imply that a review took place.

Storage binds owner, connection generation, consumer generation, provider revision
and authenticated connector digest. Internal `AuthorizeUseGrant` requires current
authority and returns a SQL guard for subsequent guarded work. Token version is a
per-use snapshot: refresh preserves consent but invalidates an old in-flight guard.
Reconnection, revoked consent, expiry or changed policy prevents subsequent use.
Revocation does not recall plaintext credentials already delivered elsewhere.
Provider client secrets and refresh tokens are not exported by these routes.

`POST /auth/v1/connection-grants/{grant_id}/refresh` is a strict, server-only
HTTPS operation for a confidential human consumer whose grant explicitly has
`allow_refresh=true`. It accepts only `{"credential_version": <positive int64>}`
and returns public OAuth2 status (`provider_id`, `account_id`, `scopes`, `version`,
`connected`, `state`). Cookies, Origin, Fetch Metadata, query parameters, CSRF,
If-Match, machine authentication and DPoP are rejected. The provider is called at
most once under grant/client/authority guards; stale versions make no upstream
call, and uncertain outcomes fail closed. Consumers can inspect current public
OAuth2 metadata with `GET /auth/v1/connection-grants/{grant_id}/credential-status`
using the same confidential human Bearer authorization, exact resource audience
and current consent. This no-store, bodyless, read-only endpoint performs no
upstream call, permits expired access-token status inspection, and returns 404 for
API-key/proxy or stale authority/grants. A concurrent state/version change during
the final snapshot recheck can also return 404; this alone does not prove permanent
revocation. Fail the current operation closed without cached-credential fallback
or automatic refresh retry. A `ready` status with the current version
may be explicitly refreshed only when consent has `allow_refresh=true`; otherwise
it is delivery-only. `refreshing` means wait without exchanging again, while
`uncertain` or `revoked` requires owner reconnect/recovery. Consumers must not
guess versions, retry exchanges blindly, or substitute an owner cookie. Delivery
never refreshes automatically and no scheduler exists.

## Verification and remaining integration

Focused real-Rhiza tests cover owner CRUD, strict parsing, stale revision, wrong
consumer, expiry, OAuth refresh and policy fences, plus schema-v76 replay.
They are not full consumer E2E evidence.

`GOAUTHY_E2E_TLS=1 GOAUTHY_E2E_USE_GRANTS=1 sh scripts/e2e-open-registration-standalone.sh`
now passes actual HTTPS standalone/restart acceptance; see status.md for logs.
The previously failing API-key provider binding is implemented in schema v77.

API-key collections accept `provider_ids: []` for legacy storage or exactly one
registered enabled API-key provider. An owner reviews
`GET .../api-key/connector` (id, digest, header, prefix, allowed operations) and sends
`{"api_key":"<key>","version":0,"connector_digest":"<reviewed digest>"}` to PUT
`.../api-key`. Rotation uses the current version and the reviewed digest. A digest
is public configuration integrity metadata, not a secret or an authorization token.
Unknown/null/duplicate fields remain invalid; a stale digest or version is rejected.
Empty-provider legacy keys remain usable for storage management but cannot obtain
use grants unless explicitly connector-bound by trusted internal code.

The `/account` API-key editor now displays provider settings and requires explicit
review before sending the digest. It clears keys on save/failure/cancel/navigation;
this is key-custody confirmation, not consumer usage consent. Registered-key
Chromium standalone/restart coverage is recorded in status.md.

Historical API-key panel milestone (superseded by the OAuth milestones in
[STATUS.md](STATUS.md)): the native `/account` service-access panel connected owner grant list/revoke
and explicit proxy creation for registered API-key connections. It displays the
provider's operation settings and asks for the administrator-supplied consumer
client ID, purpose and expiry. A separate unchecked confirmation authorizes the
displayed operations; changing input resets it. Creation submits the reviewed
digest. Other connection types currently support list/revoke in this panel only.
It is not a consumer handoff or an automatic return flow. Stored metadata does not
prove that current execution policy will allow a later call.

Current: OAuth approval creation UI/handoff and explicitly consented consumer
refresh are implemented and standalone browser-tested. Actual consumer OAuth
integration and full E2E remain open; credential-status is implemented while
application wiring remains.
Registered API-key proxy handoff and Bearer status verification are available.

## Confidential-consumer API-key delivery

Registered `Authorization` supports exact prefixes `""`, `"Bearer "` and
`"Token "`; `X-API-Key` requires `""`. Empty means the raw API key, not a missing
credential. Prefix is part of the reviewed digest, so changing authentication
format requires new binding/consent. Arbitrary prefixes and control characters
remain invalid. This concerns outbound SaaS authentication, not GoAuthy's inbound
human Bearer authorization.

`POST /auth/v1/connection-grants/{grant_id}/credential` accepts an empty body
(not `{}`) and one human Bearer token with `goauthy.connections.use` and the exact
connections resource audience. The token's managed consumer must be confidential.
Cookie, Origin, Sec-Fetch-Site, query (including bare `?`), If-Match and CSRF
headers are rejected. This endpoint requires an HTTPS issuer.

An explicit `credential_delivery` grant is required; proxy consent cannot export.
For registered API-key connections, response fields are `kind`
(`api_key`), `api_key`, `grant_id`, `provider_id`, `connection_generation`,
`credential_version`, `connector_digest`, `header`, `prefix` and
`consent_expires_at_unix_ms`. This API-key variant returns no OAuth token.
Neither variant returns provider client secrets or refresh tokens.
Responses are no-store/no-referrer; consumers must
disable authorization-header and response-body logging and keep the key out of
browser state, URLs, telemetry and normal collection records.

Current owner, consumer, grant, expiry, generation, provider and credential
version are rechecked after decryption. Revocation/expiry blocks future retrieval;
it cannot recall an already delivered key or shorten the provider's key lifetime.
The recipient can use the raw key outside the proxy's operation/projection limits:
the digest identifies reviewed settings, not an enforceable SDK restriction.
Provider-side revocation is needed to invalidate a previously delivered key.
The separate delivery handoff now displays a raw-key warning and explicit delivery
confirmation. Do not relabel proxy consent or stored consent as SDK readiness.

### Consumer integration contract

Registered OAuth connections use the same bodyless endpoint with `kind=oauth2`.
Its exact fields are `kind`, `access_token`, `token_type` (`Bearer`), `grant_id`,
`provider_id`, `connection_generation`, `credential_version`, `account_id`,
`scopes`, `token_expires_at_unix_ms`, and `consent_expires_at_unix_ms`.
It requires its own confidential consumer's current `credential_delivery` grant;
an API-key adapter must not infer OAuth support from the shared endpoint.
The OAuth variant carries no API-key connector digest or destination. Its
provider/account/scopes and trusted destination mapping must be checked by the
consumer. All upstream granted scopes are delivered, not a per-operation subset.
The token's known future expiry is checked again immediately before return.
Unknown/expired tokens fail closed; retrieval does not refresh or call upstream.
Consent expiry stops retrieval but cannot shorten the upstream token's validity.
Refresh completion must preserve the exact stored account ID (including whether
it is empty). A changed account is a reconnect/new-generation operation, not a
token rotation under old consent. A mismatch after exchange leaves the refresh
uncertain and unusable, without silently installing or retrying the new token.
The explicit registered-provider refresh adapter now additionally looks up the
new token's upstream identity before committing. This local invariant also guards
other internal refresh callers. Subsequent OAuth-specific HTML approval/handoff
and public browser E2E now pass (see [STATUS.md](STATUS.md)); full consumer-app
OAuth E2E remains open. Raw-key approval is not a substitute for OAuth approval.

Owners can explicitly refresh with browser session + CSRF using
`POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh`
and strict JSON `{"version": <current positive int64>}`. An HTTPS issuer is
required; no Bearer/API-key authentication, query or If-Match is accepted.
The endpoint returns the same metadata-only status as OAuth status GET, never
access/refresh tokens. It is not a background scheduler or consumer auto-refresh.
One durable claim permits one refresh exchange, followed by a new-token identity
lookup. The exact account must match and scopes cannot exceed the stored scope
set. Omitted refresh tokens retain the old value; known refresh expiry is carried
conservatively. Unknown access-token expiry remains zero and cannot be exported
through the credential-delivery endpoint. An ambiguous exchange/commit or failed
post-exchange verification leaves the connection unusable, without retrying the
possibly consumed refresh token. Inspect owner status and revoke/reconnect;
do not interpret a 503 as permission to reuse cached credentials.

- Acquire a human token for the execution consumer's own confidential OAuth
  client using authorization code + PKCE and server-side client authentication.
  Register the exact connections resource audience and required scopes first;
  pass `resource` at authorization. Service/client-credentials tokens and another
  application's user token are not substitutes. A handoff requester can be a
  different client, but retrieval must use the grant's execution client. For
  queued jobs, expired/revoked authority stops execution; reacquire authorization,
  not a token synthesized from job metadata. Offline/refresh support must be
  explicitly configured and verified by that consumer, not assumed by this API.
- Treat grant ID, provider ID and `connection_generation` as opaque strings,
  never local numeric revisions or upstream account IDs. `credential_version`
  is a positive signed int64 local to the connection; use a lossless JSON integer
  decoder. Key rotation increments this version without replacing logical
  consent. Reconnection replaces the generation and invalidates the old grant.
  Provider configuration revisions invalidate old grants/digests. A local adapter
  decides explicitly whether a new credential version is acceptable; it must
  never silently accept changed generation/provider/digest/consumer/mode.
- Register an operator-reviewed mapping from GoAuthy provider to the SDK's fixed
  endpoint, header and prefix. Do not infer this mapping from equal ID strings or
  let delivery metadata select an arbitrary URL/header. The handoff `review`
  includes the authenticated connector settings for the requester to bind into
  its own trusted server-side snapshot; normal users do not need provider-admin
  privileges. An execution service must receive this binding via trusted internal
  configuration, not unsigned browser callback values. Delivery itself contains
  no destination or upstream account identity. Disable redirects when injecting
  keys into provider calls.
- Compare digest strings exactly. The current server digest is SHA-256,
  base64url without padding, over the v1 `saas-api-key-connector` canonical JSON:
  provider ID, canonical header, exact prefix, operations sorted by ID with fixed
  GET method and exact URL, response fields sorted by name/type. It is not a
  general JSON canonicalization standard. Consumers should store the server's
  authenticated digest and not reimplement its serialization. No cross-version
  digest stability is promised; changes require new reviewed binding/consent.
- Retrieval errors: 400 invalid request (fix it); 401 invalid/currently
  unauthorized human token (reauthorize); 404 unavailable matching grant/binding
  (stop); 409 conflicting/changed current state (review again); 503 unavailable
  configuration/store (no key usable). The shared error catalog reserves 502,
  but this API-key path makes no upstream call. Network/5xx failures do not
  authorize cached-key fallback. Retrieving a key again does not repeat a provider
  operation, but there is no automatic retry contract: keep provider-operation
  retries separate and require their own idempotency rules.
- The API-key response has ten fields and `kind=api_key`; OAuth has the eleven
  fields above and `kind=oauth2`. Ignore unknown additive
  metadata only after validating all required fields and supported kind; do not
  infer new credential kinds or privileges. Breaking field/semantic changes need
  an explicit contract revision; no generic SDK wire version is currently exposed.
  Keys/tokens stay in execution-service memory, not job payloads, DB records,
  browser state, callbacks or logs. Fetch under current authority for each use.

## Consumer invocation (2026-09-07)

`POST /auth/v1/connection-grants/{grant_id}/invoke` accepts only JSON
`{"operation":"account"}` (8 KiB maximum). Operation IDs match
`^[a-z0-9][a-z0-9_-]{0,63}$`. The consumer supplies its human Bearer access token
with `goauthy.connections.use` and the exact configured connections resource
audience. Owner and consumer identities come from the verified token, not JSON.
Cookies, query parameters, machine/exchanged/DPoP tokens are not accepted.

The current grant must authorize this owner/consumer in proxy mode. The registered
API-key connector, digest and operation allowlist determine the destination and
authentication header; callers cannot supply URLs or headers. Only configured
scalar JSON response fields are returned, with no-store and no upstream headers.
The current authority and credential are checked before dispatch and again before
returning the result. Revocation cannot undo a request already sent upstream.

Responses: 200 projected JSON; 400 invalid body/operation; 401 authentication;
404 unavailable grant/connection; 409 conflicting current state; 502 upstream
failure; 503 missing configuration/internal unavailability. No automatic retries.

Real Rhiza plus a local TLS provider verifies successful header injection and
projection, zero dispatch for invalid grants, and result discard when revocation
occurs inside the provider handler. A separate actual HTTPS standalone/restart
test uses real code+PKCE tokens to verify unknown operation, missing grant,
missing token, missing audience and revoked grant denial. It deliberately does
not dispatch a positive outbound request: this is not full positive public-route
or consumer-application E2E evidence. Production private-network restrictions
have not been relaxed for the fixture.

Registered-provider support reuses `authcollection.validateDefinition`,
`rbac.collectionProviderAuthority`, API-key storage and use-grant policy. Provider
kind, enabled state, singleton reference and revision are checked at the guarded
write/read. The provider-removal trigger revokes disconnected keys, while a legacy
empty-list edit preserves the key. Disabled-provider status/revoke remain available.

## Backoffice integration feedback (2026-09-07)

Backoffice's BFF holds its own OIDC access token, not the GoAuthy browser cookie or
CSRF token. It cannot proxy these owner-session routes. Do not copy session cookies
or put credentials in redirect URLs. The next integration needs a documented
GoAuthy-origin settings/approval URL, server-validated connection/consumer targets,
allowlisted return URL and one-use state. Consumer/mode/purpose preselection must
be presented for confirmation, not silently treated as consent. On return, the
BFF must use its own read-scope Bearer token with the owner-oriented grant-status
route to verify stored consent; it cannot use credential-status for a different
execution consumer. Returning from the settings page alone is not proof of completion.
The [one-use handoff contract](connection-use-handoffs.md) and HTML approval page
are implemented for registered API-key proxy and separate credential-delivery
consent. The native owner panel
does not replace it or accept untrusted URL preselection. Actual Backoffice
integration still needs consumer-side validation and feedback.

## Owner-side Bearer status verification

`GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}`
requires a human Bearer token with `goauthy.connections.read` and the exact
configured connections resource audience. The token owner determines ownership;
the observing application need not be the grant's execution consumer. This permits
Backoffice to verify its user's consent targeting Conductor, without sharing a
GoAuthy cookie. Read scope never authorizes invocation or grant mutation.

The 200 response is `{ "grant": <stored grant metadata>,
"connection_generation": "<current parent generation>" }`. Grant and current
parent generation are read in one linearizable Rhiza query. No credential is
decrypted or returned. Revoked and expired grants remain readable; deleted/missing
parents, other owners, mismatched paths/resources and failed SQL authority do not
return the record. A new connection generation is distinguishable from the
historical grant's `generation`.

Consumers should compare the expected connection, consumer client ID, mode,
resource and `allow_refresh` (omission means false), require matching generations,
compare the connector digest for API keys only, and inspect revoked
and expiry fields. This verifies stored consent only: current provider/client
policy and credential state are still checked at actual invocation. It is not
a capability, an `active`/readiness result or permission to export credentials.

Requests have no body, query (including a bare `?`), Cookie or If-Match. Responses
are no-store: 400 invalid request, 401 authentication, 404 unavailable target,
503 missing configuration/internal unavailability. Existing owner browser/CSRF
routes remain the only public grant mutation paths.
