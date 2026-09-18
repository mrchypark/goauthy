# Lifecycle events

Baseline: Rauthy v0.36.2 (`dd61ac3c84d6b238108dc8438b53043b5177a662`),
Rhiza v0.12.0, GoAuthy schema 60. This is not the existing pseudonymous
API-key/master-key audit API. Full event parity is **incomplete**.

## Feature and package ledger

| Status | Feature | Implementation / verification |
|---|---|---|
| [x] | Typed event record and durable schema | stdlib JSON, `crypto/sha256`, `encoding/base64`, `net/netip`; Rhiza SQL. Real migration, constraints, nullable wire fields, deterministic query tests. |
| [x] | `NewUserRegistered` from public and administrator creation | Existing identity transaction; commit-time creation witnesses. Duplicate, denied and rolled-back creation adds no event. |
| [x] | `NewRauthyAdmin` on direct administrator creation | Same transaction, resulting `rauthy_admin` membership; Info registration plus Notice admin event. |
| [x] | `POST /auth/v1/events` | stdlib HTTP/JSON, existing API-key and browser/RBAC guards; single linearizable query; OpenAPI schema tests. Live evidence is scoped in [status](status.md). |
| [x] | Retention worker | stdlib context/ticker and Rhiza ordered DELETE, 1000 rows per transaction; fixed-cutoff drain, same-clock progress and cancellation tests. |
| [ ] | Configurable per-type levels and persistence threshold | Defaults only: registration Info, administrator Notice. |
| [x] | `GET /auth/v1/events/stream`, bounded history and live delivery | stdlib `net/http.ResponseController`, JSON, context/ticker; schema 60 monotonic SQL sequence. Standalone and exact-three live evidence in [status](status.md). No Last-Event-ID replay protocol is advertised. |
| [x] | `POST /auth/v1/events/test` | stdlib HTTP/IP parsing, existing random IDs, Rhiza guarded insert and commit receipts; Events:create or direct browser admin + CSRF. Payload/query/SSE/restart evidence in [status](status.md). Notification adapters remain separate unfinished work. |
| [ ] | `UserPasswordReset` lifecycle | Reset-form consumption (including first-password setup) and public administrator password assignment append Notice events in the corresponding password transaction. Admin payload/null-IP and rollback plus standalone/HA POST/restart evidence are in [status](status.md). Configurable level, notification and full flow/SSE gates remain unfinished. |
| [ ] | `UserEmailChange` lifecycle | Public administrator PUT appends the old→new admin text with Notice/null IP/data in the profile transaction. Fixed-clock/rollback/race and standalone/HA POST/restart gates pass. Self-service confirmation, configurable level, external event notifiers and emitter-specific open-SSE/chaos remain incomplete. |
| [x] | `JwksRotated` from automatic signing-key activation (scoped) | Existing activation transaction appends one Notice/null-payload event for the winning old/pending key pair. Fixed-clock race/rollback tests, standalone cold restart, exact-three HA same-event POST/SSE and Pod replacement pass; [evidence](status.md). Configurable levels and broader key-management parity remain unfinished. |
| [x] | `IpBlacklisted` from automatic failed-login blocking (scoped) | Existing counter/prune/upsert transaction, stdlib event identity and Rhiza `OutputRefs` bind the stored finite expiry. Warning/host IP/Unix-second expiry/null text. Fixed-clock negative/rollback/concurrent race 2x, standalone cold restart and exact-three HA event/Pod replacement pass; [evidence](status.md). |
| [x] | `InvalidLogins` from the shared password/passkey failure policy (scoped) | stdlib event identity; Rhiza `RETURNING`/`OutputRefs` bind this commit's count and default level. Independent of automatic blacklist enablement, host IP, uint32-capped data, null text. Fixed-clock counter/concurrent/rollback race 2x and actual password-failure standalone/HA POST/SSE/restart pass; [evidence and remaining gates](status.md). |
| [x] | `BackchannelLogoutFailed` at failed delivery attempt limit (scoped) | Existing lease-guarded completion, stdlib event identity, Rhiza `RETURNING`/`OutputRefs` and atomic event/order insert. Critical/null IP/actual attempts/client-sub text. Fixed-clock Step/concurrent/rollback race 2x and actual 100-send standalone/HA POST/SSE/restart gates pass; [evidence and retry-policy gaps](status.md). |
| [x] | `ScimTaskFailed` at failed outbox attempt limit (scoped) | Failed completion and expired-final-claim recovery use stdlib crypto identity/quoted actions and Rhiza guarded atomic INSERT/UPDATE. Whole-package, fixed-clock/race/rollback and actual user-create failure 5-attempt standalone/HA POST/SSE/restart gates pass. Group-create/user-delete workflows also pass both modes with five failed provider lookups per resource and restart persistence; actual mutation-method failures have separate HTTPS integration tests. Group-update/delete/full-sync live gates and full retry/configuration remain separate. Explicit upstream type inconsistency and quoting adaptation in [research](package-research.md); [current evidence](status.md). |
| [x] | `ForcedLogout` on per-user administrative logout (scoped) | Mounted `DELETE /auth/v1/sessions/{subject}`; existing Rhiza batch captures authoritative email, revokes local artifacts, enqueues subject-only user/client back-channel work and appends Notice/null IP/data. Local store/HTTP/OpenAPI race and standalone/HA session/access-token/fresh-login/POST/SSE checks pass, including cold restart/Pod replacement persistence. Actual per-user subject-only RP delivery and preservation of the other user's same-client session also pass standalone/exact-three HA; broader gates remain open in [status](status.md). |
| [ ] | Email, Matrix and Slack delivery thresholds/retry | Existing `go-mail` can send email; durable delivery and notifier adapters are not implemented. |
| [ ] | Event management UI, all-type E2E and delivery/stream chaos | Not implied by the creation/query tests. |

The other DTO types are accepted for filtering but have **no lifecycle emitter**
yet: `IpBlacklistRemoved`,
`NewRauthyVersion`, `PossibleBruteForce`, `RauthyStarted`, `RauthyHealthy`,
`RauthyUnhealthy`, `SecretsMigrated`,
`UserLoginRevoke`, `SuspiciousApiScan`, `LoginNewLocation`,
`CredentialStuffing`, `EmailSendError`. Similar existing audit records do not
count as these emitters.
The [24-type matrix](event-emitter-matrix.md) keeps per-type implementation and
package/integration anchors separate from transport and notification completion.

## Password-reset lifecycle

The pinned [reset form service](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/password_reset.rs)
emits after successful password application for both an existing user's reset
and a new user's first password. Issuing or opening a link does not emit it.
The [constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs)
stores caller text verbatim, not its separate notification display formatting.
GoAuthy records `Reset via Password Reset Form: {profile email}`, Notice, null
data, and the resolved request IP. The HTTP boundary uses trusted middleware
context or the direct peer, never interprets forwarding headers itself; invalid
IP fails instead of persisting upstream's `UNKNOWN` placeholder.

The existing event constructor/INSERT builder and Rhiza receipt path are reused.
A shared SQL expression reads the nonempty profile email, falling back to the
bound recovery email for legacy bootstrap identities. That value is captured
before hashing and checked again in the token-consumption statement. A concurrent email change rejects the reset
without consuming its proof. Token consumption, password/history/session
changes and the guarded event INSERT commit together; a rejected event INSERT
rolls all of them back. The event uses the final post-hash clock sample and
the same operation identity, subject, consumed attempt and resulting password
generation. No password, reset bearer token or CSRF secret enters its payload.

This is product-specific transaction/payload glue, not a new protocol or broker;
no extra package/schema was added. The [upstream admin update](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users.rs)
has a separate reset-event payload and null IP; that branch is now connected
through public PUT. `UserEmailChange` is not synthesized during first-password setup:
email verification is not an address change. Configurable per-type levels,
notifier delivery and all-flow parity remain unchecked.

## Test-event mutation

The production [upstream test route](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/events.rs)
requires Events:create or a direct administrator; the
[event constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs)
assigns Info, Test, requester IP, null data and `This is a Test-Event` text.
GoAuthy implements that empty-200, no-body endpoint. It additionally rejects
query parameters/nonempty bodies, requires browser CSRF and same-site admission,
never falls back from a supplied API key to an ambient cookie, and repeats the
exact key/session/direct-role/account guard in the INSERT transaction. Delegated
group-admin event visibility remains read-only. IP comes from trusted middleware
or parsed RemoteAddr, never directly from forwarding headers.

Existing stdlib-backed random IDs give each HTTP invocation a fresh operation
ID; the event ID includes that operation and type. The existing Rhiza receipt
recovery reuses the exact SQL request after an ambiguous commit. This prevents
internal retry duplication, but independent HTTP POSTs are distinct, including
at identical timestamps; there is no HTTP idempotency-key contract. GoAuthy
returns success only after durable insertion, not just an in-memory enqueue.
Denied writes and entropy/database failures produce no event/order row.

No new schema or dependency is needed: `Event.Statement`, existing RBAC/browser
guards and `storage.Execute` already provide the building blocks. Only the
product permission/payload mapping and HTTP glue are direct code. The upstream
debug-only all-type sample generator and real email/Matrix/Slack notification
delivery are not claimed by this route's completion.

## Query and privacy contract

The [upstream query handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/events.rs#L28)
and [DTO](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/events.rs#L46)
define required `from` Unix seconds and lowercase `level`, optional `until`
seconds and PascalCase `typ`, with a bare JSON array response. From/until are
inclusive; level is a minimum threshold. Default until uses whole seconds,
not current fractional milliseconds. An inverted interval returns an empty
array. Responses retain `ip`, `data`, `text` even when null.

GoAuthy additionally rejects overflow on seconds-to-ms conversion, case aliases,
duplicate/unknown keys, invalid UTF-8, non-JSON content types and bodies over
8 KiB. Event timestamps are milliseconds. Sorting adds deterministic ID ordering
when timestamps tie. IDs are opaque 43-character SHA-256/base64url values from
the operation ID and type, rather than upstream's random short IDs.

Events:read API keys and current browser direct/delegated administrators can
read events. The session/key and role/account conditions are rechecked in the
same linearizable SQL snapshot as the returned data. This preserves upstream
group-admin visibility; it is not a per-user event filter. Anonymous requests
cannot retrieve event payloads. The legacy `GET /auth/v1/events` audit shape is
unchanged and is not an alias for this POST.

Creation events deliberately store canonical email in `text` and trusted request
peer IP in `ip`; `data` is null. These are personal data, not the audit store's
pseudonymous identifiers. No passwords, setup bearers or credentials are added.
The event table is not individually envelope-encrypted. Restrict DB/backups and
Events:read grants accordingly. User deletion does not immediately remove these
retained operational records.

`GOAUTHY_EVENTS_CLEANUP_DAYS` defaults to 31, accepts 1..3650 days, and removes
timestamps strictly older than the cutoff. On startup and hourly, all nodes may
submit serialized, bounded Rhiza deletes; no separate leader election is added.
Each pass fixes its cutoff and drains batches until empty or canceled. SQL
serialization makes concurrent cleaners safe. This adapts the upstream
[hourly cleanup](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/schedulers/src/events.rs#L10).
Retention is periodic, not a promise of deletion at the exact expiry instant.

## Stream contract and Rhiza research

The pinned [upstream SSE handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/events.rs#L63)
uses Events:read or browser/group-admin authority, optional `latest` and `level`,
JSON `data:` frames, and a ten-second reconnect hint. Its
[router](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/listener.rs#L90)
holds recent history, filters by minimum level, then takes the requested tail.
GoAuthy accepts `latest=0..1000` (default 0), `level=info|notice|warning|critical`
(default info), selects the last 100 retained committed rows before filtering,
and emits the selected tail in commit order. No SSE `id:` or Last-Event-ID
resume guarantee exists; reconnect requests a new bounded snapshot. Clients
wanting older retained records must use the POST query.

Schema 60 backfills `event_log_order` deterministically by timestamp/ID, then
assigns AUTOINCREMENT sequence numbers through insertion triggers in the same
transaction. Deletion removes the mapping, not the persistent high-water mark.
Both filtered pages and deleted tails advance without wall-clock comparisons.
Reopening the database preserves order; a backward clock cannot hide a new row.

Rhiza v0.12.0's public Notify API was inspected: its
[materializer](https://github.com/mrchypark/rhiza/blob/3b5a5a07aaf83b5ed279f75b920395bda7179577/pkg/materializer/materializer.go#L1146)
uses bounded live at-most-once queues and can drop notifications. The
[SQL request](https://github.com/mrchypark/rhiza/blob/3b5a5a07aaf83b5ed279f75b920395bda7179577/pkg/network/server.go#L565)
does not atomically publish a Notify message with its statements. Thus a Notify
payload alone cannot be the durable cursor or an authorization boundary.
Current SSE reconciles the existing durable log once per second per connection;
no broker, extra package or separate notification mutation is needed. This is
O(active streams) idle reads, capped at 64 streams per handler/node. A shared
notification wakeup can later reduce latency/read load, but must retain durable
reconciliation. Nonpersisted-event streaming with configurable persistence
thresholds remains part of the unchecked full event parity work.

Each page couples current authority and data in one linearizable snapshot.
Authority is checked again before each data frame and heartbeat; revocation
closes an already-started stream without writing a JSON error into SSE. Reads
and actual writes have five-second deadlines. The write deadline is cleared
after flush so HTTP/2 idle time does not expire the stream. Heartbeats are every
15 seconds; shutdown/cancellation closes streams and releases their capacity.
Multiple authorized clients behind one IP are independent. Retention can remove
events before a slow reader sees them; this is not an exactly-once delivery log.

## Why direct code remains

The stdlib already provides the transport, strict decode building blocks, time,
hashing and cancellation. Rhiza supplies replicated transactions and linearizable
reads; existing RBAC/session stores supply current authority predicates.
Fosite handles OAuth, and `go-mail` handles SMTP, but neither owns this product's
event DTO, identity-creation commit or retention schema. Consequently only that
policy/SQL glue is direct implementation. No dependency, cryptographic primitive,
broker or generic event framework was added. Notifier delivery research remains a
prerequisite for the unchecked features, not a reason to call them complete.


## Token issuance events

`GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED` defaults to `true` and accepts only
`true`/`false`. `GOAUTHY_EVENT_LEVEL_TOKEN_ISSUED` defaults to `info`;
accepted levels are `info`, `notice`, `warning` and `critical`.
Invalid values reject startup, including an invalid level while generation is disabled.

The post-issuance callback emits for authorization-code, client-credentials,
Device, password and token-exchange grants; refresh is excluded. This does not
enable otherwise unsupported/disabled grants. Text is exactly
`client_id (flow) email-or-empty`, with a trailing space for a machine token,
and null IP/data. Device uses `device_code`; exchange retains its grant URN.
Raw tokens, client secrets and passwords are not supplied to the event sink.

Events use the existing Rhiza event table and notification polling. Event
persistence occurs after token persistence, matching the pinned event enqueue
ordering: an event error returns token-endpoint server_error for non-Device
grants even though token persistence may already have completed. Device logs
the event failure and returns its token. This is not an atomic event/token
transaction or an exactly-once HTTP-delivery guarantee.

Machine CC/exchange generation on/off and user authorization-code/refresh
selection pass standalone E2E. Current cross-Pod, notification and failure-path
qualification is tracked in [status](status.md); full event parity remains open.

### Password grant dependency: pinned contract still unimplemented

Source check: Rauthy v0.36.2 `src/service/src/oidc/grant_types/password.rs` and
`src/service/src/token_set.rs::TokenSet::from_user`. The password producer passes
no explicit scopes, nonce, session ID or resource to `from_user`; this selects
client default scopes. It does not forward the request scope or resource.
Authentication validates client enablement/secret/flow, account enablement and
expiry, password and client user groups before issuance. Successful authentication
updates login counters and may upgrade the password hash. Token issuance precedes
TokenIssued, followed by login-state insertion and background location checking.
The producer has DPoP and validated-origin handling; adding only an event selector
or a generic password factory does not implement this contract.

GoAuthy currently excludes password from OAuth provider composition and client
admission (`internal/oauth/server.go`). `identity.Store.Authenticate` provides
constant-work credential failures and account/password-expiry checks, but returns
only a subject. Any new grant must preserve current credential/authority checks
through the issuance transaction; a later active-user read alone cannot prove
that the password verified before a concurrent change is still current.
The existing `persistedRequestForm` already excludes raw password and client
credentials. Password grant HTTP, DPoP, scopes, failure and concurrency tests and
standalone/three-peer qualification remain required. This is a contract record,
not implementation completion.

Independent review corrections (2026-09-11): the generic Fosite password factory
is not a drop-in parity implementation. Its handler validates requested scopes,
where the pinned producer selects client defaults. Managed clients must support
explicit password-flow configuration for parity; a blanket prohibition is not
an upstream requirement. `clients.Store.GetClient` already rejects disabled
clients, and TokenHandler already runs common DPoP verification/binding after
NewAccessRequest. Reuse those paths and verify their password behavior instead
of duplicating them. Authenticate performs best-effort rehash internally and
always reports NeedsRehash=false; no caller rehash adapter is required.
Account-enabled/expiry checks do not replace a captured credential-generation
commit guard. These corrections supersede the corresponding independent-review
suggestions; no factory or managed-grant admission has been enabled yet.
