# Package research

## Password grant and expired-password recovery (2026-09-11)

Existing Fosite v0.49.0 supplies client authentication and the resource-owner grant protocol. `internal/oauth/password_grant.go` adapts it to pinned Rauthy default scopes, password-origin ID tokens, conditional refresh, recovery errors and guarded persistence; `internal/identity` owns credential verification, generation snapshots, login timestamps and schema86 failure counters. Managed/DCR registration remains in `internal/clients` and `internal/dcr`; signing uses existing `internal/oidc` and go-jose. No new dependency was added.

`internal/recovery` reuses its reset issuance, cookie/CSRF consumption and go-mail SMTP sender. `TestExpiredPasswordGrantDeliversResetSMTP` now joins the OAuth HTTP endpoint, real recovery service, loopback SMTP, delivered link consumption and signed ID-token checks. This is a local integration qualification, not production email or distributed DR. Fosite wraps non-NotFound credential errors; the scoped handler preserves the explicitly signaled reset-required denial without changing unrelated credential checks.

Remaining application work includes unconditional sessionless login state, managed per-client logout metadata and endpoint isolation, location notifications, and full pinned failure/error parity. Existing logout tables and consumers must be integrated rather than treating a configured global callback URI as a substitute for a client's own endpoint. Runtime and DR evidence remains in `status.md` and `no-pvc-dr.md`.

## Encrypted snapshot artifact (2026-09-09)

`filippo.io/age v1.3.2` now supplies streaming authenticated encryption in
`internal/backup`; stdlib `archive/tar` supplies USTAR encoding and `os.OpenRoot`
confines extraction beneath an owned private temporary directory. The official
[pinned API](https://github.com/FiloSottile/age/blob/v1.3.2/age.go) supplies native
X25519/Hybrid identities and requires complete stream consumption for payload
authentication. Tests exercise both key types; the Rhiza integration uses Hybrid.

Custom code enforces GoAuthy's object names, duplicate/size/count limits, complete
input reads and staging cleanup. These are application publication constraints,
not missing cryptographic primitives. No custom cipher, AEAD framing or Rhiza
binary codec was necessary. The dependency's x/tools v0.49.0 requirement raises
x/mod to v0.39.0 and x/net to v0.58.0 through Go module selection. Command packages
compile after this change. Full backup product parity remains tracked separately
in [the implementation evidence](encrypted-backup-design.md).

Current dependency baseline (2026-09-08): official Rhiza v0.12.3,
commit `97a9d18aadc66d3b5390f6fa64de2d65dd9f0d48`, with LatticeDB v0.6.0.

The [v0.12.3 release](https://github.com/mrchypark/rhiza/releases/tag/v0.12.3)
updates LatticeDB and bounds archive GC deletion concurrency. GoAuthy keeps its
existing public Go integration and startup-close guard. Duplicate SQL requests
also recheck configured before-ack object-store durability in this version;
`storage.Execute` must propagate `ErrCommitUnknown` while storage is unavailable.
The regression now restores storage before expecting successful replay, retaining
the original statement results and exactly two inserted rows. No new adapter or
dependency beyond the required Rhiza/LatticeDB versions is needed. See the dated
[verification record](status.md); upstream CI is not GoAuthy E2E evidence.

Caller reconciliation also must not turn an uncertain write into success merely
because a linearizable local read finds its rows. Bootstrap now derives its
request ID from the complete SQL statements and arguments, eliminating timestamp
fingerprint conflicts and the readback-on-error shortcut. CIMD propagates
`ErrCommitUnknown` before accepting a winner. DCR replay needs a durable Rhiza
acknowledgement before returning stored credentials; query consistency alone does
not provide the configured object-store acknowledgement. These application
boundaries reuse `encoding/json`, SHA-256, existing envelope guards and Rhiza;
they do not implement a replacement durability protocol.
Earlier v0.10.0 package evaluations below are historical evidence, not separate
runtime backends. The Go API remains cgo-free; no Rust SDK is added.
Upgrade verification and retained startup-close guard are tracked in [status.md](status.md).

## Consumer credential metadata recovery (2026-09-08)

Reuse the existing `OAuth2Status` six-field DTO and encrypted credential decoder,
the common stored-consent lookup, and `usePolicyWithoutState` for current owner,
provider, client and generation fences. The read-only wrapper intentionally
admits non-ready states and expired upstream access tokens, unlike delivery and
refresh. It rechecks authorization and the observed version/state after decoding.
No provider exchange, storage write, package, schema or credential cache is added.
This local wrapper is necessary because the existing owner status API uses a
different authorization boundary, while OAuth client packages do not know local
consumer consent. `net/http` serves the strict Bearer-only GET; recovery decisions
remain with the caller and uncertain states require owner intervention.

## Explicit consumer refresh delegation (2026-09-08)

Reuse `RefreshOAuth2`, `ClaimRefresh`/`CompleteRefresh`, existing sealed credentials,
and the current human/resource authorization predicate. Rhiza supplies the atomic
claim and commit checks; `net/http` and the existing strict JSON decoder supply
the public route. No dependency was added. Existing OAuth packages perform the
provider exchange, but cannot enforce GoAuthy's owner consent, consumer generation,
provider revision and cancellation-after-network policy. The small local adapter
is therefore necessary: add an opt-in bit (schema82), bind it into handoff review,
and recheck consent during claim and commit. A ready-only delivery guard cannot
be reused verbatim after a claim changes the credential to `refreshing`; the
refresh guard permits that state while existing version/claim CAS remains strict.
No background scheduler, credential cache or automatic exchange retry is added.
See [grant contract](connection-use-grants.md) and [status](STATUS.md) for evidence.

## OAuth consumer consent handoff (2026-09-08)

The existing package inventory already supplies the required mechanisms:
`internal/saas` owns sealed OAuth credentials, public `OAuth2Status`, version-pinned
`CreateUseGrant`, and one-use API-key handoffs; Rhiza supplies the atomic
proposal/consent transaction. `net/http`, `html/template`, `net/url`, and the
existing SHA-256 review commitment handle the transport, escaped form, return
URI and snapshot marker. No new dependency or cryptographic construction is needed.

The remaining custom code is application policy, not an OAuth protocol engine:
GoAuthy's collection owner, managed requesting/receiving clients, connection
generation, provider revision and reviewed credential version must be checked
together in its Rhiza schema. Reusing an external OAuth client would not enforce
these local consent invariants. Extend the existing handoff with schema81's
`credential_version` (zero for legacy API keys, positive for OAuth) and reuse
the existing grant version precondition. Account/scopes remain in the sealed
credential, not a duplicate plaintext authorization record. A refresh before
approval invalidates the proposal; later refresh under unchanged authorization
does not invalidate already approved consent. Delivery still does not refresh.
See [handoff contract](connection-use-handoffs.md) for the exact public boundary.

## Device browser handoff and managed clients (2026-09-06)

### DPoP token error interoperability (2026-09-07)

[RFC 9449 section 5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5)
requires `invalid_dpop_proof` for an invalid presented token-endpoint proof,
distinct from the server nonce challenge. Existing go-jose proof verification
and Rhiza nonce/replay logic are retained. Fosite's existing RFC6749Error type
supplies the response; only the application-specific error mapping was missing.
Empty/duplicate/malformed proofs and a proof using the wrong refresh-bound key
now return that standard error, without proof material in the description.
Unsupported grants and missing required proof remain separate request-policy
errors; UserInfo challenges are unchanged. No new dependency is justified.
This error fix alone does not enable Device/token-exchange support.

### Device grant DPoP integration (2026-09-07 follow-up)

RFC 9449 section 5 applies token-endpoint proofs to extension grants too.
Reuse the existing DPoP verifier, Rhiza nonce/replay store, Fosite session cnf
and signed access/refresh persistence for the Device grant. No new crypto or
database column is needed. This binds the issued tokens, not the initial device
code; device approval remains its existing independent authorization step.

Local Fosite v0.49.0 `access_request_handler.go` invokes the grant handler in
NewAccessRequest, before GoAuthy's DPoP verification. Therefore the device claim
exists when nonce/proof/policy checks run. Pre-response failures release that
claim through the existing conditional Complete operation. Immediately before
NewAccessResponse the grant handler takes ownership; outer cleanup must never
release a potentially committed claim. This is application transaction glue,
not functionality provided by a crypto package. No session.Extra rewrite is
needed: the verified cnf is attached after the device request handler has run.
Standalone public HTTP and HA evidence are tracked separately from unit tests.

### Authorization Code form redirect policy (2026-09-07)

[CSP form-action](https://www.w3.org/TR/CSP3/#directive-form-action) restricts
form navigation destinations. Our native Chromium regression demonstrates that
self-only policy blocks this login form's registered external callback redirect.
Fosite validates the OAuth redirect; it does not render our HTML response policy.
The application-specific glue therefore derives one callback origin only after
`ValidateAuthorizationRequestForLogin` succeeds, never from raw query input.
It preserves the existing policy on all other pages and emits no callback path,
query, credentials or wildcard. Redirect registration remains authoritative.

Use stdlib `net/url` for parsing and the already installed
[`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna) for ASCII host
serialization: net/url alone does not supply IDNA conversion. No new dependency
or alternate OAuth implementation is needed. The helper's product-specific CSP
composition is the only direct implementation. Unit tests cover HTTP(S), ports,
IDN, IPv6 and rejected unsafe inputs; actual Chromium qualification currently
covers the HTTP loopback callback, not every redirect type. See STATUS.md for
the exact local artifact and incomplete consumer/release gates.

### Owner OAuth connection controls (2026-09-07)

Local code review found existing owner OAuth start/status/refresh/revoke/reconnect
handlers and the account `connections.js` request/CSRF/generation guards. The UI
adapter reuses those routes and native select/button/anchor/confirm/URL/JSON APIs;
no frontend or OAuth package is added. Installed `golang.org/x/oauth2` continues
to perform provider exchanges on the server. The small state-to-control mapping
is application-specific: browser primitives and x/oauth2 do not know GoAuthy's
draft/ready/uncertain/reconnecting states or its explicit refresh policy. This is
UI glue, not a replacement OAuth implementation or an exhaustive package survey.
Node VM tests reuse the existing dependency-free test pattern; real browser checks
reuse the installed chromedp harness. Verification status is tracked separately.

### Connection consent handoff adapter (2026-09-07)

The browser adapter uses stdlib `html/template`, native form validation and the
existing account stylesheet, with no frontend package. Login shares the existing
one-use browser interaction/password/session rotation implementation, with typed
device versus connection purposes and fixed same-origin return destinations.
The custom portion is that small purpose/destination and consent DTO adapter.
`net/http.CrossOriginProtection` supplies native Fetch Metadata checking instead
of adding a CSRF package; the existing session CSRF is still required. A verified
Chromium no-referrer form sends `Origin: null`, so null requires exact same-origin
metadata rather than unconditional rejection/acceptance. Sources:
[Go standard library](https://pkg.go.dev/net/http#CrossOriginProtection),
[MDN referrer policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).

Reuses existing human OAuth resource validation, managed-client redirect/scopes/
audience metadata, owner session/CSRF, registered connector digest and consent
policy SQL. Stdlib `crypto/sha256`, `encoding/base64` and `net/url` cover ticket
hashing/encoding and safe return construction. Existing Rhiza v0.12.0 transactions
and bounded `RETURNING`/`WantRows` results atomically create consent and consume the
ticket. No dependency added. The custom adapter is necessary because these
application-specific connection/provider/consumer generation and digest predicates
are not an OAuth grant implemented by Fosite or x/oauth2; implementing a second
OAuth stack would not supply that policy. This local dependency/code review does
not claim an exhaustive survey of all public packages. See the bounded backend
[contract and remaining integration](connection-use-handoffs.md).

### Persisted SaaS provider registry (2026-09-07)

Local implementation research: `internal/saas/oauth2.go` already wraps installed
`golang.org/x/oauth2` and validates explicit auth style, scopes and endpoints;
`api_key_connector.go` already validates fixed destinations/header injection.
Provider registration reuses these rather than implementing OAuth or HTTP crypto.
Existing `oidc.Keyring`, `storage.ExecuteEnvelope`, RBAC browser/CSRF decoder and
master-key workers cover secret custody and request boundaries. No new dependency.
The remaining custom code is a Rhiza schema/authority/CAS/tombstone adapter and
collection-reference policy: those application-specific replicated predicates are
not implemented by `x/oauth2` or the existing config-file loader. Provider secret
purpose binds ID/generation; its encoded length is tested by real envelope use.

| Capability | Reuse | Why direct implementation remains necessary |
|---|---|---|
| Cold-browser device login | stdlib `net/http`, `net/url`, `html/template`; existing login/password/CSRF/session/interaction stores | RFC 8628 separates end-user authentication from explicit consent. Existing authorization-code interactions return to authorize, not the device verifier. A small typed, one-use device continuation adapts the existing login boundary; it does not implement passwords, sessions or cryptography again. [Protocol reference](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.3). |
| Device token protocol | installed Fosite v0.49.0 token framework and existing Rhiza device store | The pinned [Fosite composer](https://github.com/ory/fosite/blob/v0.49.0/compose/compose.go) does not compose a Device Grant handler. Existing custom handler implements the required polling/approval state adapter and atomic DB consume; token validation and cryptographic primitives remain in installed packages. |
| Device client authentication | installed [Fosite AuthenticateClient](https://github.com/ory/fosite/blob/v0.49.0/client_authentication.go), stdlib `net/http` and `net/url` | [RFC 8628 §3.1](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.1) requires confidential-client authentication at creation. Reuse Fosite's existing secret verifier and registered Basic/post policy. Direct boundary code only enforces bounded, single-valued form/header input, rejects mixed credentials and mismatched IDs, and rejects credential-bearing requests for public clients, including an empty Basic secret. Existing Rhiza rate limiting runs before secret verification. No new auth/crypto package is necessary. |
| Managed client registry | Fosite Client interface, stdlib strict JSON/URL/crypto/rand, installed bcrypt and existing keyring | DCR stores per-registration authority and hash-only authentication; it is not the administrator's separately authorized plaintext-secret retrieval/rotation API. A dedicated Rhiza registry and authority/revision/generation SQL conditions are product policy. No new ORM, RBAC engine, encryption or consensus package was added. |
| Secret retirement | existing keyring envelopes, rewrap worker and retirement zero-reference gates; stdlib SHA-256/base64 | A new secret-bearing table must participate in the existing reference scan and ciphertext CAS. A bounded ID/generation digest fits the keyring's 64-byte purpose limit without weakening client binding. |
| E2E | Go `net/http`, cookiejar, httptest, existing local/Kind runners | The RP fixture introspects through the deployed issuer; no fake token issuer or sleeps were added to the new happy path. These are actual HTTP form flows, not Chromium rendering evidence. |

Supported fields, unresolved security/spec limits and evidence are recorded in
[device pilot](device-flow-pilot.md) and [managed clients](managed-clients-implementation.md).
Confidential creation authentication now uses the existing Fosite provider. This does
not claim full RFC parity: the current device policy still requires an explicit scope
and rejects OpenID/custom-user scopes. Runtime evidence is tracked in the pilot ledger.

## Profile, browser administration and bootstrap batch (2026-09-06)

Second-batch additions reuse existing dependencies rather than introducing a
queue broker, frontend framework or cryptographic implementation:

| Capability | Existing/standard implementation | Why direct code is necessary |
|---|---|---|
| Slack and Matrix delivery | stdlib `net/http`, `encoding/json`, TLS validation and context deadlines | The official [Slack incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) and [Matrix room send](https://spec.matrix.org/v1.16/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid) contracts need only small JSON envelopes. A full vendor SDK adds no needed capability here. The event-to-envelope mapping and secret-safe error policy are product code, not a new transport stack. |
| Durable notification retry | Rhiza atomic SQL/linearizable reads, existing event schema, stdlib clock/context | Rhiza replicates data; it cannot atomically acknowledge an external email/webhook acceptance. The application must keep lease ownership and durable acknowledgement/retry state. Reuse existing DB primitives; no Redis/Kafka or bespoke consensus. |
| Event SMTP | existing `go-mail`, shared SMTP environment parser | Existing recovery sender is coupled to reset/setup templates, so its public DTO is not a generic event sender. Reuse its configuration and the mature MIME/TLS library; only event subject/body adaptation is new. |
| Generated-secret retrieval and recovery | stdlib `crypto/rand`, `flag`, filesystem and JSON; existing ChaCha20-Poly1305 | Pinned Rauthy generated-container format is not supplied by installed Go libraries. A bounded format adapter, immutable publication and DB/artifact retry policy are required; encryption and randomness remain package-provided. Retrieval/purge is an explicit operator CLI, not a secret-bearing HTTP endpoint. |

Native browser CRUD now also has actual Chromium standalone/HA evidence; it is
not just the dependency-free JavaScript simulation described in the first batch.

| Capability | Reused package/platform | Necessary application-specific implementation |
|---|---|---|
| Standard OIDC profile claims | existing `ory/fosite` scope/grant handling, `go-jose/go-jose/v4` signing/verification, stdlib JSON, Rhiza current reads | The pinned `src/service/src/token_set.rs`, `oidc/userinfo.rs` and `src/jwt/src/claims.rs` determine which local profile fields/scopes map to each claim. These packages do not know GoAuthy's schema or preferred-name policy; only projection/allowlisting glue is direct code, not JWT or OAuth cryptography. |
| Administrator screens | stdlib `embed`/`net/http`, existing admin browser guard, native HTML inputs/forms and DOM/fetch | Existing Rauthy-specific JSON APIs remain the policy authority. No generic admin framework is installed or needed to supply transport, rendering, escaping or authorization. Screen-to-DTO mapping is necessarily product code: PUT clears omitted values and rejects response-only preferred_username, so generic object round-tripping is incorrect. No replacement ORM, frontend runtime or authorization engine was added. |
| Rauthy encrypted API-key import | existing `golang.org/x/crypto/chacha20poly1305`, stdlib base64/binary/JSON, existing digest-only bootstrap transaction | Pinned `src/data/src/migration/bootstrap/api_key.rs` uses Rust `cryptr` 0.10 EncValue. The installed upstream `cryptr-0.10.0/src/value.rs` and `src/encryption.rs` establish the header/nonce layout. Existing Go crypto handles authentication; a bounded format decoder is required because the current Go dependencies do not decode this Rust container. Generate/retrieval/TTL is not silently substituted with Plain. |
| Deterministic UI checks | Node built-in `vm` and `assert`, existing Go HTTP fixtures | Run actual routing/form/fetch functions and await their promises, not sleep or search source strings as proof of behavior. This is distinct from remaining real-browser UI E2E. |

Details and verification boundaries: [profile claims](profile-claims-implementation.md),
[admin UI](admin-ui-implementation.md), [bootstrap](api-key-bootstrap-implementation.md).

## Administrator user update: decoder and transactional authority (2026-09-06)

`PUT /auth/v1/users/{subject}` is now mounted. Its request decoder, current
browser/key authority and atomic identity command implement the administrator
update path, not a substitute expiry-only endpoint. The
[field and completion checklist](user-management.md) separates this implementation
from remaining full policy, response-field, UI, remote SCIM and broader chaos gates.

| Boundary | Selected implementation | Why application code remains necessary |
|---|---|---|
| JSON, body/media limits and ambiguous fields | stdlib `net/http`, `mime`, `encoding/json`, existing duplicate-field scanner | The pinned DTO's required false booleans, nested allowlist and optional-field semantics are application-specific; no new validation framework is needed. |
| Email, language, role/group and display names | existing `identity.CanonicalEmail`, `i18n.ValidUserLanguage`, `canonicalNames`, `validCreateName` | Reuse current admission rules, with the existing strict control-character/name constraints; do not create a second normalizer. Configurable required-profile policy is not implemented by this decoder. |
| Profile field syntax | stdlib `regexp`, `unicode/utf8`, `time.LoadLocation` and existing embedded `time/tzdata` | The pinned [regex definitions](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/common/src/regex.rs) require nonempty alphanumeric ZIP, syntax-only birthdate and bounded profile strings. Rust Unicode `\s` requires explicit separators/NEL/vertical-tab in Go RE2; Go `\s` alone is narrower. |
| PUT target/field authorization | existing admin-role SQL plus Rhiza SQL `json_each` and `WantRows`/`ExpectedReturnedRows` barrier | Rauthy's [delegated change policy](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/principal.rs#L363) compares current role sets and the symmetric difference of groups. Existing PATCH allows a previously unmanaged target into scope and cannot be substituted. A pure in-memory policy library would not make this decision atomic with Rhiza writes. No cache, new table or policy engine is added. |

The predicate deliberately receives submitted names **before** sanitization:
unknown out-of-scope additions must not silently disappear before permission
checking. Nil membership slices become JSON arrays, not JSON `null` (which is a
scalar row to `json_each`). Self-edit skips only the managed-target/admin-target
check, not role equality or group scope. Disabled targets remain administrable.
The browser route composes the current session predicate; API
keys require their own current Users:update predicate. The helper alone is not
authentication, final-admin protection, or a complete mutation API.

Pinned [User::update and User::save](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users.rs#L1223)
also establish distinctions for the next integration step: email changes
invalidate sessions and notify old/new addresses; saving a disabled user
invalidates sessions and refresh tokens. They do **not** directly invoke
subject-wide back-channel logout there. The expiry scheduler and deletion
handler do, so reusing ForceLogout wholesale for every edit would change the
contract. Password assignment uses password policy/history and emits the admin
reset event, while role promotion emits the new-admin event. SCIM update is
scheduled after the handler's successful change. General profile values are
replaced/cleared but the separately managed preferred username is preserved.

Existing Go password rules/hasher/history, event constructors, Rhiza guarded
transactions, SMTP transport and SCIM runtime are reusable. The password-only
methods execute independent mutations and require a user's current password or
one-use proof, so an admin wrapper around those methods would not implement the
full atomic PUT. The recovery Sender was extended with an email-change method,
reusing its SMTP transport, rather than repurposing a password-link message.

The next implementation step now adds `identity.UpdateUserWithGuard` using
those native Rhiza batch barriers and a private state snapshot, without a new
schema, dependency or transaction framework. `preparePassword` is shared with
the existing change/reset methods; admission stays specific to each caller.
The engine stores profile/memberships/password effects and lifecycle events
atomically and returns committed mail metadata. The connected HTTP handler sends
email-change notices and wakes SCIM after this commit. Remote SCIM's complete
field projection/delivery matrix remains unverified for this update workflow.

Two security details are explicit GoAuthy adaptations. First, changing the
email deletes existing reset proofs and the public recovery service calls
`IssuePasswordResetForEmail`: its first SQL barrier verifies that the address
which will receive the link is still authoritative, before replacing any
existing proof. This also covers an old address lookup racing with a committed
admin update. Second, the update command accepts an authority **factory**, not
expiry arguments frozen before expensive hashing. The factory is called for
both the initial read and the final mutation preparation. Bound current-time
arguments are still supplied to Rhiza; no wall-clock SQL function is added.

Reusing `ChangePassword`, `ResetPassword` or `ForceLogout` as separate complete
operations would break atomic update semantics or introduce the wrong external
back-channel scope. The application-specific SQL therefore remains necessary;
Go stdlib parsing, the existing Argon2 hasher/rules, eventlog constructors and
Rhiza's verified transaction/receipt mechanism do the reusable work. Disable
and password assignment cancel in-flight factor proofs without deleting
enrolled factors. Explicit legacy login names remain stable; email-as-login
names move with their address. These choices and their tests are recorded in
[user-management](user-management.md), not claimed as exact unmodified upstream
behavior. An optional sanitized Pro consultation could not pass its pre-send
project/model checks because the Mac was locked; no packet was sent and no Pro
review is claimed. Local source review and deterministic tests are the evidence.

The public response is now read as the final statement in the same mutation,
using Rhiza's existing statement-result/receipt recovery. `UserResponse` and its
safe JSON projection moved from RBAC to identity and are aliased for existing
consumers; GET and PUT share it. Re-reading authorization after the mutation
would wrongly deny a self email change (its session was revoked) or a delegated
last-group removal, and could return a subsequent editor's state. No new
transaction API, generic callback SQL or duplicated wire projection is needed.

Pinned [administrator update](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users.rs#L1274)
sends the same completed-change confirmation to **both** new and old addresses,
not the self-service new-address challenge. The copied nine-language text comes
from [confirm_change.rs](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/email/i18n/confirm_change.rs).
Existing `html/template`, `text/template`, strict TOML catalog and `go-mail`
handle rendering/configuration/TLS. Application glue selects the committed
language and addresses and continues to the other recipient after failure.
`email_change_confirm` overrides use existing `text`/`footer` fields for upstream
`msg`/`msg_from_admin`; exact upstream config naming/theme/subject-prefix parity
is not implied. SMTP is synchronous and bounded, best effort like current
recovery delivery; cancellation/process exit can lose a notice. A durable
notification outbox/retry is still a separate incomplete requirement.

Current HTTP 409 deliberately groups email collision, final-administrator
protection and concurrent state/authority changes. The final transaction cannot
be classified by an unsafe later state read; exact upstream per-error mapping
remains an unchecked compatibility gap. Full detail metadata, configurable
required profile policy and general self/PATCH/UI work also remain unfinished.

## Forced logout and unknown-login revocation research (implementation incomplete)

The pinned [sessions API](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/sessions.rs)
emits `ForcedLogout` specifically after `DELETE /sessions/{user_id}`. It checks
Sessions:delete or administrator/delegated authority and managed-user scope,
invalidates the user's sessions, refresh and issued tokens, invokes back-channel
logout, then emits. Deleting all sessions or one session by ID does not emit this
type in that file. GoAuthy's existing RP-initiated logout must not be relabeled.

The [unknown-login revoke API](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs)
checks the emailed code, invalidates sessions/refresh tokens, clears login
locations, performs back-channel logout, deletes the revoke row and emits
`UserLoginRevoke`. Crucially, its `bad_ip` comes from **query `params.ip`**, not
the request peer. The event/geolocation lookup therefore does not by itself
prove the address belongs to the original login. Code-to-login binding needs an
explicit security contract before implementing this flow in GoAuthy.

The [constructors](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs)
use null IP/data and email text for ForcedLogout; UserLoginRevoke has that bad IP,
null data and email/IP/location text with an unknown-location fallback. Their
[default levels](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/rauthy_config.rs)
are Notice and Warning. Sequential upstream calls do not establish one atomic
transaction across revocation, HTTP delivery and event persistence.

GoAuthy now mounts per-user logout, session listing, single-session deletion and
all-session deletion; the emailed-login-revoke route remains absent.
Reuse existing browser/OAuth storage, delegated RBAC predicates, back-channel
outbox and Rhiza transactions. Fosite does not own this administrator policy or
emailed security flow. No substitute event was added to password reset, account
deletion or ordinary logout, and these feature rows remain unchecked.

The `rbac.Store.ForceLogout` implementation uses one guarded Rhiza
batch: capture target/email with `RETURNING` and exact-row precondition, enqueue
one subject-only back-channel delivery per known target user/client association,
revoke browser and OAuth artifacts, clear only that user's mappings, then
append `eventlog.ForceLogout`. `OutputRefs` binds the authoritative email without
a second application read. A full/admin/API-key policy belongs to GoAuthy;
neither Fosite nor Rhiza supplies these application-specific tables and rights,
so direct orchestration SQL is necessary. Existing Fosite, browser, RBAC and
back-channel implementations are reused; no custom token cryptography, new
broker, dependency or schema is introduced. Email-less local bootstrap accounts
emit an empty text string, not a session identifier or null, as an explicit
adaptation of the upstream mandatory-email model.

The pinned [back-channel implementation](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/oidc/logout.rs#L249)
uses `find_by_user` and a `sub` without `sid` for the per-user API, then clears
that user's login states. GoAuthy now uses the schema-61 `oidc_user_clients`
records for the same scope, even when a local browser session is gone or revoked.
Two sessions on one client produce one subject delivery; other users of the
same client retain their mappings and local credentials. Unlike the upstream
request's awaited remote calls, GoAuthy commits the existing durable outbox and
returns before delivery. This preserves atomic local revocation/event/enqueue
and retries without a new dependency. It does not promise synchronous or
exactly-once remote effects. Fixed-clock store checks and public multi-user
deployment evidence are tracked separately in [status.md](status.md).

### Account expiry and hard deletion: subject-wide back-channel scope

The pinned [user expiry scheduler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/schedulers/src/users.rs#L50)
disables expired users, invalidates sessions/refresh tokens and calls
`execute_backchannel_logout(None, Some(user.id))`. The shared
[user deletion handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L2230)
uses that same subject-wide call before deleting the identity.
Both GoAuthy paths now enqueue from `oidc_user_clients`, not from browser SID
rows, and clear only the target's user/client records. This uses the existing
schema 61, JWT signer and durable worker; no new dependency or schema is needed.
Explicit INSERT errors roll back the operation rather than silently dropping
an invalid delivery. The expiry deadline/enabled guard remains on every statement
until the final disable. Hard deletion retains its authority snapshot,
final-admin protection and SCIM tombstone transaction. Repeated/losing expiry
workers cannot enqueue another copy after the winner clears the user records.

Stdlib HTTP/crypto and the existing Rhiza atomic SQL provide the primitives,
but neither Rhiza nor Fosite owns identity expiry, target authorization, or SCIM
tombstones. That existing application transaction is therefore the necessary
direct integration; a separate KV mirror or notification write would lose the
single-commit relationship. As above, GoAuthy uses asynchronous outbox delivery,
not an assertion that a remote RP has already logged out when DELETE returns.

Password reset is **not established as the same upstream requirement**:
the pinned [password-reset service](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/password_reset.rs#L139)
validates MFA/magic-link, applies password rules, saves the user, emits the reset
event and invalidates browser sessions, but does not directly call back-channel
logout. GoAuthy's pre-existing extra OAuth revocation/SID delivery on reset is
unchanged in this pass. Its full reset policy/MFA parity needs its own review;
do not label converting reset to subject-wide delivery as a proven missing
upstream behavior. Expiry-specific public E2E still needs the missing admin
expiry-update workflow; fixed-clock store/runtime tests are not live proof.

The production login layer already calls `CompleteAuthorizationWithSession`
for OAuth and OIDC. The shared code/PKCE persistence guard now binds the supplied
browser SID and subject for both flows, retaining OIDC-only nonce/authentication
claims and ID-token behavior. This reuses the existing browser row instead of
inventing another user generation counter. The explicitly server-trusted
sessionless `CompleteAuthorization` API remains separate. Source tests and live
deployment evidence are tracked independently in [status](status.md).

### Session list contract and reuse (partial parity)

The pinned sessions API defaults `session_state` to `Auth`, grants delegated
administrators a read-only view of **all** sessions, and selects 200/all versus
206/paginated using **user count**, not session count. Page size is the maximum
of the requested/default 20 and the configured threshold. The pinned
[session entity](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/sessions.rs)
orders by expiry descending; backward selection chooses the oldest slice and
reverses it. Session state is stored separately from expiry: `Auth` must not be
presented as a guarantee of current validity. DTO timestamps are Unix seconds;
`user_id` is omitted when absent and `remote_ip` remains an explicit nullable key.

`rbac.listSessions` uses the existing Rhiza linearizable query and current
API-key/browser/role predicates in one snapshot. The existing user-list parser,
nullable-value helpers, stdlib JSON/base64/binary encoding and OpenAPI generator
are reused. Fosite does not own the administrative browser-session projection,
nor can Rhiza infer the application's ACL; only this query/HTTP orchestration
is direct code. No dependency, schema or duplicate session store was added.

Explicit adaptations: IDs are existing stored cookie digests, never bearer
cookies. Existing local revocation retains rows (upstream per-user revocation
deletes them), so retained revoked rows appear as `LoggedOut` until existing
cleanup removes them. The opaque `s1.` cursor adds an ID tie-breaker to avoid
duplicate/omitted rows at equal expiry and uses the correct directional boundary;
it is not an upstream continuation-token decoder. Below threshold, valid cursor,
offset and direction do not change the full descending result. Shared browser
authorization failure remains generic 401; insufficient API-key rights use 403.

MFA parity is explicitly unfinished: the current projection reports only local
`auth_method=mfa`. Pinned `src/service/src/oidc/authorize.rs` calls `set_mfa(true)`
for WebAuthn-enabled authentication, while
`src/service/src/oidc/auth_providers/login_finish.rs` also considers provider MFA.
Local WebAuthn and external-login metadata must be reconciled with those paths
before marking full session DTO parity complete. This display field must not
replace the existing authentication/authorization guards.

### Single-session administrative deletion

Pinned `src/api/src/sessions.rs::delete_session_by_id` permits a direct
administrator or Sessions:delete API key, not a delegated group administrator.
It deletes the identified browser session, deletes its refresh tokens, revokes
issued tokens for that SID and calls back-channel logout. It returns empty 200
and does **not** emit `ForcedLogout`. Deleting all of the user's other sessions
would therefore implement a different operation.

GoAuthy's existing `oauth.Store.RevokeOIDCSession` already assembled the
session-bound code/PKCE/refresh/access/request and back-channel cleanup. It now
uses `oauth.SessionRevocationStatements`, shared with `rbac.Store.DeleteSession`.
The latter adds a current-authority exact-row transaction barrier and deletes
the browser row after shared cleanup. The existing browser-interaction table is
also cleaned by SID. This is application transaction composition, not a second
OAuth implementation; Fosite does not supply administrator ACLs or atomically
combine them with Rhiza's application-owned browser tables. No schema, package,
custom cryptography, broker or additional session store is introduced.

The common helper accepts the clock instant for deterministic tests. Same-user
other-session and sessionless artifacts remain untouched; device grants have
no browser SID and are not incorrectly revoked by subject. Existing storage
represents refresh revocation as `active=0`, rather than physically deleting
refresh rows. Back-channel delivery is queued transactionally and remains
asynchronous; remote relying parties must handle their own JWT validity/logout.
The HTTP route validates canonical digest IDs and retains current direct-admin
session/CSRF or API-key permission checks at the commit boundary. A missing SID
is 404 on initial classification; a target/authority change before the exact-row
barrier fails closed. Native implementation and deployment gates are tracked in
[status](status.md); API-key/delegated live, actual external delivery and broader
concurrent issuance/chaos gates remain separate requirements.

### Global administrative session logout

Pinned [Rauthy sessions API](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/sessions.rs)
`delete_sessions` authorizes a direct administrator or Sessions:delete key,
invalidates all sessions and refresh tokens, revokes all issued tokens, and
starts asynchronous back-channel logout. It returns empty 200 and does not emit
the per-user `ForcedLogout` event. `IssuedToken::revoke_all` also covers issued
device/client-credentials tokens; the route does not erase account credentials
or pending device authorizations. This is revocation of existing state, not a
global ban on subsequent issuance or login.

GoAuthy reuses the single-session HTTP permission/CSRF/input boundary and the
existing Rhiza tables, storage receipt handling and back-channel outbox. One
native Rhiza transaction checks current authority with `SELECT ...` and
`ExpectedReturnedRows=1`, queues each known `(subject,client)` login and revokes
browser/code/PKCE/access/refresh/request state. The native SELECT precondition
works with no browser rows and checks authority before revoking the caller.
The global outbox event key includes subject, deduplicating multiple sessions of
one user/client. Schema 61 extends the existing outbox with a subject and nullable
SID and adds `oidc_user_clients`; no KV mirror, broker, dependency or new crypto
implementation is added. Existing SID-only consumers keep their current behavior.

Direct code is required only to compose this product's admin ACL and owned
browser/OAuth tables: neither Go's standard library nor the installed Fosite
storage adapter defines this Rauthy administrative operation. The implementation
uses stdlib HTTP/errors/time plus existing Rhiza transaction capabilities rather
than a new transaction abstraction. Pinned upstream expires browser rows and
marks issued tokens revoked; local storage retains browser rows as `LoggedOut`,
deactivates refresh rows and removes access-token indexes. External JWT consumers
must still validate revocation or process logout; queued delivery is not proof
of delivery. Pending/approved device authorization rows remain unchanged, whereas
already issued device access/refresh credentials are revoked with all issued
tokens. Deterministic store tests cover that distinction and transactional
rollback. Deployment evidence and remaining full-matrix gates are in [status](status.md).

**Subject-only global delivery (schema 61):** pinned
`src/service/src/oidc/logout.rs::execute_backchannel_logout_for_everything`
iterates configured clients, deduplicates their login states by user and emits
subject-only logout tokens (`sub`, no `sid`). The
[OIDC Back-Channel Logout specification, sections 2.4 and 2.6](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken)
allows subject-only, SID-only or combined tokens. The installed `go-jose/v4`
already signs and verifies `sub`; the existing token wrapper now requires at
least one identifier, omits absent SID, and rejects malformed present `sub`/`sid`
instead of interpreting malformed SID as permission to log out a whole user.
Nonce prohibition and existing issuer/audience/algorithm/key/time checks remain.

The existing authorization-code token transaction records both SID/client and
subject/client mappings. Failure to record the latter rolls back issuance. A
subject/client record survives local browser cleanup and single-SID logout, as
upstream's session-independent login record does. Global logout queues subject-only
deliveries before clearing both mappings, so a later login can create a new
mapping and later global delivery. The worker reuses its guarded lease/retry,
network ceiling, TLS and signature path and includes subject in terminal failure
events. Hard account deletion removes the new per-user record with its existing
authorization guard. Administrative per-user force logout, account expiry and
hard user deletion now use subject-only delivery too. Reset and other revocation
paths retain their existing contracts pending separate policy/parity review;
single-session logout remains deliberately SID-scoped.

Migration preserves legacy pending/leased/delivered/failed rows, including all
lease/attempt/error timestamps, and deterministically backfills subject/client
records from existing browser-associated registrations, including revoked rows.
Historical associations whose browser/subject was already removed cannot be
reconstructed; migration does not invent an identity. Old/new mixed-version live
operation is not a verified upgrade mode. Non-browser password-grant login-state
tracking, per-client policy/algorithm/encryption breadth and the full multi-user
deployment matrix remain part of the overall port. Async subject-wide delivery
may also log out a new RP session created before that delivery arrives; response
200 does not promise delivery completion or exactly-once remote effects.

## EmailSendError research and existing package boundary (not implemented)

The pinned [SMTP sender](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/email/mailer.rs)
retries a failed send once after 500 ms; only a second send failure emits
`EmailSendError`. Building an invalid message is a separate path. XOAUTH2 renews
its mailer before retry. The [Microsoft Graph sender](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/email/mailer_microsoft_graph.rs)
also retries once before emitting. Neither path is a durable delivery outbox.
The event defaults to Critical, null IP/data and mail-type plus recipient text;
the constructor does not include message bodies, bearer links or SMTP errors.

GoAuthy's `recovery.SMTPSender` already uses `go-mail v0.7.0`, stdlib TLS and
text/HTML templates, but currently calls send once. The dependency's
[DialAndSendWithContext](https://github.com/wneessen/go-mail/blob/v0.7.0/client.go)
is a connect/send/close operation, not the Rauthy retry policy. It can return a
close error after sending succeeded. Blindly retrying every returned error can
resend accepted mail; preserve the accepted-send boundary when adding policy.
Its lower-level `DialToSMTPClientWithContext` and `SendWithSMTPClient` are reuse
candidates, not justification to write another SMTP implementation.

Retry/cancellation, event delivery when the request or database is unavailable,
recipient retention, notifier recursion and the remaining mail types/providers
need implementation and deterministic tests. This research is not an emitter,
SMTP retry, Graph/XOAUTH2, or notification-delivery completion claim.

## Health-event research (not implemented)

The pinned [server](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/bin/src/server.rs)
starts a [health watcher](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/health_watch.rs)
after migrations and the event listener. Its state is process-local. Healthy
events are transition-gated; confirmed DB failures after earlier health can emit
repeatedly. Before that earlier health, even a twice-failed DB check can yield
`db_healthy=true`. These are source observations, not a proposed ideal state
machine. The leader-only comment has no explicit leader predicate in this watcher.

The [debug/dev test generator](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/events.rs)
calls the Started constructor; that alone does not require production startup
emission. GoAuthy has neither watcher nor independent nonpersisted notification
delivery yet. Reuse stdlib timers/context and existing Rhiza reads, but keep
`readyz` side-effect-free. Specify how failures reach operators when database
writes themselves are unavailable before claiming full health-event parity.
No health framework, leader election, package or emitter was added from this
research.

## SCIM retry-limit event: explicit upstream inconsistency

The pinned [scheduler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/schedulers/src/scim_tasks.rs)
sends a failure event at the configured retry limit. Its
[constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs#L844)
uses the SCIM level but selects `BackchannelLogoutFailed`, despite declaring a
separate `ScimTaskFailed` enum and formatter. GoAuthy selects **ScimTaskFailed**:
the goal is SCIM failure reporting, not misclassifying it as logout. This is an
explicit wire-type departure from the pinned constructor, not byte-for-byte parity.
Default level is Critical; IP is null and data is the actual stored attempt count.

The action text uses Debug-style `UserCreateUpdate("id")`, `UserDelete("id")`,
`GroupCreateUpdate("id")` or `GroupDelete("id")` after the client ID and ` / `.
The `uc_`/`ud_`/`gc_`/`gd_` forms in the
[failed-task model](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/failed_scim_tasks.rs)
are Display/storage keys, not this event's Debug payload. Stdlib `strconv.Quote`
escapes identifiers: ordinary identifiers match that form, but unusual Unicode
and control-character spelling is Go-quoted rather than an emulation of Rust's
Debug implementation. Full sync-cursor actions are not synthesized from local
per-resource jobs. Request bodies, credentials and transport errors are excluded.

The existing outbox, Rhiza SQL/receipts and event INSERT builder are reused.
Both normal failed completion and recovery of an expired final claim insert the
event and finish the row in one transaction. Snapshot payloads are rechecked by
digest/revision/count/lease and current projection/tombstone predicates. Stale
revision completion still resets to pending; a stale dead-letter candidate remains
a no-op. Each invocation uses stdlib `crypto/rand.Text` for the request identity,
also used by the event; storage retries reuse it. The atomic old-state guard
prevents duplicate events, without confusing a recreated job with its old event.
The native exact-row precondition on normal completion rolls back a preceding
event if its lease is lost. No new schema, package, generic event framework or
notification broker is needed. SCIM protocol libraries cannot own this local
outbox's atomic state/DTO mapping; this is the remaining direct domain SQL glue.

The local limit counts attempts, whereas upstream initializes a failure row's
retry counter at zero. Full retry-policy equivalence remains open. Current runtime
uses five attempts and a five-minute scan/creation wake; a due retry alone does
not wake that scheduler. Live gates retain these settings. Early permanent
failure, success and intermediate retry do not emit a retry-limit event.
Verification and unfinished deployment gates are tracked in [status](status.md).
An advisory Pro consultation could not pass the project/composer pre-send gates;
no packet was submitted and no Pro review is claimed.

## Invalid-login lifecycle event

Pinned Rauthy's [login-delay producer](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/login_delay.rs)
increments the peer counter, caps its event payload at `u32::MAX`, and emits
`InvalidLogins` before optional IP blocking. Its
[constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs)
uses host IP, failure count and null text. The
[default levels](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/rauthy_config.rs)
are Info for 1–6, Notice for 7–9, Warning for 10–19, and Critical for 20+.
Upstream separately configures thresholds 10/15 and 20/25; this implementation
currently matches their defaults, not configuration parity.

The existing password and passkey failure handlers already share
`loginpolicy.Failure`. Rhiza's SQLite `RETURNING`, exact returned-row precondition
and `OutputRefs` bind this mutation's resulting counter and level directly into
its event INSERT. Reading `Check` afterward for the payload would race with
another failure. The same request includes any subsequent IP-blacklist event;
failure of either event or its ordering trigger rolls back the entire request.
No new dependency, schema, broker, separate KV write or custom transaction engine
is needed. Stdlib hashing/encoding and the existing event constructor cover
identity/serialization; Fosite and WebAuthn packages do not own this application's
counter schema or event contract. Direct code is only the domain-specific SQL
and payload mapping left after reusing those native capabilities.

The wire cap does not clamp the stored counter. Existing GoAuthy clock policy
is unchanged: a rejected stale mutation emits nothing, while an accepted
large-forward or same-clock observation records the retained counter; the next
fresh observation records the reset counter. Successful login does not emit this
event and does not clear the existing GoAuthy attack counter. That last policy
differs from the upstream success reset and is not claimed as identical behavior.
Automatic-blacklist disablement does not disable InvalidLogins. Event persistence
failure returns the existing unavailable response instead of a successful,
unrecorded policy mutation. Per-type levels/persistence, notifier delivery and
all upstream failure-entry-point parity remain unchecked. Live evidence is
reported separately in [status](status.md), not inferred from skipped opt-in tests.

## Back-channel logout retry-limit event

The pinned [Rauthy scheduler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/schedulers/src/backchannel_logout.rs)
emits `BackchannelLogoutFailed` when the stored failure count reaches the
configured limit, then deletes that failure record. It does not emit for each
retry. Its [constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs)
uses configured/default Critical, null IP, count data and `client_id / sub` text.
For sid-only deliveries, `sub` is empty; replacing it with sid or response text
would not match that contract.

GoAuthy already has a durable delivery worker, stdlib HTTP/TLS, existing JOSE
logout-token signing and Rhiza mutation receipts. `Worker.complete` now uses a
native exact-row precondition for the lease winner. On a failed attempt reaching
its existing limit, SQLite `RETURNING` and Rhiza `OutputRefs` bind the updated
attempt count to an event in the same request. Event identity is derived from the
delivery event/client pair, not a worker lease or wall clock. SQL constraints and
the cleared lease prevent losing/repeated completions from adding events.
No new package/schema/broker is required: Fosite/JOSE do not own the worker's
delivery-state schema, and an external notifier cannot atomically commit it.
Direct code is restricted to this domain-specific transition/DTO binding.

Success, intermediate retries and existing early permanent failures do not emit
this retry-limit event. Event/order write failure rolls back completion and
retains its lease; recovery can retry after lease expiry. This is not exactly-once
HTTP delivery: a remote request may already have happened before persistence
fails. The current runtime still uses 100 total attempts and a separately
configurable retry base; full upstream retry configuration/scheduling, early
permanent failure policy, per-event levels and subject-based delivery remain open.
This slice does not declare those existing policies upstream-identical.

The test-only RP sink reuses its bounded 128-observation capacity for configurable
failure counts and accepts `LISTEN_ADDR` (default unchanged at `:8081`) so local
fixtures can bind loopback without colliding with other tasks. Production retry
limits and TLS/network policy are not weakened for testing. Deterministic tests
advance `Step` using persisted next-attempt state; actual deployment tests use the
public logout and 100 real failed sends, with time only pacing/bounding observation.
See [status](status.md) for actual completed gates and remaining fault coverage.

## JWKS rotation lifecycle event

Pinned Rauthy emits `JwksRotated` after successful
[key rotation and cache invalidation](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/jwk.rs#L274).
Its [constructor](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs#L812)
has null IP/data/text and the configured level defaults to Notice.
GoAuthy reuses its existing `go-jose` signing-key machinery, stdlib SHA-256/base64
event identity, and Rhiza atomic SQL request. Neither a JOSE library nor an event
broker owns this application's active/pending state transition. Consequently
direct code is limited to a guarded event INSERT in the same activation request.
The event guard runs before retirement/activation; losing callers see no eligible
old/pending pair. Event identity uses the key pair, independent of callers' clock
values; mutation receipt identity still binds all SQL timestamp arguments.
Preparation, initial key creation, envelope rewrap, and retired-key cleanup do not
emit a rotation event. No new package, schema, broker, or leader election is added.
An event write failure fails key activation atomically and the existing worker
retries; this availability tradeoff prevents successful unrecorded activation.
Fixed-clock worker/transaction tests and explicitly opt-in real five-minute
cache-boundary E2E are distinct evidence. Per-type level configuration and full
upstream key-management parity are not implied by this adapter.

## Automatic IP-blacklist event

Pinned Rauthy's [failed-login producer](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/login_delay.rs#L66)
uses counts 7/10/15/20 and each count >=25 for automatic blocking. Its
`IpBlacklisted` payload is Warning by default, a host IP, absolute expiry in Unix
seconds, and null text. The pinned manual blacklist API does not call this emitter.
GoAuthy attaches it to the existing `loginpolicy.Failure` transaction only when
the blacklist feature is enabled and a finite automatic block is admitted.

Rhiza v0.12.0's [native SQL result references](https://github.com/mrchypark/rhiza/blob/3b5a5a07aaf83b5ed279f75b920395bda7179577/README.md)
already bind a prior one-row result to a later statement. A scalar SELECT reads
the stored expiry after the existing counter/prune/upsert. `OutputRefs` bind it
to the event's data and non-null admission condition. This avoids a separate
read/write window, another TTL formula, connection-local `changes()` assumptions,
or an event broker. The existing event constructor supplies the ID/host IP/level;
the only direct mapping is application-specific SQL binding. No package or schema
is added. Fosite/JOSE libraries do not own failed-login counters or this schema.

The counter's native exact-row precondition and timestamp predicate reject a
stale observation that loses a concurrent update after the preflight read.
Automatic prune/upsert/projection also require a current counter with a future
block deadline, so a large-forward-clock observation marker is not a new block.
Event/order insertion failure rolls back the counter, reclaimed entries and block.
The next independent failure gets a new request/event ID; internal receipt replay
uses the existing storage wrapper. Direct code does not replace Rhiza receipts.

GoAuthy intentionally preserves an existing longer finite block and records its
actual expiry; permanent manual entries stay permanent and do not produce this
finite-expiry event. Full-capacity non-admission, nonthreshold calls, blocked
middleware requests and disabled automatic blacklisting add no such event.
There is no new manual-delete/expiry event. The separate admin API commit-time
authority work remains open; `InvalidLogins` is described above. Deterministic tests use
fixed timestamps and transaction interposition; deployed tests use a specifically
trusted loopback proxy fixture to keep the observer distinct from the blocked IP.

## User management and passkey wire compatibility

Administrator/public creation now reuses the existing SCIM runtime and durable
outbox: a stdlib capacity-one channel coalesces post-commit wakeups, and the
existing startup/periodic scan recovers missed process-local notifications from
durable identity state. No message broker, scheduler package, schema or provider
network call is added to the creation transaction. This is application wiring,
not a replacement SCIM implementation. The existing scan is O(users*providers)
and drains at most 64 due jobs per pass; targeted durable projections should
replace that scan if measured creation load exceeds this ceiling. Retry/backoff,
mapping and claim fences remain in `internal/scim`. Pending password accounts
are deliberately projected inactive until usable authentication exists.
Abandoned password-new cleanup now reuses the existing tombstone/provider
snapshot format and the same ordered SQL candidate set before deleting local
rows, so an already-delivered inactive remote account is not orphaned. Existing
Rhiza atomic batches and stdlib randomness cover this local lifecycle contract;
the package candidates evaluated in the outbound SCIM section do not own it.

Schema 58 account-expiry policy reuses stdlib `time` and existing Rhiza
`CHECK`/`MIN`/`COALESCE`/`EXISTS` SQL with identity/browser/Fosite integration.
No dependency was added. Fosite does not own the local identity row or Rhiza
claim/role/session atomicity, so direct code is limited to those application
guards, stored-deadline projection and token lifetime caps. Existing Fosite
session expiries drive access signing, persistence and response metadata;
GoAuthy adds the identity/actor snapshot and atomic Rhiza conditions, not new
token cryptography. The expiry worker now reuses stdlib `context`/`time.NewTicker`,
Rhiza conditional atomic batches, existing guarded deletion, SCIM reconciliation
and durable backchannel delivery. A cron/distributed-scheduler dependency would
not provide the local identity/session mutation contract. Direct code is limited
to that policy and bounded periodic execution; full lifecycle/PAM and expiry-specific
live gates remain open. The pinned upstream scheduler/config comparison and
explicit HA/batching/SCIM-latency adaptations are in the user-management contract.
The same account snapshot now guards authorization completion and caps code/PKCE
storage after Fosite sets its default lifetime. A shared Rhiza policy helper checks
owner/actor eligibility at current token consumption boundaries. Raw Fosite getters
remain unchanged because revocation discovers tokens through them and inactive
refresh errors mean reuse, not account expiry. The source-backed placement rationale,
deterministic checks and explicit offline/live limitations are documented there;
no additional package or cryptographic implementation is required.
The pinned Fosite source review and direct-policy rationale are linked in the
user-management contract. Upstream contract, the explicit
exclusive-boundary adaptation and unchecked gates are in
[user-management.md](user-management.md).

The full CRUD request/response contract, installed-package mapping, direct
policy boundary and deterministic acceptance gates are in
[user-management.md](user-management.md). No new dependency was added for the
passkey list correction: stdlib `time.Time.Unix` and `encoding/json` convert
the internal model into the exported HTTP DTO, which the existing OpenAPI
generator reuses. Actual Chrome standalone/three-peer management gates passed;
whole account CRUD and passkey parity remain incomplete. Kubernetes key
preparation reuses the existing init-container image and a memory-backed
volume, keeping the owner's-only file permission requirement intact.

Schema v56 adds durable user creation and last-login metadata using existing
Rhiza SQL constraints, `MAX`/`COALESCE`, and the existing identity/browser stores.
New bootstrap/open-registration inserts supply creation time; historical rows
retain the explicit unknown sentinel `0`, with last login `NULL`. The shared
login rotation records the persisted authenticated session's creation time,
not a new timestamp inferred in the HTTP response. No new package or generic
CRUD framework is needed. This policy glue is specific to the existing schema
and session lifecycle; it does not implement the still-missing public user CRUD
or credential-generation fencing. See the metadata checks and remaining gates
in [user-management.md](user-management.md).

The detail endpoint reuses the same Rhiza SQL/JSON machinery, existing exact
session/API-key guards, and standard `encoding/json` DTO projection. Its target
view policy follows pinned Rauthy `ReqPrincipal::validate_group_admin_can_view`
(self/full admin, protected admin targets, exact/prefix groups, 403/428).
`identity.PasswordExpiresAt` shares the existing UTC password lifetime calculation
with authentication; no additional date or policy package is needed. No public
CRUD package owns this repository's session and delegated-group snapshot semantics,
so the small query/HTTP policy glue is local. Remaining expiration lifecycle,
failure-history and federation-source state remain implementation gaps, not
justifications to synthesize values. See [user-management.md](user-management.md).

Schema 57 language selection reuses `net/http` cookies, the bounded existing
Accept-Language parser (`strings`/`slices`), Rhiza CHECK constraints, and the
existing TOML/`text/template`/`html/template`/`go-mail` pipeline. No dependency
was added: parsing, escaping and transport already exist. Direct code is limited
to the pinned nine-value account policy, `zhhans`→`zh_hans` catalogue mapping,
legacy fallback and stored-preference wiring; a generic locale package cannot
own these schema/compatibility rules. Compare pinned upstream
[language.rs](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/language.rs),
[password_reset.rs](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/email/password_reset.rs),
[email_registered_already.rs](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/email/email_registered_already.rs).
The existing parser's primary-tag/strict bounds are an explicit adaptation,
not a full reimplementation of upstream's language-negotiation dependency.
Stored language does not imply complete translated UI/copy or timezone handling.

The user-list endpoint now reuses RBAC/browser/API-key SQL predicates in the
same linearizable read as count and page data. HTTP/query/JSON parsing uses
`net/http`, `net/url`, `strconv`, `encoding/json`; opaque cursor encoding uses
`encoding/binary` and `encoding/base64`. Rhiza SQL supplies ordering, keyset
selection, count and null projection. Neither Fosite nor a generic pagination
library owns these current-session/delegated-role/grant predicates or legacy
identity semantics, so only that application-specific query/DTO adapter is
directly implemented. No package was added. Cursor and default-threshold
source decisions, deterministic tests and live verification limits are in the
user-management contract above.

## OpenAPI / Swagger

OpenAPI 3 모델·참조 해석·검증은 `github.com/getkin/kin-openapi v0.149.0`, UI는
MIT `github.com/swaggo/files/v2 v2.0.2`의 embedded assets를 사용한다. `net/http`,
`io/fs`, `encoding/json`을 재사용하고 새로운 HTTP framework는 추가하지 않는다.
표준 Go/Fosite에는 전체 관리·계정 API 문서 생성기가 없으므로 핸들러별 operation
메타데이터와 private wire schema만 직접 연결한다. 공개 Go 타입은 `openapi3gen`으로
재사용한다. 선택 근거·공식 출처·정책·검증 한계는 [OpenAPI 문서](openapi.md)를 참조한다.

## Global JSON KV (schema v55)

Rauthy v0.36.2의 [KV API](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/kv.rs)와
[저장 모델](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/kv.rs)을
대조했다. 필요한 기능은 네임스페이스, 공개 단건 읽기, 전용 접근키, JSON 값과 선택적
암호화다. TTL/CAS API는 해당 upstream에 없으므로 기존 계획에서 제거했다.

- JSON/HTTP/입력 제한: 표준 `encoding/json`, `net/http`, `net/url`, `mime`, `regexp`.
- 무작위 ID·접근키와 검증: 표준 `crypto/rand`, `crypto/sha256`, `crypto/subtle`.
- 암호화: 이미 사용하는 `oidc.Keyring`의 표준 AES-GCM envelope. 새 암호화 구현 없음.
- 영속성과 일관성: 이미 사용하는 Rhiza v0.10.0의 SQL·외래키·선형화 읽기·조건부 변경.

별도 KV 엔진을 추가하면 요청된 Rhiza 단일 backend에서 벗어난다. Fosite는 OAuth
프로토콜을 담당하며 이 관리·네임스페이스 권한 모델을 제공하지 않는다. 선택한
기존 패키지 어느 것도 브라우저 관리자 CSRF, 네임스페이스별 접근키, Rhiza의
커밋 시점 자격 재검사 및 기존 키 폐기 fence를 함께 제공하지 않으므로 그 연결
정책만 `internal/kv`에 직접 구현했다. 네임스페이스의 불변 식별자는 이름 변경 시
암호화를 유지한다. 공개 JSON scalar의 HTML 반환은 보안상 복제하지 않는다.
전체 API와 차이·검증 명령은 [KV 계약](kv.md)에 기록한다.

## Rhiza runtime profiles

Production has two explicit Rhiza `v0.12.3` modes. `standalone` is one
embedded member with no peer or object-store inputs; legacy `dev` is an alias
with the same rejection rules. `make e2e-standalone` passed runtime smoke,
restart/JWKS persistence, and the shared browser authorization-code/refresh
flow with both E2E URLs pointed at the same standalone endpoint. `cluster` is
exactly three embedded voters with
distinct per-member voter tokens in Secret JSON and a separate admin token.
Source validation and static Kubernetes configuration are verified; preferred
hostname anti-affinity and a `minAvailable: 2` PDB protect voluntary HA
disruption, and the `deploy/standalone` overlay has a static render test. The
earlier Docker inotify limit blocker is historical: subsequent standalone and
exact-three Kind gates passed. Current scope and backup/restore verification
limits are tracked in [status.md](status.md), not inferred from manifest tests.
Standalone and exact-three HA have identical application semantics; HA pods
must use matching SCIM provider configuration, including stable IDs and
policies.
The guard introduced for Rhiza v0.10.0 remains with v0.12.0: startup failure
paths skip `db.Close()` until all startup initialization succeeds;
normal post-start shutdown still closes the database as usual.

Bootstrap authentication is password-only for the initial administrator by
default; passkeys are optional. `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` is an
explicit opt-in that fails startup unless the complete passkey configuration is
valid, rather than falling back to password-only login. Forward Auth identity
headers are independent of passkey configuration: when
`GOAUTHY_FORWARD_AUTH_HEADERS=true` and passkeys are disabled,
`X-Forwarded-User-MFA` is emitted as `false`. See the
[bootstrap passkey policy](passkey-bootstrap.md).

Rhiza schema v58 is the current source baseline. Schema v53 persists an
optional DCR `software_statement`; schema v54 adds the canonical replicated
`dcr_software_statement_trust` digest/topology fence. Deterministic
source/HTTP/idempotency and trust-fence tests cover the static issuer-to-JWKS
trust policy, and the standalone live software-statement replay/readiness E2E
passes. The exact-three HA gate
`KIND_CLUSTER=goauthy-software-statement-ha-e2e-20260905i` on ports
`19840-19842` also passes with all three pods Ready and identical trust,
cross-pod GET persistence,
invalid signature/issuer/audience rejection on all pods, pod-0 UID replacement,
byte-identical idempotent replay after restart, and cleanup.

DCR `last_used` updates for successful `PUT` and dynamic token issuance are
verified source behavior (monotonic commit-time timestamps); excluded grant
and failure paths remain intentionally unsupported.

Master-key envelope maintenance is source-wired: a minute worker independently
cursor-scans bounded signing-key, live DCR-idempotency, and unexpired
upstream-transaction rows, authenticates old envelopes, and exact-CAS rewraps
them under the active key. OAuth persisted request forms redact credential,
bearer, and one-use fields while retaining non-secret protocol metadata. This
does not complete critical DB-value encryption; passkey/nonrotating values,
automatic key removal and CookieKey rotation remain pending. Deterministic
standalone exact-one and exact-three state-machine/replay/revocation-
interposition/chain-integrity tests cover the source contract.

The master-key retirement barrier is implemented as an operator-controlled,
replicated `prepared` -> `fenced` -> `ready` (or `aborted`) protocol.
`prepared` records an epoch, old/replacement key IDs, and the exact membership
digest. `fenced` is a replicated commit-time SQL guard that rejects compliant
envelope writes using the old key while allowing the replacement. `ready`
requires fresh attestations from all members with distinct current process
`boot_id`s, the replacement active, and zero old, non-active, legacy, tamper,
OIDC, DCR, upstream, or passkey references. Guarded prepare/fence/ready/abort
transitions recheck API-key authority in the same Rhiza transaction and append
exactly-once append-only audit events with API-key HMAC pseudonyms and
epoch-only targets. Standalone exact-one and exact-three deterministic tests
cover state transitions, replay, migration, revocation interposition, and
chain integrity. The live exact-three gate
`KIND_CLUSTER=goauthy-master-key-e2e-20260905c E2E_PORT=19700` passed all three
zero-reference checks, pod-restart boot-ID change with attestation sequence 2,
Ready, key retention, and cleanup. No state transition deletes a key
automatically.

Rhiza v0.10.0's `DB.Ready`, linearizable `DB.Query`, `DB.Execute`, and
`RequestStatus` provide fixed membership, replicated SQL, quorum reads, and
request-status recovery (`rhiza.go:230-233`, `pkg/network/server.go:1021-1041`),
but have no opaque-envelope/key-retirement API; GoAuthy owns the direct
application schema/SQL guards and per-member attestation rows, with schema v52
adding the retirement-audit constraints/triggers and schema v54 adding the
canonical replicated DCR software-statement trust digest/topology fence, plus
worker integration. Deterministic migration, replay, commit-time A/B,
fresh exact-three attestation, old/legacy/tamper and disabled-family policy,
and authorization tests cover the source contract. No public endpoint or
automatic deletion is implied by these guards.

## Roles, groups, and OIDC claims (schema v24)

| Need | Selected implementation | Why |
|---|---|---|
| Role/group request and admin HTTP boundary | stdlib `net/http`, `encoding/json`, `regexp`; existing browser-session, CSRF and Fetch-Metadata policy | The routes are a strict, small JSON boundary. A new web or RBAC package would not provide this deployment's issuer-bound browser session, exact reserved-role rule, or same-transaction active-admin check. |
| Replicated entities and memberships | official Rhiza `v0.10.0` (commit `2e645f913ba58574c001900eecab43b06aa4a590`) schema v24 relational SQL | Rhiza owns replicated storage and atomic writes. No selected package owns Rauthy's role/group entity contract plus immutable identifiers, name uniqueness, membership cascade, bootstrap convergence and cross-pod authorization revocation. |
| Dynamic user membership replacement | stdlib strict JSON + Rhiza conditional SQL | Upstream uses `PATCH /auth/v1/users/{id}` with a generic `PatchOp`; it is a complete-list replacement, not an add/remove-members endpoint. Neither Rhiza nor a Go RBAC library owns the required active-admin, last-admin, identity, revision and current-token-claim invariants. |
| OAuth/OIDC claim carriage and JWT | existing `ory/fosite v0.49.0` session `Extra` + `go-jose/v4`; stdlib slices/JSON validation | Fosite owns OAuth mechanics and can carry session values, while `go-jose/v4` owns EdDSA JWT signing/verification. Neither supplies an RBAC model, role/group CRUD, scoped claim policy, or a current-membership resolver; those product semantics must be direct code. |

`Casbin` and `Oso` were considered and not selected. Both are general policy
engines; neither supplies Rauthy's `PatchOp` wire contract, durable normalized
membership model, browser-session/CSRF authorization boundary, or a single
Rhiza transaction which prevents removing the final active `rauthy_admin`.
Adding either would duplicate the small direct policy and make replicated
revision/CAS behavior less auditable. Re-evaluate only if a future feature
needs configurable multi-resource policy beyond this fixed user-membership
contract.

The in-flight slice follows fixed Rauthy v0.36.2 role/group CRUD routes and
uses `rauthy_admin` only as the initial bootstrap administrator. Roles are
canonical, bounded arrays in every end-user ID token, UserInfo and
introspection response. Groups are released only for a granted `groups` scope;
client-credentials, device authorization and token exchange reject that scope.
At authorization-code exchange, refresh, UserInfo and introspection, the
service resolves the current principal instead of treating persisted Fosite
`Extra` as authorization truth. Code/refresh persistence repeats an
active-identity plus principal-revision predicate, so a membership change after
resolution cannot mint or rotate artifacts from a stale snapshot. Role/group
rename or delete bumps every affected principal revision. Admin list/get reads
are guarded too, not only writes. GoAuthy deliberately accepts group names only
as `[A-Za-z0-9-_/,:*]{2,64}`: this is narrower than Rauthy's `\s`-permitting
group grammar, avoiding whitespace/control/backslash ambiguity in future prefix
authorization.

### Dynamic user role/group assignment: narrow implemented subset

Rauthy v0.36.2 has no dedicated assignment route. It mounts
`PATCH /auth/v1/users/{id}` and accepts `PatchOp`:

```json
{"put":[{"key":"roles","value":["operator"]},{"key":"groups","value":["engineering"]}],"del":[]}
```

`put` for `roles` or `groups` replaces that whole list; `del:["roles"]` or
`del:["groups"]` clears it. The success response is the complete upstream
`UserResponse`, whose `roles` is an array and whose `groups` is optional.
Rauthy sanitizes submitted names against existing entities and silently drops
unknown names. Its general `PUT /auth/v1/users/{id}` also replaces both lists.
Sources: [handler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs#L1939-L2051),
[request/response](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/users.rs#L158-L187),
[PatchOp](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/lib.rs#L29-L38), and
[sanitization](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/roles.rs#L218-L231).

GoAuthy now wires the roles/groups-only subset at
`PATCH /auth/v1/users/{subject}` and returns `{id,roles,groups}`. It does **not**
yet emulate the full upstream `UserResponse` or expose Rauthy's full-user
`PUT`. The GoAuthy security deviation is explicit:
unknown role/group names will fail closed instead of being silently dropped,
and a mutation must reject removal of the final active `rauthy_admin` in the
same Rhiza request. That protects availability of the management boundary but
is not wire-identical upstream behavior. Delegated `rauthy_admin:<prefix>`
group administration and API-key `Users:Update` remain unimplemented.

Deterministic fixed-clock/random tests cover request shape, replacement/clear,
unknown/duplicate names, authorization, final-admin/self-demotion and CAS
conflicts. A fresh three-pod run covered cross-pod assignment and UID-verified
pod replacement; clocks/randomness are injected and timeouts only cap external
execution. Full-user/API-key/delegated-admin parity remains pending.

Tests are deliberately deterministic: clocks/randomness are injected where
needed, memberships and token state are asserted directly, and test timeouts
only bound execution. A deterministic pre-commit revision-bump barrier verifies
that stale code/refresh snapshots persist no token artifacts. The local-kind
profile runs three pods, exercises create/rename/delete, cross-pod membership,
current claims and refresh, deletes a named pod, requires a different pod UID
plus Ready, and reads preserved membership with an empty PatchOp. That
deterministic CRUD/assignment/claims/refresh/replacement slice passes.

The earlier follower `sqlite3: disk I/O error` / `no such savepoint:
rhiza_command` sequence was traced to SQLite having no writable temporary path
under the main container's `readOnlyRootFilesystem`. The deployment correction
is a main-container `/tmp` `emptyDir` with `SQLITE_TMPDIR=/tmp`; it uses no
new Go package or Rhiza fork. The final full gate also passed the corrected
RBAC slice; that evidence does not mark unrelated historical failures complete.
Delegated group administration/API keys and the custom-claim gaps documented
below remain unimplemented.

## Custom scopes, user attributes, and bootstrap client scope policy (schema v26)

| Need | Selected implementation | Why |
|---|---|---|
| Scope/attribute admin HTTP boundary | stdlib `net/http`, `encoding/json`, `regexp`; existing browser session, CSRF and Fetch-Metadata policy | The wire contract is small and security-sensitive. No web/admin package owns GoAuthy's issuer-bound browser session, exact `rauthy_admin` authorization rule, strict JSON rejection, or the bootstrap-client-only partial route surface. |
| Catalog, per-user values, and bootstrap scope policy storage | official Rhiza `v0.10.0` (commit `2e645f913ba58574c001900eecab43b06aa4a590`) schema v26 relational SQL | Rhiza owns replicated storage and atomic writes. No maintained Go package owns Rauthy's custom-scope mapping contract plus canonical JSON defaults/values, rename-delete cascades into scope mappings and bootstrap client policies, current-admin checks, and cross-pod catalog revision semantics. |
| OAuth/OIDC custom-claim carriage | existing `ory/fosite v0.49.0` session `Extra` + `go-jose/v4`; stdlib JSON normalization | Fosite carries restored session values and `go-jose/v4` signs ID tokens, but neither package decides which custom attributes appear on which surface, how root collisions fail closed, or how catalog/principal races prevent stale artifacts. That product policy must stay in direct code. |

Rauthy v0.36.2 fixes the public admin surface at `GET`/`POST /auth/v1/scopes`,
`PUT`/`DELETE /auth/v1/scopes/{id}`, `GET`/`POST /auth/v1/users/attr`,
`PUT`/`DELETE /auth/v1/users/attr/{name}`, and per-user value management at
`GET`/`PUT /auth/v1/users/{id}/attr`. GoAuthy follows that surface and adds one
explicitly narrow route that Rauthy folds into full static-client replacement:
`GET`/`PUT /auth/v1/clients/{id}/scopes` for configured bootstrap clients only.
That keeps the public API honest while full client management is still absent.

The selected direct model stays smaller than adding a policy engine or claims
framework. Attributes accept Rauthy's current practical contract: arbitrary
canonical JSON values and defaults, `typ:"email"` only, and a
`user_editable` flag. Scope mappings accept `attr_include_access`, `attr_include_id`, and
`claims_at_root`; built-in scopes (`address`, `email`, `groups`, `openid`,
`phone`, `profile`) remain reserved and cannot be remapped. Empty string or
JSON `null` clears a user value. Rename/delete cascades update scope mappings
and bootstrap allowed/default scope lists in the same Rhiza request.

OAuth claim surfaces are intentionally explicit. `attr_include_id` appears on
ID tokens. `attr_include_access` is resolved from current state for UserInfo and
opaque-token introspection and is emitted under `custom`; authorization-code
and refresh JWT access tokens now carry the same current scoped claim routing.
When `claims_at_root`
is true, custom claims are merged at the top level only if they do not collide
with reserved or existing token fields; any collision aborts issuance before
authorization-code consumption or token minting. Authorization-code exchange and
refresh both recheck the active subject, principal revision, and claims catalog
revision atomically so stale scope or attribute snapshots fail closed.

Rauthy's [`DynamicClientRequest`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/clients.rs#L14-L91)
has no `scope` field: dynamic client scopes come from the operator's
`dynamic_clients.allowed_scopes` and `default_scopes` configuration, and an
update preserves the stored policy. GoAuthy mirrors that boundary with strict
stdlib `strings.Fields` parsing of `GOAUTHY_DCR_ALLOWED_SCOPES` (default
`openid profile email groups`) and `GOAUTHY_DCR_DEFAULT_SCOPES` (default
`openid`), followed by a small direct unique-token/subset validator. DCR JSON
rejects a client-supplied `scope`. A configured nonstandard scope is admitted
only after current catalog lookup and only for authorization-code/refresh;
device, client-credentials and token-exchange remain denied. Fosite models
registered client scopes but does not own operator policy, custom-scope catalog
lookup, or this grant restriction, so no package can replace that direct glue.

Anonymous DCR rate limiting is likewise direct code: stdlib `crypto`, `net/http`,
`net`, and `net/netip` provide the request digest and canonical peer identity,
while Rhiza provides the shared conditional state required for HA exact
fixed-window semantics. `golang.org/x/time/rate` is local-only, and available
Redis packages do not match Rhiza's HA/exact fixed-window transaction contract,
so neither can own this boundary.

Rauthy v0.36.2 documents `cleanup_minutes` as minutes but subtracts that value
directly from Unix seconds in its scheduler. GoAuthy intentionally follows the
documented unit, not that source bug: the default retains never-used anonymous
clients for 60 minutes, and deterministic tests inject the cleanup clock.

Package search did not find a better ownership split. Fosite does not expose a
complete custom-claims policy layer, bootstrap-client dynamic scope source, or
signed access-token claim surface. `go-jose/v4` signs JWTs but does not
normalize arbitrary custom JSON or protect root-claim collisions. Rhiza offers
the replicated SQL/CAS substrate but not these application semantics. Direct
implementation was therefore unavoidable for the narrow boundary above.

Deterministic verification is complete for the focused slice: schema-v26
migration replay, strict decoders, canonical response ordering, attribute/scope
rename-delete cascade, custom-scope grant denial outside authorization-code and
refresh, root-collision failure before artifacts, and catalog/principal
revision races. `[x]` On 2026-09-01, fresh three-pod roles/groups profile E2E
passed pod replacement plus the static-client custom-scope/attribute flow
(`4.392s`) using cross-pod state/revision barriers and no test sleeps. The new
dynamic policy has deterministic parser/store/OAuth tests; its fresh-kind E2E
remains unchecked. A true non-admin self-attribute PUT E2E is also pending.
API-key administration and signed JWT access-token custom-claim parity have the
bounded schema-v28 implementation below. Schema v29 now adds the separate
bootstrap `client_credentials` claim policy documented after it; full static
client management remains out of scope.

## API keys and signed access tokens (schema v28)

| Need | Selected implementation | Why |
|---|---|---|
| Scoped administrator API keys | stdlib `crypto/rand`, `crypto/sha256`, `crypto/subtle`, `encoding/base64`, existing browser-admin policy, and Rhiza v0.10.0 schema v28 | Rauthy's API keys need one-time secrets, expiry, rights checks and mutation authorization tied to replicated state. No selected Go package owns that application authorization model or Rhiza atomic guard. The direct boundary is deliberately small: 64-character random alphanumeric secret, SHA-256 base64url digest, constant-time comparison, and transactional rights guard. API keys managing API keys and JSON bootstrap/import remain separate unchecked capabilities. |
| Signed JWT access-token verification | existing `go-jose/v4`, existing Ed25519 JWKS/key rotation and retained opaque-token `jti` index | Fosite's default HMAC token format is not a Rauthy-compatible public JWT access token. `go-jose/v4` signs/verifies compact EdDSA JWTs, but GoAuthy must verify EdDSA/JWKS/claims before deriving the `jti` index or querying Rhiza, then bind claims to the Fosite request and retain revocation/introspection/DPoP/token-exchange state. Retiring JWKS keys remain through the 24-hour maximum signed-access lifetime plus JWKS cache window. |

The API-key HTTP surface is intentionally restricted to
`/auth/v1/api_keys` and its named subroutes; API-key authorization is only
bound into the explicit roles/groups/claims administration handlers. A supplied
API-Key header cannot fall back to ambient browser authority, and no OAuth,
DCR, account, login or browser-session route accepts it. Browser use repeats
the existing same-site, authenticated-current-subject, current-`rauthy_admin`,
and mutation CSRF checks.

Rauthy encrypts its stored API-key digest. GoAuthy schema v28 stores only a
one-way SHA-256 digest, so it intentionally cannot recover or re-encrypt a
digest; this is a documented storage-format deviation rather than a claim of
wire-compatible cryptography. Deterministic store/handler/race and signed-token
tests use injected randomness/state where needed. The dedicated three-pod API-key
E2E is source-complete and has passed create/use/rotate/delete, expiry, scoped
denial and no-fallback boundaries. Strict JSON startup import now supports only
explicit 64-character alphanumeric `Plain` secrets in one Rhiza transaction;
Rauthy's `generate`/`Encrypted` forms, encrypted-digest parity, bootstrap Kind
evidence and management UI remain unchecked.

## Bootstrap client-credentials claims (schema v29)

Rauthy stores static-client `claims` plus `claims_at_root` and injects them
only into `client_credentials` access JWTs. GoAuthy uses stdlib strict JSON,
Rhiza CAS and the existing `go-jose/v4` signer; no new package is needed or
owns this static-client policy. The explicit partial management route is
`GET`/`PUT /auth/v1/clients/{id}/claims` for configured bootstrap clients.
It accepts a JSON object or `null`, caps the serialized object at Rauthy's
1,024-byte limit, and keeps revision changes atomic with browser-admin or
`Clients:read/update` API-key authorization.

Token issuance reads the current policy and repeats its absent-row or exact
revision predicate in the same Rhiza request that stores both access-token
records. A concurrent policy change therefore returns no token and leaves no
artifact. Nested claims appear under `custom`; root claims are merged only
after the existing JWT reserved-name/collision preflight. As in Rauthy, a
reserved root key may be stored but makes issuance fail. Dynamic/CIMD clients,
token exchange, UserInfo and introspection never receive these machine claims.

GoAuthy's shared JWT normalizer retains stricter key-count, key-length and
nesting limits than Rauthy's object-only 1,024-byte validator. This is an
intentional defense-in-depth compatibility narrowing, not an accidental
package limitation. Relax it only with interoperability evidence and a new
security review. Deterministic fixed-clock/state tests cover nested/root/clear,
reserved collision, dynamic denial and a revision interposition barrier. The
fresh three-pod public-JWKS E2E is wired but remains pending until Docker
recovers.

## Static-client `restrict_group_prefix` (schema v25)

| Need | Selected implementation | Why |
|---|---|---|
| Static-client login restriction storage and admin route | stdlib `net/http`, `encoding/json`, `regexp`, `strings`; existing browser-admin session, CSRF and Fetch-Metadata policy; Rhiza `v0.10.0` schema v25 | Rauthy stores `restrict_group_prefix` as part of static-client replacement, but GoAuthy does not yet expose full static-client management. A narrow explicit `GET`/`PUT /auth/v1/clients/{id}/login-restriction` route reuses the existing admin boundary and keeps the public surface honest. No package owns this route, the nullable prefix/revision CAS, or the exact bootstrap-client allowlist. |
| OAuth/forward-auth enforcement | existing `ory/fosite v0.49.0` session `Extra` plus direct Rhiza-backed policy | Fosite carries session state but does not know Rauthy's current-group admission rule. The restriction must be checked against the caller's current full groups at authorize completion, authorization-code redemption, refresh and `forward_auth`, and the same Rhiza transaction/revision guard must fail closed when group membership or policy changes concurrently. |

The fixed upstream behavior is intentionally small. Validation follows
Rauthy's `^[a-zA-Z0-9-_/,:*\s]{2,64}$` grammar for the stored prefix string, but
enforcement is the same raw case-sensitive `strings.HasPrefix` check upstream
uses. `*` is therefore a literal character, not a wildcard. A missing row or
stored `NULL` means unrestricted. Dynamic/CIMD clients are unmanaged, and
client-credentials remains unaffected because the gate is only for user login.
Dynamic Client Registration must reject `restrict_group_prefix` so the field
cannot appear on managed dynamic clients before full static/dynamic client
policy exists.

Deterministic tests cover the whole slice without sleep-based oracles:
strict admin JSON, bootstrap-client scoping, CAS create/update/clear, stale
revision `409`, unauthorized no-op retry after admin loss, revision-bound
unrestricted clears, current-group enforcement on code/refresh/forward-auth,
scope-independent admission groups, raw case sensitivity, literal `*`, and DCR
rejection. On 2026-09-01, the dedicated three-pod
`TestBootstrapClientGroupRestrictionAcrossPods` passed in 1.610s using
linearizable cross-pod GET barriers rather than time delays.

## `forward_auth`

| Need | Selected implementation | Why |
|---|---|---|
| Reverse-proxy authorization check | `net/http` handler plus existing OAuth opaque-access-token and session storage | Rauthy's simple endpoint validates a bearer user token before admitting the request ([source](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/oidc.rs#L1197-L1235), [documentation](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/forward_auth.md)). No new package or protocol engine is needed. |

The direct code is limited to handler glue: GET only; reject query and body;
return empty `200` for a valid bearer user token and generic `401` otherwise.
Version 1 rejects DPoP-bound tokens and emits no identity headers unless the
opt-in trusted identity-header mode is enabled. That mode is independent of
passkey configuration and emits `X-Forwarded-User-MFA: false` when passkeys are
disabled. The no-passkey standalone gate `E2E_PORT=18087
scripts/e2e-forward-auth-standalone.sh` passes password bootstrap,
`X-Forwarded-User-MFA: false`, restart persistence and forced-MFA/no-passkey
startup failure; the standalone
`scripts/e2e-forward-auth-standalone.sh` E2E passes identity projection and
hostile, duplicate, malformed, and overlong header checks. The final exact-three
gate `KIND_CLUSTER=goauthy-forward-auth-ha-e2e-final7 E2E_PORT=20400
./scripts/e2e-forward-auth-ha-kind.sh` runs on application ports `20400-20402`
and passes all-pod identity headers/hostile clearing, pod-0 UID replacement
with persisted-token validation, revocation, final-admin self-delete denial,
and cleanup. It remains a narrow
bearer-validation slice, not Rauthy's proxy modes.
The no-passkey exact-three gate
`KIND_CLUSTER=goauthy-forward-auth-ha-nopasskey-final E2E_PORT=20500
scripts/e2e-forward-auth-ha-kind.sh` passes three Ready pods without passkey
assets, `MFA=false`, hostile-header clearing, pod-0 replacement, revocation,
final-admin self-delete denial, and cleanup on ports `20500-20502`.

## Ephemeral URL-document clients (CIMD)

| Need | Selected implementation | Why |
|---|---|---|
| OAuth Client ID Metadata Document discovery | stdlib `net/http`, `net/url`, `net/netip`, `crypto/tls`, `crypto/x509`, `encoding/json`, `crypto/sha256`; Fosite public-client types; Rhiza schema-v13 cache | The active [OAuth CIMD draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02) defines a remote-document trust boundary. The standard library provides transport and parsing primitives, but not the combined URL validation, IANA special-use address policy, DNS-to-dial pinning, document policy or durable cache. Fosite v0.49 provides client mechanics, not CIMD discovery or persistence. |

The partial implementation is disabled unless `GOAUTHY_CIMD_ENABLED=true`.
It accepts only public HTTPS TCP/443 with an exact client-ID/document match; resolves every DNS
result before connecting and pins the selected validated address; rejects
special-use addresses, redirects, proxies, cookies, compression, non-200
responses and bodies over 5 KiB. Documents may define only a public
authorization-code client with S256 PKCE, constrained scopes and same-origin
HTTPS redirect URIs. Rhiza schema v13 holds the shared, policy-digested cache;
persisted authorization/code/access requests use a sanitized metadata snapshot.
RFC 8707 `allowed_resources` entries are exact absolute HTTPS URLs, including an
explicit empty-list default-deny snapshot; unlisted resources remain denied
unless `GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE=true` is explicitly set,
and that danger path still admits only valid HTTPS URLs. The immutable Rhiza
snapshot is the policy source at authorization and token use.
Public token-client authentication performs a shared cache-only lookup, never a
remote refetch. Production egress must align to public TCP/443; CNI-enforcement
proof remains pending. Discovery advertises support only when configured.

The `ignore_unknown_auth_flows` parser policy core is deterministic and keeps
known grants while requiring `authorization_code`; production wiring accepts the
strict default or the opt-in `GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS=true` policy.

Focused tests are deterministic: injected clocks, resolver/dialer behavior and
request counters replace sleeps. Wall-clock timing is reserved for unavoidable
deployment boundaries. CIMD Kind E2E has not run; S256
login/code/public-token exchange, cross-pod cache reuse and
mismatch/malformed/redirect-private/private-literal denial remain Kind evidence
gates, while DNS rebinding is unit-only. The feature remains `[ ]`:
cross-pod cache-expiry E2E, policy-enforcing egress and chaos are pending. The fixture's `externalIPs`
route is deprecated in Kubernetes 1.36 and disposable-kind test-only, not
production egress. The pinned `make e2e-kind-cimd-cilium` gate avoids timing as
an outcome oracle: CiliumEndpoint revisions bound policy rollout and synchronous
fixture counters judge deny/cache/recovery. Its fresh Dory run failed closed
before application deployment because Cilium v1.20.0's route reconciler returned
`protocol not supported`; enforcement remains unchecked. There is no
local/private-address bypass. The CIMD RFC 8707 `allowed_resources` policy is
implemented with exact absolute HTTPS matching and immutable snapshots; a
separate default-off basic WebID Turtle profile route is now implemented. The
standalone WebID E2E passes, and the exact-three `scripts/e2e-webid-ha-kind.sh`
live gate passes cross-pod output and replacement-pod checks, while Solid and
dynamic default audiences remain pending. Rauthy's fixed-tag
[lookup/cache](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs#L469-L494), [fetch](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs#L1550-L1608) and [ephemeral-client documentation](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/ephemeral_clients.md) are the behavior baseline.

## Passkeys / WebAuthn

| Need | Selected implementation | Why |
|---|---|---|
| WebAuthn ceremony verification | `github.com/go-webauthn/webauthn v0.18.0` | The maintained verifier owns WebAuthn protocol parsing and authenticator validation. GoAuthy pins the current zero-major release and does not reimplement WebAuthn cryptography. |
| Ceremony, credential and account security state | Rhiza `v0.10.0`, stdlib `crypto/aes`/`cipher.AEAD`, `crypto/rand`/SHA-256, small direct policy | No package owns exact RP/origin/UV admission, subject/browser/OAuth binding, account-mode transition, registered-UV predicate, `MfaModToken`/`PasswordNew` purpose binding, or one-use proof consumption with the verifier/mode CAS. Those share GoAuthy's schemas v20--v21 and must remain a small direct boundary. |
| Forced-client MFA policy | `go-webauthn/webauthn`, Fosite, stdlib JSON/crypto and Rhiza schema v22/CAS | Rauthy's dynamic-client mapping fixes `force_mfa` false. GoAuthy keeps the initial/bootstrap administrator password-only by default; only explicit `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` opts into forced MFA and startup rejects missing or invalid complete passkey configuration. It rejects DCR `force_mfa` and keeps dynamic clients unforced. No selected package owns legacy-session revoke, session/original-interaction binding, current active-subject/policy recheck, or exact ID-token `amr` lifecycle. GoAuthy directly implements that narrow bootstrap policy; `go-webauthn` verifies UV assertions, Fosite issues OAuth results, stdlib supplies primitives, and Rhiza makes each security mutation atomic. Static admin-managed per-client policy is pending. |

The runtime slice is opt-in: the RP ID, exact comma-separated origins and a
32-byte key file must be configured together; display name defaults to
`GoAuthy` and forced UV defaults to false. Fixed configuration and injected
clock/random seams keep unit/handler/config/schema tests deterministic. Registration
finish uses the configured session idle timeout and an atomic Rhiza guard for the
active, non-disabled identity; it upgrades only the exact bound `pwd`/`webauthn`
session to `mfa` and preserves `external`. Focused replay/stale-session/disable
interposition tests pass, but cross-pod E2E for this upgrade remains pending. `[x]`
Fresh `E2E_PROFILE=passkey KIND_CLUSTER=goauthy-passkey-deterministic-e2e make e2e-kind`
used Chrome CDP virtual authenticator and passed `test/e2e/passkey` in `5.086s`
with cluster cleanup: pod-A registration plus origin/RPID and bad-UV denials;
cross-pod MfaModToken proof/final-token exchange and replay denial; pod-B
one-way password-to-passkey conversion (empty `200`), preserved established
browser/OAuth session and password-login denial; PasswordNew reverse update
and replay denial; and passwordless sign-counter advance with pod-C replay
rejection. The direct conversion CAS
erases the verifier/history/reset/MFA-modification-token state only after a
stored registered user-verified credential exists. `[x]` The narrow reverse
self slice uses a UV `PasswordNew` proof bound to purpose, subject and browser
session; its one Rhiza transaction consumes the proof, writes the verifier,
switches mode, preserves passkeys/established sessions, and removes pending,
reset and MFA artifacts. Deterministic unit/race checks and the fresh passkey
E2E cover the narrow reverse path. Recovery/admin reverse conversion and full
forced-MFA parity remain `[ ]`.

Schemas v20--v21 add the narrow Rauthy MfaModToken and PasswordNew analogues. `go-webauthn` owns the
assertion parser/signature/challenge/origin/RP-ID/UV verification; stdlib owns
unbiased random codes, SHA-256 digests and AEAD encryption; Rhiza owns atomic
conditional mutation. Direct policy remains necessary to select password only
when zero passkeys exist, bind ceremony/proof/final token to subject and
browser session, use a 48-alphanumeric encrypted ceremony/digest-only code,
issue a 90-second one-use proof and a 120-second one-use token, record the
factor marker and invalidate all pending state during conversion. Unit/race
coverage and fresh kind E2E are `[x]`; the passkey profile covers bad-UV
rejection, cross-pod MfaModToken proof/final-token exchange and replay denial.
Rauthy's IP-bound reusable final token and `ip` response are intentionally not copied: GoAuthy uses a
session-bound one-use token and omits `ip`. Browser-session IP binding is implemented in schema v31 via
`peer_ip` column, `LoadSessionForPeer`/`LoadSessionReadOnlyForPeer` methods, and `peerIPMiddleware`.

Schema v22 adds browser-session `auth_method` and revokes legacy sessions
without it rather than inferring MFA. `GOAUTHY_BOOTSTRAP_FORCE_MFA` requires
an enrolled registered-UV credential to complete a current UV assertion after
password before bootstrap-client code/session issuance. DCR `force_mfa` is
rejected and dynamic clients are always unforced, matching Rauthy's
dynamic-client mapping. Proofs bind the session digest and original interaction,
and the commit rechecks the active subject and bootstrap policy. ID tokens
preserve `amr=pwd,mfa` through refresh; access tokens intentionally carry no
`amr`. Deterministic unit/race checks pass. The forced-MFA kind profile now
targets this bootstrap policy; its fresh replacement E2E result is pending.
Static admin-managed per-client policy, Rauthy `admin_force_mfa`/admin
management and upstream-provider MFA remain `[ ]`; full passkey parity remains
`[ ]`. The upstream baseline is Rauthy's
[client validation](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs#L1213-L1237),
[authorize policy](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/authorize.rs#L127-L154),
and [principal policy](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/principal.rs#L160-L180).

The Rauthy-compatible administrator credential reset is now a separate direct
policy on top of `go-webauthn`: active browser administrators may list and
delete another subject's named credential, while `Users:read` API keys are
read-only. The destructive DELETE repeats the actor's active identity and
current `rauthy_admin` membership inside the same Rhiza credential-version CAS.
An administrator deleting their own key must use the normal one-use
`mfa_mod_token` self flow. This safety narrowing prevents stale-role and
self-bypass races while preserving the upstream ability to reset another
user's final UV credential, which may lock that passkey-only user out until an
administrator completes a recovery path. Deterministic tests cover role
revocation between HTTP authorization and deletion without sleeps; the
three-pod Chrome E2E is wired and pending Docker recovery.

## Email templates

| Need | Selected implementation | Why |
|---|---|---|
| Strict optional reset copy | `github.com/pelletier/go-toml/v2`, stdlib `text/template` and `html/template`, existing `go-mail` | TOML decoding does not own the supported language/event set, 64 KiB bound, duplicate/unknown-field rejection, CR/LF subject check, fixed layouts, HTML escaping, or event delivery. GoAuthy keeps those direct and uses `go-mail` for multipart transport. |

`GOAUTHY_EMAIL_TEMPLATES_FILE` is optional; `GOAUTHY_EMAIL_TEMPLATE_LANG` must
select an exact supported language (default `en`). `password_reset`,
`password_new` and `registered_already` layouts are parsed and rendered
deterministically. Unsupported language/type, duplicate entries, unknown keys
and unsafe subjects fail startup. Reset and open-registration SMTP delivery
have kind evidence; full account-registration parity remains pending. Fresh
`E2E_PROFILE=password-reset E2E_PORT=28210 KIND_CLUSTER=goauthy-template-28210 make e2e-kind`
passed the root and browser suites for the reset-template slice only; full
template parity remains `[ ]`.

## Open registration

### Preferred-username mutation policy (2026-09-06)

The pinned [update endpoint](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L2322)
defines self, full-admin/key force, and delegated initialization-only authority.
Its [DTO](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/users.rs#L134)
uses nullable fields; the [entity write](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users_values.rs#L205)
updates only the username. Source was inspected at the pinned SHA, not moving HEAD.

| Need | Reused implementation | Why direct implementation remains necessary |
|---|---|---|
| Wire validation | stdlib `net/http`, `encoding/json`, `mime`, `unicode/utf8`, existing duplicate-field scanner and 8 KiB bound | No new parser/framework is needed; two nullable product fields are sufficient. |
| Current authority | existing browser cookie/CSRF/session SQL guard, API-key `Users:update` guard and delegated group matcher | A general RBAC library does not encode Rauthy's distinction between self, force, and initialization-only delegated access. |
| Immutable/required/blacklist | existing `identity.PreferredUsernamePolicy`, one private mutable boolean and copy-returning configuration method | Regex libraries cannot decide endpoint-specific exemptions. Defaults and configured policy are shared, not reimplemented. |
| Atomic mutation | existing Rhiza `storage.Execute`, transactional SELECT decision and conditional profile upsert | Authority, immutable state and uniqueness must be decided against the committed database; an HTTP-only check or node-local lock is insufficient. No cache, new schema, queue or extra service is necessary. |

The receipt supplies the transaction's response status. An unsuccessful database
write cannot return 200; profile columns other than preferred username are preserved.
The nullable legacy-profile boundary and exact HTTP responses are documented in
[user management](user-management.md); test evidence is in [status](status.md).

### Preferred-username admission policy (2026-09-06)

The pinned [administrator and public DTOs](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/users.rs#L54)
both use the configured regex. The [public validator](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/user_values_validator.rs#L18)
adds presence/blacklist checks before PoW; administrator POST deliberately skips
that validator. Defaults come from [runtime configuration](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/rauthy_config.rs#L1056),
with the [Linux regex fallback](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/rauthy_config.rs#L3517).

| Need | Reused implementation | Why direct policy is necessary |
|---|---|---|
| Runtime regex | Go standard [`regexp`](https://pkg.go.dev/regexp), compiled once; `unicode/utf8` and existing storage bounds | The library already provides linear-input-time matching. No custom matcher or dependency is justified. Go RE2 syntax is explicit; arbitrary Rust regex syntax equivalence is not claimed. |
| Presence, admin exemption, blacklist | Small immutable `identity.PreferredUsernamePolicy`; `strings.ToLower` and a bounded copied string slice | A generic regex/validation package cannot decide which endpoint exempts required/blacklist checks, when to consume PoW, or preserve the upstream candidate-only case conversion. These are product rules, not missing regex functionality. |
| Wire/storage integration | Existing strict JSON decoder, pointer for supplied/absent values, recovery service and Rhiza transaction guards | Validate before PoW and again at the store boundary using the same policy. Existing username uniqueness/authority transactions remain authoritative; no new schema, cache, service or database is needed. |

The constructor rejects malformed configuration without echoing it. The public
boundary returns 406 for unavailable reserved names without reflecting the name.
Runtime/static OpenAPI distinctions and remaining full-policy gaps are tracked
in [user management](user-management.md); [status](status.md) records actual tests.

| Need | Selected implementation | Why |
|---|---|---|
| Request parsing and profile validation | stdlib `net/http`, `encoding/json`, `net/mail`, `regexp`, `net/url` | The request is a small JSON boundary; a new framework would not improve strict unknown-field, size, canonical-email, or exact-URI validation. |
| Abuse proof and delivery | existing Rauthy/spow-v1 adapter, `crypto/sha256`/`crypto/rand`/`encoding/base64`, existing `go-mail` SMTP/template path | Reuse the already security-reviewed single-use PoW and TLS/MIME transport rather than adding a Captcha SDK. New and already-registered requests both synchronously cross the sender boundary, so SMTP latency/error handling does not become an account-existence oracle. Captcha remains a pending product integration. |
| Pending identity and first password | Rhiza v0.10.0 schema v23/CAS plus existing Argon2/password-reset primitives | No public Go package owns a multi-row, cross-pod pending-user lifecycle: duplicate convergence without bearer leakage, token-purpose separation, current-PHC/generation checks, email verification, and expiry cleanup must commit atomically with Rhiza. |
| Domain and redirect admission | narrow direct policy over stdlib parsing | Rauthy's source uses suffix-style domain/redirect comparisons. GoAuthy intentionally requires canonical exact email-domain membership and exact configured URI equality, preventing `evil-example.test` and URI-prefix/open-redirect bypasses. No package can apply the deployment's allowlist/blacklist and client registry policy. |

The fixed upstream contract is Rauthy's [`POST /auth/v1/users/register`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs#L360-L525): it is opt-in, asks for a solved PoW, returns the same empty success shape for a newly created or existing email, and starts a password-new magic-link lifecycle. GoAuthy schema v23 records a canonical email/profile and a `password_new` token purpose distinct from `password_reset`; the first successful password writes the verifier and marks the email verified. The token table stores only token digests and an optional exact redirect URI. `GOAUTHY_OPEN_USER_REG=true` requires recovery and wires `POST`/`OPTIONS /auth/v1/users/register`; a bounded 64-row hourly cleanup removes expired passwordless identities without relying on request traffic.

#### Ordinary required-profile policy (2026-09-06)

The pinned [runtime defaults](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/rauthy_config.rs#L1056)
require given name and leave other ordinary fields optional. The example TOML
is not the runtime default. The [validator](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/user_values_validator.rs#L18)
checks required presence, not a ban on hidden fields, and checks nested values
only inside a supplied `user_values` object. The [admin POST exemption](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L162)
is deliberate. GoAuthy preserves these distinctions; it does not copy upstream
debug logging of submitted profile values.

Package decision: reuse existing strict `encoding/json` boundaries, nullable Go
fields and `errors`; move the existing seven-field PUT DTO to identity and
alias it in RBAC. Existing `kin-openapi` remains the static API-description
dependency, not a second runtime validator requiring marshal/schema round trips.
Neither standard JSON decoding nor a generic required tag determines Rauthy's
admin-create exemption, hidden admission or absent-parent-object semantics.
Those are the narrow, unavoidable product-policy branches in
`identity.UserValuesPolicy.ValidateFields`; no new validator/dependency/schema,
policy service, cache or database is introduced. Existing format/length/email
validators remain authoritative. This is not a replacement for syntax validation.

The nine GoAuthy env settings map the upstream ordinary `[user_values]` TOML
fields to the existing environment deployment convention. Policy is immutable
after startup and identical across HA nodes; there is no dynamic-policy CAS
claim. Preferred-username policy, the config discovery endpoint, login-time
revalidation and UI remain unfinished. Full details and the nested-null
compatibility limitation are in [user management](user-management.md).

The deployed policy matrix reuses the existing `net/http`/`encoding/json`
browser E2E helpers, real Rhiza and SMTP sink, standalone restart, and the
existing Kind Pod-replacement harness. No additional test framework or mock
database is needed: compare HTTP responses, all nine persisted values, mailbox
counts and reuse of an unconsumed PoW. The three homogeneous configurations
are not exhaustive mixed-policy or rolling-policy coverage; verified runs and
remaining gates are recorded in [status](status.md).

Focused tests inject clock/random/sender seams and assert token/state/profile outcomes; fixed windows are advanced by supplied timestamps, never sleeps. The hourly tick receives its time explicitly in tests; it is a bounded maintenance cadence, not a time-based test oracle. A test timeout is only an execution ceiling. `[x]` On 2026-09-01, `make e2e-kind-open-registration KIND_CLUSTER=goauthy-openreg-v081-e2e` passed fresh smoke `./test/e2e` (`15.421s`), `TestOpenRegistrationAcrossPods` (`3.232s`), and SMTP/pod-replacement chaos `TestOpenRegistrationPendingPasswordSurvivesPodReplacement` (`5.956s`). Captcha, passkey-first registration, and broad Rauthy account/profile parity remain pending.

## Password hashing, policy, and calibration

| Need | Selected implementation | Why |
|---|---|---|
| Argon2id KDF | `golang.org/x/crypto/argon2` | The maintained Go package supplies the Argon2id KDF and is the only cryptographic primitive used for password derivation. GoAuthy does not reimplement Argon2. |
| PHC records, policy, safe upgrade, and Rhiza persistence | Small direct wrapper over `x/crypto/argon2`, `crypto/rand`, `crypto/subtle`, and Rhiza conditional SQL | `x/crypto/argon2` intentionally does not parse or encode PHC records, choose deployment bounds, bound concurrent work, perform indistinguishable dummy verification, decide non-downgrading upgrades, or persist a compare-and-swap. No maintained Go package found owns that combined security boundary and Rhiza contract. GoAuthy therefore directly implements only strict canonical Argon2id-v19 PHC/policy handling and successful-login-only Pareto-safe CAS rehash. |
| Composition policy, history, self-service change and CSRF | stdlib `unicode`, `unicode/utf8`, and `crypto/hmac`, with the existing Argon2/Rhiza components | No new dependency owns the application semantics: bounded UTF-8/rune and character-class rules, no-normalization behavior, prior-PHC verification, history prune, and the one Rhiza conditional update must share a security transaction. The standard library classifies/validates input and derives a session-bound CSRF token; direct code owns only the policy, history and CAS boundary. Rune counting deliberately hardens the Rust/Rauthy byte-length behavior without changing password bytes. |
| Reset-token/revocation and HTTP recovery | stdlib `crypto/rand`, `crypto/hmac`, `crypto/sha256`, `encoding/base64`, `net/http` and Rhiza conditional SQL | Existing packages do not own domain-separated keyed token digests, subject/password-generation binding, single-use consumption, browser binding/CSRF, history update and coordinated browser/OAuth/device/back-channel invalidation in one Rhiza request. Schema v23 purpose-separates password reset from first-password activation so a token cannot cross either ceremony. Direct code is required for that security transaction; standard crypto is used rather than reimplementing entropy or a MAC. |
| Password-reset PoW (Rauthy/spow v1 wire format) | stdlib `crypto/sha256`, `crypto/rand`, `encoding/base64` and Rhiza v0.10.0 conditional SQL | `spow` is Rust; no published Go package owns exact v1 textual compatibility together with strict canonical parsing, secret-derived challenge creation, digest-only persistence, expiry, direct-peer distributed admission, bounded global live state and cross-pod exactly-once consumption. Schema v30 adds a five-per-minute direct-peer table; the same atomic mutation removes stale rows, bounds TTL to five minutes, and caps that table plus all unexpired challenge rows (including consumed) at 256. The adapter is deliberately small and security-reviewed rather than introducing a second protocol implementation. |
| SMTP reset delivery | `github.com/wneessen/go-mail v0.7.0` plus stdlib `crypto/tls`/`net/mail` | `net/smtp` is frozen and deliberately low-level: it does not supply the maintained MIME/message and TLS-aware client boundary required here. `go-mail` owns SMTP/MIME transport mechanics; GoAuthy still directly validates canonical addresses and reset URLs, requires TLS 1.2+ by default, bounds delivery by context, and keeps bearer URLs out of logs. |
| Offline parameter recommendation | `x/crypto/argon2` plus stdlib `flag`, `encoding/json`, `slices`, and `time` | No dependency can safely choose a deployment's capacity or mutate its configuration. `goauthy-password-calibrate` stays recommendation-only: it emits bounded JSON and never writes a file, environment value, or credential. Tests inject measurements; wall-clock timing is operational input only. |

GoAuthy writes the OWASP Argon2id baseline `m=19456,t=2,p=1` with two
per-instance concurrent work slots by default. Accepted write-policy bounds are
`m=19456..131072` KiB, `t=2..5`, `p=1..8`, and `max=1..8`. Rauthy v0.36.2's
fixed [hashing configuration](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/config.toml)
instead defaults to `m=131072,t=4,p=8,max_hash_threads=2`; GoAuthy documents
that difference rather than silently treating its portable default as parity.

Rauthy's default lifetime is 180 days. GoAuthy's `DefaultRules` now carries the
same `ValidDays=180` and rejects authentication strictly after (not at) the
changed-at plus that number of calendar days. Startup forces zero only while
recovery is disabled; opt-in recovery requires its 32-byte reset-key file and
SMTP configuration before a nonzero `GOAUTHY_PASSWORD_VALID_DAYS` is accepted.

Schema v14 adds non-negative `password_changed_at_unix_ms`, monotonic
`password_generation`, and strict bounded history. Schema v15 adds
`identity_password_reset_tokens`: only a 43-character keyed digest is stored,
with subject/generation, issued/expiry times, optional binding pair, optional
consume-attempt pair, checks, and an expiry index. Schema v16 adds the strict,
canonical `identity_recovery_emails` subject mapping. Fresh install, legacy v6
upgrade, constraints and idempotence are deterministic storage tests.

Schema v17 adds `identity_password_reset_pow_challenges`: a 43-character
SHA-256 challenge digest primary key, second-precision non-negative expiry,
optional 22-character consumption-attempt digest/timestamp pair, and expiry
index. `POST /auth/v1/pow` issues an unsigned spow-v1 challenge;
`POST /auth/v1/users/request_reset` consumes a solved one. Runtime defaults
are `GOAUTHY_POW_DIFFICULTY=19` (canonical decimal `10..98`) and
`GOAUTHY_POW_EXPIRY=30s` (positive Go duration). The password-reset kind
overlay chooses difficulty `10` only to keep test work bounded. Clock/random
injection makes format, expiry, replay and race tests deterministic; hash-search
elapsed time is never a pass/fail oracle.

The fresh `2026-08-31` `make e2e-kind E2E_PROFILE=password-policy
E2E_PORT=28280` run deployed the schema-v15 image to three pods, passed
migration/readiness and baseline `test/e2e` in `17.583s`, then rolled the
stronger hash policy and completed cross-pod browser login in `1.596s` before
cleanup. This is migration/readiness evidence only, not public reset E2E.

Fresh schema-v16 recovery evidence is now separate: `E2E_PROFILE=password-reset
E2E_PORT=28080 make e2e-kind` passed three-pod readiness, public request and
SMTP-link delivery, cross-pod reset GET/PUT, replay rejection, prior browser
session revocation, and old-password denial/new-password login. The first
default-port (`18080`) attempt stopped before product tests because LeafWiki
held that port; the explicit port-range rerun passed, so this is a deterministic
harness-isolation requirement rather than a product failure.

The reset slice uses injected clock/random/sender functions in tests and proves
strict expiry, stale generation, replay, complete random reads, last browser
binding wins, and exactly one concurrent consumer. Its HTTP tests judge
response/cookie/message state rather than elapsed time: request enumeration
shape and limiter, sender failure non-disclosure, strict JSON, Fetch-Metadata,
cookie+CSRF and replay. The SMTP local fixture proves composition and
TLS-required failure without an external mail service. One guarded Rhiza request
consumes the token, writes password/history, revokes subject browser/OAuth/device
artifacts and creates back-channel logout deliveries.

The earlier schema-v16 evidence predates the proof prerequisite. The PoW engine,
public route, single-use Rhiza mutation and deterministic tests are `[x]`; a
fresh `E2E_PROFILE=password-reset E2E_PORT=28080 make e2e-kind` built schema
v17, readied three pods, passed `test/e2e` in `15.938s` and
`test/e2e/browser` in `1.320s`, including invalid-proof denial, successful
request and cross-pod replay rejection.
Email OTP is unreleased and is not Rauthy v0.36.2 parity.

Public recovery remains `[ ]` overall despite this implemented slice: there is
retry/outbox/audit/metrics, template management/i18n, recovery-address
lifecycle, or full
Rauthy MFA/redirect/passkey parity.
Rauthy preserves self-change sessions while reset invalidates sessions; GoAuthy
implements that reset effect but does not claim complete recovery parity.

## Outbound SCIM package re-evaluation (2026-09-04)

No maintained Go package owns Rauthy v0.36.2's complete outbound SCIM
contract: encrypted per-client Bearer configuration, user and group
reconciliation, delete-versus-unlink policy, group membership patching,
prefix policy, and durable retry/full-sync state.

The closest active candidate, [`github.com/ncarlier/scim-ctl`](https://github.com/ncarlier/scim-ctl),
is an MIT-licensed CLI with generic CRUD/PATCH support. It is not safe to embed
here: its authentication model is OIDC-oriented rather than a stored static
Bearer and its verbose output is unsuitable for a secret-bearing worker.
[`grokify/go-scim-client`](https://github.com/grokify/go-scim-client) is a
generated RingCentral Users-only client without Groups;
[`elimity-com/scim`](https://github.com/elimity-com/scim) and
[`imulab/go-scim`](https://github.com/imulab/go-scim) are server/model
libraries, not outbound reconciliation clients. None supplies GoAuthy's
bounded response handling, encrypted configuration or
Rhiza-backed lease/outbox semantics.

The unavoidable direct slice is therefore limited to stdlib transport and
Rauthy-specific state: `net/http`, `net/url`, `crypto/tls`, `crypto/x509`, `encoding/json`,
bounded `io` reads, an HTTPS/no-proxy/no-redirect default, envelope-
encrypted Bearer storage, optional per-provider `ca_file` roots with hostname
verification/TLS 1.2+ and `InsecureSkipVerify=false`, and a deterministic
`Worker.Step(ctx, now)` over a
Rhiza lease/outbox. This is not a plan to reimplement generic SCIM models; it
is the security and reconciliation boundary none of the evaluated packages
provides. `internal/scim` now has source-tested user and group cores plus
schema-v37 durable user outbox/serialization support, schema-v39 tombstone
projection, schema-v41 immutable deletion-time provider ID/policy snapshot, and
schema-v42 tombstone generation/enqueue fencing support:
lookup by immutable `externalId`, safe `userName` fallback without
seizing a conflicting identity, mapped externalId exact checks,
schema/status/Location-validated create/update/delete-or-unlink, deterministic
coalescing/lease/retry state, provider fan-out, and terminal mapping/outbox CAS.
`identity.DeleteUser` atomically snapshots a tombstone, cleans owned identity
rows, invalidates stale user-sync outbox rows, and durably enqueues SCIM
backchannel work. `sync_delete_users` defaults to RFC 7644 unlink and opts into
hard DELETE when true; explicit user deletion always forces hard `DELETE`
independently. The users-only full
local scan/upsert runtime and worker are production-wired behind
`GOAUTHY_SCIM_PROVIDERS_FILE`. No new package or queue is needed: the existing
Rhiza outbox carries provider-scoped delete work. Private endpoints and an
injected HTTP client are trusted operator configuration because on-premise
enterprise SCIM is a valid deployment. Production HTTP/admin/self user-delete
routes are source-wired. Encrypted per-client configuration remains absent.
Bounded tombstone cleanup removes oldest rows only when every snapshotted
provider's exact delete job has succeeded; hard local deletion requires
`DeleteRemote`, pending/processing/dead/missing jobs retain them, and terminal
delete outbox rows remain while tombstones exist. Legacy v39/v40 tombstones have
incomplete or malformed hard-delete snapshots fail closed and are never auto-cleaned. A removed provider blocks
cleanup until the same stable ID returns, while a new provider receives no
historical deletes. Schema v42's opaque 128-bit/22-character base64url
generation and exact-generation enqueue fence prevent stale-pod deletes of
recreated subjects. The generation is persisted inside delete-job JSON, and both
claim and cleanup require an exact current generation; legacy/raw/no-generation
rows are unclaimable. Complete empty-generation tombstones are retained and
skipped without blocking later work. Dead-letter retry is operator-controlled
(provider re-add alone does not revive dead jobs). SCIM broader Kind/chaos live
evidence remains unverified. The standalone live SCIM E2E
passed in repeated runs (`14.9s` and final post-hardening `18.6s`), covering
SMTP registration, restart-immediate sync, exact `externalId`, public admin
delete, restart-exact remote `DELETE`, and login rejection. The exact-three Kind harness passes
source/static checks but its broader user/full-feature run stops at Docker
inotify `128<256`, so no broader HA runtime claim is made. The final narrow
exact-three gate `E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final
scripts/e2e-scim-delete-chaos-kind.sh` passes three Ready pods, creation, two
full restarts, browser-admin/API-key deletion on different pods, cross-pod
session/token invalidation, final-admin protection, pod-0 replacement, tombstone
plus two remote `DELETE` convergence, and cleanup. Standalone exact-one
group E2E on port `18981` passes user-first/retry/full-member and delete
convergence; exact-three Kind `KIND_CLUSTER=goauthy-scim-e2e-20260905d
E2E_PORT=19380` passes three Ready pods, full group members, pod-0 UID
replacement after delete, empty/deleted convergence, and cleanup. Transport/
DNS/TLS/drop failures and `429`/`5xx` retry, while
malformed/permanent `4xx` responses dead-letter. The full SCIM feature remains
unchecked. Delivery is designed as at-least-once across crashes, not exactly-once;
the external SCIM service must make writes idempotent.

No evaluated package owns the Rhiza-atomic local deletion, deletion-time
provider-obligation snapshot, tombstone-generation fence, and outbox lifecycle
together, so this boundary remains direct implementation.

### User deletion boundary

No package was selected for permanent user deletion. The production admin
`DELETE /auth/v1/users/{subject}` route reuses the existing browser
same-origin/CSRF boundary or a scoped `Users:delete` API key, requires an empty
body, and returns `204` on success (`404` missing/inactive, `409` final active
admin). Self deletion is `GET`/`DELETE /auth/v1/users/{subject}/self/delete`,
strict default-off via `GOAUTHY_ENABLE_SELF_DELETE=false`; it is an authenticated
same-subject browser flow (`202` capability, `204` delete with cookie clear,
CSRF required for DELETE, `406` when disabled/admin/final-admin). The
bootstrap `GOAUTHY_BOOTSTRAP_FORCE_MFA` policy gates browser-admin deletion only;
API keys are unaffected. Fixed-tag Rauthy source research found no final-admin
guard in its admin delete path, so GoAuthy intentionally hardens this boundary
with an atomic guard. Deterministic handler/store tests cover status/auth/CSRF
boundaries, no-fallback, forced MFA, API keys, rollback, concurrent final-admin
protection, cleanup enqueue, and explicit hard-delete projection.
The standalone `scripts/e2e-user-deletion-standalone.sh` live PASS covers
browser self/admin deletion, `Users:delete` API-key boundaries, final-admin
`409`, admin survival, SCIM create plus durable tombstone `DELETE` across cold
restarts, deleted-login denial, and remote cleanup. The final narrow exact-three
gate `E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final
scripts/e2e-scim-delete-chaos-kind.sh` passes three Ready pods, creation, two
full restarts, browser-admin/API-key deletion on different pods, cross-pod
session/token invalidation, final-admin protection, pod-0 replacement, tombstone
plus two remote `DELETE` convergence, and cleanup. Broader user-management/full-
SCIM parity and unrelated chaos remain pending.

No package was selected for FedCM. Its Rauthy-compatible HTTP contract,
client-ID/origin binding, Fetch Metadata and CORS rules, separate secure
cookie/logout, and one-time CAS are small direct policy code with deterministic
tests. Production is source-wired behind the strict default-off
`GOAUTHY_FEDCM_CONFIG_FILE` HTTPS configuration: manifest/config,
accounts/client-metadata/assertion/status routes land only at `/auth/login` or
`/auth/v1/account` password flows, with active identity+peer binding; direct
passkey/passwordless login is intentionally absent and bootstrap forced-MFA
coexistence is rejected at startup. HTTPS `/readyz` probes and their manifest
static test are covered; real browser, Kind and chaos
interoperability remain pending. The exact-three
`scripts/e2e-issuer-path-kind.sh` gate
passes RFC 8414 and prefixed discovery/OAuth/DPoP flows, negative path checks,
pod-0 replacement, and cleanup; broader issuer-path/browser parity remains
pending. RFC 8252 likewise reuses stdlib URL parsing plus Fosite matching. The
fresh exact-three HA gate `scripts/e2e-rfc8252-loopback-kind.sh` passes literal IPv4/IPv6 port variation,
exact-port localhost, hostile host/userinfo/path/query negatives, cross-pod
authorization/code exchange, and pod-0 replacement. Custom schemes,
confidential/static clients and unsafe URI components remain fail-closed. The
run `KIND_CLUSTER=goauthy-rfc8252-loopback-ha-e2e-20260905a E2E_PORT=19860
./scripts/e2e-rfc8252-loopback-kind.sh` completed successfully and cleaned up
its cluster.

## Root-approved core slices

Status note (2026-09-04): Rhiza is pinned to official `v0.10.0`, commit
`2e645f913ba58574c001900eecab43b06aa4a590`; v0.9.0 is retracted because its proxy-cached commit was wrong. Rhiza v0.10.0 adds bounded graph reachability APIs; GoAuthy does not need or use them, and successful local tests confirm compatibility of the existing `Open`/`Ready`/`Query`/`Execute` APIs.
Core symbols,
mounted routes, and focused deterministic tests below are source evidence.
Geoblock, login-policy, IP-blacklist, command admission/config/
browser-authority, and token-metrics focused tests passed with `-p 1 -count=3`;
the Fosite race build was safely aborted under low disk, so race/vet and the
full suite remain unverified. Kubernetes
results are prior evidence only and current Kubernetes status is unverified.
The Fosite request-state race root fix, authorization no-fallback,
XFF/Forwarded hardening, configured header-name validation via
`golang.org/x/net/http/httpguts`, corrupt-row and dual-forwarded-header
fail-closed handling, deterministic goroutine cleanup, and serialized E2E
ports are implemented. Upstream-provider broader E2E/parity, automatic blacklist, outbound
SCIM, and full UI/OpenAPI/backup/event-stream/PAM remain
incomplete.

The metrics boundary has bounded live evidence. `scripts/e2e-metrics-standalone.sh`
passed with app port `19880` and metrics port `19881`, including
auth/isolation, metrics-listener bind collision, and restart-preserved JWKS.
The final exact-three HA gate
`KIND_CLUSTER=goauthy-metrics-e2e-20260905c E2E_PORT=20080
./scripts/e2e-metrics-kind.sh` passed on app/metrics ports `20080`-`20085`,
checking all-pod readiness/auth/isolation, pod-1 replacement, and byte-identical
post-replacement JWKS/metrics rechecks. This does not establish complete
observability parity; traces/exporters and broader metrics coverage remain
pending.

| Core | Reused packages/stdlib | Direct code that remains necessary | Status/evidence |
|---|---|---|---|
| Audit event ordering and bounded pagination | Rhiza v0.10.0 replicated SQL; SQLite window functions/indexes/triggers; stdlib `crypto/hmac`/`sha256`/`encoding/base64` | Schema-v49 assigns a replicated sequence inside each append transaction while `occurred_at` remains display data; schema-v51 adds non-destructive duplicate/type/actor guards and schema-v52 extends constraints/triggers for guarded master-key retirement events. Deterministic migration/API-key cursor validation remain application policy. | Append-only API-key events and successful guarded retirement transitions paginate by descending sequence across backward clocks and interleaved writes; focused migration, cross-store, malformed-cursor, exactly-once and DB-boundary tests pass. |
| Rhiza schema v33--v42 retention, provider, SCIM and anonymous-DCR state | official Rhiza v0.10.0 (commit `2e645f913ba58574c001900eecab43b06aa4a590`) public transaction API; SQLite DDL/index/trigger | v33 rate-limit retention, v34 DCR idempotency, v35--v39 existing provider/SCIM state, v40 anonymous-DCR cleanup indexes, v41 immutable provider snapshots, and v42 tombstone generations/enqueue fencing are product policy and transaction contracts, not generic package features. | focused migration tests through v42 passed; SCIM group exact-one/exact-three live gates pass, and final narrow exact-three user-delete `E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final scripts/e2e-scim-delete-chaos-kind.sh` passes creation, restarts, cross-pod invalidation, replacement, two remote deletes and cleanup; broader SCIM Kind/chaos evidence remains unverified |
| Back-channel logout delivery | `go-jose/v4`, stdlib `net/http`/`crypto/tls`/`crypto/x509`, Rhiza outbox and lease/CAS | No package owns the configured bootstrap RP delivery contract. Direct code enforces custom CA roots, TLS 1.2+, hostname/SNI verification, no proxy/no redirect, and atomically retains the last known-good CA bundle after a failed reload. | Unit/worker tests cover CA rotation and last-known-good retention; `make e2e-kind-backchannel-https` source/static checks PASS for the dedicated TLS fixture and CA rotation. Live HA execution fails preflight at Docker `fs.inotify.max_user_instances=128<256`; pending-pod/quorum, CNI, log-redaction and multi-client evidence remain pending. |
| Master-key envelope rewrap and OAuth persisted-form redaction | `crypto/aes`, `cipher.AEAD`, `crypto/rand`, `encoding/base64`; direct Rhiza cursor/CAS workers | No package owns durable envelope migration, all-member attestation, or an opaque-envelope key-retirement API; GoAuthy directly owns the commit-time writer fence and retirement state machine. The worker independently processes bounded batches of signing-key, live DCR-idempotency, unexpired upstream-transaction, and retained passkey credential/ceremony envelopes, authenticating old values before active-key rewrap and fencing each batch all-or-zero by exact old rows. Passkey legacy DB ciphertext uses strict dual-read and forward migration; its CookieKey remains separate for browser cookies. OAuth persistence copies protocol metadata while dropping credential, bearer, and one-use fields. | Source-wired minute worker with strict JSON, tamper, wrong-context, bounded-cursor, CAS-convergence and OAuth no-mutation tests (`internal/{oidc,dcr,upstreamprovider,passkey,oauth}/*_test.go`). Guarded prepare/fence/ready/abort transitions append exactly-once audit events in the same Rhiza transaction; deterministic standalone/exact-three state-machine, migration, replay, revocation-interposition and chain-integrity tests pass. Live exact-three `KIND_CLUSTER=goauthy-master-key-e2e-20260905c E2E_PORT=19700` evidence passed three zero-reference checks, restart boot-ID/sequence 2, Ready, key retention, and cleanup. Full critical DB-value encryption remains unchecked: automatic key removal, CookieKey rotation, and remaining nonrotating values remain pending. |
| DCR per-registration DELETE and anonymous admission | Fosite resolves clients but provides neither RFC 7592 management/persistence nor anonymous admission. The direct boundary uses stdlib `crypto`, `net/http`, `net`, and `net/netip` plus Rhiza conditional mutations for canonical-IP, exact fixed-window HA state and configured startup cleanup. Device-only and hybrid RFC 8628 DCR admission has deterministic handler/store coverage. `x/time/rate` is local-only and Redis packages are incompatible with Rhiza HA/exact fixed-window semantics. Standalone E2E passed create, byte-identical replay, `429`, different-IP success, management, device-only registration through `/oidc/device`, and restart cleanup; the readiness-gated three-pod rollout source remains unexecuted. |
| Manual and automatic IP blacklist | Rhiza v0.10.0; stdlib `net/http`, `net/netip`, `time` | exact-IP/CIDR matching, expiry semantics, canonical rejection shape, resolver/storage fail-closed behavior and CRUD contract; failed-login counter, bounded expired-row reclamation, and exact-host auto-upsert share one Rhiza transaction, preserve permanent/manual entries, and honor the 10k cap. Automatic expiry transitions occur only at 7/10/15/20 and 25+ failures; persisted clock regressions or jumps over 48 hours fail closed | Opt-in `GOAUTHY_IP_BLACKLIST_ENABLED` middleware and `/auth/v1/blacklist` admin routes are source-wired in `cmd/goauthy/main.go`; automatic thresholds are source-wired through `loginpolicy.NewStoreWithBlacklist` only when enabled. Focused normal and race package tests pass; current Kubernetes verification remains absent |
| Geoblock decision core | stdlib `net/http`/`net/netip`, `golang.org/x/net/http/httpguts`, plus `maxminddb-golang` | trusted immediate-proxy header admission, configured header-name syntax, strict ASCII ISO alpha-2 normalization for header/database values, allow/deny/unknown policy and fail-closed middleware are application policy; header sources require trusted proxies and local MaxMind is the alternative | Opt-in `GOAUTHY_GEOBLOCK_*` configuration and middleware are source-wired in `cmd/goauthy/main.go`; focused package tests passed `-p 1 -count=3`. Standalone `scripts/e2e-geoblock-standalone.sh` and exact-three `scripts/e2e-geoblock-ha-kind.sh` live gates pass health, all-pod admission, pod-1 replacement, malformed/ambiguous forwarding, and trust-boundary rollout/spoof denial. MaxMind success fixture remains unit-only; no downloader/update scheduler |
| Upstream provider transaction/ID-token/HTTP adapter | `golang.org/x/oauth2`, `go-jose/v4`; stdlib `crypto/rand`, SHA-256/constant-time compare, JSON, `net/http`, `net/url`; direct `cmd/goauthy` and `internal/{login,account,identity}` glue | `golang.org/x/oauth2` covers the real authorization-code exchange and `go-jose/v4` the JWKS-backed ID-token verification, but neither decides issuer/JWKS trust, stored transaction binding, safe public errors, account-link conflict policy, or local session completion. That application policy remains direct code. | schema v35 persists local session/interaction bindings in columns plus the encrypted envelope; schema v36 records external authentication truthfully. `cmd/goauthy` source-wires local login completion, existing-link lookup, and explicit authenticated link/unlink. Root integration and focused verifier race coverage passed. The TLS fake issuer, black-box flow, Kind harness and pod-replacement scenario are source-complete and statically checked; live Kind/chaos and broader provider-parity evidence remain pending. |

The direct link policy follows the fixed Rauthy v0.36.2 surface: authenticated
explicit link/unlink routes are registered in
[`server.rs`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/bin/src/server.rs#L403-L430),
link start requires the current authenticated user in
[`auth_providers.rs`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/auth_providers.rs#L470-L519),
and callback completion resolves conflict/auto-link policy in
[`login_finish.rs`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/auth_providers/login_finish.rs#L18-L125).
GoAuthy deliberately implements only explicit linking and existing-link login;
it does not email-auto-link identities. No evaluated transport, JWT, or storage
package owns that account-takeover boundary, so the minimal policy remains
direct code with one-use state, authenticated-session binding, and atomic
provider/subject uniqueness.

GitHub OAuth Apps are a separate non-OIDC case: GitHub's documented
[authorization-code flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
returns an access token rather than an OIDC `id_token`, and Rauthy v0.36.2
therefore calls GitHub's `/user` API after exchange
([Rauthy GitHub provider](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/auth_providers/github.md)).
`golang.org/x/oauth2` still owns the code exchange, but no selected package can
decide that GitHub's immutable numeric user `id`—never mutable login/email—is
the external subject or enforce GoAuthy's bounded, no-proxy/no-redirect API
boundary. The implementation consequently keeps this small resolver in stdlib
HTTP/JSON code and retains explicit linking; email auto-link/onboarding is not
part of this slice.

No selected package owns these cross-layer security contracts. Reusing a
transport, JWT verifier or Rhiza transaction primitive does not decide which
state is trusted, when it is consumed, how concurrent changes fail closed, or
what public error shape is safe; those narrow policy decisions therefore stay
direct and auditable. Exact startup evidence is `DB.Ready` plus a linearizable
schema query; any multi-pod gate must additionally wait for Kubernetes
readiness/UID and use explicit read-after-write barriers, never elapsed time.

## Audited remaining capabilities

These are intentionally separate unchecked items in the feature ledger. No
selected public package owns the product contract, so direct code should be
added only with the named deterministic and Kubernetes evidence.

| Capability | Reuse first | Why direct work is still required |
|---|---|---|
| True passwordless account lifecycle and post-registration session MFA upgrade | `go-webauthn/webauthn`, existing browser sessions, Rhiza CAS | Ceremony verification is packaged; account enrollment/recovery and lifecycle authorization remain direct policy. Registration finish now atomically upgrades the exact active `pwd`/`webauthn` session to `mfa` with configured idle-timeout and active-identity guards; deterministic unit tests pass, while cross-pod E2E remains pending. |
| Forward Auth trusted headers | stdlib `net/http`/`net/netip` and existing peer-IP middleware | No package can safely choose the immediate trusted peer, canonical forwarded-header grammar, or identity-header disclosure contract; the standalone and final exact-three gates provide deterministic/live coverage for that direct policy. |
| CIMD `ignore_unknown_auth_flows` | existing CIMD parser and Fosite flow validation | The parser policy core is implemented and deterministically tested; production wiring accepts the strict default or opt-in `GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS=true`. Lenient-policy Kind E2E remains pending. |
| Resource Indicator `default_aud` and ephemeral danger option | Fosite audience storage and stdlib strict config parsing | Bootstrap/CIMD resource policy is implemented with exact HTTPS/default-deny checks and an explicit default-off danger mode; dynamic default audiences and live Kind evidence remain pending. |
| TOML secrets, encrypted generated-secret container, API-key JSON bootstrap | `pelletier/go-toml/v2`, stdlib JSON/AEAD, existing Rhiza keyring | File decoding is packaged; precedence, generated-secret persistence, tamper behavior and one-time bootstrap semantics are deployment policy. |
| API keys managing API keys and JSON import/export | existing API-key store, stdlib JSON, Rhiza CAS | The current API-key boundary deliberately cannot self-manage or import recoverable secrets; expanding it needs separate authorization and secret-lifecycle review. |
| Independent favicon behavior | stdlib `html/template`, `image`, `mime` | Branding asset isolation, content validation, cache keys and CSP are client-facing product policy, not supplied by a selected package. |
| DCR `client_uri` and RFC 7592 replacement semantics | stdlib `net/url`, `encoding/json`, `crypto/subtle`; existing Fosite client and Rhiza CAS store | Fosite does not provide an RFC 7591/7592 registration server or decide strict metadata replacement. GoAuthy directly validates/persists the URL, binds it into idempotency, and requires the PUT body `client_id` to match the path. |
| DCR `contacts` metadata and RFC 7592 replacement semantics | stdlib `encoding/json`, `regexp`, `sort`; existing DCR validation and Rhiza CAS store | Contacts are optional Rauthy-compatible ASCII contact strings (max 32 entries, 1--48 bytes each), canonicalized and persisted as nullable JSON; POST null is rejected, while PUT omission/null/empty clears the field. Values are included in idempotency and exact update CAS; no email parsing or network validation is performed. |
| DCR `logo_uri`, `tos_uri`, and `policy_uri` metadata | stdlib `net/url`; existing DCR validator and Rhiza CAS store | Optional human-readable metadata URLs are HTTPS absolute URLs, canonicalized by exact parsed spelling with lowercase host, no userinfo/query/fragment, and max 2048 bytes. They are persisted as nullable columns, returned unchanged, included in idempotency and exact update CAS, and never fetched or followed. POST null is rejected; PUT omission/null clears each field. |
| DCR `software_statement` (RFC 7591) | `go-jose/v4` plus stdlib JSON/file handling and existing DCR/Rhiza CAS store | Operator-provided `GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE` supplies static issuer-to-JWKS trust. A compact JWS must use exactly one configured public key, match `iss`, and satisfy optional `aud`; verified statement metadata overrides duplicate request JSON, the original JWT is returned unchanged, and invalid/untrusted statements fail closed. Schema v53 persists the value; schema v54 adds the canonical replicated `dcr_software_statement_trust` digest/topology fence accepting exactly one or three members and failing closed on mismatch. Source/HTTP/idempotency and trust-fence tests pass; `scripts/e2e-software-statement-standalone.sh` passes live standalone replay/readiness checks. Exact-three HA gate `KIND_CLUSTER=goauthy-software-statement-ha-e2e-20260905i` on ports `19840-19842` passes all three pods Ready with identical trust, cross-pod GET persistence, invalid signature/issuer/audience rejection on all pods, pod-0 UID replacement, byte-identical idempotent replay after restart, and cleanup. |
| Core browser localization | stdlib `embed`, `encoding/json`, `html/template` | The standard library supplies immutable assets, strict decoding and escaping; a small direct RFC 9110/4647 resolver is still required for supported-language selection, qvalue rules and deterministic fallback. |
| Standalone backup/restore (historical) | graceful process shutdown plus cold filesystem copy | Earlier cold-copy test evidence only. The current Rhiza v0.12.3 default requires object storage and disposable local state; see [no-PVC DR contract](no-pvc-dr.md). Cold-copy success does not qualify the default object-store DR design. |

## TinyAuth clean-room research reference (2026-09-01)

[TinyAuth](https://github.com/tinyauthapp/tinyauth) is an AGPL-3.0 licensed
Go authorization server. Its latest stable release is v5.1.3 (2026-07-30);
Basic OP certification remains at v5.1.0 (2026-06-25). Its AGPL-3.0 license
means no source code copying under GoAuthy's current project policy; any
incorporation of TinyAuth code would require explicit legal and project
approval to satisfy AGPL obligations. Do not claim that GoAuthy's Apache-2.0
and BSD-3-Clause dependencies themselves conflict with AGPL-3.0—only that
incorporating AGPL-3.0 source imposes distribution obligations incompatible
with the current project stance. The research below is clean-room:
architecture and security patterns only, not code reuse.

### Evaluated patterns

| Pattern | TinyAuth source | GoAuthy relevance | Decision |
|---|---|---|---|
| Kubernetes Ingress auto-discovery | `internal/service/kubernetes_service.go`: dynamic client watches Ingress resources, extracts hosts from rules, periodic resync with watcher fallback | GoAuthy currently has no K8s-native service discovery; Ingress-aware routing could reduce manual configuration | architectural candidate only; no code reuse (AGPL) |
| Multi-proxy auth modules | `internal/controller/proxy_controller.go`: supports Traefik ForwardAuth, Nginx AuthRequest, Caddy, Envoy ExtAuthz via user-agent detection | GoAuthy's `forward_auth` is bearer-only v1; multi-proxy support is a natural extension | architectural candidate; the ForwardAuth/AuthRequest/ExtAuthz module pattern is reusable as a design reference |
| ACL/policy engine | `internal/service/policy_engine.go`, `internal/service/access_controls_rules.go`: rule-based per-host/path/IP/user evaluation | GoAuthy's login abuse policy and client group restriction are narrow direct implementations; a general ACL engine could unify future access policy | not adopted: GoAuthy's Rauthy-parity scope is narrow enough that direct code remains smaller and more auditable |
| Goroutine lifecycle management | `github.com/steveiliop56/ding` (AGPL-3.0): ring-based shutdown ordering (Minor → Normal → Major → Critical) | GoAuthy uses structured concurrency with context cancellation; no ring-based shutdown is needed at current scale | not adopted: AGPL license and unnecessary complexity |
| Cookie domain isolation | `internal/bootstrap/app_bootstrap.go`: UUID-based cookie names for multi-instance, subdomain-aware domain calculation | GoAuthy's cookie naming uses issuer-bound HMAC; UUID isolation is not needed for single-issuer deployments | not adopted: GoAuthy's model is simpler and sufficient |
| Config loading layers | `github.com/tinyauthapp/paerser` (AGPL-3.0): file → flags → env layered config | GoAuthy uses environment variables exclusively; layered config is not needed for current scope | not adopted: AGPL license and unnecessary complexity |

### License constraint

TinyAuth is AGPL-3.0. GoAuthy's current project policy does not incorporate
AGPL-3.0 source code; doing so would require explicit legal and project
approval to satisfy AGPL distribution obligations. Apache-2.0 and BSD-3-Clause
licensed dependencies may coexist with AGPL-3.0 in a combined work under
suitable distribution terms, but the AGPL-3.0 copyleft obligations apply to
the AGPL-3.0-covered components. The research above references architecture
and security lessons only, consistent with the project's clean-room and
no-source-copying policy.

### What TinyAuth lacks relative to Rauthy v0.36.2 parity

TinyAuth is a simpler authorization server focused on reverse-proxy
authentication. It intentionally lacks features that GoAuthy must implement for
Rauthy parity:

- **No SCIM v2** user/group synchronization
- **No HA clustering** (single-instance design, no distributed state)
- **Process-local rate limiting** (TinyAuth's published advisory documents
  process-local login-attempt/lockdown state; GoAuthy targets distributed
  Rhiza-backed admission)
- **No event audit** or alerting system
- **No full back-channel logout parity** (GoAuthy implements the bootstrap single-RP subset)
- **No token exchange** (RFC 8693)
- **No DPoP** (RFC 9449)
- **No WebAuthn/passkey** support
- **No dynamic client registration** management
- **No custom scopes/attributes** or RBAC claims

GoAuthy's parity target remains Rauthy v0.36.2, not TinyAuth. TinyAuth-missing
features must not be weakened or deprioritized because of this research.

### Security advisories (negative-test and security lessons only)

The following GitHub Security Advisories are recorded only as negative-test
and security-design lessons. They are not implementation sources; no code is
derived from them.

- **[GHSA-r27r-rr9v-vv37](https://github.com/advisories/GHSA-r27r-rr9v-vv37)**:
  Rauthy `forward_auth` path allow/block regex matched against the whole
  `RequestURI`, so an allowed path in a query string bypassed authentication.
  GoAuthy `forward_auth` v1 rejects `RawQuery` and body, closing this
  entire class of path-vs-query mismatches.
- **[GHSA-328g-jx67-v94g](https://github.com/advisories/GHSA-328g-jx67-v94g)**:
  Case-sensitive host ACL lookup combined with a fail-open miss allowed
  unauthenticated requests when the comparison did not match. GoAuthy has no
  host-derived ACL mode; `forward_auth` returns empty `200` or generic `401`
  with no host routing semantics.
- **[GHSA-3q28-qjrv-qr39](https://github.com/advisories/GHSA-3q28-qjrv-qr39)**:
  A TOTP/MFA-pending session could obtain OIDC authorization codes before the
  second factor completed. GoAuthy `force_mfa` uses a sole
  `completeAuthentication` transition at `internal/login/handler.go:334` that
  rechecks active subject and bootstrap policy, with deterministic unit and
  prior Kind evidence; current race/vet evidence remains unverified.
- **[GHSA-9q5m-jfc4-wc92](https://github.com/advisories/GHSA-9q5m-jfc4-wc92)**:
  Singleton mutable OAuth verifier/token fields caused a cross-account race
  under concurrent authorization requests. GoAuthy's upstream provider core
  uses request/browser-bound state, digest-only one-use transactions, strict
  OIDC ID-token checks and a stateless stdlib HTTP adapter. Production exchange,
  local login completion, explicit link/unlink, and public route wiring now
  exist; race/vet, full provider Kind E2E, and broader parity remain unverified
  or incomplete.
- **[GHSA-xg2q-62g2-cvcm](https://github.com/advisories/GHSA-xg2q-62g2-cvcm)**:
  Authorization code was not bound to the redeeming client, allowing code theft
  by a different client. `TestAuthorizationCodeClientBinding` provides an
  explicit GoAuthy two-client regression test.
- **[GHSA-456h-ww26-f758](https://github.com/advisories/GHSA-456h-ww26-f758)**:
  Username timing oracle leaked user existence through response-time
  differences. GoAuthy `VerifyOrDummy` and generic failures provide structural
  mitigation, but wall-time distribution proof is not claimed.
- **[GHSA-9xhm-w3wj-xhqh](https://github.com/advisories/GHSA-9xhm-w3wj-xhqh)**:
  Attacker-controlled distinct usernames filled a process-local map and
  triggered a global-lockdown denial-of-service. GoAuthy has no global
  lockdown; admission is peer-IP keyed, while schema v33 now records expiry
  metadata and bounds insert-trigger `oauth_rate_limits` cleanup to 64 rows.
  The manual blacklist store and middleware remain a separate schema-v32,
  fail-closed core; opt-in `/auth/v1/blacklist` admin routes are source-wired,
  while current Kubernetes verification remains absent.
- **[GHSA-pcj4-r7vg-3jvw](https://github.com/advisories/GHSA-pcj4-r7vg-3jvw)**:
  A development Kubernetes Ingress annotation could claim an unrelated domain
  through missing annotation validation. GoAuthy has no Ingress ACL discovery.

These advisories inform GoAuthy's negative-test coverage and security
review posture but do not represent code, packages, or patterns incorporated
from any external source.

### Administrator user creation (schema 58)

The existing `identity`/`recovery` stores and SMTP sender provide password-new
issuance, keyed token storage, cookie/CSRF binding and language-aware delivery.
Use stdlib `net/http`, `encoding/json`, `net/mail`, `regexp`, `time` and
`time/tzdata` (for the scratch image), plus existing Rhiza atomic statements.
No new dependency or cryptography implementation is needed.

The [fixed Rauthy create handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L130)
and [creation DTO](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/users.rs#L54)
define application-specific delegated group policy and pending-account fields.
Neither Fosite nor a generic CRUD package owns these identity/RBAC/reset tables
or their shared replicated authorization boundary. Direct implementation is
therefore limited to the strict DTO, same-batch authority/collision predicates,
membership inserts and existing response projection. The normal registration
path also checks preferred-username collisions; existing pending cleanup now
removes role/group edges and preserves completed passkey identities.

Full event/notification parity, all-change immediate SCIM synchronization, mail retry, configurable
preferred-username policy and administrator UI remain tracked in
[user management](user-management.md). Synchronous post-commit SMTP success is
not claimed as durable delivery or exactly-once email.

### Lifecycle creation events (schema 59)

Use stdlib HTTP/JSON/time/crypto and the existing Rhiza/RBAC/session stores.
No general event framework or extra dependency is needed for same-transaction
creation records, a guarded query and retention. The pinned upstream contract,
package reuse/direct-policy rationale, privacy differences and pending notifier
research are detailed in [events.md](events.md). Schema 60 adds guarded SSE with
stdlib `http.ResponseController` and a persisted SQL commit cursor. Rhiza's
bounded at-most-once Notify API cannot replace the transactional event log;
the one-second reconciliation and 64-stream/node bound avoid a new broker or
dependency. Notification delivery, nonpersisted streaming and the other event
emitters remain incomplete.

`POST /auth/v1/events/test` reuses the existing event INSERT builder, Rhiza
receipt recovery and direct product authorization. Reset-form consumption also
reuses that builder and password transaction: a native SQL expression selects
profile email or the legacy bootstrap recovery email. It is a commit-time
predicate, and the successful token attempt
guards the event INSERT. Stdlib HTTP peer handling and the already-installed
password hasher cover the remaining mechanics. No library can define this
product's exact password-generation/token/profile witnesses or lifecycle text;
that small mapping is direct code. It emits for both reset and first-password
forms, matching the pinned Rauthy service; the admin-password branch, configurable
levels and notification delivery remain incomplete. See [event research](events.md).

The test endpoint reuses Rhiza
receipt recovery, RBAC random IDs and live key/session guards, plus stdlib
HTTP/IP parsing. No library can supply GoAuthy's exact Events:create versus
group-admin visibility policy or same-transaction guard. The small adapter
therefore remains direct code, with the pinned production payload and explicit
notifier/debug-mode limitations documented in [events.md](events.md).

### Account and API-key browser composition (2026-09-06)

The new account dashboard and API-key editor reuse the installed server's
identity/account/claims/RBAC/API-key handlers and their existing test helpers.
Stdlib `net/http`, `embed`, `html/template`, `encoding/json` and native browser
forms/fetch cover rendering, embedding and transport. No additional package is
needed. Direct code is confined to the product-specific current-account
projection, issuer-bound CSRF handoff and exact existing DTO/form mapping;
generic CRUD packages do not supply these authorization and policy contracts.
The API-key plaintext response uses the existing response reader and remains
transient in the DOM, never in persistent browser storage. Existing chromedp
provides real-browser tests; Node's built-in assert/vm checks exact payloads and
error states with explicit promises, not sleeps. See the
[account contract](account-dashboard-implementation.md) and
[admin contract](admin-ui-implementation.md) for implementation and open gaps.

### OAuth2 external account identity (2026-09-07)

The installed `golang.org/x/oauth2` remains responsible for authorization-code,
PKCE and token exchange. Identity retrieval reuses the existing restricted SaaS
HTTP client, JSON media-type check and duplicate-key object decoder, with stdlib
`net/http`, `encoding/json`, `io` and `strconv`. No dependency was added.
The small provider-configured endpoint/field mapping is direct code because
OAuth2 does not define a universal account-profile response schema. It accepts
only a stable string or canonical int64 field without floating-point conversion;
it is not an email-based account merge or arbitrary JSON expression engine.

The access token, not the provider application secret, is presented to the
resource endpoint ([RFC 6749 §7](https://www.rfc-editor.org/rfc/rfc6749.html#section-7)).
This helper is **not an OIDC RP verifier**: an OIDC mode additionally needs ID
token validation and an exact UserInfo/ID-token subject match
([OIDC Core §5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)).
No full user connection/callback completion is claimed by this helper.

### SaaS OAuth connection state and completion (2026-09-07)

The connection runtime reuses `x/oauth2` (S256/code exchange), the SaaS restricted
transport/identity adapter, existing credential installation CAS, and keyring
envelopes. `upstreamprovider.RhizaStore` was considered but rejected here: its
persisted purposes are IdP login/link and its callbacks consume the same namespace.
Pretending an external-credential connection was an IdP link would conflate trust
boundaries. A nullable verifier envelope on the **existing SaaS authorization row**
is the smallest isolated persistence change; existing digest-only callers remain
compatible. Its key-reference scan, rewrap and retirement barrier are wired.

Custom code is limited to GoAuthy's owner/collection/provider-revision/session
binding, atomic one-use consume, identity/scope mapping and HTTP DTO composition.
Generic OAuth libraries do not supply those application authorization rules.
No custom cryptography or additional dependency was introduced.
The installed `oauth2.Token.Extra` represents both absent scope and explicit null
as nil; this adapter follows omitted-scope semantics for both. Non-string values,
invalid scope-token syntax, duplicates and requested-scope escalation are rejected.
This limitation is recorded, not a claim of strict raw-token-response JSON validation.

### OAuth connection status and local revoke (2026-09-07)

Status projection reuses authenticated credential envelopes; the response only
contains provider/account/scopes/state/version metadata. The local-revoke path
reuses Rhiza's one-statement compare-and-swap and existing refresh states. A
small owner cleanup predicate is direct code because the normal credential-use
predicate requires enabled provider/collection policies, whereas an owner must
still be able to revoke after those are disabled. The shared one-use callback
consume rejects pre-existing credentials unless the explicit reconnect rules
below permit replacement of a revoked prior generation. No package or cryptography was added. HTTP version decoding reuses
the existing strict JSON version-body decoder; this is not RFC 7009 provider-side
revocation and must not be described as such.

### OAuth reconnect (2026-09-07)

Reconnect reuses the existing connection generation, credential row, Rhiza CAS,
PKCE exchange and encrypted proof. Schema v74 adds a target token version to the
existing authorization request; there is no new credential history service or
dependency. Direct code is required for the application-owned generation/version
authorization rule: only a revoked prior generation can be replaced, at exactly
old version + 1. Resetting to version 1 would let an old version-only DELETE match
a newly connected account (ABA). Preserving the revoked ciphertext until the
guarded replacement also avoids destructive cleanup during an incomplete flow.
OAuth libraries handle the protocol exchange, not these local ownership/CAS rules.

### Consumer-bound use authentication (2026-09-07)

Consumer use authentication reuses the existing Fosite bearer-token validation,
Rhiza resource authorization predicate and current account/client/group checks.
The shared helper now also returns the authenticated client ID; the small new
wrapper fixes the use scope and refuses cookie authentication. No token parser,
signature algorithm or dependency was added. Direct composition is necessary
because Fosite does not define this application's owner-to-consumer connection
consent. This wrapper does not replace the still-required generation-bound grant
or authorize raw credential export.

### Managed resource audiences (2026-09-07)

Managed clients reuse their existing JSON metadata column and Fosite's
`GetAudience` contract. No schema migration or package is needed. Stdlib
`net/url`, string checks and `slices.Equal` validate bounded exact HTTPS resource
lists and identify policy changes. The existing client generation and envelope
reseal path invalidate old grants on an audience change while retaining the
client secret. Direct code only composes management DTOs, compatibility rules
(omitted PUT preserves, [] clears), native textarea input and the existing CAS.
This does not add Device resource issuance or authorize SaaS credential use.

### References

- [W3C WebAuthn Level 3 JSON conversion](https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON): account passkey forms use the browser's native creation/request parsers and credential `toJSON()`, with the existing `go-webauthn` server. There is no new custom base64 adapter, cryptography, or dependency. Direct code only composes the existing password-or-WebAuthn proof, one-use modification token, registration and deletion endpoints. Legacy browsers lacking these native methods remain an explicit compatibility gap, not a silent fallback.

- TinyAuth repository: https://github.com/tinyauthapp/tinyauth
- AGPL-3.0 license: https://www.gnu.org/licenses/agpl-3.0.html
- OpenID Certification: TinyAuth v5.1.0 (2026-06-25) achieved Basic OP certification; latest stable is v5.1.3 (2026-07-30)
## Device resource indicators (2026-09-07)

Device request parsing reuses stdlib net/http, net/url and encoding/json; stored
state reuses the existing Rhiza device-grant table with one nullable resource
column (schema v75). Fosite Requester audience state, matching strategy and the
existing server allow-list are reused for issuance and refresh. No package added.
The existing custom RFC 8628 handler bypasses Fosite's authorization-code handler,
so explicitly bridging its validated persisted resource into Fosite is required;
omitting that bridge produces audience-less tokens. Platform resource permission
scopes retain current catalog/claim resolution and commit-time revision guards;
arbitrary custom user scopes remain outside Device support.

## Connection use consent (2026-09-07)

Reuses stdlib net/http, net/url, encoding/json and time, the existing keyring,
managed-client metadata and Rhiza conditional writes (schema v76). No dependency
added. Existing OAuth token authentication is not consent to use an external
account. The project-specific owner/connection/consumer generation and provider
revision relationship therefore needs explicit persistence and SQL guards; the
existing Fosite token validator and credential store remain responsible for their
own concerns. This is a local reuse assessment, not a claim that every public
consent package was surveyed. API-key registry binding now reuses the existing
connector digest, credential envelope, provider CRUD and conditional SQL paths
(schema v77); no new cryptography or package was introduced. Public consumer
execution/delivery remains incomplete; see connection-use-grants.md.

## Registered-key review UI and browser fixture (2026-09-07)

Existing DOM construction, textContent, native checkbox, CSRF request helper and
chromedp E2E are reused; no frontend or crypto dependency added. Key-custody review
does not grant consumer use. A screenshot caught author CSS overriding HTML hidden;
the shared account rule and real computed-style assertion prevent recurrence.
Chromium does not inherit the fixture Go client's CA configuration. The test-only
profile pins the leaf SPKI after a normal Go CA/hostname-verified HTTPS request,
using Chromium's [documented SPKI exception switch](https://chromium.googlesource.com/chromium/src/+/8402d3c5bc13e018fa75eba650ed881755e0223b%5E%21/).
No global certificate-error bypass or system trust-store change is used.

## Consumer API-key invocation (2026-09-07)

The HTTP adapter reuses net/http, encoding/json, the existing strict JSON decoder,
Fosite-backed AuthorizeConnectionUse, Rhiza use-grant guards, APIKeyConnector and
CallAPIKey. No dependency or cryptography was added. The adapter only composes the
existing authenticated consumer, application-specific consent and configured
operation checks; a generic OAuth package does not own these project tables.
Positive transport tests inject only the external TLS boundary; production DNS,
destination and TLS restrictions remain unchanged. This is a reuse rationale,
not an exhaustive survey or a claim of completed SDK/OAuth execution support.

## Owner service-access review (2026-09-07)

Reuses the existing account DOM/request/CSRF helpers, native checkbox and
datetime-local input, strict Go JSON decoder and authenticated connector digest.
The optional reviewed digest is compared before the existing Rhiza guarded grant
insert; no schema, crypto or dependency is added. This small project-specific
adapter is needed to connect visible settings review to the existing stored
consent, not to reimplement OAuth consent. Input changes reset confirmation;
success is not optimistic. Node VM checks control clock and pending responses;
Chromium uses the existing verified-CA fixture without weakening production TLS.

## Owner-side Bearer grant status (2026-09-07)

Reuses the existing connection resource boundary and Fosite human read-scope
authorization, grant decoder/owner SQL guard and a single linearizable Rhiza
query. The response binds stored grant metadata to its current parent generation;
no keyring access, schema or dependency is needed. Backoffice is an observing
application, not necessarily the grant's execution consumer, so the existing
owner read scope is used rather than repurposing connection-use authority.
The shared resource boundary now also rejects empty Cookie headers and bare
query markers, consistently across its callers. The metadata lookup is required
application composition; it is not a replacement authorization protocol.

## Registered API-key delivery (2026-09-07)

Reuses `AuthorizeConnectionUse` (existing Fosite token validation),
`AuthorizeUseGrant`, `APIKeyConnector` and `loadAPIKey` (existing authenticated
keyring envelope). HTTP/JSON use Go `net/http` and `encoding/json`; no dependency
or schema is added. Existing confidential-client metadata supplies the consumer
restriction. Proxy consent is never converted to delivery consent.

The application-specific composition is necessary: neither Fosite's OAuth token
validation nor the encryption library defines GoAuthy's Rhiza owner/consumer/
provider/generation grant policy. The implementation only joins these existing
primitives and rechecks their linearizable guard after decryption. It introduces
no custom cipher, token protocol or SDK framework. Raw-key delivery cannot retain
the fixed proxy's operation/projection limits or recall a key already returned.
Tests mutate the real store at authorization callbacks (including the final
post-decryption check), rather than using sleep-based revocation races.

Delivery handoff extends the same `UseHandoffInput.Mode` and `usePolicy` checks;
no second consent protocol is introduced. Schema79 only widens the mode check in
an atomic table rebuild with all existing ticket data preserved. Go
`html/template` conditions distinguish raw-key delivery warnings/confirmation from
proxy promises; native required controls and the existing CSRF handler are reused.
The existing chromedp and TLS fixture verifies the rendered flow, rather than
adding a UI dependency or weakening production TLS/private-network restrictions.

## Raw Authorization API-key compatibility (2026-09-07)

Conductor's pinned `github.com/Conalog/gowid-api-go` revision
`e939fc41d3d4` sets `Authorization` to the key without a prefix
([client source](https://github.com/Conalog/gowid-api-go/blob/e939fc41d3d4/client/client.go)).
The local module source and Conductor AMP mapping were inspected; this is not
evidence of a live Gowid API call or a newly verified upstream service contract.
Header-carried API keys are also a standard OpenAPI security-scheme model
([OpenAPI guide](https://swagger.io/docs/specification/v3_0/authentication/api-keys/)).

The existing Go `Header.Set(header, prefix+key)` already implements injection.
Only `validPrefix` needed to allow the exact empty Authorization prefix; adding
an auth SDK or Gowid-specific server branch would duplicate that primitive.
The existing digest includes prefix, preserving mode distinction; HTTPS,
header/key validation, current consent checks, no redirects, SSRF protection and
output filtering remain unchanged. Tests verify distinct digests and exact raw
header injection through certificate-verified local TLS without an external call.

## OAuth access-token delivery composition (2026-09-07)

[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-5.3) requires
protecting Bearer tokens in transport and storage; possession permits their use.
[RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
distinguishes access-token lifetime and refresh tokens. These standards do not
define GoAuthy's application-specific owner/consumer connection consent policy.

Reuse the existing `golang.org/x/oauth2` exchange adapter (already validates
Bearer type), encrypted credential store, `AuthorizeUseGrant`, Rhiza linearizable
guards and Go HTTP/JSON. No dependency, cipher, token-exchange protocol or schema
is added. The required custom composition binds the existing credential to the
current confidential consumer, provider revision, connection generation, token
version and explicit delivery consent; an OAuth library alone cannot enforce
those application records.

The delivery read performs no network request or automatic refresh. Unknown or
expired token lifetimes fail closed; this is a GoAuthy policy, not an RFC claim
that providers always return an expiry. Token and consent expiry remain separate:
ending GoAuthy consent prevents later retrieval but cannot shorten or recall an
upstream token already returned. Refresh tokens and provider client secrets stay
in GoAuthy. Full refresh orchestration, OAuth handoff/UI and live consumer OAuth
acceptance remain separate work, not completion implied by this read primitive.

Refresh completion also compares the incoming account ID with the authenticated
existing envelope under the exact refresh claim. It reuses the current keyring,
linearizable read and commit-time CAS/authority rather than adding an identity
store. `golang.org/x/oauth2` exchanges opaque tokens but cannot enforce a local
connection's account/generation invariant. Changed or missing account metadata
therefore requires reconnect, while the refresh orchestrator treats a mismatch
after exchange as uncertain and never retries that possibly consumed refresh.
This validates stored identity continuity; it does not independently prove the
new upstream token's subject. The registered-provider refresh adapter below adds
that lookup; full public OAuth browser/consumer E2E remains unfinished.

## Registered OAuth refresh orchestration (2026-09-07)

Reuse `golang.org/x/oauth2` through the existing explicit-auth-style `OAuth2.Refresh`,
the registered provider's `OAuth2.Identity`, `oauthGrantedScopes`, and durable
`refreshCredential` claim/commit/uncertain handling. HTTP uses existing owner
session/CSRF/version parsing; no new package or schema is needed. The necessary
custom code connects these primitives to local owner/generation/provider fences,
not a second OAuth implementation.

[RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) limits
refresh scope to the original authorization and defines refresh-token replacement.
GoAuthy conservatively rejects a refreshed scope set wider than its current stored
snapshot; a provider response cannot silently broaden existing local consent.
The shared completion method enforces this even for internal callers. Same-account
identity is checked with the newly received access token before persistence.
Neither this explicit owner endpoint nor credential receipt schedules background
refresh. If expiry is unknown it stays unknown (zero), not an invented lifetime.
Tests substitute only the external HTTP transport with certificate-verified local
TLS and assert exact request counts; the public loader retains restricted egress.

### Registered OAuth test provider and public HTTP gate

`cmd/goauthy-saas-oauth-fixture` is test scaffolding, not a production OAuth
implementation: stdlib `net/http`, `crypto/sha256`, `crypto/rand`, `encoding/json`
and a mutex provide synthetic one-use PKCE codes, refresh rotation, stable
identity and metadata-only counters. The existing upstream fixture issues signed
OIDC/GitHub responses but does not provide this opaque-token refresh/identity
contract; no new runtime dependency or general authorization-server abstraction
was added for the test. Production still reuses `golang.org/x/oauth2`.

The [isolated Dory runner](../deploy/e2e-saas-oauth/README.md) now exercises the
public successful owner connection/refresh/revoke path without replacing the
production HTTP transport. A network-none namespace confines its public-unicast
loopback alias to the test container, leaving production SSRF and TLS guards intact.
It does not replace remaining browser UI, consumer, persistence and HA gates.

### SaaS OAuth browser completion representation (2026-09-07)

The successful callback reuses stdlib `html/template` and the existing account
stylesheet. Only document navigation receives HTML; API callers retain JSON.
This is application-specific presentation after the existing OAuth save, not a
new OAuth implementation: `golang.org/x/oauth2` still performs token exchange.
No package, schema, redirect configuration, credential exposure or automatic
consumer grant is needed. Tests cover header selection, escaping and JSON
compatibility; the isolated browser profile checks the real redirect path.

### Device request review and approval binding (2026-09-07)

[RFC 8628 section 3.3](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.3)
requires user-code validation and an accept/decline interaction. The application
must supply its own consent UI; a token-grant library cannot render our Rhiza
grant metadata or bind our browser form. Reuse the existing device store,
`html/template`, native GET/POST forms and account stylesheet. A linearizable
pending/unexpired lookup returns only client ID, scopes and optional resource.
No schema or package is added.

[Go crypto/hmac](https://pkg.go.dev/crypto/hmac) supplies HMAC, so no cryptographic
primitive is implemented locally. A domain-separated SHA-256 MAC keyed by the
existing random HttpOnly CSRF cookie covers the normalized reviewed user code.
The existing constant-time comparison verifies it on POST. Grant client/scopes/
resource are immutable; the decision still checks pending state and expiry.
This small application-specific binding prevents substituting another code
after review. Existing origin/Fetch Metadata and authenticated-subject checks
remain mandatory. GET lookups have a separate direct-peer/subject rate bucket;
invalid/expired/decided codes reveal no request metadata or approval controls.

### Native Device approval forms and Origin (2026-09-07)

The [Fetch Origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header)
can serialize Origin as `null` for a native POST form under `no-referrer`.
Device verification had rejected this legitimate browser request while HTTP-form
tests supplied the issuer Origin explicitly. The fix reuses the existing login
and handoff policy: exactly one `Sec-Fetch-Site: same-origin`, stdlib
`net/http.CrossOriginProtection.Check`, and the unchanged authenticated-subject
and double-submit CSRF checks. Null Origin alone is never sufficient. Referrer
suppression, same-site/cross-site rejection and duplicate-header rejection remain.
No dependency, custom cryptography or generic middleware abstraction was added.
`internal/device/http_native_form_test.go` fixes time and verifies approve/deny
plus rejected requests leaving the grant pending; cold Chromium E2E exercises the
actual browser header behavior instead of synthesizing the Origin header.

### Dynamic registration DPoP policy (2026-09-07)

[RFC 9449 section 5.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-5.2)
defines `dpop_bound_access_tokens` as a boolean, default false; true requires a
DPoP proof on access-token requests. The existing Fosite v0.49.0 integration
does not implement this application-owned DCR/Rhiza metadata or its concurrent
write boundary. Reuse encoding/json strict decoding, Fosite errors/client
interfaces, existing go-jose verification, and Rhiza atomic SQL; no new package
or cryptographic primitive is needed.

Schema80 adds a constrained integer boolean. A small Fosite client wrapper
carries the already-resolved metadata snapshot, avoiding a second policy read
that could misclassify a concurrently deleted dynamic client. The token handler
rejects missing required proof. The transaction captures verified-proof state
before any grant mutation, and the shared SQL guard checks current client
existence and either optional policy or verified proof. Client credentials and
token-exchange storage guard both token artifacts as well. This final guard is
custom glue because only GoAuthy knows its Rhiza transaction and grant schema;
preflight-only enforcement cannot prevent a policy change racing token issuance.

Existing fixed-state hooks test false-to-true changes without sleeps. Exchange
cutoff positions account for the added guard arguments; source and actor expiry
tests inject the storage clock and verify neither artifact is left behind.
This storage regression is not a claim that token-exchange DPoP is implemented.

### General TOML secrets follow-up (2026-09-09, implementation pending)

The pinned [Rauthy secrets loader](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/secrets.rs)
separates cluster, database, dynamic-client, email, encryption, event, geolocation
and picture-store secrets. This is distinct from the already implemented API-key
JSON bootstrap. Reuse the installed `pelletier/go-toml/v2`; a new TOML parser is
not justified. Mapping fields to existing GoAuthy credential consumers, resolving
precedence, and rejecting unsupported Rhiza-excluded database settings are
application policy rather than parser functionality.

The pinned [configuration loader](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/rauthy_config.rs)
uses environment-over-TOML scalar precedence (`t_str`), a configured secrets path
over the startup default (`parse_secrets`), and explicit `$SECRETS` references.
Its dynamic-client `reg_token` branch references database migration-password fields
in both branches; do not copy this apparent field-routing defect into Go. A future
implementation needs a regression proving that a dynamic-registration credential
reaches only its intended consumer and does not alter database credentials.
This research is not evidence that general configuration parity is implemented.

### OAuth storage-failure response normalization (2026-09-09)

The installed Fosite v0.49.0 [error conversion](https://github.com/ory/fosite/blob/v0.49.0/errors.go)
assigns untyped internal failures the generic code `error`, while its standard
`ErrServerError` produces `server_error`. During real MinIO outage, the token
endpoint returned HTTP 500 in 16 seconds with the generic code. GoAuthy now uses
one token-error response boundary to replace only that fallback with the existing
Fosite server error. Typed OAuth errors still pass through Fosite's serializer,
cache headers, and debug-detail suppression. No new package or custom JSON error
serializer is justified; mapping application/storage failures is application
policy that Fosite's generic fallback does not implement for this service.

Regression tests cover request/response storage failures, cancellation, preserved
client/grant/temporary errors, no token/detail disclosure, and no-store headers.
The original classification failed before the fix; focused race and vet passed.
Live final-candidate status is recorded in status.md.

### Corrupt archive recovery boundary (2026-09-09)

Rhiza v0.12.3 already implements archive format validation and before-ack startup
failure propagation in `pkg/recovery/archive_codec.go` and `pkg/node/node.go`.
GoAuthy reuses these directly; adding an archive parser or automatic repair logic
would duplicate the database's recovery authority. The application qualification
uses existing Go subprocess/filesystem tests and Kubernetes/containerd/MinIO
commands to inject invalid bytes into an owned fixture and restore a known-good
object. These orchestration assertions are project-specific E2E code, not a new
recovery implementation or package. Graceful Rhiza shutdown explicitly runs
`CheckpointOnShutdown`, so the archive-only Kind test reuses abrupt process loss.
See [DR acceptance and evidence](no-pvc-dr.md#corrupt-archive-acceptance) for the
precise supported failure and remaining corruption cases.

The missing-block gate additionally reuses Rhiza `readExtent`/`readObject`
(`pkg/recovery/archive.go`) and the existing object-store adapters. The filesystem
adapter preserves an `os.ErrNotExist` error; pinned MinIO Go v7.0.95 maps
`NoSuchKey` to `The specified key does not exist.` (`s3-error.go`,
`api-error-response.go`). The E2E requires the archive-load context and actual
missing-object error, rather than treating any startup failure as data-integrity
protection. No additional dependency or custom archive decoder is needed.

Block-content corruption uses Rhiza's existing SHA-256 comparison in
`readExtent` (`pkg/recovery/archive.go:1482`), followed by its decoder and extent
validation. Reimplementing this in GoAuthy would duplicate the database trust
boundary. The app adds only fault-injection and restore assertions through the
existing subprocess/Kind harnesses. No additional production code or package is
required to reject content inconsistent with the archived reference.

Checkpoint-pointer corruption reuses Rhiza `checkpoint.Manager.Load` and
`Node.Open` failure propagation. The existing reader distinguishes missing CURRENT
(initial checkpoint not yet published) from malformed CURRENT and a missing or
invalid referenced immutable root. The test injects an invalid root hash into valid
JSON; GoAuthy adds no pointer parser or fallback recovery policy. Normal checkpoint
publication and stdlib subprocess/filesystem plus the existing Kind fixture provide
the acceptance evidence, documented in [DR](no-pvc-dr.md#checkpoint-pointer-corruption-acceptance).

Checkpoint-root integrity reuses Rhiza `readRoot` (`pkg/checkpoint/checkpoint.go`)
for bounded reads, SHA-256 verification and metadata validation. Tests use existing
stdlib JSON/hex formatting to address only the immutable object named by CURRENT,
then restore its saved original. The production behavior already exists in Rhiza;
no GoAuthy recovery algorithm or dependency is added.

Checkpoint data-block acceptance reuses Rhiza `checkpoint.Verify` and
`downloadFile` size/hash checks (`pkg/checkpoint/checkpoint.go`), plus the checkpoint
validator registered by `Node.Open`. No new dependency is justified: stdlib fixture
file operations and existing MinIO commands can corrupt/restore owned test objects,
while Rhiza remains responsible for interpreting and validating checkpoint contents.

During same-length checkpoint-block E2E, the restore harness exposed a MinIO copy
semantics issue: pinned `mc mirror --overwrite` skipped same-size changed contents
in a deterministic local fixture. Existing `mc cp` did replace them. The fix reuses
explicit per-object copies and byte comparison after download before restarting
voters; it adds neither a storage library nor a custom repair algorithm. Earlier
fresh-destination backup tests do not establish overwrite behavior against already
existing same-size corrupt objects.

Interrupted checkpoint recovery also reuses Rhiza v0.12.3 rather than introducing
a GoAuthy restore journal. `pkg/node/node.go` downloads certified checkpoint files
into a `.rhiza-checkpoint-restore-*` directory before installing them.
`pkg/materializer/materializer.go` calls `recoverRestore` on open and implements
`restoreParts` with a fsynced/renamed restore journal and SQLite/graph backups.
Uncommitted journal phases roll back saved files; committed state retains the
installed files and removes backups. These are source contracts, not proof that
our deployment survives every interruption. Tests must distinguish an interrupted
block read/download from interruption during journaled installation, and retry
with both retained partial local state and a fresh emptyDir. Killing a process only
after Open returns does not prove interruption during recovery. No replacement
production journal, object decoder or new dependency is justified by this research.

The interrupted-recovery fixture exposed a native filesystem-provider contract:
`thanos-io/objstore` stores SHA-256 version metadata in the
`user.thanos.objstore.sha256sum` extended attribute. `Attributes` returns no
version if it is absent, and Rhiza's `readStableHead` cannot accept an unversioned
archive head. A plain `os.CopyFS` fixture clone therefore failed with
`shared archive head did not stabilize`; copying bytes alone is insufficient for
this provider. Reuse the installed filesystem bucket's Upload when cloning test
objects to generate its native version metadata. This is a fixture-copy constraint,
not evidence that S3 or GCS objects require local filesystem extended attributes.

For the real MinIO interrupted-download gate, use the standard library
[`net/http/httputil.ReverseProxy`](https://pkg.go.dev/net/http/httputil#ReverseProxy):
its response hook and immediate flushing support a controlled streaming boundary.
A test-only body wrapper must hold the selected block after a prefix and observe
Rhiza's local restore file before reporting interruption readiness. That
application-specific observation cannot be replaced by a fixed delay or a generic
connection outage. The proxy forwards real MinIO requests and preserves the signed
Host; it does not implement S3 storage or signature verification. The fixture has
its own Docker target and is excluded from the default GoAuthy runtime image.
Only the observation/release coordination is custom test code; protocol forwarding
is stdlib. This implementation choice does not itself constitute live acceptance.

The first real-MinIO observation attempt exposed a difference from the filesystem
FIFO test: the pinned MinIO Go client (`v7.0.95`, `api-get-object.go`) fills the
requested Read buffer with `readFull`. Thanos' S3 reader returns that object, and
Rhiza's `downloadFile` uses `io.Copy` through a TeeReader/LimitReader, whose current
Go implementation allocates a 32 KiB buffer. A 64-byte withheld response cannot
complete that read. The Kind fixture therefore must deliver 32 KiB and select a
block strictly larger than that before stalling. This changes only the test fault
boundary, not production buffering or the separately passing filesystem test.
A matching reader regression and a new live run are required to validate this
source-derived explanation; the failed run did not retain sidecar status values.

The peer-partition gate reuses the repository's pinned Cilium 1.20.0 chart/images
and CiliumNetworkPolicy. [Cilium's deny-policy documentation](https://docs.cilium.io/en/stable/security/policy/deny/)
confirms that deny rules override allow rules, including Kubernetes NetworkPolicy.
The existing policy targets only the selected pod's peer TCP/UDP 8444 traffic,
so no custom packet filter or new chaos dependency is needed. GoAuthy's existing
Fosite token creation and linearizable Rhiza introspection exercise acknowledged
state during isolation and after healing. The test owns only a disposable Cilium
Kind cluster and the policy within it; neither source documentation nor readiness
checks alone establish live acceptance.

### Current Cilium host prerequisite (2026-09-09)

The pinned [route reconciler](https://github.com/cilium/cilium/blob/v1.20.0/pkg/datapath/linux/route/reconciler/reconciler.go)
opens a [safenetlink handle](https://github.com/cilium/cilium/blob/v1.20.0/pkg/datapath/linux/safenetlink/netlink_linux.go)
with default configuration. The pinned [netlink handle](https://github.com/vishvananda/netlink/blob/v1.3.1/handle_linux.go)
opens ROUTE, XFRM and NETFILTER families. A disposable stdlib socket-only probe on
current Dory 6.12.30 succeeded for protocols 0/12 but returned `protocol not
supported` for XFRM (6). No route or firewall mutation was performed. This narrows
the previously recorded startup failure to a missing current runtime prerequisite;
it does not qualify Cilium enforcement. No replacement CNI, custom packet filter
or host-kernel change was introduced. The strengthened OAuth network partition
script remains live-unverified until a compatible environment is available.

## Journal installation interruption: native syscall observation

Rhiza v0.12.3 already owns the SQLite/graph restore journal and rollback/finalize
logic in [materializer.go](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/materializer/materializer.go).
Its public API exposes completion, not an intermediate-phase pause. A production
hook or replacement journal implementation is unnecessary. The Linux-only test
reuses [strace](https://strace.io/) 6.19-r1 from digest-pinned Alpine 3.24.1;
[documented path filtering and delay injection](https://man7.org/linux/man-pages/man1/strace.1.html)
can pause the real successful journal rename without replacing its result.
A disposable-container smoke confirmed the selected rename returned zero and was
marked `DELAYED`. The application and Rhiza source remain unmodified.

The observation boundary is after journal rename, before the following parent
folder fsync. SIGKILL there tests process-crash recovery, not disk power loss.
The test-only image contains strace; the default production image does not.
A small Go test orchestrator is required to select actual journal phases, kill
the exact tracee and reuse existing account/key recovery checks; strace owns
ptrace and syscall handling, so no custom debugger or syscall shim is added.
Live qualification is recorded separately after the final test candidate runs.

Final Linux acceptance: `make test-no-pvc-journal-linux` passed all five real
journal phases and its trace oracle in 37.40 seconds (2026-09-09). The oracle
rejects parent-directory fsync after the last delayed rename, including an
unfinished syscall. Both retained and fresh local-state account/JWKS recovery
pass; MinIO/Kind and generated-key qualification remain separate.

### Generated API-key recovery oracle reuse

The shared no-PVC recovery helper now reuses `apikey.NewStore`,
`BootstrapWithSharedGeneratedSecrets`, `ReadGeneratedBootstrapSecrets`,
`Authenticate` and `Authorize`. The fixed test configuration asks for Generate;
it never supplies the original token as bootstrap input. The encrypted local
export is written inside disposable DataDir. A separately copied, mode-0600
expected token is only an assertion input and is never logged.

Before any bootstrap/export can repair rows, recovery must authenticate the
original key, reject a modified token, permit Clients Read and deny Clients
Update. The subsequent fresh export must contain the same winner, permissions
must remain unchanged, and queries must show a zero-deadline singleton and one
API-key row in total. No production code, additional cryptography or module
package was introduced. The fixture uses TTL0; it adds no expiration claim.

### Kubernetes wrapper uses the same native syscall boundary

The Kind candidate reuses strace 6.19-r1 and jq 1.8.2-r0 in a separate
`journal-fault` image based on the existing digest-pinned Alpine 3.24.1 image.
It copies the same production GoAuthy and bootstrap CLI binaries. Shell handles
process lifecycle, jq validates the known phase, and awk checks the bounded
syscall trace; no custom ptrace implementation or Rhiza production hook was
added. The default image and module dependencies remain unchanged. The wrapper
holds after child SIGKILL so the existing external harness can compare objects
before permitting any recovery writer to restart.

## Native checkpoint GC is not backup-retention parity

[Rauthy v0.36.2 backup configuration](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/config/backup.md)
specifies scheduled backups, day-based S3/local retention, active-key encryption
for remote backups and selection of a backup object for restore. Those are
separate feature goals from recovery of the current durable state. The project's
no-PVC requirement makes the object-store path authoritative; historical local
cold-copy tests cannot discharge these backup requirements.

Rhiza v0.12.3 exposes `ObjStoreGCInterval` and `ObjStoreGCGracePeriod` in
[rhiza.go](https://github.com/mrchypark/rhiza/blob/v0.12.3/rhiza.go). Its
[node GC loop](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/node/node.go)
only starts for a positive interval, retains recovery/seal/archive-base roots,
passes a keep count of two plus the archive floor to checkpoint GC, and cleans
the archive after successful checkpoint GC. GoAuthy's current environment
adapter does not set either GC field. This native recovery-safe cleanup is not
a dated backup catalog, a configurable backup schedule or encrypted retained
backup export. The backup ledger stays unchecked for those missing behaviors;
no GC setting was silently enabled while crash qualification was running.

### Native network fault injection capability (2026-09-09)

The current Dory 6.12.30 kernel accepts `tc clsact` and a software `flower`
UDP-port filter with `gact drop`. `sh scripts/test-e2e-tc-capability.sh`
passed in the pinned Kind node image, in a disposable network-none container
with only NET_ADMIN added. One UDP/8444 packet incremented the drop counter;
a UDP/9000 control did not. Removing the owned qdisc removed its filter.
The check uses existing iproute2 and Bash, with no Go dependency or application
privilege change. It does not prove Kubernetes peer partition or CNI policy
support. The Cilium XFRM blocker remains a separate unresolved gate.

The [iproute2 flower manual](https://www.man7.org/linux/man-pages/man8/flower.8.html)
defines protocol/port matching; the
[tc action manual](https://www.man7.org/linux/man-pages/man8/tc-actions.8.html)
defines drop actions. Native kernel fault injection is the next implementation
candidate; a custom packet proxy is unnecessary if the actual peer-path gate
passes. Application HTTP and object-store traffic must remain reachable during
the fault, and live drop counters must prove enforcement.

### OAuth client lookup availability errors (2026-09-09)

The real native Kind partition exposed HTTP 401 on the isolated voter. GoAuthy's
bootstrap scope lookup discarded its database error; additionally,
[Fosite v0.49.0 client authentication](https://github.com/ory/fosite/blob/v0.49.0/client_authentication.go)
wraps client lookup errors as `invalid_client` for both Basic and JWT paths.
Changing credentials or accepting 401 in the chaos gate would hide the failure.

Retain the original bootstrap lookup error and use stdlib `errors.Is` at the
existing token error response boundary to recognize wrapped Rhiza quorum,
readiness, durability and unknown-commit errors, plus request cancellation or
deadline expiry. Return a generic `server_error`, never the internal cause.
Genuine client-not-found and secret mismatch retain their protocol errors.
Fosite and Rhiza already supply error wrapping and typed causes; no new package,
custom authentication strategy, retry or preflight database read is needed.

### Generated API-key peer-partition qualification (2026-09-09)

Reuse the existing generated-bootstrap Kustomize overlay, TTL0 shared winner,
bootstrap retrieval CLI and private curl configuration from the DR harness.
The network fault remains native iproute2; this extension needs no new package
or cryptography. Existing API-key authentication performs a linearizable read.
The self-test and RBAC authentication boundary currently return generic 401 when
that read fails; unlike the OAuth token protocol test, this gate checks their
existing fail-closed behavior rather than claiming availability classification
parity. During the fault, the isolated voter must return no protected data.

`internal/claims/http.go` selects Clients Update permission and calls
`actorOrKey` before decoding a bootstrap-scopes PUT body. A malformed-body PUT
with the generated Clients Read key must therefore return 403 without changing
client state.
Require that denial and successful read both before and after healing, alongside
identical shared exports and full-token/bare-secret log checks. These are
qualification requirements, not a live PASS until the expanded gate completes.

### Dated encrypted backup boundary (2026-09-09)

See [snapshot/export and encryption design](encrypted-backup-design.md).
The DB facade's missing export API is not proof of impossibility: public Rhiza
managers provide paired recovery pins and verified readers. A version-pinned
capture adapter is being prototyped; neither consistency nor GC safety is yet
accepted. Evaluate the public age Go library before considering custom streaming
AEAD framing. No encryption dependency or production backup code was added by
this research step, and the backup feature remains unchecked.

### Offline encrypted backup operator (2026-09-09)

The operator uses stdlib `flag`, signal/context, SHA-256, private temporary files,
`File.Sync` and exclusive `os.Link` publication; no CLI or atomic-file package
is necessary. Native age recipient/identity parsers cover both supported key
formats. Rhiza's bucket factory is under `internal/objstore/provider.go` and is
not importable by GoAuthy, so `storage.OpenObjectStore` is the small unavoidable
adapter over the same installed public Thanos S3/GCS constructors. It mirrors
pinned v0.12.3 authentication/default mappings rather than implementing storage
protocols. The CLI reuses existing validated environment parsing. Real S3 is
qualified; GCS operator transport has not been exercised. Manual trusted digest
provisioning is explicit until authorized catalog support exists; it is not an
automated catalog or sender-signature implementation.

### Signed remote completion catalog (2026-09-09)

Rauthy v0.36.2's [backup guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/config/backup.md)
defines seven-field scheduling (default `0 30 2 * * * *`), named S3/file restore
with the cluster offline, and separate S3/local retention (30/3 days by default).
GoAuthy's encrypted Rhiza format is feature-goal parity, not Hiqlite binary
compatibility. Scheduling and retention remain open.

No new dependency is needed for completion authorization: stdlib Ed25519 signs
exact JSON bytes; x509/PEM decode native PKCS8/PKIX keys; SHA-256, bounded I/O and
existing Thanos conditional writes implement verified publication/download.
The project-specific signed record and deterministic object paths are necessary
glue: neither Rhiza's live archive nor age recipients supply a dated, authorized
backup catalog. No custom cryptographic primitive or Rhiza codec is implemented.
Catalog/source namespaces, artifact ID, size and digest are signed; a single
externally pinned public key establishes reader trust. Freshness, deletion
resilience, automated key rotation and retention are not inferred from signatures.

### Completed-artifact retention and scheduler research (2026-09-09)

Retention needs no new dependency: reuse authenticated `ListCompleted`, native
object-store Delete, streaming SHA-256 and stdlib UTC calendar arithmetic. Native
Delete's not-found classification allows retry after artifact-first partial
cleanup; no private Rhiza retention or live-GC mechanism is reused for dated
backup deletion. Keeper verification reuses publication's remote digest check.

A repository search found no installed compatible cron parser. Existing
`time.NewTicker` workers support intervals only. [Kubernetes CronJob](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)'s five fields
cannot preserve the pinned Rauthy seven-field expression including seconds/year;
[robfig/cron/v3 parser](https://github.com/robfig/cron/blob/v3.0.1/parser.go) also has no year field. The parser-only gorhill/cronexpr
`v0.0.0-20180427100037-88b0669f7d75` and
[HashiCorp cronexpr v1.1.3](https://github.com/hashicorp/cronexpr/releases/tag/v1.1.3)
were rejected for direct parity. Rauthy's pinned Rust cron 0.17 uses years
1970–2100, Sunday=1 through Saturday=7 and DOM AND DOW; both Go candidates
use 1970–2099, Sunday=0/7 and DOM OR DOW, and silently ignore fields beyond
seven. Their Next mutates expression state, requiring serialization. Isolated
Go probes also found gorhill returning a past instant for the New York spring
2027 DST gap; HashiCorp skips that nonexistent time. Rauthy's Rust scheduler
uses local time and preserves both ambiguous fall-back occurrences. Sources:
[pinned Rauthy scheduler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/schedulers/src/lib.rs),
[pinned dependency lock](https://github.com/sebadob/rauthy/blob/v0.36.2/Cargo.lock),
[Rust cron source](https://github.com/zslayton/cron).

No dependency or custom grammar was added. A faithful parser, cancellation,
non-overlapping execution and HA ownership remain unimplemented; accepting only
the default expression would not satisfy arbitrary Rauthy schedule parity.

### Executable scheduler reference and Quartz candidate (2026-09-09)

The upstream parser's year is optional: six-field longhand and `@yearly`,
`@monthly`, `@weekly`, `@daily`, `@hourly` are accepted. Exactly-seven-only
validation would be an incompatible restriction. The pinned development-only
[reference checks](../test/compat/rauthy-cron/README.md) execute Rust cron 0.17.0
and verify accepted/rejected inputs, DOM/DOW conjunction, year 2100/exhaustion
and both New York DST transitions. They are not Go scheduler completion evidence.

[go-quartz v0.15.2](https://github.com/reugn/go-quartz/tree/v0.15.2) is another
candidate: isolated probes support year 2100, six fields, Sunday=1, and spring DST gap handling. Direct adoption still fails: `0 0 0 1 * 2 *` is
rejected as `day field set twice`, whereas Rust accepts the conjunction. A public-API
intersection adapter can combine two triggers for DOM/DOW, but sequential
NextFireTime calls skip the second fall-back occurrence: New York November 7,
2027 01:30 EDT is followed by November 8 01:30 EST, whereas the Rust reference
yields November 7 01:30 EST. The initial probe only asserted distinct instants,
which was insufficient; exact timestamps now have a runnable
[isolated candidate check](../test/compat/go-quartz/compat_test.go).
Run `cd test/compat/go-quartz && go test -race ./...`; passing confirms the
known incompatibilities, not parity. The candidate's parsed fields are private,
so there is no exported field matcher to reuse for a faithful conjunction/DST
evaluator. No production dependency or custom scheduler was added.

### Standard-library calendar implementation (2026-09-09)

The [scheduler component](backup-scheduling.md) now uses stdlib `time.ZoneBounds`
to enumerate constant-offset intervals and a bounded cron field parser. This
avoids relying on `time.Date` to choose ambiguous wall times. An opt-in
cross-language gate compares Go acceptance/field values with the actual pinned
Rust parser. The native Go checks cover New York gaps/folds, Lord Howe's
half-hour fold and Apia's skipped day. A further Rust probe showed that its
iterator itself can move backward in UTC during a repeated hour; GoAuthy
explicitly corrects that behavior with strictly future chronological results.
Automatic backup dispatch, HA ownership and scheduler E2E remain open.

### Complete creation trigger (2026-09-09)

`backup.Create` and the `create` operator command reuse `Export`, `Publish`,
stdlib private temporary files and the existing storage configuration/provider
factory. No new package, cipher or Rhiza encoding is introduced. The small
composition ensures a failed export never reaches catalog publication and
removes owned local ciphertext on every return. Independent destination
configuration is validated without inheriting explicit source credentials.
This is the executable unit needed by scheduled dispatch; it does not establish
HA scheduling or exactly-once execution.

### Backup worker coordination (2026-09-09)

The implementation uses Rhiza v0.12.3 public `KVCAS` with native TTL and committed
mutation receipts, stdlib context/timer/randomness and a SHA-256 scope key. It
avoids a custom object-store lease protocol and a new SQL schema. Native CAS
compares the holder bytes atomically; renewal and conditional expiry reuse it.
Cancellation/lifecycle glue is application code because no investigated package
owns the existing Rhiza handle and this callback contract.
[Lease tests and limits](backup-scheduling.md) distinguish cooperative ownership
from remote publication fencing and same-schedule-slot deduplication.

Completion slots reuse the same Rhiza KV API: linearizable reads, a canonical
Unix-second value, and exact previous-value CAS only after the callback succeeds.
This small application policy prevents successful sequential replays without
adding a table or an external job framework. It intentionally leaves the remote
publication/marker crash gap visible; see [slot contract](backup-scheduling.md).

Timer dispatch reuses stdlib `time.Timer`, context cancellation/deadlines and
the existing `RunSlot` wrapper. No external scheduler dependency or persistent
local job state is added. The actual standalone/S3 callback now composes
`Create` and `Prune`, with remote fetch/restore SQL verification; production
configuration and three-voter failure qualification remain open.

### Scheduled backup server configuration (2026-09-09)

The server reuses `internal/backupconfig` for the existing CLI's bounded native
age recipient and Ed25519 PKCS8 readers and independent object-store destination
settings. Standard `time/tzdata` supplies named zones in the scratch binary;
standard context, timers and the existing worker WaitGroup manage shutdown.
No additional runtime dependency or Kubernetes CronJob/PVC is introduced.

### Snapshot acquisition collision (2026-09-09)

The real three-voter scheduled gate reported `source archive changed during
snapshot acquisition` under the one-second checkpoint stress profile. Rhiza
v0.12.3's native loader deliberately rejects a changing head; its snapshot and
compaction paths also share the archive GC lock. GoAuthy retains these checks.
`Create` owns the unpublished temporary file, so a bounded standard `time.Timer`
loop retries only the exact native moving-head/maintenance-busy outcomes and
resets that file before each attempt. A generic retry package would add no
needed behavior and could accidentally retry remote publication; no package was
added. Direct `Export` still requires callers to discard output on any error.

### Backup signing-key overlap (2026-09-09)

The previous single-key catalog reader prevented changing signers while keeping
old backups. Existing [stdlib Ed25519 verification](https://pkg.go.dev/crypto/ed25519#Verify),
[PKIX parsing](https://pkg.go.dev/crypto/x509#ParsePKIXPublicKey) and
[PEM decoding](https://pkg.go.dev/encoding/pem#Decode) already provide the needed
cryptography and wire formats. No JOSE envelope, custom cipher or dependency is
needed. A local bundle contains at most 32 distinct public keys/16 KiB; each
unchanged signed receipt must verify under one configured key. The application
code supplies only bounded input validation, operator trust selection and the
current-signer-in-bundle requirement. Standard PEM decoding can skip malformed
blocks, so skipped blocks/junk are explicitly rejected. No remote key discovery
or record rewrite is introduced; rotation uses overlap trust and process restart.
Removing an old key intentionally makes remaining old receipts fail closed.

### Checkpoint publisher contention during export (2026-09-09)

Rhiza v0.12.3's [checkpoint recovery pin](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/checkpoint/checkpoint.go)
uses the same native `checkpoint/PUBLISHER` claim as checkpoint publication and
GC. A real native-claim regression proves that an active claim returns
`checkpoint.ErrPublisherBusy` before backup publication and that explicit claim
release makes the same snapshot inputs succeed. This is a transient acquisition
failure. GoAuthy's existing six-attempt stdlib timer loop now also permits that
exact error string. No new retry framework or native lock implementation is
needed. Each retry discards unpublished capture state; a joined cleanup error,
fenced pin or integrity error is not included. The older generic Kind failure
remains unexplained; the independently reproduced collision is the evidence for
this change.

### Paused-backup observer: native Rhiza read replica (2026-09-09)

The Kind chaos observer reuses Rhiza v0.12.3 `OpenReadReplica`, `Sync`, and
`KVGet` rather than exposing a production admin endpoint or reading live SQLite
files. The native replica follows certified checkpoint/archive state without
voting or writing cluster state. This is eventual evidence, not a linearizable
read. The small test executable only maps fixture configuration, reproduces the
existing scheduler storage-identity hash, and checks an expected watermark under
a 90-second context. Those application-specific assertions are not a replacement
DB, lease implementation, or new package. Source inspected: pinned module
`replica.go` and `pkg/materializer/materializer.go`; no new dependency is needed.

### Exact remaining retention differences (2026-09-09)

Rauthy v0.36.2 pins Hiqlite 0.14.0. Its
[backup job implementation](https://github.com/sebadob/hiqlite/blob/c8316c53799c509990475ea8e2aa2ef8679e070e/hiqlite/src/backup.rs)
uses a strict UTC `created < now - keep_days` cutoff after backup, default 30 days.
GoAuthy already implements that cutoff and successful scheduled Create/Prune
sequence. Two actual behavior differences remain: GoAuthy preserves the newest
signed entry per source, while upstream deletes every recognized expired entry;
GoAuthy accepts 1..36500 days while upstream's u16 accepts 0..65535. Thus the
remaining parity item is concrete policy/range compatibility, not a need for a
new retention library. Standard time arithmetic and existing catalog validation
are sufficient. Any compatible mode must retain fail-closed signature validation.

Required acceptance evidence for an upstream-compatible policy: all entries for
one source expired (including the newest), multiple sources, exact cutoff,
zero-day retention, maximum u16 input, and malformed/untrusted catalog with zero
deletes. The server must pass the selected policy through its actual scheduled
Create/Prune path. Existing keep-newest behavior must be explicitly documented
when selecting a policy; the unchecked parity item is not resolved by this research.

Persistent local backup retention is outside this project's explicit no-PVC,
object-storage DR architecture: local ciphertext is owned temporary staging and
removed by Create. The official Rauthy backup documentation's local three-day
statement differs from the pinned Hiqlite code's default 30, so it is not treated
as executable evidence. Unsigned orphan sweeping remains separate from this
upstream-compatible completed-backup policy.

The explicit policy and u16 range above are now implemented through
`PruneWithPolicy`, CLI `-retention-policy`, and server
`GOAUTHY_BACKUP_RETENTION_POLICY`. Existing Prune/default config preserves
keep-latest; selecting expire-all provides the upstream expiration capability.
Focused library race, full backup/CLI race and real MinIO operator/runtime tests
passed. New-policy Kind qualification is still outstanding; the concurrently
running pause gate uses its earlier built candidate, not this retention change.

### Backup-key provisioning requirement audit (2026-09-09)

Pinned Rauthy v0.36.2's
[backup guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/config/backup.md)
uses the preconfigured active encryption key for remote backup encryption and
requires operators to retain that key for DR. Its
[encryption guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/config/encryption.md)
assigns key maintenance and Secret updates to administrators. Rauthy does not
provide an independent backup signer/age-recipient distribution controller.
CLI config/key generation is a separate bootstrap capability and remains subject
to its own feature ledger; it is not automated running-cluster secret delivery.

Accordingly, GoAuthy's previously listed backup-secret auto-distribution is an
optional operational enhancement, not a missing Rauthy backup feature. The user
requires no-PVC/object-store DR and secure implementation, not an automatic secret
control plane. Existing operator-managed private keys/trust bundles, overlap
rotation and independently restored identities remain required and tested.
No secret-generation controller or new dependency is added merely to satisfy an
unsupported inferred requirement. Any future automation must independently
persist its secrets outside disposable application storage.

### DPoP output for token exchange (2026-09-09, implementation qualification pending)

Pinned Rauthy v0.36.2 validates an optional token-endpoint DPoP proof and passes
its thumbprint to the issued token, while requiring Bearer subject and actor
inputs in the shared input validator:
[grant implementation](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/grant_types/token_exchange.rs),
[token-exchange guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/work/token_exchange.md).
[RFC 9449 section 5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5)
applies DPoP to access-token requests regardless of grant type;
[RFC 8693 section 2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1)
requires validation appropriate to each input token type and does not require
accepting DPoP-bound inputs.

Reuse the existing Fosite exchange handler, go-jose proof verification and
Rhiza nonce/replay persistence. Only the token-endpoint grant allowlist needs
extension; no new protocol implementation or dependency is warranted. Preserve
Bearer-only input validation, client authentication, scope/audience/expiry
constraints and no-refresh behavior. A request proof must not rebind a stolen
constrained subject/actor token. Supporting differently bound inputs would
require a separate ownership/delegation design and is not pinned upstream
behavior. Browser E2E now includes output signature/cnf, cross-pod nonce replay
and bound subject/actor rejection assertions, but only compilation has passed;
new-image live qualification remains pending.

The first new-image Kind run (`/tmp/goauthy-dpop-exchange-kind-20260909.log`)
reached successful DPoP exchange issuance and signature verification, then failed
the new test's audience assertion. Existing `access_jwt.go` intentionally signs
`aud=[clientID, grantedResource]`, whereas introspection exposes granted resource
audiences. The test incorrectly expected only the resource. It now requires the
exact existing two-element signed audience and reports only comparison booleans.
No runtime audience policy was changed. Full live qualification remains pending.

DPoP fault continuity reuses the existing Kind full-profile faults and browser
proof helpers. `GOAUTHY_E2E_DPOP_CONTINUITY=1` prepares one private 0600 fixture
after the initial suite; verifies its saved access/refresh/key after Pod
replacement, quorum recovery and rolling restart; and checks refusal with one
voter. The fixture is inside the driver's already-cleaned temporary directory.
No new package or production API is needed. Make dry-run shell parsing passed;
`/tmp/goauthy-dpop-continuity-kind-20260909.log` is the pending live qualification,
not evidence of a pass yet.

The first continuity run failed during preparation with login HTTP 429, before
any continuity fault: the immediately preceding brute-force test intentionally
leaves a one-minute block. Preparation now runs after the initial OAuth/JWKS
suite but before that brute-force test, using its already-open pod forwards.
The attack test remains intact and the saved credential is checked only after
subsequent faults. No cooldown was shortened or protection disabled. The
unavailable test now requires the actual handlers' 401 Bearer UserInfo and
500 server_error token responses, not arbitrary non-200 errors. Updated Make
shell parsing passes; the original run is not a continuity PASS.

The reordered continuity run completed with exit 0:
`/tmp/goauthy-dpop-continuity-kind-order-20260909.log`. Five phases passed:
prepare 1.12s, post-Pod-replacement verify 1.71s, one-voter unavailability 0.02s,
post-quorum-recovery verify 1.78s, post-rolling-restart verify 1.62s. The original
access/refresh/key lineage is reused across each fault, and availability failures
match the explicit public-handler responses. This qualifies auth-code DPoP
credential continuity, not every grant's policy-update race.

Dynamic confidential-client DPoP policy now has an opt-in
`GOAUTHY_E2E_DCR_DPOP=1` cross-pod E2E. It reuses DCR and existing proof/JWKS
helpers to check authenticated PUT true/false/true, required-proof authorization
code and client-credentials issuance, missing-proof denial, third-pod metadata
and introspection, and bearer issuance when optional. Compilation and vet passed;
its new live gate is pending. The sequence does not claim a concurrent policy
update versus issuance-commit interleaving; existing real-Rhiza policy race
regressions cover that narrower storage invariant.

The first dynamic-DPoP Kind run ended before issuance, at registration HTTP 400
(`/tmp/goauthy-dcr-dpop-kind-20260909.log`). The public DCR request validator
at that candidate rejected `client_credentials` grants and authorization-code-only
`refresh_token` registration, despite underlying client/storage support. The
new test requested a confidential mixed auth-code/client-credentials client.
This exposes a registration-surface boundary, not a demonstrated DPoP verifier
failure. Upstream DCR admission must be checked before changing that boundary;
no new live policy qualification is claimed.

Pinned Rauthy DCR admission check confirms this is a real gap:
[`DynamicClientRequest`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/clients.rs)
uses the typed grant list, and
[`Client::try_from_dyn_reg` / `create_dynamic`](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs)
copies it into enabled flows. Confidential client-credentials and auth-code plus
refresh are not admin-only. Reuse GoAuthy's existing DCR request/store validation
and Fosite grant handlers; no extra package is justified. Preserve confidential
client-credentials admission, auth-code redirect/response metadata, unsupported
grant denial and refresh-only denial. Dynamic token-exchange execution remains
separate because pinned Rauthy rejects dynamic clients for that grant.

### Remaining token-exchange parity after DPoP output (2026-09-09)

Pinned Rauthy preserves `actor_claims.act` beneath the immediate actor's `sub`:
[token-exchange handler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/grant_types/token_exchange.rs),
[guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/work/token_exchange.md).
GoAuthy currently retains only the immediate `act.sub` in persisted session and
introspection, and its signed access-token claim type has no actor field. This
is an implementation gap. Existing stdlib JSON validation, reserved custom-claim
names, go-jose signing and the depth limit already used for custom JSON can be
reused; no new package is indicated. Correct completion needs signed/persisted
actor matching and account-validity checks for the whole bounded chain, not just
adding an output JSON property.

Rauthy also authorizes the confidential exchanging client independently of the
source/actor client IDs and uses that client's configured target allowlist and
default audiences. GoAuthy's same-client/single-granted-audience containment is
narrower. That coupled authorization/target-policy change remains separate and
must preserve authenticated grant opt-in, valid active Bearer inputs, scope
restrictions and expiry/revocation checks. Multiple request targets are not
required: Rauthy still selects one requested audience/resource.

`may_act`, external JWT/SAML inputs and refresh output are not supported by the
pinned Rauthy exchange implementation. They are not unfinished upstream parity
features merely because RFC 8693 can describe broader deployments.

DCR grant admission is now implemented in the shared HTTP create/update decoder
and Store validation. Focused real-Rhiza race tests passed (28.446s), including
confidential code/client-credentials policy updates, pure client credentials,
public code plus refresh, and invalid grant combinations. Existing untrusted
HTTP input regressions passed (30.819s). OpenAPI grant metadata was updated and
its package tests passed (2.331s). The combined live Kind rerun is pending;
these local results do not qualify dynamic DPoP issuance across pods.

The combined live rerun completed with exit 0:
`/tmp/goauthy-dcr-dpop-kind-grants-20260909.log`, cluster
`goauthy-dcr-dpop-20260909b`, all four DCR/Device/continuity flags enabled.
Dynamic required-DPoP policy issuance passed in the 35.768s browser suite.
Bootstrap credential continuity passed prepare/replacement/quorum loss/recovery/
rolling restart (1.03/1.57/0.01/1.61/1.72s). This supersedes the pending live
qualification above; dynamic credential fault continuity is still separate.

### Dynamic DPoP credential fault continuity (2026-09-09, pending live gate)

The healthy three-pod dynamic policy test does not establish that the same
dynamic client's key, refresh credential and required-proof policy survive
faults. Extend the existing Kind continuity phases with a second private
fixture and reuse stdlib JSON/0600 atomic files, DCR HTTP helpers and existing
DPoP proof verification. No production package or new fault driver is needed.
After each recovery, a fresh client-credentials request without proof must
still fail: rejecting a previously bound refresh token alone would not prove
that the client's required-proof metadata survived. Both bootstrap and dynamic
credentials must retain their existing access/refresh/key checks. Cleanup must
run after the final phase, not as prepare-process test cleanup.

The driver requires full profile, `GOAUTHY_E2E_DPOP_CONTINUITY=1`,
`GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1` (DCR offline-access scope policy), and
`GOAUTHY_E2E_DCR_DPOP_CONTINUITY=1`. Shell syntax validation passes; invoking
the dynamic flag without its prerequisites fails before cluster creation.
Live qualification remains pending.

Nested actor issuance review found an existing reusable security fence:
`Store.issuanceAccounts` captures account deadlines, `BeginTX` carries them
into the exchange transaction, `accountExpiryGuard` guards both target INSERTs,
and `validateIssuanceAccounts` rechecks before response. The current actor
lookup collects only its immediate subject. A bounded actor-chain decoder must
feed all asserted ancestors into this existing account context as well as
consumption validation; otherwise adding signed `act.act` alone would leave
ancestor disable/deadline races unguarded. Keep the direct source/actor token
revocation guards. Regression evidence must include ancestor disable/deadline
change at the existing issuance hook with no target row, earliest-deadline
expiry capping, and inactive introspection after ancestor disable. This is
design evidence only; nested-actor implementation remains pending.

Dynamic continuity final evidence: the named pending gate above passed with
exit 0, cluster `goauthy-dynamic-continuity-20260909`, log
`/tmp/goauthy-dynamic-continuity-kind-20260909.log`. Dynamic phases passed
prepare 0.58s, replacement 1.00s, unavailable 0.01s, recovery 0.74s, rolling
restart 0.75s, cleanup 0.03s. Bootstrap continuity and the complete selected
profile also passed. Read-only requirement audit found no additional concrete
pinned-Rauthy DPoP feature gap after this gate; the feature row is now checked.
This qualification neither closes actor-chain exchange parity nor claims all
optional RFC 8693 deployments. Existing stdlib/Go-Jose/Rhiza helpers sufficed.

### Nested actor implementation candidate (2026-09-09)

The existing OIDC claims layer now defines a bounded typed `ActorClaims` chain.
It reuses `encoding/json`, Go-Jose signing and the existing JSON-depth ceiling
(8 actor nodes). A strict shared decoder accepts only nonempty `sub` and an
optional nested `act`; null, unrelated fields and excessive depth are rejected.
Typed signing also rejects cyclic chains before JSON encoding. The OIDC package
tests passed (42.011s); the final focused test additionally checks correctly
signed malformed actors and the maximum-depth signed round trip (0.828s).
No new dependency is needed: delegation semantics are application policy,
while cryptographic verification remains in Go-Jose.

OAuth integration and live actor-chain qualification are pending. Existing
actor E2E used optional externally provisioned credentials and could skip the
actor branch; the new opt-in gate must provision its own distinct actor or fail,
so a generic token-exchange PASS cannot substitute for nested-chain evidence.

Upgrade behavior: earlier actor-exchange JWTs omitted signed `act` even though
their stored sessions contained `act.sub`. Strict signed-versus-persisted actor
matching intentionally rejects those old credentials; callers must obtain new
actor-exchange tokens. Accepting a missing signed actor as equivalent would
weaken the new authority binding. Ordinary tokens without a stored actor remain
unaffected. No permissive migration exception is introduced.

The ancestor commit-race test exposed an existing error-classification issue:
token exchange mapped every `Store.Commit` error to `server_error`, including
`fosite.ErrSerializationFailure` returned when the guarded target rows are
absent. That sentinel distinguishes an invalidated grant/account snapshot from
a database failure. The candidate maps only that typed sentinel to
`invalid_grant`; provider errors retain `server_error`. Regression tests must
check exact response and absence of both access-token and token-request rows
for ancestor disable and deadline mutation.

Final focused OAuth actor selection passed normally (7.314s) and with the race
detector (48.793s). It covers nested JWT/session/introspection equality, absent
and altered signed actor denial, ancestor expiry capping/inactivity, both
disable and exact-deadline commit races with no target access/request rows,
and existing actor revocation/expiry guards. OIDC and OAuth vet passed. The
self-provisioned `GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR=1` full-profile Kind gate
is running; no live nested actor pass is claimed yet.

First actor-enabled Kind run ended before actor issuance with HTTP 405 creating
the fixture (`/tmp/goauthy-nested-actor-kind-20260909.log`, exit 2). The main
router registers administrator user creation only when password recovery is
configured, and the default full profile had no mail/recovery service. Reuse
the existing password-reset Kustomize overlay and SMTP sink when actor E2E is
enabled, keeping the full profile's test/chaos sequence. No production bypass
or direct DB fixture insert was added. Render and shell syntax checks pass;
the corrected live gate is running.

Corrected nested actor Kind gate passed with exit 0:
`/tmp/goauthy-nested-actor-smtp-kind-20260909.log`, cluster
`goauthy-nested-actor-20260909b`. Mandatory self-provisioned actor exchange
(including nested public JWT and cross-pod introspection) passed in 19.396s.
The rest of the full profile and generic replacement/quorum/restart checks
passed. No same-nested-credential fault-continuity claim follows from generic
post-fault smoke checks; that qualification and cross-client target policy
remain open.

### Nested actor credential continuity (2026-09-09, live pending)

The preceding nested-actor live gate deleted its actor fixture before the
generic fault phases. Extend the existing credential-continuity driver rather
than treating generic post-fault smoke as actor evidence. A separate private
fixture must retain the original nested token and expected subjects across
replacement/quorum recovery/rolling restart, with signed chain and active
introspection checked on all three pods. The final phase revokes that same
token and verifies cross-pod inactivity, then removes the actor account.

`GOAUTHY_E2E_ACTOR_CONTINUITY=1` enables the existing SMTP/recovery actor
fixture automatically. The driver now has common credential-continuity function
names; DPoP phase semantics are unchanged. Shell syntax passes, and a non-full
profile is rejected before cluster creation. Reuse existing HTTP/JWKS helpers
and stdlib private-file handling; no new production package is needed.

Cross-client next-step source audit confirms separate exchanger-owned
`allowed_resources` and `default_aud` policies:
[Rauthy exchange handler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/grant_types/token_exchange.rs),
[audience construction](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/token_set.rs).
Input client/audience equality is not its admission rule. The exchanger must
be enabled, confidential, explicitly grant-enabled and not dynamically
registered. Its output audiences contain its own ID, all configured defaults,
and the one optional requested resource/audience (deduplicated). GoAuthy's
managed `Audiences` can represent allowed targets, but its one-value process
default map is insufficient for multiple managed-client defaults. Preserve
separate metadata and generation guards rather than treating allowed targets
as defaults. This remains unimplemented design evidence; source/actor validity,
revocation, account and proof constraints must remain covered during the change.

Actor continuity final live evidence: combined gate
`goauthy-actor-continuity-20260909` completed with exit 0; log
`/tmp/goauthy-actor-continuity-kind-20260909.log`. Actor phases passed prepare
4.66s, replacement 1.27s, unavailable 0.01s, recovery 1.29s, rolling restart
1.29s, revoke/delete cleanup 2.02s. The SAME stored nested token was verified
after each fault, and final revocation was inactive on all three pods before
actor deletion. Existing bootstrap/dynamic DPoP continuity and the selected
full profile passed in this same run. This closes the prior nested-token fault
qualification gap, not cross-client exchange/default-audience policy.

### Cross-client exchange implementation candidate (2026-09-09)

Managed clients now persist independent `default_aud` lists in existing
metadata JSON; no schema migration or dependency is required. Missing updates
preserve defaults, [] clears them, and changed defaults invalidate the client
generation. Pinned Rauthy keeps defaults independent of allowed requested
resources, so no default-subset constraint was invented. Focused managed
metadata/validation tests passed (4.548s); OpenAPI tests passed (2.414s).

The exchange handler now admits confidential bootstrap/managed clients with
explicit exchange flow, defers resource/audience handling to that handler, and
checks the single requested target against exchanger/global policy. It emits
exchanger ID + configured defaults + optional target, rather than restoring
input audience. Other grant use of the new managed defaults is a separate
remaining policy task.

Security review identified a newly reachable input-client race: existing
output managed-client guards do not protect a different source/actor client's
generation. Source token row existence is insufficient after that originating
client is disabled or its generation changes. The candidate must guard both
input clients' persisted generation at the same replicated target commit,
while preserving ordinary cosmetic-update compatibility. No live qualification
is claimed until these regressions and the cross-pod gate pass.

Input-lifecycle follow-up: `dcr.Store.DeleteRegistration` deletes the dynamic
client row without deleting OAuth access/request rows. Cross-client exchange
therefore also needs a commit-time existence predicate for dynamic input
clients; token-row presence alone would allow a post-validation deletion race.
Bootstrap and immutable CIMD/ephemeral input representations must not be
misclassified as DCR. This guard belongs beside the managed-input generation
predicate on both target INSERTs, and needs a real Rhiza regression.

The input-client fence is implemented on both target INSERTs. Managed generation/
active-state races and DCR source/actor deletion now reject without target rows;
unchanged managed inputs survive cosmetic revisions, and unchanged dynamic
source+actor inputs still issue. Cutoff argument positions are captured when
appended, avoiding the actor-signature overwrite caused by deriving positions
from variable-width trailing guards. Focused HTTP/commit controls pass; integrated
race and Kind qualification remain pending at this entry.

Remaining scope/claim parity was checked against pinned Rauthy's
[token_exchange.rs](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/grant_types/token_exchange.rs)
and [token_set.rs](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/token_set.rs).
Rauthy narrows requested scopes against the subject token, uses the actor for
`act` without intersecting its scopes, and populates user roles, scoped groups,
and configured custom access claims. GoAuthy still rejects groups/custom scopes
in exchange inputs/requests, intersects actor scopes, and clears target extra
claims. These are concrete remaining gaps, not RFC features unsupported by the
pinned upstream. Existing account/role/custom-claim snapshot and commit guards
must be reused when closing them; merely removing admission checks would not
supply or fence the missing claims.

Live qualification caught two integration gaps before completion. The first
Kind run rejected managed `default_aud` at HTTP decoding: both strict create/
update field allowlists now admit it, and real handler CRUD/null/duplicate
regressions pass (4.225s). The second run passed issuance/JWT verification but
exposed an incorrect E2E expectation: the existing Fosite introspection writer
returns granted resource audiences and a separate `client_id`, while the signed
JWT additionally includes the exchanger ID in `aud`. The E2E now checks each
existing contract independently; the matching real HTTP regression passes
(1.905s). Neither failed Kind run is treated as qualification.


Final cross-client gate `goauthy-cross-client-20260909c` completed with exit 0
(`/tmp/goauthy-cross-client-final-kind-20260909.log`). The new real API cross-client
case passed inside the 43.756s browser suite; existing actor exchange passed
20.907s. The combined run also passed original actor/bootstrap-DPoP/dynamic-DPoP
credential continuity through pod replacement, quorum loss/recovery and rolling
restart, with final revocation/cleanup. Cross-client fixtures are cleaned before
those separate continuity phases. New runtime dependencies and schema changes:
none. Detailed scopes and remaining parity are recorded in features/status.

### Token-exchange user claims and subject-only scope policy (2026-09-09 candidate)

The exact pinned Rauthy tag was rechecked with `git show v0.36.2` at commit
`dd61ac3c84d6b238108dc8438b53043b5177a662`; the neighboring checkout's HEAD is
not the baseline. Its token-exchange handler narrows only the subject token's
scopes, without intersecting actor/exchanger scopes or applying browser group
admission. Its TokenSet resolves the current user and custom mappings at issuance.

GoAuthy now reuses currentPrincipal, currentCustomClaims, setPrincipalClaims,
setCustomAccessClaims and the existing principal snapshot/commit guard for user
exchange. It does not copy stale source Extra. Both target INSERTs retain input
lifecycle/account fences and add principal/catalog revisions. No package or
schema change is required; this is wiring existing OAuth/claims/Rhiza machinery.

Review reproduced two valid optional-resolver gaps: custom catalog snapshots
were discarded without a principal resolver, and subsequent per-user attribute
changes still escaped a catalog-only fence. BeginTX now imports independent
snapshots independently; without role/group resolution, currentPrincipal reads
the user's existing RBAC revision before resolving custom values. This protects
both catalog and per-user changes without manufacturing role/group claims.
All four focused controls pass (4.094s), including the previously failing
no-resolver user-revision case. Subject scopes outside exchanger registration
and absence of browser-group admission also pass (1.499s).

The opt-in real API E2E creates current role/group/custom mappings, changes them
after source issuance, and verifies target JWT/introspection plus downscoping.
It passes standalone before and after restart (1.43s/1.44s). Combined Kind/race
qualification is in progress. Machine subject/actor inputs (GoAuthy's empty-sub
machine representation) and managed default audiences in other grants remain
separate incomplete work; this candidate does not mark full exchange parity.


Final user-claim qualification passed: combined Kind
`goauthy-exchange-claims-20260909` exit 0, user-claim/cross-client browser suite
51.350s and existing actor exchange 18.350s. Original actor and bootstrap/dynamic
DPoP continuity passed replacement, quorum loss/recovery, rolling restart and
cleanup. Final absent-resolver/catalog/user-revision and subject-only scope
race controls passed 37.752s after the broader 303.385s OAuth/claims race pass.
Standalone new claim E2E passed before/after restart 1.43s/1.44s. Current named
commands, log paths and remaining machine/default-audience work are in status.


### 2026-09-10: machine subject mapping implementation

Pinned Rauthy v0.36.2 `src/service/src/token_set.rs` selects the issuing client ID for a no-user subject only when global `client_credentials_map_sub` is enabled. Existing Fosite sessions and the existing signed access-token strategy carry this behavior without another dependency or schema migration. GoAuthy keeps the durable user subject empty and stores the selected public subject in a private session marker. This distinguishes validated client-credentials/exchange origins from deleted user accounts, which must remain invalid.

The small custom adapter is necessary because Fosite's session subject alone cannot distinguish a mapped client ID from an identity ID. A positional boolean mask beside the already bounded actor chain preserves account checks for real-user actors, including user/client ID collisions. Markers are excluded from introspection. Stdlib environment parsing supplies GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB; no cryptographic primitives are reimplemented.

Focused machine tests verify mapped/unmapped issuance, actor acceptance/rejection, chained exchange after configuration changes, and introspection marker non-disclosure. Broader OAuth/CLI regressions passed (80.492s / 1.472s). Default and mapped standalone E2E both passed before and after restart; these runs retain DataDir and do not by themselves qualify diskless DR. Kubernetes and race results remain pending.

### 2026-09-10: shared managed default audiences (candidate)

Pinned `git show v0.36.2:src/service/src/token_set.rs` builds access audiences
from the client ID, always-on `default_aud`, and the explicit resource. Defaults
are independent of the resource request allowlist. Fosite v0.49.0's refresh
handler revalidates the original granted audience against `Client.GetAudience`;
merging defaults there would reject valid refreshes or require widening explicit
resource admission. Neither change is needed.

The existing signed-access-token adapter now writes a copied private string-array
snapshot only during GenerateAccessToken. This occurs after Fosite's second
code-session load, avoiding a new exception to storage's strict rehydration.
Fosite's DefaultSession.Clone uses a deep copy for refresh, and JSON decoding
provides independent stored sessions. Missing fields retain exact old-token
semantics; new empty defaults use an explicit empty array. The existing strict
string-list decoder and HTTPS resource validator reject malformed snapshots;
custom-root collisions cannot become audience authority. No dependency or SQL
schema is added. Existing client revision/generation guards remain authoritative.

JWT matching and introspection use persisted defaults, not current metadata.
The access-token index records effective resource audiences for existing atomic
resource mutation guards, while request JSON keeps explicit grants for refresh.
New exchange requests use the same shared snapshot boundary; previously stored
exchange grants are not reclassified or rewritten. Bootstrap resource defaults
keep their existing behavior. This is a candidate pending full grant/live gates.

A Pro consultation independently recommended this boundary over modifying Fosite
refresh policy or inferring old token semantics from current client metadata.
Its suggested versioned object was unnecessary for this single fixed string-array
format: field presence distinguishes legacy from newly applied empty defaults,
and invalid types fail closed. Mixed old/new application binaries remain a
rollout limitation: old validators do not understand newly signed default
extensions, so coordinated replacement or a future staged activation is needed.

### 2026-09-12 Per-client logout metadata and recovery

Managed and dynamic registration use existing `internal/clients`, `internal/dcr`, stdlib JSON/regexp and Rhiza transactions for nullable backchannel URI metadata. No new dependency was introduced. Subject and optional browser-session associations live in the same issuance transaction; dynamic URI values are resolved there to avoid stale client snapshots. Metadata updates synchronize existing associations atomically; authenticated dynamic deletion and anonymous cleanup remove their associations and queued deliveries. Signing/TLS delivery reuses `internal/oidc`, `go-jose/v4` and `internal/backchannel`.

Focused evidence includes real managed/dynamic TLS delivery, delayed URI registration, update/removal races, guarded deletion rollback, schema87 migration and fresh-directory S3 recovery with retained password refresh claims. Linux interrupted-install tests cover five SIGKILL phases. These package mappings do not mark multi-host/Kubernetes or whole-port parity complete.
