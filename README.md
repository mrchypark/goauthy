# goauthy

[**Current product capabilities:**](docs/capabilities.md) use this matrix to decide which
features are Qualified, Preview, Experimental, or Unsupported. The dated execution ledger
remains in [docs/status.md](docs/status.md), while Rauthy parity is tracked separately.

[**Qualification (2026-09-17):**](docs/status.md) All six audit gates PASS — normal, race, vet, Kind pre/post pod replacement, schema v97→v102 upgrade, and real MinIO v98–102 fresh-dir recovery. Full pinned Rauthy goal remains incomplete; see [docs/status.md](docs/status.md) for current ledger.

[프로젝트 목표·진행 현황·남은 작업](docs/status.md)

GoAuthy uses Rauthy `v0.36.2` as a fixed behavior baseline while also providing
GoAuthy-specific external-connection and credential-delegation capabilities. Rauthy parity
is a compatibility ledger rather than the sole product roadmap. GoAuthy uses
official Rhiza `v0.12.3` (commit `97a9d18aadc66d3b5390f6fa64de2d65dd9f0d48`) as its only database. Rhiza
`v0.9.0` is retracted because its published proxy-cached commit was wrong.
v0.10.0 remains the historical baseline for earlier recorded runs.
Rhiza v0.10.0 introduced bounded graph reachability APIs; GoAuthy does not need or
use them. Existing `Open`/`Ready`/`Query`/`Execute` APIs remain compatible,
as covered by successful local tests.

The default deployment goal is **no GoAuthy PVC**, with object-store disaster
recovery. Local QLog/SQLite/LatticeDB files are disposable recovery state;
acknowledged writes require Rhiza `before-ack` publication. Master keys and
cluster identity are supplied independently. See [the storage contract](docs/no-pvc-dr.md).

The current database stack also uses official LatticeDB v0.6.0 through `latticedb-go`.
The Go integration does not require cgo, and no Rust SDK is required.

## Status reconciliation (2026-09-05)

Core symbols and routes mounted in `cmd/goauthy/main.go` are the source of
truth. The focused geoblock, login-policy, and IP-blacklist tests passed with
`go test -p 1 -count=3`; focused command admission/config/browser-authority
tests and `TestTokenMetricsConcurrentTokenRequests` also passed at count 3.
The full serial Go suite passes. A fresh exact-three-node `make e2e-kind`
passes RFC 8252, DCR, JWKS rotation, pod replacement, quorum loss/recovery,
and rolling restart. Specialized Kubernetes profiles remain independently
tracked below. Recent fixes include the Fosite request-state race root fix,
authorization-code client binding, Authorization/API-Key no-fallback,
canonical X-Forwarded-For/Forwarded handling, deterministic goroutine cleanup,
and serialized E2E port allocation.

Geoblock and manual IP-blacklist cores are implemented and source-wired behind
opt-in configuration (`GOAUTHY_GEOBLOCK_*`, `GOAUTHY_IP_BLACKLIST_ENABLED`),
including the `/auth/v1/blacklist` admin routes. Geoblock accepts either a
trusted country header (requiring configured trusted proxies) or a local
MaxMind database; country values are strict ASCII ISO alpha-2, with explicit
allow/deny and unknown-country policy. The standalone
`scripts/e2e-geoblock-standalone.sh` and exact-three
`scripts/e2e-geoblock-ha-kind.sh` live gates pass health, allow/deny/unknown,
malformed/ambiguous forwarding, all-pod admission, pod-1 replacement, and
trust-boundary rollout/spoof denial. Real official MaxMind test-database
lookups now pass standalone and exact-three HA; there is no downloader or
update scheduler. Manual blacklist tests
and automatic failed-login admission also passed focused `-p 1 -count=3`
coverage with exact 7/10/15/20/25 thresholds, replicated atomicity, and a
two-observation clock-skew guard.
Upstream-provider live Kind E2E/chaos verification,
SCIM encrypted per-client configuration, FedCM password-only landing
limitations and real browser/Kind/chaos E2E, and full UI/OpenAPI/backup/event-stream/PAM
surfaces remain incomplete. The standalone Forward Auth identity/header and
hostile-header E2E passes via `scripts/e2e-forward-auth-standalone.sh`. The
final exact-three Forward Auth gate
`KIND_CLUSTER=goauthy-forward-auth-ha-e2e-final7 E2E_PORT=20400
./scripts/e2e-forward-auth-ha-kind.sh` runs on application ports `20400-20402`
and passes all-pod identity headers and
hostile-header clearing, pod-0 UID replacement with persisted-token validation,
revocation and final-admin self-delete denial, and cleanup. Broader proxy modes
and ACL parity remain incomplete.
A standalone no-passkey gate `E2E_PORT=18087
scripts/e2e-forward-auth-standalone.sh` also passed password bootstrap,
`X-Forwarded-User-MFA: false`, restart persistence, and the expected
forced-MFA/no-passkey startup failure. The exact-three no-passkey gate
`KIND_CLUSTER=goauthy-forward-auth-ha-nopasskey-final E2E_PORT=20500
scripts/e2e-forward-auth-ha-kind.sh` passed three Ready pods without passkey
assets, `MFA=false`, hostile-header clearing, pod-0 replacement, revocation,
final-admin self-delete denial, and cleanup on ports `20500-20502`.

Rhiza schema v102 is the current source baseline. The SCIM users-only full scan,
user-first reconcile, provider-scoped remote-user mapping, group enqueue/runtime,
and v39 tombstone/delete projection are source-tested; worker wiring remains
production-wired behind `GOAUTHY_SCIM_PROVIDERS_FILE`. Optional per-provider
`ca_file` configuration builds a stdlib `x509.CertPool`; the client preserves
hostname verification, requires TLS 1.2 or newer, disables proxy use and
`InsecureSkipVerify`, and uses a deterministic TLS fixture in E2E. Transport,
DNS, TLS and dropped-connection failures plus `429`/`5xx` retry; malformed or
permanent `4xx` responses are dead-lettered. `identity.DeleteUser`
atomically snapshots a tombstone, cleans owned identity state, invalidates stale
user-sync outbox rows, and durably enqueues SCIM delete work. Admin deletion is
`DELETE /auth/v1/users/{subject}` for a direct `rauthy_admin` browser session
with same-origin `X-CSRF-Token`, or a `Users:delete` API key; an empty body and
`204` success are required, with `404` for missing/inactive subjects and `409`
for the final active admin. Self deletion is `GET`/`DELETE
/auth/v1/users/{subject}/self/delete`, authenticated same-subject browser-only,
strict default-off via `GOAUTHY_ENABLE_SELF_DELETE=false`: `GET` returns `202`,
and enabled `DELETE` requires CSRF, clears the cookie, and returns `204`;
disabled/admin/final-admin cases return `406`. `GOAUTHY_BOOTSTRAP_FORCE_MFA`
gates browser-admin deletion on a current MFA session; API-key deletion is
unaffected. Explicit user deletion always projects to SCIM hard `DELETE`,
independent of `sync_delete_users`; ordinary synchronization defaults to RFC
7644 unlink. Tombstones fan out per provider with mapped `externalId` exact
checks and terminal mapping/outbox CAS. Encrypted per-client configuration
remains absent. After a bounded drain, tombstone cleanup removes oldest
tombstones only when exact delete jobs for every snapshotted provider have
succeeded; hard local deletion requires `DeleteRemote`, while pending,
processing, dead, or missing jobs retain the tombstone. Terminal delete outbox
rows are retained while their tombstone exists. Schema v41 snapshots each
deletion-time provider's immutable ID and delete policy. Legacy v39/v40
tombstones have incomplete snapshots and are never auto-cleaned; a removed
provider blocks cleanup until that same stable ID returns, while a new provider
does not receive historical deletes. Schema v42 adds an opaque 128-bit/
22-character base64url tombstone generation and a Rhiza-atomic exact-generation
enqueue fence, so a stale pod cannot delete a recreated subject. Empty
generations, incomplete snapshots, and malformed hard-delete snapshots fail closed; legacy/raw/no-generation
delete rows are unclaimable. Complete tombstones with empty generations are
retained and skipped without blocking later work. The generation is persisted
inside delete-job JSON, and both claim and cleanup require an exact current
generation. Dead-letter retry is operator-controlled, so provider re-add alone
does not revive a dead job. The standalone exact-one SCIM group gate on port
`18981` passed user-first, retry, full-member and delete convergence. The
exact-three Kind group gate `KIND_CLUSTER=goauthy-scim-e2e-20260905d
E2E_PORT=19380` passed with three Ready pods, full group members, pod-0 UID
replacement after delete, empty/deleted convergence, and cleanup. Passkey
database credential and ceremony envelopes
use GAOP active-key envelopes with strict dual-read: legacy CookieKey
ciphertext is read only for non-GAOP rows, while malformed or unknown-key GAOP
values never fall back. The bounded passkey rewrap worker preflights each
credentials/ceremonies batch and commits all-or-zero under Rhiza; strict JSON
decoding and bounded envelope inspection are covered. CookieKey rotation,
remaining nonrotating values, and automatic key removal remain pending. The
master-key envelope worker is also
production-wired: every minute it independently cursor-scans bounded
signing-key, live DCR-idempotency, and unexpired upstream-transaction
envelopes, authenticates old values, and exact-CAS rewraps them under the
active key. OAuth persisted request forms redact credential, bearer, and
one-use fields while retaining non-secret protocol metadata and without
mutating the live request. Full critical-DB encryption is not complete:
nonrotating values, CookieKey rotation, and automatic key removal
remain pending. Master-key retirement Stage A prepare, Stage B commit
fencing, and Stage C runtime admission/attestation/ready/abort are implemented;
successful guarded transitions append exactly-once audit events in the same
Rhiza transaction, with API-key pseudonyms and epoch-only targets. Deterministic
standalone exact-one and exact-three state-machine/replay/revocation-
interposition/chain-integrity tests cover the source contract; no automatic key
removal exists. The live exact-three gate
`KIND_CLUSTER=goauthy-master-key-e2e-20260905c E2E_PORT=19700` passed all three
zero-reference checks, pod-restart boot-ID change with attestation sequence 2,
Ready, key retention, and cleanup. The
source-integrated deterministic
`make e2e-kind-user-delete` profile has a live Kind run that remains
UNVERIFIED because current Docker `fs.inotify.max_user_instances=128` is below
the required `256`. SCIM delivery is
intended to be at-least-once across crashes, not exactly-once.
The standalone live SCIM E2E passed in repeated runs (`14.9s` and final
post-hardening `18.6s`), covering SMTP registration, restart-immediate sync,
exact `externalId`, public admin delete, restart-exact remote `DELETE`, and
login rejection. The
standalone `scripts/e2e-user-deletion-standalone.sh` live PASS additionally
covers browser self/admin deletion, `Users:delete` API-key boundaries,
final-admin `409`, admin survival, SCIM create plus durable tombstone `DELETE`
across cold restarts, deleted-login denial, and remote cleanup. This is
standalone evidence only. The final narrow exact-three gate
`E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final
scripts/e2e-scim-delete-chaos-kind.sh` also passed three Ready pods, creation,
two full restarts, browser-admin/API-key deletion on different pods,
cross-pod session/token invalidation, final-admin protection, pod-0 replacement,
tombstone plus two remote `DELETE` convergence, and cleanup. The broader
exact-three user-delete/full-SCIM profile below remains UNVERIFIED, so no full
SCIM parity claim is made. The
exact-three-voter SCIM user/full-feature harness passes source/static checks but
its live run stops at the same Docker inotify limit, so no broader HA runtime
claim is made. Group-specific HA evidence is limited to the exact-three gate
above.

Metrics also have bounded listener evidence: `scripts/e2e-metrics-standalone.sh`
passed with the app on `19880` and metrics on `19881`, including unauthorized
and authorized scraping, application/metrics endpoint isolation, bind-collision
failure, and restart-preserved JWKS. The final exact-three HA gate
`KIND_CLUSTER=goauthy-metrics-e2e-20260905c E2E_PORT=20080
./scripts/e2e-metrics-kind.sh` passed on app/metrics ports `20080`-`20085`,
checking readiness, auth and isolation on every pod, then pod-1 replacement
and byte-identical post-replacement JWKS/metrics rechecks. This does not claim
complete observability parity: traces/exporters and broader metrics coverage
remain pending.
FedCM has a Rauthy-compatible, strict default-off production source wiring via
`GOAUTHY_FEDCM_CONFIG_FILE`: HTTPS-only config, mounted manifest/config/
accounts/client-metadata/assertion/status routes, exact `/auth/login` or
`/auth/v1/account` password landing, active-identity+peer binding, CSRF/origin/
Fetch-Metadata checks, one-time CAS and separate secure-cookie/logout handling.
It intentionally has no passkey/passwordless direct login; startup rejects
simultaneous FedCM and bootstrap forced-MFA. HTTPS `/readyz` probes and their
manifest static test are covered; real browser, Kind and chaos E2E
remain pending. The
the exact-three issuer-path Kind gate passed RFC 8414 and prefixed discovery/
OAuth/DPoP flows, negative path checks, pod-0 replacement, and cleanup. Broader
issuer-path/browser parity remains pending.

## Rhiza production profiles

GoAuthy has two explicit Rhiza `v0.12.3` runtime modes. `standalone` is the
production single-node topology: one embedded member and no peer inputs.
The default Kubernetes profile uses `emptyDir`, an object-store bucket/prefix,
fixed `before-ack` durability and `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true`.
Its local state is rebuildable. The runtime still permits explicitly configured
local-only standalone fixtures; their cold-copy tests are not object-store DR. The legacy `dev` profile remains local-only. Both
single-node profiles reject peer, voter-token and admin-token settings.
The isolated [Ternal no-PVC profile](deploy/ternal-no-pvc/README.md) does not
change existing deployments. `make e2e-standalone` passed runtime
smoke plus restart verification, including persistence of the JWKS key ID, and
the shared browser authorization-code/refresh flow with primary and secondary
URLs pointed at the same standalone endpoint; the authorization-code/refresh
flow is a live PASS.
The standalone admin E2E also passes bootstrap login, exact admin links and
security headers, and anonymous/Init/stale-session plus Authorization/API-key/
cross-site/query rejection checks.

`cluster` is the production HA profile and requires exactly three embedded
voters. `GOAUTHY_RHIZA_MEMBERS` is Secret JSON containing distinct per-member
voter tokens; `GOAUTHY_RHIZA_ADMIN_TOKEN` is a separate admin token (the old
`GOAUTHY_RHIZA_PEER_TOKEN` name remains a legacy alias). Preferred hostname
anti-affinity and a `minAvailable: 2` PDB protect voluntary disruption. Source
validation and the static Kubernetes configuration are verified; the
`deploy/standalone` overlay has a static render test. The exact-three base HA
gate passed earlier on Rhiza `v0.10.0`. The fresh `v0.12.0` full Kind profile
also passes normal/cross-pod flows, pod replacement, quorum-loss readiness 503,
quorum restoration and rolling restart; see [dated verification](docs/status.md).
Standalone and exact-three HA have identical application semantics; HA pods
must use matching SCIM provider configuration, including stable IDs and policies.
With the current Rhiza v0.12.3 integration, startup failure paths still
intentionally skip `db.Close()` until all startup initialization succeeds; the
startup-close workaround remains pending verification against the upgraded runtime;
normal post-start shutdown still closes the database as usual.

Bootstrap authentication is password-only for the initial administrator by
default; passkeys are optional. `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` is an
explicit opt-in that fails startup unless the complete passkey configuration is
valid, rather than falling back to password-only login. Forward Auth identity
headers are independent of passkey configuration: when
`GOAUTHY_FORWARD_AUTH_HEADERS=true` and passkeys are disabled,
`X-Forwarded-User-MFA` is emitted as `false`. See the
[bootstrap passkey policy](docs/passkey-bootstrap.md).
The [backup operator](docs/backup-operator.md) provides encrypted export/restore
and signed independent-object-store publish/list/fetch. Scheduling and retention
remain incomplete; [current verification](docs/status.md) separates each gate.
An earlier raw exact-three HA backup/clean-restore gate passed: checkpoint index `82`,
`config_id` `1`, generation `11`, with `2` files and `2` blocks verified. The
durable-profile `GOAUTHY_RHIZA_CHECKPOINT_INTERVAL` override accepts `1s`
through `24h`; `1s` is the deterministic HA backup-test value, while an unset
value keeps Rhiza's default. Dev rejects this setting; standalone requires
complete object-store configuration with it. Durable standalone and cluster
both use fixed S3 `before-ack`.

The project is pre-alpha. The single-node development Rhiza integration,
deterministic Rhiza schema migrations through v102, encrypted Ed25519 signing-key bootstrap and
safe two-phase rotation, public JWKS and OpenID Provider metadata, Fosite-backed
client-credentials/authorization-code/refresh engines, EdDSA ID tokens and
GET/POST UserInfo for `openid` browser grants, client-credentials RFC 8707
resource indicators, introspection/revocation handlers, RP-initiated logout,
and liveness/readiness probes are implemented. A live client-credentials E2E
also checks configured token expiry; the browser E2E checks RFC 8707 resource
audiences across pods. Dynamic Client Registration has an authenticated-only
create/read slice backed by schema v9: when a mounted global bearer is
configured, it publishes `registration_endpoint`, serves registration and
self-read HTTP routes, and its clients resolve in OAuth. Authenticated
per-registration `PUT` strictly replaces metadata using optimistic CAS, rotates
the registration access token and (for confidential clients) client secret as
one-time response values, and never re-exposes either value on `GET`.
Registration responses explicitly return `client_secret_expires_at: 0`.
Schema v44 also persists the RFC 7591 `client_uri`; POST rejects explicit null,
while RFC 7592 PUT requires the body `client_id` to match the canonical path and
uses omitted/null `client_uri` to remove that metadata.
Schema v53 persists an optional RFC 7591 `software_statement`: when
`GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE` is configured, a compact JWS must be
signed by exactly one statically trusted issuer key, with `iss` and optional
`aud` checks; verified statement metadata overrides duplicate request metadata,
and the original compact JWT is returned unchanged. Schema v54 adds the
canonical replicated `dcr_software_statement_trust` digest/topology fence:
startup and readiness accept exactly one or three members and fail closed on a
configuration or topology mismatch. Source/HTTP/idempotency and trust-fence
tests pass, and `scripts/e2e-software-statement-standalone.sh` passes its live
standalone replay/readiness check. The exact-three HA gate
`KIND_CLUSTER=goauthy-software-statement-ha-e2e-20260905i` on ports
`19840-19842` also passed: all pods reached Ready with identical trust,
cross-pod GET persistence held, invalid signature/issuer/audience inputs were
rejected on every pod, pod-0 replacement changed its UID, and the
byte-identical idempotent response survived restart before cleanup.
The verified RFC 7592 per-registration `DELETE /oidc/register/{id}` slice accepts
only the canonical unescaped item URI, an empty body and no query, rejects the
global bearer and duplicate/malformed credentials, and returns generic
`401`/`400` failures or `204` on success. Its Rhiza conditional mutation binds
the client ID to the SHA-256/base64url registration-token digest at commit time,
so a stale token after PUT rotation or a concurrent update cannot delete the
newer registration; deletion is visible to OAuth client resolution on every pod.
Deterministic source E2E covers create/delete/readback across pods, credential
masking, wrong/stale bearer, URI/body/query rejection, replay and update/delete
contention. The full RFC 7591/7592 management surface remains incomplete, and
Rauthy parity for `last_used` is verified for successful DCR `PUT` and
successful dynamic `client_credentials`/authorization-code token issuance,
using monotonic commit-time timestamps; it excludes `GET`, refresh, device,
exchange and failure paths. Deterministic and race review is clean. The
opt-in anonymous profile now has Rhiza-backed canonical-IP rate limiting and
bounded startup cleanup; standalone E2E passed, while live Kind execution
remains unverified because current Docker
`fs.inotify.max_user_instances=128` is below the required `256`. Browser E2E remains
blocked by follower materialization instability (`context deadline exceeded`,
then 400/500/503), consistent with the known Rhiza savepoint failure. The public browser
boundary provides `GET /oidc/authorize` and `POST /auth/login`: a mounted
Argon2id-PHC bootstrap identity signs in through an opaque, digest-only,
one-time interaction and receives an authorization code. Opt-in stdlib TLS with
atomic certificate reload is wired through
`GOAUTHY_TLS_CERT_FILE` and `GOAUTHY_TLS_KEY_FILE`. Automatic key-rotation
scheduling uses a bounded 30-day default period. A fresh three-pod kind gate
also verifies automatic JWKS rotation/overlap, public ID-token and UserInfo
verification, deployed idle-session expiry, and cross-pod RP-initiated logout.
The bootstrap back-channel delivery subset supports an explicit custom CA,
TLS 1.2+, hostname/SNI verification, no proxy or redirects, and atomic
last-known-good CA reload. The dedicated `make e2e-kind-backchannel-https`
harness source/static checks PASS; its live HA execution fails preflight because
Docker `fs.inotify.max_user_instances=128` is below the required `256`.
Authorization-code resource audiences persist through refresh.
The bootstrap client may opt into a single configured default audience with
`GOAUTHY_BOOTSTRAP_DEFAULT_AUD`; it must be one of the configured HTTPS
resource allow-list entries and is applied only when `resource` is omitted.
Dynamic/CIMD default audiences and Kind E2E evidence remain pending; the
ephemeral-audience danger option is implemented as an explicit default-off
policy.

Ephemeral URL-document clients (OAuth Client ID Metadata Documents, CIMD) are a
default-off partial slice (`GOAUTHY_CIMD_ENABLED=false`). When enabled, the
stdlib/Fosite/Rhiza schema-v13 resolver admits only a tightly constrained public
authorization-code client: public HTTPS TCP/443 only, exact document binding,
pinned validated DNS dialing, special-use-address/redirect/proxy rejection, 5 KiB JSON bound,
same-origin HTTPS redirects and S256 PKCE. Persisted authorization/code/access
requests use a sanitized metadata snapshot; public token-client authentication
performs only a shared cache lookup, never a remote refetch. The
RFC 8707 `allowed_resources` field is matched as an exact list of absolute
HTTPS URLs and persisted immutably in the Rhiza snapshot; an explicit empty list
is default-deny. Unlisted resources remain denied unless the separate
`GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE=true` opt-in is set, and even
then only valid HTTPS URLs are admitted. The
`ignore_unknown_auth_flows` parser policy core is deterministic and keeps known
grants while requiring `authorization_code`; production wiring accepts the
strict default or the opt-in `GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS=true` policy.
A pinned kind TLS-fixture E2E has not run. DNS rebinding is deterministic unit
coverage only; cross-pod cache expiry, Cilium NetworkPolicy enforcement and
chaos remain pending. `make e2e-kind-cimd-cilium` is the fail-closed gate:
it uses Cilium endpoint policy revisions plus synchronous fixture counters to
check uncached deny, cached cross-pod continuity and recovery. On the current
Dory host Cilium v1.20.0 stops in its route reconciler with `protocol not
supported`, so no enforcement pass is claimed. The fixture's `externalIPs` routing is deprecated in
Kubernetes 1.36 and is disposable-kind test-only, not a production egress
design. Basic WebID profile documents are now available behind `GOAUTHY_WEB_ID_ENABLED=true`;
the standalone live WebID E2E passes strict content negotiation/path/method,
privacy, and restart-stability checks, and the exact-three
`scripts/e2e-webid-ha-kind.sh` live gate passes cross-pod output and replacement
pod checks. Solid support remains pending. The
lenient-policy Kind E2E remains pending;
discovery advertises CIMD only when enabled.

RFC 8628 Device Authorization is an implemented bootstrap and dynamic-client slice:
`POST /oidc/device`, the CSRF-protected browser verification page, and the
custom Fosite token handler use Rhiza schema v10 digest-only state and atomic
claim/token issuance. It rejects `openid`; DCR accepts device-only and
authorization-code-plus-device metadata. A standalone public HTTP E2E covers
dynamic registration through `/oidc/device` without time-based polling. The
bootstrap cold-browser flow now includes `/oidc/device/login`, explicit approval,
access/refresh and an introspection-backed HTTP resource check, with standalone
restart and exact-three Pod replacement evidence. See the [device pilot checklist](docs/device-flow-pilot.md)
for commands and remaining public-operation limits. Device creation now reuses
Fosite confidential-client authentication; public device+refresh DCR and cold-login
flows pass standalone, restart, and exact-three HA E2E. A pending grant also survives
Pod replacement and is redeemed once on surviving Pods. The Dory VM inotify limit
was raised to 512 after reset; recheck it after engine restarts. Device
abuse limits use the direct remote peer and deliberately ignore
forwarded headers until an explicit trusted-proxy policy exists.

RFC 9449 DPoP is an implemented but partial vertical slice for authorization
code, refresh and UserInfo: `go-jose/v4` plus stdlib proof/JWK/`ath` validation,
Fosite `cnf.jkt` session binding, and schema-v11 digest-only nonce/replay state
enforce one-use nonces and multi-pod `jti` replay protection with bounded 128-row
cleanup. Discovery advertises supported proof algorithms. Client credentials,
Device Grant and token exchange are not DPoP-enabled. Client-credentials DPoP
is enabled. Local and focused race
tests pass, but fresh kind smoke (9.985s) reached a primary nonce challenge and
then failed same-code secondary exchange with 500 while followers logged
`no such savepoint: rhiza_command` and sync timeouts; full DPoP E2E is blocked.

RFC 8693 Token Exchange has a deliberately narrow OIDC bootstrap-confidential
same-client slice: a GoAuthy user access token with one audience can be
downscoped by scope/resource into an access token only. A same-client opaque
access-token actor is accepted only for the focused delegation slice; audience,
external JWTs, DPoP-bound sources and unsupported token types are rejected.
A direct Fosite handler uses existing Rhiza conditional atomic issuance, clamps
target expiry to the source and rechecks it at commit. Local full/race tests and
fresh three-node kind smoke (29.553s) plus `TestTokenExchangeAcrossPods`
(8.877s) passed; subsequent DPoP remains blocked by the follower savepoint
failure. An actor access-token unit slice is present only for the same
confidential client and records `act.sub`, but full RFC 8693 delegation/actor
parity is not claimed.

Password login now includes schema-v12 replicated, pre-Argon2 direct-peer IP
protection: a fixed-window gate plus escalating failure delay/block thresholds,
dummy credential verification, and a 24-hour idle counter TTL. The
peer-IP middleware resolves the canonical peer IP once at the HTTP boundary for
every request. In direct mode it uses `RemoteAddr`; when a trusted-proxy
configuration is present it also reads `Forwarded`/`X-Forwarded-For` from the
immediate trusted peer. Session-IP binding is implemented in schema v31 (see
below). Fresh
three-node `TestLoginBruteForceBlockAcrossPods` PASS (49.851s) runs sequentially
across pods: failures 1–6 return 401 and failure 7 returns 429 with bounded
`Retry-After`. It deliberately has no concurrent goroutines, real one-minute
sleep, or recovery assertion; expiry/recovery remains fake-clock unit coverage.
The earlier 17.5-second EOF was the server's 15-second `WriteTimeout` being
shorter than the initial unblocked delay. The global timeout is now one minute,
and each delayed credential failure deterministically extends only its response
deadline to the computed delay plus a five-second write margin. Full login
policy parity remains `[ ]`.

RFC 8252 dynamic loopback redirects are default-off
(`GOAUTHY_RFC8252_LOOPBACK_REDIRECTS=false`). When explicitly enabled, only
public dynamic authorization-code clients may register literal `127.0.0.1` or
`[::1]` HTTP callback templates; the authorization request may vary only the
port while retaining the registered host/path/query. `localhost` remains
available only with an explicit, exactly matching port. Static, confidential,
other DNS-name and custom-scheme redirects retain exact matching. Source tests
cover hostile variants; the fresh exact-three HA gate
`scripts/e2e-rfc8252-loopback-kind.sh` covers literal IPv4/IPv6 port variation,
exact-port localhost, hostile host/userinfo/path/query negatives, cross-pod
authorization/code exchange, and pod-0 replacement.
The run
`KIND_CLUSTER=goauthy-rfc8252-loopback-ha-e2e-20260905a E2E_PORT=19860
./scripts/e2e-rfc8252-loopback-kind.sh` completed successfully and cleaned up
its cluster.

For deterministic Kubernetes fault coverage,
`scripts/e2e-pod-restart-chaos.sh` creates an isolated kind cluster, verifies an
issued token across all pods, replaces one StatefulSet pod, then verifies
consistency after readiness. The bucket-readiness initContainer removes the
object-store startup race, and the script now fails if any GoAuthy init/main
container has restarted before the fault. Fresh
`make e2e-kind-chaos E2E_PORT=28080` passed: issue on pod 0, introspect on pods
1/2, delete pod 2, recheck survivors, wait for its replacement, then introspect
the same token there.

The opt-in password-recovery profile is isolated from the base manifests:
`E2E_PROFILE=password-reset E2E_PORT=28080 make e2e-kind` passed on a fresh
schema-v16 three-pod cluster. It requests a reset, reads the local SMTP sink,
binds the browser cookie/CSRF challenge on one pod, consumes it on another,
rejects replay, revokes the old browser session, rejects the old password and
accepts the new one. Pick a distinct `E2E_PORT` range when other local services
or parallel jobs are running.

Password-reset requests now require the Rauthy/spow-v1 textual proof-of-work
challenge issued by `POST /auth/v1/pow`; the solved proof is submitted as the
`pow` member of `POST /auth/v1/users/request_reset`. GoAuthy stores only a
SHA-256 digest of the unsigned challenge and atomically consumes it, so a
proof cannot be replayed across pods. Schema v30 additionally admits only
five issuances per direct TCP peer per minute and caps both unexpired challenge
rows (including consumed rows) and peer-admission rows at 256; expired rows
are atomically removed. This
engine/route has
deterministic clock and entropy-injection coverage for issuance, expiry,
format validation and concurrent exactly-one consumption. Fresh
`E2E_PROFILE=password-reset E2E_PORT=28080 make e2e-kind` evidence built a
schema-v17 image/cluster, readied three pods, then passed `test/e2e` in
`15.938s` and `test/e2e/browser` in `1.320s`: invalid proof rejection,
successful request and cross-pod replay rejection are covered. Email OTP is
unreleased and is not claimed as Rauthy v0.36.2 parity.

Rhiza remains pinned to official `v0.12.3` (commit `97a9d18aadc66d3b5390f6fa64de2d65dd9f0d48`); v0.10.0 remains
the historical baseline for earlier runs. Schema v32 adds the manual IP-blacklist store,
schema v34 adds DCR idempotency, schema v35 adds the upstream-provider
transaction/link state, schema v36 extends browser-session truth with
explicit external `auth_method` support, schema v37 adds durable SCIM
user outbox/serialization state, schema v38 adds provider-scoped remote
user mappings, schema v39 adds SCIM deletion tombstones, schema v40 adds
anonymous-DCR cleanup indexes, schema v41 adds immutable SCIM provider
ID/policy snapshots, schema v42 adds tombstone generations and the
exact-generation enqueue fence, schema v43 adds per-client favicon rows,
schema v44 adds dynamic-client `client_uri` metadata, schema v45 adds the
append-only API-key audit slice, schema v46 adds canonical DCR contacts, and
schema v47 adds HTTPS `logo_uri`, `tos_uri`, and `policy_uri` metadata, and
schema v48 adds the master-key retirement barrier base, schema v49 adds the
audit sequence, schema v50 adds barrier compatibility state, schema v51 adds
audit integrity guards, schema v52 extends audit constraints/triggers for
master-key retirement events, schema v53 adds the persisted DCR
`software_statement` metadata column, and schema v54 adds the canonical
replicated DCR software-statement trust digest/topology fence;
schema v33 retains expiry metadata
plus a bounded 64-row `oauth_rate_limits` insert-trigger cleanup. The
upstream-provider core (`internal/upstreamprovider`) now has digest-only
one-use transactions, state/browser/provider binding, PKCE/state/nonce
generation, provider-scoped subjects, a stdlib HTTP start/callback adapter, a
production `golang.org/x/oauth2` code exchanger that fails closed on nil
results, GitHub OAuth App exchange plus immutable numeric `/user` subject
resolution, and a production `go-jose/v4` JWKS verifier with an asymmetric-alg
allowlist, exact `kid`/public-key selection, bounded hardened fetch, and
per-instance concurrent cache/rotation. Schema v35 persists the local
session/interaction digest pair in dedicated columns plus the encrypted
upstream transaction envelope, and canonical base64url digest SQL constraints
now enforce the persisted opaque identifiers. Root integration
`go test -p1 -count=1 ./internal/storage ./internal/browser ./internal/oauth ./internal/upstreamprovider ./internal/identity`
passed, and `internal/upstreamprovider` also passed `-count=3` plus focused
JWKS verifier race coverage. Race/vet and the full suite remain unverified. The
exact barriers are `DB.Ready` plus a linearizable schema query for startup, then
Kubernetes readiness/UID and explicit cross-pod read-after-write barriers; no
elapsed-time assertion is a success oracle. Upstream-provider runtime, local
OAuth interaction/session completion, and explicit account link/unlink are
source-wired. A TLS fake issuer, black-box client, three-pod Kind harness, and
pod-replacement scenario are present and statically checked for OIDC and
GitHub; the live Kind run, broader provider parity, and
full Rauthy parity remain incomplete.

Roles/groups plus custom scopes and user attributes are now an in-flight
schema-v26 slice, not completed Rauthy parity. It uses Rhiza for normalized
entities, memberships, attribute/scope catalog state and bootstrap static-client
scope policy; stdlib HTTP/JSON validation for the admin boundary; Fosite only
for OAuth session carriage; and `go-jose/v4` for ID-token signing. Roles are
always current end-user token/UserInfo/introspection claims; groups require a
granted `groups` scope; custom scope bindings emit `attr_include_id` on ID
tokens and `attr_include_access` on UserInfo/introspection as the honest
opaque-token surrogate. Code/refresh persistence repeats the active identity,
principal revision and claims-catalog revision predicates, preventing stale
membership or custom-claim snapshots from minting artifacts. Admin reads and
writes require current browser `rauthy_admin`; bootstrap client scope policy is
an explicit partial route at `GET`/`PUT /auth/v1/clients/{id}/scopes`.
`claims_at_root` is supported and fails closed on reserved-name collisions.
Deterministic focused tests cover strict JSON, migration replay, rename/delete
cascade and revision-race denial without sleep-based assertions. On 2026-09-01,
fresh `make e2e-kind E2E_PROFILE=roles-groups KIND_CLUSTER=goauthy-claims-v081-e2e`
passed pod replacement and the custom-scope/attribute flow (`4.392s`) using
cross-pod state/revision barriers with no test sleeps. Dynamic registration now
takes its scope policy only from the operator: `GOAUTHY_DCR_ALLOWED_SCOPES`
defaults to `openid profile email groups`, and
`GOAUTHY_DCR_DEFAULT_SCOPES` defaults to `openid`. Both are whitespace-separated
unique scope lists; every default must be allowed or startup fails. RFC 7591
requests cannot supply `scope`, and registration updates preserve the stored
operator policy. Configured dynamic custom scopes are admitted only by
authorization-code and refresh flows; device, token-exchange and
client-credentials remain denied. Fresh three-pod E2E now covers DCR request-scope
rejection, operator defaults, PUT preservation, credential rotation and dynamic
custom-scope authorization-code issuance across pods. Self-subject editable-attribute
GET/PUT also covers default/value/delete and cross-pod visibility; the true non-admin
fixture remains unit/store-only. Anonymous DCR is an explicit opt-in runtime
profile: `GOAUTHY_DCR_ANONYMOUS=true` permits bearerless create and
`GOAUTHY_DCR_RATE_LIMIT_SECONDS` supplies its fixed window, while
`GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES` controls never-used retention,
`GOAUTHY_DCR_ANONYMOUS_INACTIVE_DAYS=0` disables used-client cleanup, and
`GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT=100` bounds each pass. Its standalone
E2E passed, including restart-driven immediate cleanup; the three-pod Kind harness is
source-complete but pending execution under the Docker inotify prerequisite. Both
harnesses assert unauthenticated create, exact replay, canonical-IP cross-pod limiting,
independent-IP admission and per-registration management without waiting for expiry.
Schema-v28 now wires scoped administrator API
keys at `/auth/v1/api_keys`: browser administrators retain the existing
same-site/CSRF boundary, while an `API-Key name$secret` header is accepted only
by these explicit admin routes and the scoped roles/groups/claims operations.
Secrets are one-time create/rotate outputs and only a SHA-256 base64url digest
is stored, unlike Rauthy's encrypted digest-at-rest design. Authorization-code
and refresh access tokens are now EdDSA JWTs backed by the existing Rhiza index
for revocation/introspection/DPoP/token-exchange; active and retiring public
keys are loaded at verification. Deterministic unit/race coverage exists. A
fresh dedicated three-pod API-key E2E now passes cross-pod create/use/rotate,
scope denial and deletion; the broader user custom-claim JWT E2E remains pending.
Schema v29 adds a
bootstrap-client-only `GET`/`PUT /auth/v1/clients/{id}/claims` policy and emits
its revision-guarded nested/root values only in `client_credentials` access
JWTs; dynamic clients, UserInfo and introspection remain excluded. Its fresh
dedicated three-pod E2E passes cross-pod nested/root/clear policy, public-JWKS
verification and reserved-root collision denial. The existing membership
PATCH now includes source-tested delegated `rauthy_admin:<group>` exact,
trailing-prefix and all-groups policy with atomic escalation guards; dedicated
Kind evidence and full static-client/user management remain pending.

The completed ledger audit also keeps these capabilities explicitly unchecked:
true passwordless account lifecycle and cross-pod post-passkey-registration
session-MFA E2E; broader Forward Auth proxy-mode/ACL parity; CIMD
`ignore_unknown_auth_flows` Kind E2E evidence;
Dynamic/CIMD Resource Indicator `default_aud` and its Kind E2E evidence; the
ephemeral danger path is implemented but remains default-off; general TOML secrets
and deployed Generate expiry/quorum/restore coverage remain pending. Plain and
Encrypted API-key JSON startup import and opt-in shared Generate initialization
are implemented; see the [bootstrap contract](docs/api-key-bootstrap-implementation.md)
for settings, retrieval, expiry and verification scope. API keys
managing API keys are prohibited by Rauthy parity and are not an
implementation goal; and independent favicon cache-isolation E2E evidence.
The favicon file loader and `/favicon.ico` route are source-wired behind the
optional `GOAUTHY_FAVICON_FILE`. A bounded static-bootstrap-client subset also
serves `GET`/`HEAD` and guarded `PUT`/`DELETE /auth/v1/clients/{id}/favicon`:
conditional `If-Match`/`If-None-Match`, Rhiza API-key commit guards, and the
browser-admin preflight boundary are covered by deterministic tests. Dynamic
clients, theme/logo/i18n, and live HA evidence remain pending.

```bash
mkdir -p secrets/master-keys
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > secrets/master-keys/dev-1
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > secrets/oauth-hmac
openssl rand -base64 32 | tr -d '\n' > secrets/bootstrap-client
read -rs password; printf '\n'
printf '%s\n' "$password" | go run ./cmd/goauthy-password > secrets/bootstrap-user-password.phc
unset password
go test ./...
GOAUTHY_RHIZA_PROFILE=dev \
GOAUTHY_CLUSTER_ID=goauthy-dev \
GOAUTHY_NODE_ID=goauthy-dev-0 \
GOAUTHY_DATA_DIR=.goauthy-data \
GOAUTHY_BOOTSTRAP_USER=admin \
GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin \
GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE=secrets/bootstrap-user-password.phc \
go run ./cmd/goauthy
curl -i http://localhost:8080/readyz
curl -i http://localhost:8080/oidc/jwks.json
curl -u goauthy-dev:$(cat secrets/bootstrap-client) -d grant_type=client_credentials \
  -d scope=goauthy.read http://localhost:8080/oidc/token
```

The startup configuration that has been moved into the typed application-config
boundary can be validated without opening Rhiza or starting listeners:

```bash
GOAUTHY_RHIZA_PROFILE=dev \
GOAUTHY_CLUSTER_ID=goauthy-dev \
GOAUTHY_NODE_ID=goauthy-dev-0 \
GOAUTHY_DATA_DIR=.goauthy-data \
go run ./cmd/goauthy config check

# Prints a secret-free summary of the same centralized configuration slice.
go run ./cmd/goauthy config dump-effective
```

`config dump-effective` reports only non-secret values and boolean presence for
static object-store credentials. `config check` validates the complete startup
configuration before Rhiza is opened, bootstrap mutations run, or listeners
start: the centralised `applicationConfig` slice plus the runtime parsers for
settings, referenced file contents, and cross-field rules. Genuinely
store-dependent admission and master-key material at their default paths are
validated during startup instead, so the documented preflight keeps working
without mounted secrets.

`goauthy-password` reads one password line from standard input and prints only
its current-policy Argon2id PHC value. Mount that value as the bootstrap PHC
file; the bootstrap identity is created once and an existing credential is
never reset by a later startup.

## Password hashing policy

GoAuthy writes Argon2id v=19 credentials with the OWASP baseline by default:
`m=19456` KiB, `t=2`, `p=1`, and at most two concurrent password operations
per GoAuthy process. This is deliberately lower than Rauthy v0.36.2's default
(`m=131072`, `t=4`, `p=8`, `max_hash_threads=2`); it is a bounded portable
default, not a claim of identical cost. Rauthy's fixed-tag
[configuration](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/config.toml)
sets those values and requires production `m >= 32768`, `t >= 1`, `p >= 2`.

Set all four deployment values together after capacity planning:

```bash
GOAUTHY_ARGON2_MEMORY_KIB=32768 \
GOAUTHY_ARGON2_ITERATIONS=3 \
GOAUTHY_ARGON2_PARALLELISM=2 \
GOAUTHY_ARGON2_MAX_CONCURRENCY=2 \
go run ./cmd/goauthy
```

Every value must be an unsigned, canonical decimal integer (no sign,
whitespace, or leading zero). Accepted write-policy bounds are memory
`19456..131072` KiB, iterations `2..5`, parallelism `1..8`, and concurrency
`1..8`. Reserve at least `MAX_CONCURRENCY * MEMORY_KIB / 1024` MiB plus normal
process and node headroom; never choose a setting merely because it fits an
unloaded developer machine.

The bootstrap helper accepts the same memory/iteration/parallelism policy via
`-memory-kib`, `-iterations`, and `-parallelism`; it has no concurrency flag
because it creates one hash:

```bash
printf '%s\n' "$password" | go run ./cmd/goauthy-password \
  -memory-kib=32768 -iterations=3 -parallelism=2
```

`goauthy-password-calibrate` prints JSON recommendations only; it never writes
configuration or credentials. It measures each `t=5..1` candidate at a chosen
memory/parallelism setting and reports an odd-sample median:

```bash
go run ./cmd/goauthy-password-calibrate \
  -target=750ms -memory-kib=32768 -parallelism=2 -samples=3
```

Its wall-clock measurements are operational guidance only. Deterministic tests
inject measurements and assert the returned candidate order and median; they
do not use elapsed time as an outcome oracle. Review the JSON, capacity-plan,
then explicitly set the four environment variables above.

Stored PHC input is strict: only canonical `$argon2id$v=19$m=...,t=...,p=...$`
records with canonical raw-base64 salt/tag fields are parsed. Existing weaker
but bounded credentials may authenticate; only after a successful browser
login does GoAuthy best-effort rehash to the active policy. That update is a
Rhiza conditional compare-and-swap (`subject` plus old PHC), and only occurs
when every target cost dimension is at least the stored one and at least one is
stronger. Failed, disabled, stronger, or mixed-strength credentials are never
rewritten.

The fresh schema-v15 `password-policy` kind profile passed three-pod
deployment/migration/readiness, a `17.583s` baseline `test/e2e`, rollout from
the default policy to `m=32768,t=3,p=2,max=2` without changing the existing
bootstrap secret, and a cross-pod browser login/authorization code in `1.596s`.
The later fresh password-lifecycle profile
also passed its baseline (`18.246s`), cross-pod change (`2.203s`), and
post-write-pod-restart (`6.977s`) phases. Its observable assertions are
credential state and HTTP/OIDC results, not elapsed time; wall-clock waits are
limited to Kubernetes readiness and rollout boundaries.

## Password-reset proof of work

Proof of work is enabled only with password recovery. `POST /auth/v1/pow`
returns an unsigned spow-v1 challenge and `POST /auth/v1/users/request_reset`
requires its solved form in JSON field `pow`. The server accepts canonical
spow-v1 syntax only, verifies SHA-256 leading-zero bits, and stores only a
digest of the unsigned challenge plus expiry/consumption state in Rhiza v0.10.0
schema v17. Schema v30 uses the direct TCP peer (never forwarding headers), a
five-per-minute peer quota, a five-minute maximum TTL, and independent
256-row bounds for all unexpired challenges and current-window peer admissions;
each issuance atomically removes expired and stale-window rows before it
admits a new one. Schema v31 adds a `peer_ip` column to browser sessions for IP binding.
Every browser cookie resolved in an HTTP handler is atomically verified against
the canonical peer IP at the HTTP boundary: in direct mode (`RemoteAddr`) and,
when configured, through the trusted-proxy policy (`Forwarded`/`X-Forwarded-For`).
A `peerIPMiddleware` wraps all production routes; mismatched requests are
rejected without revoking the session. Bearer tokens, API keys and device grant
tokens remain unbound. Legacy pre-v31 sessions with an empty `peer_ip` column
are always accepted for backward compatibility. Implementation is verified by
deterministic unit/race tests and `go vet`; a fresh three-pod Kind v31 E2E
validating trusted-proxy mismatch behavior remains pending.

`GOAUTHY_POW_DIFFICULTY` defaults to `19` and must be an unsigned canonical
integer from `10` through `98`. `GOAUTHY_POW_EXPIRY` defaults to `30s` and must
be a Go duration from `1s` through `5m`. These settings are read only when
`GOAUTHY_PASSWORD_RECOVERY_ENABLED=true`; that mode also requires the existing
32-byte `GOAUTHY_PASSWORD_RESET_KEY_FILE` and SMTP configuration. The
password-reset kind overlay deliberately uses difficulty `10` only for bounded
test work. Production operators should capacity-plan and set their own
difficulty explicitly.

No Go package owns the spow wire format together with keyed challenge creation,
strict parsing, Rhiza single-use CAS and this recovery boundary. GoAuthy uses
stdlib `crypto/sha256`, `crypto/rand`, and `encoding/base64`, then implements
that small, security-reviewed protocol adapter directly. Tests inject clock and
random readers; they assert values and state transitions rather than hash-search
elapsed time. The fresh three-pod kind check above supplies the public runtime
evidence.

### Password-reset email copy

`GOAUTHY_EMAIL_TEMPLATES_FILE` optionally selects a strict TOML copy file and
`GOAUTHY_EMAIL_TEMPLATE_LANG` selects one exact supported Rauthy language
(`en` by default). Only `password_reset` entries are accepted; unknown fields,
languages, duplicate `(typ, lang)` entries, CR/LF in a subject, and files over
64 KiB fail startup. The fixed `text/template` and auto-escaping
`html/template` layouts produce a multipart text/HTML message. `password_new`
mail is deliberately not wired yet. Fresh
`E2E_PROFILE=password-reset E2E_PORT=28210 KIND_CLUSTER=goauthy-template-28210 make e2e-kind`
passed its root and browser suites. That validates only the reset-template
deployment slice; `password_new`, template management/localization, and full
template parity remain `[ ]`.

## Passkeys (opt-in)

The initial/bootstrap administrator remains password-only by default. Passkeys
are optional; enabling their configuration does not force enrollment or MFA.
Only `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` opts into forced MFA, and that setting
fails startup when the complete passkey configuration is absent or invalid.
Forward Auth identity headers do not require a passkey and report
`X-Forwarded-User-MFA: false` when passkeys are disabled. See the
[bootstrap passkey policy](docs/passkey-bootstrap.md).

The Rauthy v0.36.2-compatible WebAuthn route slice is disabled unless all of
`GOAUTHY_PASSKEY_RP_ID`, `GOAUTHY_PASSKEY_ORIGINS` (comma-separated exact
origins), and `GOAUTHY_PASSKEY_KEY_FILE` are set. The key file must contain
exactly 32 bytes. `GOAUTHY_PASSKEY_DISPLAY_NAME` defaults to `GoAuthy` and
`GOAUTHY_PASSKEY_FORCE_UV` defaults to `false`. Partial required configuration,
invalid origins/booleans, or wrong key length fails startup.

It uses `github.com/go-webauthn/webauthn v0.18.0` for WebAuthn ceremony
verification and Rhiza v0.10.0 schemas v20--v21 for encrypted credential material,
user handles, one-use ceremony/proof/token state, explicit service-proof purposes, factor markers and the
durable one-way account authentication mode. GoAuthy
directly owns origin/RP/UV policy, account binding, encrypted passwordless
cookie policy and Rhiza CAS for ceremony/credential consumption: no package can
provide those application security semantics. Unit/handler/config/schema tests
are deterministic through fixed configuration and injected clock/random seams;
they do not use elapsed time as an oracle.

Implemented opt-in routes are login `POST /auth/v1/users/webauthn_start` and
`.../webauthn_finish`, plus authenticated account list/register/delete and
`/auth/v1/users/{subject}/webauthn` routes plus
`POST /auth/v1/users/{subject}/mfa_token` and the matching
`/webauthn/auth/start|finish` step-up routes. `[x]` Fresh
`E2E_PROFILE=passkey E2E_PORT=28180 KIND_CLUSTER=goauthy-passkey-convert-28180 make e2e-kind`
used Chrome 151 CDP virtual authenticator and passed
`github.com/mrchypark/goauthy/test/e2e/passkey` in `3.682s`: pod-A
registration, wrong origin/RPID denial, ForceUV bad-UV denial, pod-B
password-to-passkey-only conversion (empty `200`), retained established
browser/OAuth session, password-login denial, UV-required passwordless login
with authenticator sign-counter increase, and pod-C replay rejection.

Registration finish now atomically upgrades the exact bound active `pwd` or
`webauthn` browser session to `mfa`, preserves `external`, uses the configured
browser idle timeout, and rejects disabled identities. Deterministic unit and
race coverage includes replay, stale-session and disable-interposition cases;
the cross-pod E2E for this upgrade remains pending.

`POST /auth/v1/users/{subject}/self/convert_passkey` is a one-way Rauthy
conversion: it requires an authenticated same-origin, CSRF-protected empty
request and an already registered user-verified credential. The single Rhiza
CAS removes the password verifier, password history, reset tokens, modification
tokens and pending service-proof state, then flips the durable account mode. Password admission
fails closed thereafter; passkey-mode ceremonies require UV, and deletion
cannot remove the last user-verified passkey. As in Rauthy, conversion does
not revoke established browser or OAuth sessions. Reverse conversion,
full recovery/admin/forced-MFA parity, and reverse credential recovery remain
`[ ]`.

`[x]` The narrow reverse self-service slice uses the same authenticated,
same-origin, CSRF-protected WebAuthn start/finish routes with
`{"purpose":"PasswordNew"}`. A user-verified, subject-and-browser-session-bound,
one-use proof is supplied as `mfa_code` to `PUT
/auth/v1/users/{subject}/self` with `password_new`. One Rhiza CAS consumes the
right-purpose proof, writes the verifier and flips passkey-only mode back to
password mode; it keeps passkeys and established browser/OAuth sessions while
invalidating pending WebAuthn/reset/MFA artifacts. Unit and race checks are
deterministic (no sleep-based correctness); local-Kubernetes `PasswordNew` E2E
is wired, but its fresh kind attempt stopped at the existing forward conversion
with `400` before this new route ran; logs also contained Rhiza v0.8.1 `no such
savepoint: rhiza_command`. It is not reverse-path evidence. Recovery/admin
reverse conversion and forced-MFA policy remain `[ ]`.

### Passkey MFA modification token (narrow slice)

`POST /auth/v1/users/{subject}/mfa_token` accepts a password only while the
account has zero passkeys. Once a passkey exists, the authenticated,
same-origin/CSRF-protected flow is `POST
/auth/v1/users/{subject}/webauthn/auth/start` with `{"purpose":"MfaModToken"}`
then `.../finish`, followed by `/mfa_token` with the returned proof. The start
code is 48 alphanumeric characters; only its SHA-256 digest and encrypted
ceremony state are persisted. A 90-second, subject-and-browser-session-bound,
one-use proof mints a 120-second, subject-and-session-bound, one-use final
modification token. Schemas v20--v21 record distinct ceremony/proof tables,
the factor marker, and explicit service-proof purposes; assertion success uses credential counter/version CAS, and
conversion removes pending ceremony/proof/token state.

`go-webauthn` verifies the assertion; `crypto/rand`, SHA-256 and AES-GCM
provide the primitives; Rhiza atomically consumes state. Account factor
selection, session binding, mode/ForceUV-aware credential admission and
one-use product semantics have no package owner and are deliberately direct.
The fresh three-pod MFA step-up gate remains `[ ]`: two clean-cluster runs on
ports 28190 and 28193 were stopped by the documented Rhiza v0.8.1 follower
materialization/savepoint failure before this flow could produce passing E2E
evidence.
This is intentionally not byte-for-byte Rauthy: Rauthy's final token is
IP-bound/reusable and returns `ip`; GoAuthy's is session-bound/one-use and
omits `ip`. Deterministic unit and race
coverage is `[x]`; fresh kind E2E for this new MFA slice remains `[ ]`.

### Bootstrap-client forced MFA (implemented slice)

Rauthy's static-client `force_mfa` setting requires a user-verifying second
factor before the authorization result is issued; the implementation checks the
client policy during authorize and retains the authenticated user until the
factor completes ([client policy](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs#L1213-L1237),
[authorize flow](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/authorize.rs#L127-L154)).
GoAuthy's schema v22 records the browser session `auth_method`, schema v36
extends that truth-preserving enum for external upstream sessions, and schema
v37 adds durable SCIM user outbox/serialization state, v39 adds SCIM deletion
tombstones, v41 adds immutable deletion-time provider snapshots, and v42 adds
tombstone generations; legacy
sessions are revoked rather than guessed. The bootstrap client may opt in with
`GOAUTHY_BOOTSTRAP_FORCE_MFA=true`; startup rejects missing or invalid complete
passkey configuration for this mode. Dynamic registration rejects `force_mfa` and
always remains unforced, matching Rauthy's dynamic-client policy. Static
admin-managed per-client policy remains unimplemented.

For the forced bootstrap client, password authentication only establishes the session.
The account must have a registered UV credential and complete a current UV
WebAuthn assertion before authorization code/session issuance. The assertion
is bound to the session digest and original interaction; the transaction
rechecks the active subject and bootstrap policy, so a stale session, disabled
subject, or reused/wrong-bound proof fails closed.
ID-token `amr` is `pwd` then `mfa` and survives refresh; access tokens do not
gain an `amr` claim. `go-webauthn` verifies the assertion, Fosite owns OAuth
request/token mechanics, stdlib owns parsing/crypto, and Rhiza owns the CAS.
No package owns the cross-layer session/client/policy binding, so that small
security policy is direct code. Deterministic unit and race tests use injected
state/time. The forced-MFA kind profile now targets the bootstrap policy; its
fresh replacement result is pending. It judges state, token and `amr` outputs,
with timeouts only as execution bounds:

```sh
E2E_PROFILE=forced-mfa E2E_PORT=28241 KIND_CLUSTER=goauthy-forced-mfa-final-28241 make e2e-kind
```

Rauthy Admin-UI `admin_force_mfa`/admin management and upstream-provider MFA
are still `[ ]`; full passkey parity remains `[ ]`. The broader passkey profile
still fails later at its older conversion step because of the Rhiza v0.8.1
savepoint defect; that is not a forced-MFA gate failure or full-passkey proof.

## Password composition and self-service change

The local library policy defaults to Rauthy's 180-day lifetime as well as
14--128 runes, at least one Unicode lowercase letter, one Unicode uppercase
letter, one ASCII digit, and a history of the current password plus two prior
passwords. Expiry is strict: it starts only after the exact changed-at plus the
configured number of calendar days. Invalid UTF-8 is rejected and length is
counted in runes rather than bytes. This deliberately hardens Rauthy's Rust
byte-length check: input is never normalized, so visually similar passwords
remain distinct.

Production startup deliberately overrides `ValidDays` to `0` and rejects a
nonzero `GOAUTHY_PASSWORD_VALID_DAYS`. The reset-delivery/UI boundary is not
yet wired; enabling expiry before a user can recover would lock users out.

Authenticated users retrieve a session-derived HMAC CSRF token and policy from
`GET /account/password`, then send it in `X-CSRF-Token` to
`PUT /auth/v1/users/{subject}/self`. The handler rejects cross-site requests,
unknown JSON fields, oversized/non-UTF-8 passwords, subject substitution, and
invalid or absent CSRF tokens. Schema v14 stores `password_changed_at_unix_ms`
and monotonic `password_generation` on `identity_users`, plus bounded
`identity_password_history(subject, generation, password_phc, changed_at_unix_ms)`;
the change and history prune are one Rhiza conditional mutation.

Like Rauthy v0.36.2, an authenticated self-change preserves the current
browser session. The reset engine core now matches the other distinction:
schema v15 stores only a keyed HMAC-SHA-256 digest of a 32-byte random opaque
token, binds it to the subject and password generation, and records consumption
in the same Rhiza request as the new credential/history and subject-wide
browser, OAuth, device, and back-channel logout revocation. Tests inject clock
and random sources and race two consumers deterministically; exactly one can
succeed.

The deterministic `make e2e-kind-user-delete` profile opens registration for
ordinary users, covers self/admin deletion, old-session and relogin denial,
replay `404`, final-admin `409`, UID-verified pod replacement/readiness, and
after-replacement persistence. It does not mark overall User deletion or SCIM
complete. The separate final narrow exact-three
`scripts/e2e-scim-delete-chaos-kind.sh` gate above is the current HA evidence
for this deletion slice; broader user-management and full SCIM parity remain
unchecked.

This is intentionally not a public recovery feature yet. Request-reset/email
delivery, reset-link cookie/CSRF HTTP endpoints, production reset-key wiring,
expired-login UX, and Kubernetes E2E remain pending. Therefore the full
password lifecycle is not claimed complete.

## Account expiration worker

Account expiration runs immediately at startup and every 60 minutes in both
standalone and HA modes. Set `GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES` to change
the interval (1–525600). Accounts are disabled and their existing login/grant
state is revoked; passwords, passkeys and profile data are retained.

Automatic deletion is off by default. Setting
`GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES` to a positive value in the same range
enables deletion only after the account has been expired longer than that
retention period. Zero is invalid, not an off switch. Each tick processes at
most 128 expirations and 128 deletions; excess work waits for later ticks.
See [the account lifecycle contract](docs/user-management.md#만료-worker-운영-계약)
for SCIM convergence, HA guards and incomplete lifecycle/E2E scope.

## E2E testing profiles

GoAuthy maintains two E2E profile categories:

- **Deterministic profiles** (default): all `make e2e-kind` profiles inject
  clock/random seams and assert state transitions rather than elapsed time.
  Wall-clock waits are limited to Kubernetes readiness and rollout boundaries.
  These profiles run in the standard CI gate and require no special deployment
  configuration.

- **Wall-clock profiles** (opt-in): `make e2e-kind-wall-clock-jwks` and
  `make e2e-kind-wall-clock-idle-expiry` run against a fresh deployment with
  explicit rotation/idle settings and observe real-time behavior. These are
  operational evidence only, not deterministic correctness proofs; they require
  `GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1` or
  `GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=1` and a matching deployment
  configuration. The deterministic suite already covers the same features with
  injected time.

Never claim wall-clock evidence as deterministic proof. The deterministic
profiles are the CI gate; wall-clock profiles are supplementary operational
validation.

See [docs/features.md](docs/features.md) for the exhaustive checklist and
[docs/parity.md](docs/parity.md) for package mapping, unavoidable direct
implementation, and E2E gates.
