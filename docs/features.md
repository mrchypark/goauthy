# Rauthy v0.36.2 feature baseline

This file is the **Rauthy parity ledger**, not the product support matrix. For the current
GoAuthy support boundary, use [capabilities.md](capabilities.md). Dated entries below are
kept as implementation and qualification evidence and may describe intermediate states
that were superseded by later source.

This is the implementation ledger for the fixed upstream tag
[`v0.36.2`](https://github.com/sebadob/rauthy/releases/tag/v0.36.2), commit
`dd61ac3c84d6b238108dc8438b53043b5177a662` (published 2026-08-08).  It is
not a statement about Rauthy `main`, which may contain newer work.

`Done` requires a real public route and deterministic evidence; security and HA
also require negative/fault evidence. `Engine` means focused Go tests exist;
`Route` means production wiring. A dash means no relevant implementation.
The dated, cross-feature verification summary is in [status.md](status.md).
Historical gate results below apply only to their named profile, not all E2E.

- [ ] Rhiza v0.12.3 runtime requalification (2026-09-08): dependency upgraded,
  API-key/CIMD/DCR before-ack reconciliation strengthened, and real filesystem
  object-store outage tests added. Unit/race evidence does not close the new
  standalone, three-peer Kubernetes, backup/restore or chaos gates. Current
  per-command results and remaining checks are in [status.md](status.md).

- [x] 2026-09-09 current Rhiza v0.12.3 full-profile Kind requalification:
  `make e2e-kind KIND_CLUSTER=goauthy-parity-20260909 E2E_PORT=59361`
  completed with exit 0. The fresh-cookie Device denial path passes (14.673s),
  as do the profile's preceding browser/API slices, cross-pod revocation/DCR,
  configured browser suite, JWKS and brute-force protection. Pod replacement,
  quorum-loss fail-closed/recovery and rolling restart checks pass. This closes
  the earlier full-profile rerun gap, not other separately gated features or
  the complete Rauthy feature ledger. See [status](status.md) for evidence.

- [x] 2026-09-09 nested actor token-exchange route and cross-pod qualification:
  bounded signed/persisted/introspection chains and ancestor commit guards pass
  focused race checks. `GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR=1` provisions its own
  actor using existing SMTP/recovery fixtures; the full Kind gate
  `goauthy-nested-actor-20260909b` passed. Nested-credential continuity subsequently passed in the combined
  `goauthy-actor-continuity-20260909` gate; cross-client policy was subsequently qualified below.

- [x] 2026-09-09 user token-exchange scope/claims qualification:
  subject-only narrowing, current roles/scoped groups/custom claims, principal
  and catalog commit fences (including absent role resolver) pass normal/race
  checks. Real API standalone E2E passes before/after restart (1.43s/1.44s),
  and goauthy-exchange-claims-20260909 passes the combined three-pod gate.
  Machine inputs and configurable mapping were subsequently qualified; see the machine-subject mapping row below.

- [x] 2026-09-09 confidential cross-client exchange/default-audience route:
  existing managed metadata and strict admin create/update APIs carry independent
  `default_aud`; one resource/audience target is checked against exchanger policy.
  Source/actor generation, active-state and DCR deletion commit guards pass
  positive/negative tests. `goauthy-cross-client-20260909c` passed with the new
  cross-pod E2E inside the 43.756s browser suite and existing actor/DPoP fault
  continuity. User claim/scope parity and other-grant managed defaults remain open.

- [x] 2026-09-09 dynamic confidential-client DPoP policy cross-pod qualification:
  DCR code/client-credentials admission, authenticated policy true/false/true,
  required-proof issuance and missing-proof rejection passed the combined Kind
  gate `goauthy-dcr-dpop-20260909b` (exit 0). Bootstrap DPoP fault continuity
  also passed; dynamic-client credential fault continuity subsequently passed in `goauthy-dynamic-continuity-20260909`.

- [x] 2026-09-09 DPoP token-exchange output qualification: existing token
  verifier now allows the exchange grant, preserving Bearer-only subject/actor
  inputs as pinned Rauthy does. Real Rhiza HTTP/race checks cover output binding,
  nonce/replay and input rejection; the extended cross-pod browser test compiles.
  Three-node live exchange E2E passes (10.109s); the surrounding full profile
  later failed a DCR fixture-scope expectation before Device DPoP tests. This does not claim support
  for exchanging DPoP-bound input tokens or successful UserInfo authorization for
  exchange tokens; the resource proof verifier is tested independently.

- [x] Consumer OAuth credential metadata route (2026-09-08): read-only
  `GET /auth/v1/connection-grants/{grant_id}/credential-status` under the exact
  confidential human consumer's use token and current OAuth delivery consent.
  Existing six-field status, no credentials/exchange/mutation, expired upstream
  access-token inspection supported. Current provider/client/generation and
  post-decryption authority checks retained. Public HTTPS browser v1/v2 status,
  other-consumer denial and revoked-grant denial pass before/after standalone
  restart. App recovery wiring and new HA/chaos qualification remain open.

- [x] Device pre-issuance failure recovery (2026-09-07): BeginDeviceTX and
  SetDeviceRequestID failures release the approved claim without touching an
  outer transaction. No access/refresh/request artifacts remain. Deterministic
  real-Rhiza regression race passes 11.089s; normal confidential/public-required
  Device HTTPS flows pass before/after restart. Ambiguous-commit claims still
  retain their lease; no new HA fault-injection claim is made.

- [x] DCR `dpop_bound_access_tokens` registration and token enforcement
  (2026-09-07): schema80 boolean default false; strict HTTP type validation;
  authenticated/anonymous create, read, replacement PUT, statement precedence
  and idempotency. Fosite client carries the resolved policy; Rhiza guards
  grant consumption and token artifacts atomically, including policy changes
  during issuance. Optional Bearer remains supported. DCR focused race and
  storage/OpenAPI tests pass. Public required-DPoP Device HTTPS before/after
  standalone restart passes (0.37/0.38s); confidential optional Device passes
  (1.99/2.08s). Log `/tmp/goauthy-dcr-dpop-live-20260907.log`.
  Auth-code/refresh policy-change rejection and successful retry are tested;
  Device policy-change leaves no token artifacts and no consumed marker.
  Exchange storage cutoff regression uses injected time (including actor-only
  expiry); it does not add DPoP token-exchange protocol support.
  Broader OAuth DPoP/dynamic-policy/token-exchange race selection passes
  140.148s; strengthened actor-expiry race selection passes 12.768s.
  New HA/full DPoP parity remain open.

- [x] Device DPoP token binding and refresh source integration (2026-09-07):
  existing proof/nonce/replay/session cnf components, pre-response device claim
  release with post-response ambiguous-commit ownership preserved. Malformed
  proof and nonce retries leave the grant available; bound access/refresh and
  wrong/missing key rejection are covered. Device/DPoP race selection passes
  206.658s. [x] Bootstrap confidential Device OIDC public HTTPS before/after
  standalone restart (2.06/2.08s): nonce retry, access/ID-token verification,
  missing/wrong-key refresh rejection, same-key refresh and bound UserInfo.
  [x] DCR public-client (`token_endpoint_auth_method=none`) HTTPS Device
  access/refresh/UserInfo before/after restart (0.28/0.26s), with exact-client
  JWT verification, wrong/missing proof errors and registration cleanup.
  [x] Device cross-pod qualification and token exchange DPoP output (2026-09-09).
  [x] DPoP auth-code access/refresh/key continuity across Pod replacement, quorum loss/recovery and rolling restart (2026-09-09).
  This supersedes the historical Device-unsupported note in the DPoP row below,
  not its unchecked full-parity status.

- [x] 2026-09-07 RFC 9449 token-endpoint invalid proof error:
  existing Fosite RFC6749Error + go-jose/Rhiza verification reuse; empty,
  duplicate, malformed and refresh-key-mismatch proofs return
  `invalid_dpop_proof`. DPoP focused race tests pass (15.744s); strengthened
  refresh error assertion passes (1.897s). New browser/K8s qualification and
  Device/token-exchange DPoP support remain open.

- [x] 2026-09-07 access-token consumption expiry over real HTTP:
  `TestAccessTokenExpiryBoundaryOverRealHTTP` uses real Rhiza and identity
  validation, token exchange, signature/issuer/client/audience preconditions,
  then atomically advances existing consumption clocks from one nanosecond
  before signed expiry to exact expiry. Introspection/UserInfo transition from
  success to inactive/401. `go test -race ./internal/oauth -run
  '^TestAccessTokenExpiryBoundaryOverRealHTTP$' -count=2 -timeout=2m` passes
  (11.189s). No sleep or new package. Fosite issuance still uses wall time;
  this does not close actual Compos/Beesuh EXPIRED fixture or HA gates.

- [x] 2026-09-07 native Chromium Authorization Code password submission:
  validated HTTP(S) callback-origin CSP via stdlib `net/url` and existing
  `golang.org/x/net/idna`; `TestAuthorizationCodeNativePasswordSubmit` passes
  before/after standalone restart; follow-up (3.70/1.27s) also exchanges the
  captured code using PKCE, validates public-JWKS ID token/nonce/subject, checks
  UserInfo without browser cookies, and rejects UserInfo after token revocation.
  This is local source-overlay evidence, not a released image. Real RP web
  session completion and IDN/IPv6 browser qualification remain open.
  Full login package passes (80.554s); unsafe host/userinfo/wildcard rejection
  has focused unit coverage. See the dated entry in [STATUS.md](STATUS.md).

User-requested product extension (2026-09-06), separate from Rauthy parity. The current
support classification is maintained in [capabilities.md](capabilities.md); the dated text
below records implementation history and should not be read as the current product state:
[administrator-defined authentication collections and user-owned SaaS/agent connections](auth-collections.md).
Draft-only metadata/ownership APIs and administrator/account management UI are
implemented, with actual Chromium standalone/restart and exact-three/pod-replacement
CRUD, typed-value checks, and same-record pod-replacement API evidence.
Encrypted credential custody and manual API-key register/rotate/local-revoke HTTP
and account UI now have focused and real Chromium standalone/restart evidence.
These reuse the existing keyring, browser session/CSRF request helper and native DOM.
Actual SaaS calls, full external-provider browser E2E and agent delegation remain
unchecked; the OAuth runtime milestones below are not a working consumer connector.

2026-09-06 implementation batch (the full feature rows below stay unchecked):

- [x] 2026-09-07 Device resource audience issuance (schema v75): initial single
  resource/default persisted through approval and refresh; current client/server
  audience revalidation; token-endpoint overrides rejected; legacy NULL preserved.
  Platform permission scopes reuse current claim/catalog guards. Deterministic
  Rhiza tests include migration replay, target removal, stale grant and catalog
  mutation with no artifacts. Isolated actual HTTPS standalone/restart Device
  approval, provider Bearer, refresh and removal pass. Consumer app integration,
  public consent/use/delivery and new HA verification remain open.

- [x] 2026-09-07 managed-client resource audience registration: existing metadata
  persistence, strict create/update HTTP, native admin textarea and OpenAPI.
  Omitted PUT preserves; [] clears; audience changes invalidate prior generation
  without rotating the client secret. Code+PKCE/refresh, use authorization and
  removal are verified with local Rhiza tests and live HTTPS admin Bearer flows.
  New textarea has deterministic VM tests; actual Chromium audience editing is
  not claimed complete. Device resource issuance is covered by the milestone above.

- [ ] Consumer usage consent and constrained execution/credential delivery:
  engine prerequisite `AuthorizeConnectionUse` returns the verified token subject
  and consumer client ID under exact use scope/audience and current SQL authority.
  Schema v76 now persists generation-bound consent, with owner browser/CSRF
  create/list/revoke routes and internal `AuthorizeUseGrant` current-state guards.
  Focused real-Rhiza race, refresh/fence and migration-replay tests pass. See
  [grant contract](connection-use-grants.md). This is not credential export permission.
  Registered API-key provider binding and public connector metadata/bound-key
  registration now pass actual HTTPS standalone/restart acceptance (schema v77),
  including wrong digest, unbound registration, rotation and stale CAS rejection.
  The native account editor now shows provider operations/digest and requires
  explicit review for bound-key writes; actual Chromium standalone/restart covers
  registration, rotation, conflict/re-review and local revoke. Admin provider-ID
  form validation has deterministic VM coverage; new admin field browser E2E remains open.
  Registered API-key fixed-GET invocation is now mounted with real consumer-token
  authorization, grant/digest/operation enforcement and scalar projection. Local
  Rhiza/TLS positive and race tests pass; real HTTPS standalone/restart covers
  public-route denial cases, not positive outbound dispatch. Native owner service
  access now lists/revokes grants and creates registered API-key proxy consent
  after explicit settings/consumer/purpose/expiry review. Reviewed digest mismatch
  and provider commit races reject creation. Chromium standalone/restart covers
  this owner UI. Owner-side Bearer read scope now exposes stored grant metadata
  and the current connection generation in one Rhiza snapshot, including revoked
  or expired grants; it is not an execution-capability response. Schema v78 adds
  API-key proxy handoff HTTP create/review/approve/deny, exact registered return URI
  and one-use ticket; real HTTPS/code-PKCE standalone/restart acceptance passes.
  [Handoff contract](connection-use-handoffs.md) now includes native HTML approval
  and cold password-login continuation; the BFF session-bound callback integration
  and full cold-MFA remain open. OAuth approval creation, OAuth
  invocation, OAuth SDK token delivery and end-to-end consumer integration remain
  open. Registered API-key delivery now uses distinct credential_delivery consent,
  a confidential consumer and the existing guarded key store. Deterministic
  real-Rhiza tests reject proxy consent, revocation, expiry and key rotation,
  including mutations at the final post-decryption authorization check. This does
  not complete consumer SDK integration. Schema79 adds separate registered API-key
  delivery handoff with explicit raw-key warning and native confirmation. Actual
  Chromium/HTTPS standalone restart coverage now approves that exact mode,
  rechecks consent with a real read token, retrieves with a real confidential
  consumer use token and verifies post-revoke denial. No OAuth token is exported.
  Actual HTTPS standalone/restart bridges now cover Conductor's exact raw-key
  adapter dispatch and Beesuh Runtime's two selected API-key profiles. Revoking
  one Beesuh grant prevents additional model dispatch for that profile while the
  other continues. These use local TLS provider/model fixtures; public consumer
  login/execution integration, full OAuth delivery E2E and new HA/chaos gates remain open.

- [x] Explicit consumer OAuth refresh consent/API (2026-09-08): schema82
  defaults existing grants and pending handoffs to `allow_refresh=false`.
  OAuth credential-delivery opt-in is included in review; consumer human-token
  authority and consent are rechecked during claim/commit. Existing encrypted
  refresh engine is reused; status-only response, no automatic refresh or retry.
  Actual HTTPS/Chromium consumer refresh, changed-token delivery and revocation
  pass before/after standalone restart. Consumer BFF/SDK end-to-end integration
  and new HA/chaos qualification remain open. See [status](STATUS.md).

- [x] OAuth access-token delivery primitive and HTTP dispatch (2026-09-07):
  existing confidential-consumer delivery consent, encrypted credential store,
  provider/generation/version fences and final expiry/authority checks; no refresh
  token/client secret, new schema, package or implicit external exchange. Response
  schema is a closed API-key/OAuth oneOf. Deterministic real-Rhiza and HTTP-boundary
  tests pass. This checkbox is only the primitive: OAuth positive HTTP/browser
  E2E, approval UI/handoff, refresh orchestration and consumer SDK use remain open.
  Refresh completion now preserves the exact stored account ID under its durable
  claim; mismatch cannot replace ciphertext or advance token version. Deterministic
  store tests cover changed/missing/new identity, same-account success and uncertain
  outcome without exchange retry. Upstream identity verification remains separate.
  Final whole `internal/saas` race suite passed (533.361 seconds, exit 0;
  `/tmp/goauthy-refresh-identity-suite-20260907.log`), not a substitute for the
  still-open positive OAuth HTTP/browser and consumer E2E gates.

- [x] Registered OAuth explicit owner refresh engine/HTTP route (2026-09-07):
  session+CSRF/current version, registered restricted provider, durable single
  refresh exchange, new-token upstream identity lookup, stored-scope subset and
  post-network commit guards. Response is metadata-only. Local TLS/real-Rhiza
  race and actual HTTPS standalone/restart negative boundary tests pass. Unknown
  expiry stays unknown and cannot be delivered. Full positive OAuth public
  HTTP/browser/consumer E2E, approval UI/handoff and background refresh remain open.
  In-flight refresh tests additionally use channel barriers to prove a competing
  request cannot cause a second token exchange, and cancellation/provider revision
  during exchange leaves version 1 uncertain with retries blocked (race PASS).
- [x] Registered OAuth public HTTP standalone success E2E (2026-09-07):
  `TestConnectionOAuth2RegisteredSuccess`, isolated Dory runner, production
  restricted egress and verified TLS; registration/PKCE callback/account identity,
  explicit refresh v1→v2, stale 404, revoke, metadata/no-store and exact external
  call counts pass before/after app restart (0.18/0.17 seconds). The second run
  creates a new provider because deleted provider IDs are tombstoned. This does
  not prove active OAuth connection persistence, Chromium UI, consumer delivery
  or HA. See [runner](../deploy/e2e-saas-oauth/README.md).
- [x] OAuth credential receipt public HTTP E2E (2026-09-07): real confidential
  consumer user code+PKCE token, explicit owner delivery consent, closed 11-field
  access-token-only DTO and verified fixture use; same consent receives changed
  access token at version 2 after owner refresh. Missing auth/other consumer/
  revoked consent are rejected, no implicit outbound refresh, no-store required.
  Dory isolated final-image workflow passes before/after app restart (0.47/0.61s).
  Downstream Beesuh/Conductor OAuth adapters and approval UI remain open.

- [x] OAuth owner credential-delivery approval UI (2026-09-07): reuses native
  account grant controls, shows provider/account/scopes and token-export limits,
  requires explicit review, resets review on input changes and pins the reviewed
  credential version. Stale 409 requires close/reopen and renewed consent. Existing
  direct API callers may omit the version; malformed JSON values and API-key misuse
  fail closed. Deterministic UI/backend race and strict HTTP/schema tests pass.
  Actual Chromium consent plus public delivery/refresh/revoke passes in isolated
  Dory before/after restart (1.16/0.92 seconds). OAuth handoff, downstream adapters,
  complete external-provider browser login and HA remain separate open gates.

- [x] OAuth consumer handoff (2026-09-08): extends the existing proposal and
  atomic consent transaction with a pinned credential version (schema81).
  Owner review shows provider/account/scopes/version; refresh before approval
  invalidates the proposal. Native cold login, unchecked form, explicit approval,
  authenticated owner grant recheck and access-only delivery/refresh/revoke pass
  in isolated HTTPS Chromium before/after standalone restart (20.24/2.97 seconds).
  Log: `/tmp/goauthy-oauth-handoff-live-20260908-v2.log`. Existing API-key paths
  remain supported; no OAuth proxy or implicit refresh is introduced.
  Real Backoffice callback/state consumption, downstream OAuth adapters,
  cold-MFA and new HA/chaos remain open.

- [x] Same active OAuth connection/grant persistence across two standalone
  restarts: `GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART=1` combined with the connection UI
  profile passed in final-source isolated Dory (5.79s); compile/shell/vet pass. It retains
  owner/consumer credentials in the running test process and checks exact v1/v2
  token preservation with no extra provider exchange. Do not count the earlier
  two independent workflows as proof of this gate.

- [x] OAuth successful callback browser completion: stdlib escaped HTML for
  document navigation, existing JSON for API requests, fixed account return and
  separate-consent warning. Selector/escaping/API tests and vet pass. Real Chromium
  synthetic-provider redirect → callback HTML → account return passes together
  with consent/refresh/revoke and two active restarts (5.36s); screenshot reviewed.
  This does not cover an external SaaS provider's own login UI or OAuth handoff.

- [x] OAuth owner connection-management UI: implementation and deterministic
  Node regression tests complete; live Chromium start/refresh/local revoke now pass
  with two active restarts (5.79s). The extended reconnect/new-consent/version-3
  receipt flow also passes (5.99s), including old-generation denial, stale-revoke
  409, exact provider counters and a reviewed reconnect-panel screenshot.
  Native provider selection and explicit authorization link, metadata status,
  confirmed refresh/local revoke/reconnect preparation reuse existing server
  handlers. Failed mutations require fresh status; uncertainty never triggers
  automatic retry. Disabled/removed-provider connections remain locally revocable.
  Browser start/refresh/revoke profile is `GOAUTHY_E2E_OAUTH2_CONNECTION_UI=1`;
  its Go helper compiles and passes the combined standalone gate. The callback
  completion page is now verified above; external provider login remains separate.

- [x] 2026-09-07 owner OAuth reconnect preparation route (schema v74):
  revoke → prepare → existing authorization start/callback; preserves connection
  ID/metadata, changes generation and atomically replaces revoked ciphertext at
  old token version + 1. Encrypted proof binds the target version. Real Rhiza/TLS
  tests cover two reconnects and stale DELETE rejection, plus migration/replay
  preservation. HTTPS pre/postrestart covers request/CSRF/draft-conflict boundaries,
  not a complete external-provider browser flow. UI/handoff and consumer grants/use
  remain open. See [current verification and limitations](status.md).

- [x] 2026-09-07 owner OAuth credential status and local revoke routes:
  authenticated metadata-only status, exact token-version/generation CAS,
  refresh completion and old pending authorization cannot resurrect revoked
  credentials. Disabled collection/provider does not block owner cleanup.
  Focused real-DB and HTTPS draft-status/revoke-boundary checks exist;
  full external-provider lifecycle E2E, UI and consumer use remain open.

- [x] 2026-09-07 initial user SaaS OAuth start/callback routes (schema v73):
  dedicated encrypted PKCE proof, authenticated metadata bindings, key lifecycle,
  current owner/provider/collection/session guard, one-use code exchange,
  account identity and granted-scope check before credential installation.
  Real Rhiza + external TLS boundary tests and standalone HTTPS start/invalid
  callback pre/postrestart checks pass. Full external-provider browser E2E,
  UI, consumer grants/use remain unchecked.

- [x] 2026-09-07 OAuth2 provider identity configuration (schema v72): persisted
  paired HTTPS endpoint/subject field and restricted access-token identity lookup.
  Reuses x/oauth2, SaaS transport/JSON decoder and stdlib; no new dependency.
  Deterministic TLS boundary tests and actual provider-registration HTTPS CRUD
  pass before/after restart. This is an engine/configuration prerequisite;
  public user start/callback and consumer consent/use remain unchecked.

- [x] 2026-09-07 persisted provider registration admin CRUD and schema v71:
  existing OAuth2/API-key validation, Rhiza authority/CAS/tombstones, envelope
  encryption/rewrap/retirement, OpenAPI and focused real-DB checks.
  [x] provider admin Bearer with exact resource/scopes/current admin and atomic
  role/token guards; actual HTTPS pre/postrestart and focused race evidence.
  [ ] Full OAuth callback browser E2E, per-consumer consent/use APIs and actual Backoffice app
  integration remain separate unfinished requirements; not a completed connector.

- [x] 2026-09-07 permission-only scopes and authenticated DCR per-client
  resource audience registration. Reuses the existing claims/DCR Rhiza schema,
  stdlib JSON/URL validation and Fosite audience checks; no new dependency.
  Actual independent Compos direct OAuth2 identity/membership isolation and
  wrong-audience/scope/revoked-token rejection passed; expired-token live fixture
  and audience-specific introspection ACL remain open. [Evidence](consumer-integrations.md).

- [x] Device approval context: server-sourced requesting client ID, scopes and
  optional resource; readonly reviewed code with explicit approve/deny. A stdlib
  HMAC binds CSRF to the normalized code; no new schema/dependency. Manual entry
  uses GET lookup before approval, with separate lookup rate limiting and no
  unavailable-grant metadata. Fixed-clock real-DB/HTTP checks cover code
  substitution, escaping, expiry, state and limits. Final-source Chromium checks
  exact client/scopes and approval → OIDC before/after standalone restart
  (2.45/2.30s). Subsequent test-only overlay verifies cold manual-code entry →
  review → approval → OIDC before/after restart (2.22/2.26s), alongside the complete
  URI path (2.57/2.26s). Latest-source Ternal CLI Device login/session/groups/logout
  now passes in isolated Linux before/after GoAuthy restart (5.54/5.56s).
  Mobile, public CLI release and full Ternal SSH/session durability remain separate
  gates; see STATUS.md for exact image/evidence.

- [x] 2026-09-07 Device OIDC ID-token/groups/refresh extension: reuses Fosite,
  existing go-jose signing and principal/policy transaction guards. Standalone HTTP
  approval, group rename/current refresh, replay rejection and revoke pass before/after
  restart; full OAuth and focused revision-race evidence in [status](status.md).
  Cold Chromium login/code review/explicit approval now passes before/after
  standalone restart (3.97/3.35s), including the native null-Origin regression fix.
  Device package race passes (191.477s). Latest-source consumer application and
  new HA verification remain unchecked; approval client/scope display is separate.

- [x] Cold-browser OAuth Device Flow login handoff, explicit approval/denial,
  access/refresh and introspection-backed protected HTTP resource; actual
  standalone and post-restart evidence in [device pilot](device-flow-pilot.md).
  Full Device Grant completion remains unchecked; this is not device inventory.
- [x] Device creation client authentication through Fosite, strict auth-input
  handling and pre-auth rate limiting; public device+refresh registration and
  standalone cold-login/restart E2E. Full parity remains unchecked.
- [x] Managed static-client core API, encrypted secret read/rotation, schema-v63
  ID ownership/tombstones, revision/generation OAuth commit guards and standalone
  HTTP E2E. [Implementation/package map and remaining fields](managed-clients-implementation.md).
- [x] Managed-client administrator UI and schema-v65 Device generation binding,
  initial policy creation, exact-revision secret rotation response. Actual
  Chromium public Device/refresh/disable and confidential secret rotation passed
  standalone and after same-DB restart. This candidate's HA/managed pending grant
  fault gate is still pending; full client/Device parity remains unchecked.

- [x] Standard profile/email/address/phone ID-token and UserInfo projection,
  current-profile refresh, locale scope isolation, configurable preferred-name
  email fallback, bootstrap scope admission; standalone and exact-three Kind
  evidence is in [status](status.md) and [claims implementation](profile-claims-implementation.md).
- [x] Administrator users/roles/groups UI route and CSRF wiring, deterministic
  JS action tests and standalone/exact-three HTTP integration.
  [UI implementation](admin-ui-implementation.md) lists missing screens and
  the real-browser action E2E results and remaining full-admin gaps.
- [x] Encrypted API-key bootstrap reader and startup wiring, real Rhiza import,
  authentication/idempotency and tamper/no-partial-write tests.
  [Bootstrap implementation](api-key-bootstrap-implementation.md) distinguishes
  the Generate shared startup/retrieval CLI from pending deployed HA verification.
- [x] Event notification worker startup/shutdown and Slack/Matrix/SMTP configuration;
  standalone SMTP receipt and deterministic queue/runtime tests. Complete notifier
  parity remains unchecked in [the contract](event-notifications-implementation.md).

The remaining user CRUD contract, package mapping and transaction prerequisites
are tracked in [user-management.md](user-management.md). Existing membership,
password and deletion routes do not complete the general user-management API.
The guarded user list now has a public route, deterministic pagination and
OpenAPI contracts; its live gates and explicit cursor/legacy-field adaptations
are recorded in that contract. A guarded detail route now projects existing
state and persisted registration language with self/direct/delegated target policy; expiry/failure-history
and federation data gaps keep full detail unchecked. Administrator creation is
now wired through the existing password-new service; full update parity remains incomplete.
The administrator PUT decoder, role/group predicate and atomic identity update
engine now have deterministic tests, including interposed authority changes,
password/profile/email effects and rollback. The public PUT now returns the
transaction's shared detail projection, sends two-address SMTP notices when
configured, and wakes existing SCIM reconciliation. Standalone/cold restart and
exact-three HA/Pod-replacement profile/password/email/disable/reactivation gates
pass; these are not full expiry/chaos or UI completion.
See [the update checklist](user-management.md) and [current evidence](status.md)
for remaining full profile policy/projection, remote SCIM and broader live gates.
The nine ordinary profile fields now share required/optional/hidden admission
policy between public signup and administrator PUT, with Rauthy's required-given-name
default and administrator-create exemption. Config discovery, preferred-username
policy and login-time profile completion remain separate unchecked work.
Creation's full event/SCIM/UI and additional live fault gaps remain unchecked below.
Schemas 59–60 implement transactional creation events, guarded lifecycle POST
query, retention and SSE with bounded history/live delivery using stdlib and
Rhiza; see the per-emitter/package/verification ledger in [events.md](events.md).
The server-defined Test event has a guarded create endpoint using the same
schema; browser CSRF/direct-admin and API-key Events:create remain distinct from
read-only group administration. Reset-form success, including first-password
setup, now records a guarded Notice event; standalone cold restart and HA
Pod-replacement evidence is in [status](status.md). JWKS activation now records
one atomic Notice event per winning old/pending pair; current verification is
tracked in the same status report. Notification delivery, configurable persistence,
13 types without GoAuthy emitters remain open; the password-reset admin branch
and administrator email-change emitter are now connected, with scoped evidence in [status](status.md);
[all 24 types](event-emitter-matrix.md) distinguish missing lifecycle wiring from
upstream-declared-but-unused types rather than treating every enum as a new detector.
Automatic failed-login IP blocking now appends a Warning event using Rhiza's native
transaction result references for the actual stored expiry; current exact-one/HA,
clock/interposition and rollback evidence is maintained in [status](status.md).
Accepted login failures now append `InvalidLogins` in the counter transaction,
using native `RETURNING`/`OutputRefs` for the exact count and default level;
the existing stdlib event identity and Rhiza receipts are reused. Automatic
blacklist disablement does not suppress this event. Dedicated password-failure
standalone/HA POST/SSE and restart evidence is in [status](status.md); full
failure-source/configuration/notification parity remains unchecked.
Back-channel failure at the attempt limit now appends `BackchannelLogoutFailed`
in the existing lease-guarded transaction; Rhiza binds the committed attempt
count. Fixed-clock/race/rollback tests and actual 100-send standalone/HA
POST/SSE/restart gates pass; [status](status.md) separates this emitter from the
unfinished full upstream retry policy and notifier/configuration work.
SCIM attempt-limit events cover both completion and expired final claims with
deterministic/race/rollback tests. Actual user-create failure 5-attempt
standalone/HA POST/SSE/restart gates pass. Group-create/user-delete workflows
also pass both modes with five failed provider lookups per resource and restart
persistence; actual POST/PUT/DELETE failures are separately HTTPS-integration
tested. The [SCIM event ledger](events.md) does not mark full-sync or complete SCIM parity done.

| Status | Administrator creation slice | Package mapping | Verification boundary |
|---|---|---|---|
| [x] | Strict create DTO, same-batch authority/state, memberships and one-use setup | stdlib `net/http`, `encoding/json`, `regexp`, `time/tzdata`; existing `identity`, `rbac`, `recovery`, `go-mail`; Rhiza v0.10.0 | Deterministic duplicate/concurrent/rollback, current browser/API-key authority, delegated exact/wildcard and independent OpenAPI schema tests; live results in [status.md](status.md) |
| [ ] | Complete administrator-create parity | Existing SCIM runtime/outbox + stdlib channel, event services and account UI; direct policy rationale in [package research](package-research.md) | [x] post-commit creation wake, pending inactive projection, abandoned-registration SCIM tombstone preservation and transactional creation lifecycle records/query; [ ] notification/SSE parity, all-change immediate sync, configurable preferred-name policy, UI, delegated/API-key live E2E and creation-specific chaos |

Schema 57 adds closed nine-language registration persistence and stored-language
reset/new/duplicate SMTP selection using the existing stdlib resolver/templates,
Rhiza constraints, TOML catalogue and `go-mail`. Legacy fallback is preserved;
the live evidence is recorded in [user-management.md](user-management.md).
General self language update, all-page UI translation and complete translated mail copy
remain open.

Schema 58 adds stored account-expiry projection, request-time identity/browser
guards and token-endpoint access/refresh/ID caps, including exchange actor limits.
Deterministic submission-clock and snapshot guards reject future shortening and
NULL-to-finite races; HTTP tests compare signatures and stored expiries.
The expiry worker now atomically disables/revokes and enqueues subject-only
backchannel work per known user/client using schema 61,
with opt-in retention deletion and existing SCIM reconciliation. Deterministic
stale-selection/concurrent-worker and retained-user projection tests cover this slice.
The final-disable rollback test preserves the user/client records and retries
without partial revocation. Hard user deletion uses the same subject-only scope;
its actual RP delivery and pre/post-deletion restart evidence is tracked in
[status](status.md), separately from the still-unverified expiry live gate.
Authorization code/PKCE caps and exact account snapshots are also wired. Current
OAuth consumption (introspection, UserInfo, ForwardAuth and exchange source/actor)
checks account eligibility without interfering with raw revocation/reuse lookup.
This is not completed account expiry: PAM/re-activation lifecycle, admin
write routes and expiry-specific live/chaos gates remain
unchecked in [user-management.md](user-management.md).

Recent source fixes include the Fosite request-state race root fix,
authorization-code client binding, Authorization/API-Key no-fallback,
X-Forwarded-For/Forwarded hardening, deterministic goroutine cleanup, and
serialized E2E port allocation. Geoblock and manual IP-blacklist cores are
implemented and source-wired behind opt-in configuration; geoblock accepts a
trusted country header or local MaxMind lookup, requires trusted proxies for a
header source, and applies strict ASCII ISO alpha-2 plus allow/deny/unknown
semantics. The standalone `scripts/e2e-geoblock-standalone.sh` and exact-three
`scripts/e2e-geoblock-ha-kind.sh` live gates pass all-pod admission, pod-1
replacement, malformed/ambiguous forwarding, and trust-boundary rollout/spoof
denial. Real official MaxMind test-database lookups now pass standalone and
exact-three HA, including replacement and trust-boundary rollout; the HA
ConfigMap namespace was corrected during the 2026-09-05 run. No downloader or
update scheduler is claimed.

The startup failure guard introduced for Rhiza v0.10.0 is retained with v0.12.0:
failure paths intentionally skip `db.Close()` until all initialization succeeds;
normal post-start shutdown still closes the database as usual.

Bootstrap authentication is password-only for the initial administrator by
default; passkeys are optional. `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` is an
explicit opt-in that fails startup unless the complete passkey configuration is
valid, rather than falling back to password-only login. Forward Auth identity
headers are independent of passkey configuration: when
`GOAUTHY_FORWARD_AUTH_HEADERS=true` and passkeys are disabled,
`X-Forwarded-User-MFA` is emitted as `false`. See the
[bootstrap passkey policy](passkey-bootstrap.md).

Master-key envelope maintenance is source-wired through the runtime worker:
every minute it independently cursor-scans bounded batches of signing-key,
live DCR idempotency, and unexpired upstream-transaction envelopes, authenticates
old envelopes, and commits exact compare-and-swap rewraps under the active key.
OAuth persisted request forms redact credential, bearer, and one-use fields while
retaining non-secret protocol metadata. The broader critical-DB encryption row
remains `[ ]`: nonrotating values, CookieKey removal, and automatic key removal
are still pending. Master-key retirement Stage A
prepare, Stage B commit fencing, and Stage C runtime admission/attestation/
ready/abort are implemented; successful guarded transitions append exactly-once
audit events in the same Rhiza transaction. Deterministic standalone exact-one
and exact-three state-machine/replay/revocation-interposition/chain-integrity
tests cover the source contract; the live exact-three gate passed all three
zero-reference checks, restart boot-ID change with attestation sequence 2,
Ready, key retention, and cleanup. No automatic key removal exists.

Rhiza schema is now v58 (account-expiry storage) on official Rhiza `v0.12.0` (commit `3b5a5a07aaf83b5ed279f75b920395bda7179577`); Rhiza
`v0.9.0` is retracted because its proxy-cached commit was wrong. The schema-v38 provider-scoped SCIM remote-user
mapping, user-first full scan/reconcile, group enqueue/runtime, and schema-v39
tombstone/delete projection have deterministic source tests; production worker
wiring is behind `GOAUTHY_SCIM_PROVIDERS_FILE`. `identity.DeleteUser` atomically
creates a tombstone, cleans owned identity state, invalidates stale user outbox
rows, and durably enqueues SCIM delete work. Schema v41 snapshots immutable
deletion-time provider IDs and policies. Legacy v39/v40 tombstones have
incomplete snapshots and are never auto-cleaned. `sync_delete_users` defaults to RFC
7644 unlink and opts into hard DELETE when true; explicit user deletion always
projects hard `DELETE` regardless of that setting. Provider fan-out uses mapped
`externalId` exact checks and terminal mapping/outbox CAS. Production
HTTP/admin/self user-delete routes are now source-wired, but encrypted
per-client configuration remains absent. After a bounded drain, tombstone
cleanup removes oldest tombstones only when exact delete jobs for every
snapshotted provider have succeeded; a removed provider blocks cleanup until the
same stable ID returns, while new providers receive no historical deletes. Hard
local deletion requires `DeleteRemote`, pending/processing/dead/missing jobs
retain tombstones, and terminal delete outbox rows remain while their tombstone
exists. Schema v42 adds opaque 128-bit/22-character base64url tombstone
generations and a Rhiza-atomic exact-generation enqueue fence, preventing stale
pods from deleting recreated subjects. Empty generations, incomplete snapshots,
and malformed hard-delete snapshots fail closed; legacy/raw/no-generation delete rows are unclaimable.
Complete empty-generation tombstones are retained and skipped without blocking
later work. The generation is persisted inside delete-job JSON, and both claim
and cleanup require an exact current generation. Dead-letter retry is
operator-controlled and provider re-add alone does not revive dead jobs.
The full SCIM
rows stay unchecked. The source-integrated deterministic
`make e2e-kind-user-delete` profile has a live Kind run that remains
UNVERIFIED because current Docker `fs.inotify.max_user_instances=128` is below
the required `256`. The standalone
`scripts/e2e-user-deletion-standalone.sh` live PASS covers browser self/admin
deletion, `Users:delete` API-key boundaries, final-admin `409`, admin survival,
SCIM create plus durable tombstone `DELETE` across cold restarts, deleted-login
denial, and remote cleanup. The final narrow exact-three gate
`E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final
scripts/e2e-scim-delete-chaos-kind.sh` also passes three Ready pods, creation,
two full restarts, browser-admin/API-key deletion on different pods,
cross-pod session/token invalidation, final-admin protection, pod-0 replacement,
tombstone plus two remote `DELETE` convergence, and cleanup. The broader
user-delete/full-SCIM profile remains unverified; no full SCIM parity claim is
made. FedCM has a
Rauthy-compatible, strict default-off production source wiring via
`GOAUTHY_FEDCM_CONFIG_FILE`: HTTPS-only config, mounted
manifest/config/accounts/client-metadata/assertion/status routes, exact
`/auth/login` or `/auth/v1/account` password landing, active identity+peer
binding, CSRF/origin/Fetch-Metadata checks, one-time CAS and separate secure
cookie/logout handling. Direct passkey/passwordless login is not supported and
startup rejects simultaneous bootstrap forced-MFA; real browser/FedCM Kind/
chaos E2E remain absent. The dedicated issuer-path Kind gate passed RFC 8414
and prefixed discovery/OAuth/DPoP flows, negative path checks, pod-0
replacement, and cleanup. Broader issuer-path/browser parity remains pending.

DCR `last_used` updates for successful `PUT` and dynamic token issuance are
verified source behavior (monotonic commit-time timestamps); the remaining
unsupported paths are intentionally excluded.

Primary protocol boundaries are [RFC 7591/7592 DCR](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693.html), and [RFC 8252 native-app redirects](https://www.rfc-editor.org/rfc/rfc8252.html). Fosite supplies OAuth request/token/client mechanics, not DCR lifecycle, delegation policy, login abuse policy or native-client admission; those narrow product policies therefore remain direct Rhiza-backed code.

| Done | Feature / subfeature | Planned package or stdlib | Engine (existing evidence) | Route | E2E required | Upstream evidence |
|---|---|---|---|---|---|---|
| [x] | Discovery metadata, issuer and endpoint advertisement | `net/http`, `encoding/json` | [x] RFC 8414 OAuth and OpenID Provider metadata: `internal/oidc/discovery_test.go` | [x] `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration` | [x] `TestCurrentProfile`: issuer, authorization/token/JWKS/introspection/revocation and OpenID Provider metadata routes, including `userinfo_endpoint`, `end_session_endpoint`, cache, and implemented grant capabilities | [README][readme] |
| [x] | JWKS: active Ed25519 public key, ETag and cache headers | `go-jose/v4`, `crypto/ed25519` | [x] `internal/oidc/{keys,http}_test.go` | [x] `GET /oidc/jwks.json` | [x] `TestAutomaticRotation`: public key set, ETag conditional request and `Cache-Control` across prepublication/activation/retiring overlap | [README][readme] |
| [x] | JWKS automatic rotation / retiring-key lifetime | `go-jose/v4`, Rhiza, `time.Ticker` | [x] two-phase prepublication, bounded token lifetime, concurrent-worker retries/convergence: `internal/oidc/{rotation,rotation_worker,token}_test.go` | [x] mandatory bounded-duration worker on every node | [x] `TestAutomaticRotation` in fresh three-pod Kubernetes: pending prepublication, active transition, retiring overlap, ETag and cache semantics | [README][readme] |
| [x] | Authorization endpoint and authenticated browser login | `ory/fosite`, `net/http`, `html/template` | [x] authorization boundary and login handler: `internal/{oauth/authorization_boundary,login/handler}_test.go` | [x] `GET /oidc/authorize`, `POST /auth/login` | [x] `TestAuthorizationCodeLoginAcrossPods`: anonymous `prompt=none`, login form, cookie/interaction binding, session rotation/old-Init rejection, cross-pod login and callback code | [README][readme] |
| [x] | Browser reauthentication directives (`prompt=login`, `prompt=consent`, `max_age`) | Fosite request parser + direct IdP policy | [x] strict prompt/max-age validation and reauthentication policy: `internal/{oauth/authorization_boundary,login/handler}_test.go` | [x] `GET /oidc/authorize` | [x] `TestAuthorizationBoundaryMatrix`: `prompt=login`, `prompt=consent`, `max_age=0`, authenticated and anonymous `prompt=none` across public pods | [Rauthy authorize][authorize] |
| [x] | Authorization code grant: code single use | `ory/fosite`, Rhiza transaction | [x] `TestAuthorizationCode*` | [x] `GET /oidc/authorize`, `POST /oidc/token` | [x] `TestAuthorizationBoundaryMatrix`: wrong verifier does not consume the code; correct exchange on pod 1; replay rejected on pod 0 | [README][readme] |
| [x] | PKCE S256 required; plain rejected | `ory/fosite` | [x] `TestAuthorizationRequiresS256PKCE` | [x] `GET /oidc/authorize`, `POST /oidc/token` | [x] `TestAuthorizationBoundaryMatrix`: missing and `plain` challenges fail without redirect leakage; S256 wrong/correct verifier cases run across pods | [README][readme] |
| [x] | Refresh-token grant and rotation/reuse detection | `ory/fosite`, Rhiza transaction | [x] `TestAuthorizationCodePKCEAndRefreshRotation` | [x] `POST /oidc/token` | [x] `TestAuthorizationCodeLoginAcrossPods`: rotation on pod 1 and old-token reuse rejection on pod 0 | [README][readme] |
| [x] | Client-credentials grant | `ory/fosite` | [x] `TestClientCredentialsToken` and configurable-lifetime coverage in `TestClientCredentialsTokenUsesClientLifespan` | [x] `POST /oidc/token` | [x] `TestClientCredentialsPublic`: authenticated request, scope denial and configured 10-second lifetime expiry through introspection for deterministic E2E timing | [README][readme] |
| [x] | Token introspection | `ory/fosite` | [x] `TestIntrospectionAndRevocation` | [x] `POST /oidc/introspect` | [x] `TestCurrentProfile` + `TestCrossPodRevocation`: active/inactive disclosure | [README][readme] |
| [x] | Token revocation | `ory/fosite` | [x] `TestIntrospectionAndRevocation` | [x] `POST /oidc/revoke` | [x] `TestCrossPodRevocation`: issue on pod 0, revoke on pod 1, reject on pod 0 | [README][readme] |
| [x] | OIDC ID token and UserInfo claims | Fosite OAuth store + `go-jose/v4` | [x] Existing EdDSA ID-token sign/verify and UserInfo boundary/subject coverage. Schema-v24 adds canonical `roles` (always an array) and scope-gated `groups`; authorization-code exchange, refresh, UserInfo and introspection resolve current principal data rather than trusting Fosite `Extra`. Token persistence is guarded by the active identity and the resolved principal revision, so a concurrent membership change fails closed. | [x] `POST /oidc/token`, `GET`/`POST /oidc/userinfo`, `POST /oidc/introspect` | Existing `TestUserInfoAcrossPods` passed. [x] focused deterministic claims/introspection and pre-commit revision-bump regression tests; final three-pod gate passed current roles/groups claims through refresh and UID/Ready-verified replacement. | [README][readme] |
| [ ] | Dynamic Client Registration / management (RFC 7591/7592) | create/update uses stdlib `net/http`, `net/url`, `encoding/json`, `regexp`, `sort`, crypto plus `x/crypto/bcrypt`, Fosite client types and direct Rhiza persistence | [x] authenticated create/read/update/delete, schema-v34 idempotency, v44 HTTPS `client_uri`, v46 canonical `contacts` (max 32 Rauthy-compatible 1–48-byte ASCII values), v47 HTTPS `logo_uri`, `tos_uri`, and `policy_uri` metadata (each max 2048 bytes; never fetched), schema-v53 optional `software_statement` persistence, and schema-v54 canonical replicated `dcr_software_statement_trust` digest/topology fence. Software statements are accepted only with `GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE`: compact JWS, exactly one statically trusted issuer key, verified `iss` and optional `aud`, with statement metadata taking precedence over duplicate request JSON; invalid/untrusted statements fail with `invalid_software_statement`/`unapproved_software_statement`, and the original JWT is returned unchanged. The v54 startup/readiness fence accepts exactly one or three members and fails closed on config/topology mismatch. URI metadata is authenticated-only; anonymous registration rejects those URI fields. Software statements require the configured trust file. POST null is rejected; RFC 7592 PUT requires matching `client_id` and omission/null/empty clears optional metadata. Device-only/hybrid grants and anonymous bounded admission are covered. | [x] mounted global bearer or anonymous `POST /oidc/register`; per-registration bearer `GET`/`PUT`/`DELETE /oidc/register/{id}`; discovery endpoint | Standalone anonymous/device E2E passed; `scripts/e2e-software-statement-standalone.sh` live replay/readiness E2E passes; source/HTTP/idempotency and trust-fence tests pass. Exact-three HA gate `KIND_CLUSTER=goauthy-software-statement-ha-e2e-20260905i` on ports `19840-19842` passed all three pods Ready with identical trust, cross-pod GET persistence, invalid signature/issuer/audience rejection on all pods, pod-0 UID replacement, byte-identical idempotent replay after restart, and cleanup. The earlier Docker inotify blocker was superseded by the 2026-09-09 full-profile Kind pass. Confidential client-credentials and authorization-code plus refresh registration now have HTTP/Store race coverage; dynamic required-DPoP policy cross-pod qualification passed in the combined 2026-09-09 Kind gate; dynamic credential fault continuity also passed in `goauthy-dynamic-continuity-20260909`. | [Rauthy dynamic request][dynamic-client-request] |
| [x] | RP-initiated logout | `net/http`, `html/template`, `crypto/rand`, `go-jose/v4`, direct Rhiza session policy | [x] `internal/logout/{logout,http}_test.go`, `internal/{browser/store,oauth/oidc,oidc/token}_test.go`: canonical `sid`/`sub`/`azp` binding; exact registered redirects; 4 KiB hint and 2 KiB state bounds; fixed 600-second logout-only ID-token leeway with 70-minute retiring-key lifetime; read-only current-session lookup; one-time same-origin confirmation; atomic Rhiza browser/OAuth `sid` revocation, including pending codes; OIDC code issuance guards revoked/expired/invalid session IDs | [x] `GET`/`POST /oidc/logout` | [x] `TestRPInitiatedLogoutAcrossPods`: invalid/open redirect and malformed/oversize inputs preserve the session; hint and confirmation paths delete the cookie and revoke access/refresh/pending code across pods; replay is rejected | [Rauthy logout][logout] |
| [ ] | Back-channel logout | `go-jose/v4`, `net/http`, `crypto/tls`, `crypto/x509`, Rhiza; no extra package | [x] Bootstrap single-RP SID delivery, transactionally recorded user/client login state and schema-61 subject-only global and per-user administrative delivery; existing Rhiza lease/CAS, custom CA roots, TLS 1.2+, SNI, no-proxy/no-redirect transport and last-known-good CA reload retained | [x] bootstrap `GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI`, optional CA file and per-pod worker; global and per-user session DELETE deduplicate by user/client | [x] fixed-clock subject/SID JWT, TLS worker, migration row preservation, issuance rollback and per-user isolation/concurrency; actual global and per-user RP receipt after standalone restart, with exact-three HA verification status in [status](status.md). [ ] full multi-client registry, non-browser grant tracking, other user-wide lifecycle parity, mixed-version upgrade, pending-pod/quorum delivery and policy-enforcing CNI matrix remain open | [Rauthy back-channel][backchannel], [research](package-research.md) |
| [ ] | Device Authorization Grant (RFC 8628) | stdlib `net/http`/`html/template`/`crypto/rand`/`crypto/subtle` + Rhiza; custom Fosite token handler | [x] schema v10 digest-only `oauth_device_grants` and rate-limit state; opaque device/user codes, normalized user-code lookup, expiry, polling interval/`slow_down`, CSRF + Fetch-Metadata/origin-protected approve/deny, claim lease and atomic Fosite token issuance/consume: `internal/{device,oauth/device_grant,oauth/grant_storage}_test.go` | [x] `POST /oidc/device`, `GET`/`POST /oidc/device/verify`, `POST /oidc/token` device-code grant | [x] final three-node `Device` E2E PASS (13.396s) covers the bootstrap path; standalone public HTTP E2E covers dynamic device-only registration through `/oidc/device` without polling sleeps. The later OIDC extension supports `openid groups` and ID-token refresh as recorded above. Dynamic-client Kind and complete approval-context UX remain open; direct-peer rate limiting ignores forwarding headers pending trusted-proxy policy | [README][readme] |
| [x] | DPoP-bound tokens (RFC 9449; pinned Rauthy feature scope) | existing `go-jose/v4` + stdlib HTTP/crypto + direct Rhiza CAS nonce/replay state | [x] schema v11 digest-only `dpop_nonces`/`dpop_replays`, client+`jkt` nonce binding, one-use consumption, cross-pod `jti` replay mark and bounded 128-row expiry cleanup. `go-jose/v4` verifies `dpop+jwt`/embedded public JWK while direct code enforces `htu`/`htm`/`iat`/`jti`/nonce and UserInfo `ath`; Fosite session `Extra` preserves verified `cnf.jkt`: `internal/{dpop,oauth/dpop,oauth/grant_storage,storage/migrate}_test.go` | [x] DPoP-aware `POST /oidc/token`, `GET`/`POST /oidc/userinfo`; discovery publishes `dpop_signing_alg_values_supported` | [x] local + focused race tests pass for authorization-code/refresh/UserInfo/client-credentials: nonce challenge, `cnf.jkt`, key binding, one-use/replay and `ath`; final three-node DPoP E2E PASS (4.576s). Device access/refresh binding and confidential/public-client standalone HTTPS/restart evidence are recorded above. Device and exchange-output binding plus DCR dpop_bound_access_tokens policy are implemented. Exchange-output live Kind qualification passes; confidential/public Device live Kind qualification passes (2026-09-09); DPoP auth-code credential fault continuity passes (2026-09-09); dynamic-client policy PUT and credential fault continuity pass (2026-09-09): required metadata, pre-fault access/key/refresh, wrong-key denial and fresh no-proof client-credentials denial survive Pod replacement, quorum loss/recovery and rolling restart. Cleanup passes. This closes the pinned DPoP row, not the separate token-exchange actor/audience gaps | [README][readme] |
| [x] | Resource indicators (RFC 8707) | Fosite + explicit HTTPS allow-list | [x] client-credentials and authorization-code audience persistence through refresh; token-side narrowing is fail-closed: `internal/oauth/resource_indicator_test.go` | [x] `GET /oidc/authorize`, `POST /oidc/token` | [x] `TestAuthorizationCodeResourceIndicatorAcrossPods`: browser authorize/login, code exchange, cross-pod audience introspection, refresh narrowing rejection and unknown-target rejection; client-credentials allow/deny is also public | [v0.36.2 changelog][changelog] |
| [ ] | Resource Indicator defaults and ephemeral danger option | direct configuration policy + Fosite audience storage | [x] Bootstrap-only `GOAUTHY_BOOTSTRAP_DEFAULT_AUD` remains strict and allow-list bound; CIMD `allowed_resources` is an exact per-document RFC 8707 allow-list of absolute HTTPS resources with default-deny for unlisted values, and `GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE` is an explicit opt-in for otherwise-unlisted valid HTTPS resources | [x] CIMD allow-list/explicit-deny parsing, immutable Rhiza snapshot round-trip, authorization snapshot immutability, exact-vs-danger audience policy, and production config wiring have deterministic unit coverage | [ ] Kind E2E evidence, dynamic-client/CIMD default audiences, and three-node operational evidence remain pending; WebID/Solid and dynamic default audience are explicitly out of scope | [v0.36.2 changelog][changelog] |
| [ ] | Token exchange (RFC 8693): impersonation/delegation | custom Fosite token handler + existing Rhiza conditional atomic issuance | [x] confidential bootstrap/managed explicit-flow exchangers accept valid cross-client Bearer subject/actor inputs; target aud is exchanger ID + independent defaults + optional allowed resource/audience. Access-only output, bounded signed/persisted nested act, input/full-chain account expiry, source/actor client lifecycle commit fences and DPoP output are implemented. [x] Current user roles/scoped groups/custom claims and subject-only scope narrowing are guarded at issuance. [x] Machine input/mapped-sub actor semantics and shared managed defaults for CC/code/refresh/Device are implemented with focused race and standalone evidence. [x] Default-unmapped and final mapped Kind same-token fault qualification, full OAuth package and current authentication vet pass. [ ] Configurable post-issuance TokenIssued emission is wired; enabled/disabled machine CC/exchange and user auth-code/password standalone tests pass, including refresh suppression, invalid-password and replayed-code event absence. Device/notification/HA qualification and pinned exchange closure audit remain open. `may_act` and external JWT/SAML inputs are not pinned-upstream requirements. | [x] `POST /oidc/token`, discovery, managed client create/update/default_aud | [x] Cross-client and user-claims E2E in 51.350s browser suite; actor exchange 18.350s; combined Kind exit 0 and standalone before/after restart (2026-09-09). Existing same actor/DPoP credentials pass replacement/quorum-loss/recovery/rolling restart and cleanup. Cross-client fixture is cleaned before these fault phases. Full feature parity remains `[ ]`. | [v0.36.2 changelog][changelog] |
| [x] | Machine subject mapping (`client_credentials_map_sub`) | existing signed-token strategy + stdlib configuration | [x] Global configuration, durable machine-origin/positional actor markers, mapped JWT/introspection and machine exchange. Broad race plus colliding-user-ancestor commit/consumption guard regressions pass; malformed markers fail closed. | [x] client-credentials and exchange output; mapped machine actor semantics | [x] default/mapped standalone before/after retained-DataDir restart; [x] mapped three-pod same-token faults and mixed user-actor deletion qualification (Kind exit 0); [x] default-unmapped final fault qualification (Kind exit 0); [x] final mapped run also proves the machine-actor exchange survives unrelated real-actor deletion (Kind g exit 0, 2026-09-10); see dated status; new focused regression PASS session71118 (TestTokenExchangeMachineSubjectMapping, TestMachineExchangeRetainsCollidingUserAncestorGuard, TestMachineAccountMarkersFailClosed, 5.874s, colliding-user-ancestor/malformed-marker only, no Kind/DR) | [v0.36.2 token set](https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/token_set.rs) |
| [ ] | RFC 8414 path-insertion metadata endpoint | `net/http`, `net/url`, existing OIDC discovery handlers | [x] canonical issuer base paths, inserted `/.well-known/oauth-authorization-server/{issuer-path}`, appended OIDC discovery, prefix stripping before policy middleware, root-only health, escaped/ambiguous-path rejection, public DPoP HTU composition, relative browser forms and path-aware upstream callbacks | [x] issuer-prefixed application routes plus root RFC 8414 alias | [x] deterministic routing/normalization/DPoP/form/callback tests pass; exact-three issuer-path Kind gate passes RFC 8414 and prefixed discovery/OAuth/DPoP flows, negative path checks, pod-0 replacement, and cleanup. Broader issuer-path/browser parity remains pending | [v0.36.2 routes][routes] |
| [x] | RFC 8252 loopback redirect opt-in | stdlib `net/url`/`net` + Fosite redirect matching; direct admission policy | [x] default-off `GOAUTHY_RFC8252_LOOPBACK_REDIRECTS=false`; public dynamic authorization-code clients admit canonical literal `127.0.0.1` and `[::1]` templates with port variation; `localhost` requires an explicit exact port. Host/path/query remain exact. Unit/handler tests cover hostile variants. | [x] DCR metadata plus `GET /oidc/authorize` | [x] fresh exact-three HA gate `scripts/e2e-rfc8252-loopback-kind.sh` covers literal IPv4/IPv6 port variation, exact-port localhost, hostile host/userinfo/path/query negatives, cross-pod authorization/code exchange, and pod-0 replacement. | [v0.36.2 changelog][changelog] |
| [ ] | Ephemeral URL-document clients (CIMD) | stdlib `net/http`, `net/url`, `net/netip`, `crypto/tls`, `crypto/x509`, `encoding/json`, `crypto/sha256`; Fosite client types; Rhiza schema-v13 cache | [x] default-off resolver validates public HTTPS TCP/443 only, exact URL `client_id`/document binding, pinned validated DNS address, no redirects/proxy/cookies/compression, 5 KiB JSON limit, public authorization-code+S256-PKCE only, same-origin HTTPS redirects, constrained scopes and shared fail-closed cache. Persisted authorization/code/access requests use a sanitized metadata snapshot; public token-client authentication uses shared cache-only lookup and never network refetch. CIMD RFC 8707 `allowed_resources` snapshots are exact (including explicit empty deny), while arbitrary valid HTTPS resources require the separate danger policy. Production egress must align to public TCP/443: `internal/{cimd,oauth}/**/*_test.go`, `internal/storage/migrate_test.go`, `cmd/goauthy/main_test.go`, `internal/oidc/discovery_test.go` | [x] opt-in `GOAUTHY_CIMD_ENABLED=true`; discovery advertises `client_id_metadata_document_supported` only then; `GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE` is default-off and production-wired | [ ] CIMD Kind TLS-fixture E2E has not run; deterministic DNS rebinding/policy coverage is unit-only, and cache expiry, Cilium NetworkPolicy enforcement, chaos and lenient-policy Kind evidence remain pending. Fixture `externalIPs` routing is deprecated in Kubernetes 1.36 and disposable-kind test-only, not production egress. No local/private-address escape hatch exists; dynamic defaults, WebID and Solid remain unsupported. | [ephemeral clients][ephemeral]; [CIMD draft][cimd-draft] |
| [ ] | Ephemeral-client Solid/WebID support | `net/http`, `encoding/json` | [x] default-off public WebID profile document: active account profile, deterministic Turtle, canonical subject path, strict content negotiation and bounded output; Solid audience/client behavior remains absent | [x] `GET /auth/{subject}/profile` when `GOAUTHY_WEB_ID_ENABLED=true` (under the configured issuer path) | [x] `make e2e-standalone-webid` proves exact Turtle subject/issuer/privacy output, strict Accept/path/method handling, and restart stability; [x] exact-three `scripts/e2e-webid-ha-kind.sh` live gate passes cross-pod output and replacement-pod checks; Solid audience opt-ins remain pending | [ephemeral clients][ephemeral] |
| [ ] | CIMD `ignore_unknown_auth_flows` | direct CIMD admission policy + Fosite flow validation | [x] `decodeMetadataWithPolicy` deterministically retains known grants and requires `authorization_code` while ignoring unknown grants; malformed values remain rejected | [x] CIMD resolver is production-wired with strict default and opt-in `GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS` policy | [ ] deterministic unit/config coverage exists; lenient-policy Kind negative/positive evidence remains pending | [ephemeral clients][ephemeral] |
| [ ] | Experimental FedCM | browser standards APIs + `net/http`, separate secure browser cookie | [x] strict default-off HTTPS config via `GOAUTHY_FEDCM_CONFIG_FILE`; mounted manifest/config/accounts/client-metadata/assertion/status routes; exact `/auth/login` or `/auth/v1/account` password landing; active identity+peer binding; CSRF/origin/Fetch-Metadata checks; one-time CAS and separate cookie/logout; deterministic `internal/fedcm` and cookie tests; bootstrap forced-MFA coexistence is rejected at startup | [x] production source-wired when `GOAUTHY_FEDCM_CONFIG_FILE` is configured | [ ] password-only landing has no direct passkey/passwordless login; HTTPS `/readyz` probes and their manifest static test are covered, but real browser/Kind/chaos E2E and disconnect/onboarding remain absent | [README][readme] |
| [ ] | `forward_auth` simple bearer-validation analogue | `net/http` + existing OAuth/session storage | [x] deterministic valid/revoked/expired/non-user/disabled/DPoP-bound and malformed-transport coverage in `internal/oauth/forward_auth_test.go` | [x] production `GET /oidc/forward_auth` route; opt-in identity-header emission is wired | [x] standalone `scripts/e2e-forward-auth-standalone.sh` identity/header and hostile-header E2E passes; [x] no-passkey standalone `E2E_PORT=18087 scripts/e2e-forward-auth-standalone.sh` passes password bootstrap, `X-Forwarded-User-MFA: false`, restart persistence, and forced-MFA/no-passkey startup failure; [x] final exact-three `KIND_CLUSTER=goauthy-forward-auth-ha-e2e-final7 E2E_PORT=20400 ./scripts/e2e-forward-auth-ha-kind.sh` runs on application ports `20400-20402` and passes all-pod identity headers/hostile clearing, pod-0 UID replacement with persisted-token validation, revocation and final-admin self-delete denial, and cleanup; [x] no-passkey exact-three `KIND_CLUSTER=goauthy-forward-auth-ha-nopasskey-final E2E_PORT=20500 ./scripts/e2e-forward-auth-ha-kind.sh` passes three Ready pods without passkey assets, `MFA=false`, hostile-header clearing, pod-0 replacement, revocation, final-admin self-delete denial, and cleanup on ports `20500-20502`. Broader proxy modes/ACL parity remain incomplete | [Rauthy forward auth][forward-auth] |
| [ ] | Forward Auth trusted identity headers | stdlib `net/http`/`net/netip` + explicit trusted-proxy policy | [x] closed-set, overwrite/clear, canonicalization and hostile-value coverage in `internal/oauth/forward_auth_headers_test.go` and handler coverage | [x] opt-in identity headers are emitted by the production Forward Auth route | [x] no-passkey standalone `E2E_PORT=18087 scripts/e2e-forward-auth-standalone.sh` confirms password bootstrap, `X-Forwarded-User-MFA: false`, restart persistence, and forced-MFA/no-passkey startup failure; [x] standalone `scripts/e2e-forward-auth-standalone.sh` covers identity projection and hostile, duplicate, malformed, and overlong headers; [x] no-passkey exact-three `KIND_CLUSTER=goauthy-forward-auth-ha-nopasskey-final E2E_PORT=20500 ./scripts/e2e-forward-auth-ha-kind.sh` covers three Ready pods without passkey assets, `MFA=false`, hostile clearing, pod-0 replacement, revocation, final-admin self-delete denial, and cleanup on ports `20500-20502`; final passkey-enabled exact-three coverage remains recorded above |
| [ ] | Outbound SCIM user synchronization | schema-v42 direct Rhiza mapping/outbox/tombstone/provider-snapshot state + stdlib `net/http`/`encoding/json`/`crypto/tls`/`crypto/x509` client core | [x] provider-scoped remote-user mapping, user-first full local scan/reconcile, `/Users` lookup/create/PUT core, durable serialized user outbox, group enqueue/runtime, and v42 `identity.DeleteUser` tombstone/owned-row cleanup are source-tested with immutable `externalId`, exact `userName`, mapped externalId exact checks, schema/status/Location checks, bounded responses, TLS 1.2+/hostname verification/no-proxy/no-redirect defaults, optional per-provider `ca_file` CertPool loading, deterministic coalescing/lease/retry state, stale user-outbox invalidation, provider fan-out, and terminal mapping/outbox CAS. Transport/DNS/TLS/drop failures and `429`/`5xx` retry; malformed/permanent `4xx` responses dead-letter. Deletion snapshots immutable provider ID/policy; v42 adds the exact-generation enqueue fence. [ ] encrypted per-client runtime configuration | — | Standalone live SCIM E2E passed in repeated runs (`14.9s` and final post-hardening `18.6s`), covering SMTP registration, restart-immediate sync, exact `externalId`, public admin delete, restart-exact remote `DELETE`, and login rejection. The final narrow exact-three gate `E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final scripts/e2e-scim-delete-chaos-kind.sh` passes three Ready pods, creation, two full restarts, browser-admin/API-key deletion on different pods, cross-pod session/token invalidation, final-admin protection, pod-0 replacement, tombstone plus two remote `DELETE` convergence, and cleanup. The broader exact-three user/full-SCIM harness still stops at Docker inotify `128<256`; duplicate-delivery/chaos and full SCIM remain unchecked; delivery is intended at-least-once across crashes, not exactly-once. | [SCIM][scim] |
| [ ] | User deletion (admin and self) | stdlib `net/http` plus existing browser/CSRF/API-key policy; direct Rhiza identity transaction | [x] `identity.DeleteUser` atomically snapshots the SCIM tombstone, removes owned identity/RBAC/session/link state, invalidates stale user outbox rows, and durably enqueues provider work. Explicit deletion is always SCIM hard `DELETE`, independent of `sync_delete_users`; final active `rauthy_admin` protection is deliberate GoAuthy hardening because the fixed Rauthy admin-delete path has no equivalent guard. | [x] Admin `DELETE /auth/v1/users/{subject}`: direct `rauthy_admin` browser + same-origin `X-CSRF-Token`, or `Users:delete` API key; empty body; `204`, `404` missing/inactive, `409` final admin, `503` backend failure. Self `GET`/`DELETE /auth/v1/users/{subject}/self/delete`: authenticated same-subject browser, `GET` capability `202`, enabled `DELETE` with CSRF `204` and cookie clear; default-off `GOAUTHY_ENABLE_SELF_DELETE=false`, disabled/admin/final-admin `406`. `GOAUTHY_BOOTSTRAP_FORCE_MFA` gates browser-admin deletion only; API keys are unaffected. | [x] deterministic handler/store tests cover default-off, exact statuses, auth no-fallback, CSRF/same-origin, forced-MFA admin denial, API-key deletion, atomic cleanup/rollback, concurrent final-admin protection, tombstone enqueue and hard-delete policy. [x] standalone `scripts/e2e-user-deletion-standalone.sh` live PASS covers browser self/admin, `Users:delete` API-key boundaries, final-admin `409`, admin survival, SCIM tombstone DELETE across cold restarts, deleted-login denial and cleanup. [x] final narrow exact-three `E2E_PORT=19980 KIND_CLUSTER=goauthy-scim-delete-chaos-e2e-final scripts/e2e-scim-delete-chaos-kind.sh` passes three Ready pods, creation, two full restarts, browser-admin/API-key deletion on different pods, cross-pod session/token invalidation, final-admin protection, pod-0 replacement, tombstone plus two remote `DELETE` convergence, and cleanup. [ ] broader user-management/full-SCIM parity and unrelated chaos remain unchecked | [Rauthy user delete source](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs) |
| [ ] | Outbound SCIM group synchronization | stdlib-backed direct SCIM group core + schema-v41 Rhiza mapping/outbox/tombstone/provider-snapshot state | [x] externalId-first lookup, safe unmanaged-name fallback, create/full-PUT/delete-or-unlink and canonical full-member replacement are source-tested with strict schema/status/Location/size checks; runtime enqueues groups after all provider-scoped user mappings exist | — | Standalone exact-one live E2E on port `18981` passes user-first/retry/full-member and delete convergence; exact-three Kind `KIND_CLUSTER=goauthy-scim-e2e-20260905d E2E_PORT=19380` passes three Ready pods, full group members, pod-0 UID replacement after delete, empty/deleted convergence, and cleanup. PATCH-delta parity, prefix/group policy, broader durable-worker/chaos and the overall SCIM feature remain unchecked | [SCIM][scim] |
| [ ] | Password login, composition policy, history, expiry, and recovery | `golang.org/x/crypto/argon2`, stdlib `crypto/rand`/`crypto/subtle`/`crypto/hmac`/`crypto/sha256`/`encoding/base64`/`unicode`/`unicode/utf8`, `github.com/wneessen/go-mail`, direct Rhiza CAS | [x] bounded Argon2id/strict PHC/dummy work/rehash; Rauthy-default `Rules.ValidDays=180` with strict post-boundary expiry; v14 history, v15 keyed reset token, v16 canonical recovery-email mapping, v17 digest-only PoW rows and v30 bounded direct-peer PoW admission. Recovery requires a solved spow-v1 proof before reset issue; fixed-clock/random tests cover issue, strict parse/verify, expiry equality, replay, exactly-one consume, five-per-peer boundary, five-minute TTL, 256 total-unexpired-challenge and 256 peer-row caps (`internal/recovery/{pow,http}_test.go`, `internal/storage/migrate_test.go`). | [x] always: `POST /auth/login`, `GET /account/password`, `PUT /auth/v1/users/{subject}/self`; opt-in recovery adds `POST /auth/v1/pow` plus request/reset routes. `GOAUTHY_POW_DIFFICULTY=19` accepts `10..98`; `GOAUTHY_POW_EXPIRY=30s` accepts `1s..5m`. | [x] Fresh `E2E_PROFILE=password-reset E2E_PORT=28080 make e2e-kind` built schema v17, readied three pods, and passed `test/e2e` (`15.938s`) plus `test/e2e/browser` (`1.320s`): invalid proof denial, successful request and cross-pod replay rejection. Overall lifecycle/public recovery remains `[ ]`: recovery-address lifecycle/admin UI, mail retry/outbox/observability, templates/localization, full Rauthy MFA/reset semantics, passkeys, and unreleased email OTP. | [Rauthy hashing config](https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/config.toml) |
| [x] | Argon2id parameter calibration helper | `golang.org/x/crypto/argon2`, stdlib `flag`/`encoding/json`/`slices`/`time`; direct recommendation policy | [x] `goauthy-password-calibrate` bounds memory to `32768..131072` KiB, parallelism to `2..8`, target to `500ms..10s`, samples to `1/3/5`, tests all `t=5..1`, and emits recommendation-only JSON. Tests inject the measurement function and assert medians/order/no persistence: `cmd/goauthy-password-calibrate/main_test.go` | [x] local CLI: `-target`, `-memory-kib`, `-parallelism`, `-samples` | [x] offline advisory CLI has no Kubernetes surface; its chosen stronger setting was accepted by the fresh three-pod password-policy rollout/login E2E. Wall-clock is operational measurement only, never a deterministic test oracle. | [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| [ ] | WebAuthn/FIDO2 passkeys | `github.com/go-webauthn/webauthn v0.18.0`, stdlib AEAD and Rhiza v0.10.0 | [x] schemas v20--v22 encrypted credential/user-handle, one-use ceremony/proof/final-token CAS, factor marker, explicit `MfaModToken`/`PasswordNew` purposes and v22 session `auth_method`; admin list/reset repeats active `rauthy_admin` inside the credential CAS and self-admin deletion stays on the one-use self flow. Deterministic unit/race coverage includes duplicate JSON and role-revocation interposition. | [x] opt-in login, self account list/register/delete, administrator/API-key read and browser-administrator reset, `/mfa_token`, `/webauthn/auth/start|finish`, narrow reverse self password update and forced-client step-up | [x] prior three-pod Chrome virtual-authenticator passkey profile PASS (`5.086s`) for self flows. [x] fresh dedicated `make e2e-kind-admin-passkey KIND_CLUSTER=goauthy-v29-admin-passkey-deterministic E2E_PORT=28400` PASS (`14.546s`) covers cross-pod administrator reset, self one-use MFA proof, API-key read-only and DELETE denial; delegated group-admin and full recovery parity remain. | [README][readme] |
| [ ] | True passwordless account lifecycle | direct account-mode policy + Rhiza CAS; `go-webauthn/webauthn` ceremony verification | [x] narrow passwordless login/conversion behavior exists in the passkey slice | — | account creation, enrollment/recovery, admin lifecycle, MFA/session upgrade and cross-pod/browser E2E are absent | [README][readme] |
| [ ] | Post-passkey-registration session MFA upgrade | `go-webauthn/webauthn`, existing browser sessions and Rhiza CAS | [x] registration finish atomically upgrades the exact active `pwd`/`webauthn` session to `mfa`, preserves `external`, uses configured idle timeout, and guards active non-disabled identity; deterministic replay, stale-session and disable-interposition tests pass | [x] existing authenticated passkey registration finish route | [ ] local-Kubernetes cross-pod E2E for the session upgrade remains pending; unit evidence alone does not complete the row | [README][readme] |
| [x] | Passkey-only account conversion, including narrow reverse self slice | `go-webauthn/webauthn v0.18.0` + direct Rhiza account policy | [x] forward conversion requires stored registration UV. Schema v21 makes `PasswordNew` service proof purpose/subject/session-bound and one-use; its atomic verifier+mode CAS preserves passkeys and established sessions while invalidating pending/reset/MFA artifacts. UV is required; deterministic unit/race tests cover replay and wrong purpose/session. | [x] forward `POST .../self/convert_passkey`; reverse `POST .../webauthn/auth/start|finish` with `PasswordNew`, then `PUT .../self` `{mfa_code,password_new}` | [x] fresh three-pod passkey E2E PASS (`5.086s`): forward conversion and replay denial; `PasswordNew` proof, reverse update and replay denial; restored-password login, preserved passkey and established-session behavior. Recovery/admin reverse conversion remains `[ ]`. | [README][readme] |
| [x] | Passkey MFA modification-token step-up (narrow) | `go-webauthn`, stdlib `crypto/rand`/SHA-256/AES-GCM, Rhiza v0.10.0 | [x] schemas v20--v21 have encrypted 48-alphanumeric ceremony code state, digest-only 90-second proof, 120-second final token, factor marker, explicit purpose, subject+session binding, mode/ForceUV credential admission, counter/version CAS and exactly-one proof/token consumption. Password input can mint a factor only while zero passkeys exist. | [x] `POST /auth/v1/users/{subject}/mfa_token`; `POST /auth/v1/users/{subject}/webauthn/auth/start|finish` | [x] deterministic unit/race coverage and fresh three-pod passkey E2E PASS (`5.086s`): password rejection after passkey enrollment, bad-UV denial, cross-pod MfaModToken proof/final-token exchange and replay denial. Intentional difference: Rauthy's final token is IP-bound/reusable and returns `ip`; GoAuthy's is session-bound/one-use and omits `ip`. | [README][readme] |
| [ ] | Password + passkey passwordless-cookie flow | master-key purpose envelopes, legacy stdlib AES-GCM dual-read, secure cookies, Rhiza v0.10.0 | [x] new cookies use the `passkey/passwordless-cookie` GAOP purpose; legacy CookieKey cookies remain read-only compatible, while malformed/tampered/unknown-key GAOP values never downgrade. A pre-decode 4 KiB bound protects the unauthenticated start path. Login ceremonies remain browser/OAuth-state bound with CAS consumption. | [x] opt-in WebAuthn login routes | [x] focused deterministic normal/race coverage and prior Chrome 151 three-pod flow prove sign-counter advance and replay rejection. CookieKey removal must wait for legacy-cookie and legacy-DB-row retirement; full passkey-only/recovery/admin parity remains `[ ]` | [README][readme] |
| [ ] | MFA forced for Admin UI and per-client | `go-webauthn`, Fosite, stdlib crypto/JSON and direct Rhiza authorization policy | [x] schema v22 revokes legacy sessions without `auth_method`; bootstrap authentication remains password-only by default, while `GOAUTHY_BOOTSTRAP_FORCE_MFA=true` is the explicit opt-in and requires valid complete passkey configuration at startup, then password plus registered-UV/current UV assertion before bootstrap-client session/code issuance. Dynamic DCR rejects `force_mfa` and is always unforced, matching Rauthy's dynamic-registration mapping. Session digest and original interaction bind the proof; active subject/policy are rechecked. ID token preserves `amr=pwd,mfa` through refresh; access tokens omit `amr`. Deterministic unit/race checks pass. | [x] bootstrap client policy plus existing password/WebAuthn authorize routes | [ ] forced-MFA kind profile now targets the bootstrap policy; its fresh replacement E2E result is pending. Static admin-managed per-client policy, Rauthy `admin_force_mfa`/admin API and upstream-provider MFA remain `[ ]`; full passkey parity remains `[ ]`. | [Rauthy dynamic-client mapping](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/clients.rs#L1804-L1889) |
| [x] | Reverse passkey-only → password conversion (narrow self slice) | direct transactional credential policy | [x] PasswordNew UV proof plus one guarded Rhiza verifier/mode transition | [x] authenticated account routes above | [x] fresh three-pod passkey E2E PASS (`5.086s`) covers PasswordNew proof, reverse update, one-use replay denial and restored-password login; recovery/admin reverse conversion remains pending | [README][readme] |
| [ ] | Magic links, email OTP, password reset/new password | stdlib `crypto/rand`/`crypto/hmac`/`crypto/sha256`/`encoding/base64` + Rhiza; `go-mail` SMTP/MIME/TLS | [x] recovery owns canonical recovery-email binding, enumeration-shaped response, opaque link, browser cookie/CSRF and subject-wide revoke. Schema v23 purpose-separates `password_reset` from `password_new`; deterministic fixed-clock/random tests cover first-password issue, activation, email verification, replay, duplicate convergence and expired pending-user cleanup. | [x] reset routes and opt-in `POST`/`OPTIONS /auth/v1/users/register`; startup starts bounded hourly pending-user cleanup | [x] On 2026-09-01, `make e2e-kind-open-registration KIND_CLUSTER=goauthy-openreg-v081-e2e` passed three-pod first-password activation/replay and pod-replacement chaos (`3.232s`; `5.956s`); email OTP and full recovery parity remain `[ ]`. | [Rauthy password reset][rauthy-reset] |
| [ ] | Configurable email templates | `github.com/pelletier/go-toml/v2`, stdlib `text/template`/`html/template`, `go-mail` | [x] strict ≤64 KiB TOML supports escaped `password_reset`, `password_new` and `registered_already` layouts; unknown/duplicate/lang/CRLF input fails. | [x] recovery SMTP startup | Reset-template evidence and [x] open-registration SMTP delivery are fresh kind-covered; preview/localization management and full template parity remain `[ ]`. | [README][readme] |
| [ ] | Upstream authentication providers (including GitHub) | `golang.org/x/oauth2`, `go-jose/v4`, stdlib crypto/JSON/HTTP/URL; `cmd/goauthy/{main.go,upstream.go}` and `internal/{upstreamprovider,login,account,identity}` direct policy glue | `[x]` one-use digest-only transactions, state/browser/provider/session binding, OIDC PKCE/state/nonce and GitHub PKCE/state, production OIDC ID-token/JWKS verification, GitHub access-token exchange plus fixed `/user` lookup using immutable numeric `id`, schema-v35 state/link persistence, schema-v36 external `auth_method`, local OAuth completion, existing-link login, and explicit authenticated account link/unlink are source-wired. Focused upstream, command, fixture, and callback integration tests pass. | [x] `GET /upstream/{providerID}/start`, `GET /upstream/{providerID}/callback`, `POST /auth/v1/providers/{providerID}/link`, `DELETE /auth/v1/providers/{providerID}/link` | `[x]` OIDC and GitHub TLS fixture paths, black-box link/login/unlink/replay tests, three-pod Kind harness and pod-replacement scenario are source-complete and statically checked. `[ ]` Live Kind/chaos execution and broader provider behavior remain pending. Secret-rewrap/inspect focused PASS (session18737, real keyring, CAS all-or-zero/deterministic-retry, key-purpose, tamper); RequestIDContentAware hash-only divergence; core rewrap race PASS (session52160, 103.230s); ProviderLogoStore+Handler httptest PASS (session60332+70254, actual Rhiza); store deletion focused PASS (session1577, nine atomic tests); mutation/delete HTTP routes not yet mounted. | [provider docs][providers] |
| [ ] | Open registration and email-domain restrictions | stdlib `net/http`/`encoding/json`/`net/mail`/`net/url`/`regexp`, existing password-reset PoW + SMTP/template components, Rhiza v0.10.0 schema v23/CAS, and narrow direct admission policy | [x] deterministic request/config/store tests cover canonical email, bounded profile values, allow-or-blacklist exact domain admission, exact redirect URI matching, PoW consumption before persistence, fixed-window direct-peer admission, duplicate enumeration shape, one-use first-password activation, registered-already synchronous SMTP boundary and expired pending cleanup. | [x] opt-in `GOAUTHY_OPEN_USER_REG` wires `POST`/`OPTIONS /auth/v1/users/register`; recovery, strict domain/TTL config and hourly bounded cleanup are required | [x] On 2026-09-01, `make e2e-kind-open-registration KIND_CLUSTER=goauthy-openreg-v081-e2e` passed fresh smoke `./test/e2e` (`15.421s`), `TestOpenRegistrationAcrossPods` (`3.232s`) and pod-replacement `TestOpenRegistrationPendingPasswordSurvivesPodReplacement` (`5.956s`). Captcha and passkey-first registration remain pending. | [Rauthy user registration](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs#L360-L525) |
| [ ] | Configurable required user-profile fields | stdlib `errors`/`regexp`/`strings`, existing strict JSON and nullable identity DTO; no new dependency/schema | [x] nine ordinary modes/defaults, hidden admission, absent-parent upstream exception; invalid deployment config rejected; [x] preferred-username creation regex, public required/blacklist and admin exemption; [x] username mutation/immutable with current transactional self/admin/key/delegated authority; [x] configurable email fallback and profile claim projection; [ ] login-time revalidation | [x] public signup and administrator PUT; admin POST exemption; [ ] values_config discovery/UI | [x] default-required policy in standalone/HA; [x] three homogeneous policies (all required/optional/hidden) with standalone restart and exact-three HA Pod replacement; dedicated matrix covers field-level omission/null/empty rejection, actual clearing, unchanged mail and same-PoW retry. Preferred-username default/custom creation and mutation pass standalone restart and exact-three HA Pod replacement, including self/admin/key/delegated authority, concurrent name collision and revoked-key rejection; scoped final evidence: [current evidence](status.md). [ ] arbitrary mixed-policy deployment and policy-change HA gates | [Pinned validator](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/user_values_validator.rs#L18) |
| [ ] | User account dashboard/self-service | stdlib `net/http`, `embed`, `html/template`, minimal native JS; existing identity/account/claims/RBAC/passkey services and native WebAuthn JSON methods | [x] current profile, preferred username, password, editable typed attributes and passkey list/add/remove, passwordless conversion/restoration and capability-gated self-delete with existing proofs; existing logout confirmation link; no Authorization fallback, escaped output, live session/active-subject checks and issuer-path assets | [x] `/account`, `/account/data` and embedded assets call existing mutation APIs | [x] deterministic HTTP/JS/OpenAPI checks and real Chromium ordinary-user form/credential behavior; passkey first/subsequent registration and server deletion proven in standalone/exact-three HA; lifecycle UI standalone/exact-three HA gate proves mode changes, old/new password effects and post-delete cookie denial. Results in [status](status.md). [ ] session/provider/recovery and explicit MFA reauthentication UI, complete profile policy, legacy-browser support, i18n and per-action chaos; [UI contract](account-dashboard-implementation.md) | [README][readme] |
| [ ] | Admin UI and management API | stdlib `net/http`, `embed`, native HTML/JS; existing browser-admin/RBAC/CSRF boundaries | [x] secured user/role/group and scope/attribute CRUD, API-key create/rights/expiry/rotate/delete, user pagination, seven user-value editors, password/expiry controls and session list/revoke/subject/global logout; issuer-cookie CSRF, escaped output and no API-key/bearer fallback | [x] `/auth/v1/admin/` pages/assets/CSRF call existing authorized APIs | [x] deterministic JS/HTTP security, actual Chromium user/role/group CRUD and API-key lifecycle; catalog CRUD and ordinary-session cookie invalidation proven in standalone/exact-three HA. Results in [status](status.md). [ ] full profile/client/provider/settings screens, delegated UI, global/subject logout browser tests, catalog reserved-name edit, editor-specific expiry/password E2E and per-action chaos; [UI contract](admin-ui-implementation.md) | [README][readme] |
| [ ] | Delegated group administrators | direct authorization policy on Rhiza schema v24 | [x] browser roles `rauthy_admin:<group>`, trailing `*` prefix and `rauthy_admin:*` can replace only managed group memberships; unmanaged groups are preserved. Atomic guards deny role edits, admin/delegated-admin targets, revoked actors, unauthorized additions and CAS races; API keys retain their own full-admin scope. | [x] existing `PATCH /auth/v1/users/{subject}` membership subset | [x] deterministic store/HTTP/API-key regression tests pass; [ ] local-Kubernetes delegated flow and full Rauthy user-management surface | [v0.36.2 changelog][changelog] |
| [ ] | Roles and groups | stdlib `net/http`/`encoding/json`/`regexp`, existing browser session/CSRF components, Rhiza v0.10.0 schema v24, Fosite session `Extra`, and `go-jose/v4` | Schema-v24 normalized roles/groups/membership state and bootstrap memberships; browser-admin `GET`/`POST`/`PUT`/`DELETE /auth/v1/{roles,groups}`; immutable reserved `rauthy_admin`; canonical sorted claims. Admin reads and writes each verify an active `rauthy_admin` membership; rename/delete bump every affected principal revision. Roles are always in ID-token/UserInfo/introspection results; groups appear only when the end-user `groups` scope is granted. Group names deliberately use hardened `[A-Za-z0-9-_/,:*]{2,64}`, narrower than Rauthy's whitespace-admitting grammar. | [x] entity management and narrow dynamic membership routes are wired | [x] deterministic store/HTTP/OAuth tests use injected clock/random or explicit state, not sleep. A deterministic pre-commit revision-bump barrier proves code/refresh cannot persist artifacts against stale membership. Fresh three-pod E2E passed CRUD, cross-pod membership, role rename, current claims through refresh, and UID/Ready-verified pod replacement. The overall gate remains in progress; scopes, custom attributes, delegated administration and full-user APIs remain `[ ]`. | [Rauthy roles](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/roles.rs), [Rauthy groups](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/groups.rs) |
| [ ] | Dynamic user role/group assignment | stdlib strict JSON + existing browser-session/CSRF/Fetch-Metadata boundary; Rhiza schema-v24 conditional membership replacement | [x] `PATCH /auth/v1/users/{subject}` accepts the roles/groups subset of upstream `PatchOp`; either `put` field replaces its complete list and `del` clears it. Atomic guards cover active actor/target, full and delegated administration, entity existence, stale revision and final-active-admin preservation. Unknown names fail closed. Response is the explicit `{id,roles,groups}` subset, not upstream's full `UserResponse`. | [x] browser-admin session/API key + CSRF/same-site route | [x] fixed-clock/random store and strict handler tests cover malformed/unknown/duplicate input, replacement/clear/no-op, API-key mutation, delegated exact/prefix/all policy, unauthorized escalation, final admin and stale CAS. Existing Kind evidence covers full-admin cross-pod replacement and pod replacement; delegated Kind evidence and full UserResponse/full-user PUT remain pending. | [Rauthy handler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs#L1995-L2051), [PatchOp](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/lib.rs#L29-L38), [assignment semantics](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/users.rs#L1103-L1220) |
| [ ] | Custom scopes and typed attributes; claim bindings | stdlib `net/http`/`encoding/json`/`regexp`, existing browser-admin session + CSRF/Fetch-Metadata boundary, Fosite session `Extra`, `go-jose/v4`, and Rhiza v0.10.0 schemas v26/v28 | [x] schema-v26 catalog/value/binding storage; strict admin CRUD; self-only editable GET and filtered PUT; SQL/CAS editability recheck; EdDSA JWT access tokens carry current scoped custom claims (nested or root), and a retained HMAC `jti` index preserves Rhiza revocation, introspection, DPoP and token-exchange semantics. Scoped API keys reach only the explicit claims-admin boundary. | [x] exact admin/self routes plus partial static-client policy | [x] deterministic fixed-claim JWT/signature/root-collision, current custom-access, DPoP and revocation coverage. `[x]` client-credentials custom-claim E2E; `[ ]` true non-admin browser fixture and fresh-kind user custom-claim JWT E2E. | [custom claims][claims] |
| [ ] | Client-credentials custom claims | stdlib strict JSON, Rhiza schema v29, existing `go-jose/v4` access-JWT path | [x] bootstrap static-client `claims`/`claims_at_root` policy with nullable clear, 1,024-byte object limit, revision CAS and same-write issuance guard; nested/root access JWT claims, reserved-root preflight failure, dynamic/CIMD denial and introspection/UserInfo omission have deterministic normal/race coverage | [x] explicit partial static-client `GET`/`PUT /auth/v1/clients/{id}/claims` with browser admin or `Clients:read/update` API key | [x] fresh three-pod `make e2e-kind-client-credentials-claims KIND_CLUSTER=goauthy-v29-client-claims-deterministic E2E_PORT=28410` PASS (`6.610s`): cross-pod nested/root/clear, public-JWKS verification and reserved collision without sleeps | [custom claims][claims] |
| [x] | Client login restriction by group prefix | stdlib `strings`/`regexp`, existing browser-admin session + CSRF/Fetch-Metadata boundary, Fosite session `Extra`, Rhiza v0.10.0 schema v25 | [x] strict static-client-only policy and admin CAS coverage: `internal/{rbac/http,rbac/store,oauth/client_group_policy}_test.go`; DCR rejects `restrict_group_prefix`; dynamic/CIMD and client-credentials stay unaffected | [x] explicit partial static-client route `GET`/`PUT /auth/v1/clients/{id}/login-restriction` | [x] `TestBootstrapClientGroupRestrictionAcrossPods`: cross-pod GET state barriers, matching allow, stale-revision `409`, case mismatch deny, literal `*` deny, null clear allow, and DCR-field rejection without sleeps | [README][readme] |
| [ ] | Fine-grained admin API keys | stdlib `crypto/rand`/`crypto/sha256`/`crypto/subtle`/`encoding/base64`, Rhiza schema v28 | [x] strict browser-admin creation/update/delete/rotation plus `API-Key name$secret` authentication only on explicit API-key, roles/groups and claims-admin routes. Browser fallback is forbidden when an API-Key header is supplied; OAuth, DCR and account routes never bind API-key auth. Secrets are one-time create/rotation text responses; only a SHA-256 base64url digest is stored. | [x] `GET`/`POST /auth/v1/api_keys`, `PUT`/`DELETE /auth/v1/api_keys/{name}`, `PUT /auth/v1/api_keys/{name}/secret`, `GET /auth/v1/api_keys/{name}/test` | [x] deterministic store/HTTP tests and fresh three-pod `make e2e-kind-admin-api-keys KIND_CLUSTER=goauthy-v29-admin-api-keys-deterministic E2E_PORT=28420` PASS (`2.679s`) cover rights, cross-pod create/use/rotate/delete, expiry, scoped denial and no-fallback boundaries. Upstream encrypted-digest-at-rest parity, provider/API-key scopes and full UI remain pending. | [API keys][api-keys] |
| [ ] | API-key JSON bootstrap | strict stdlib JSON/crypto/filesystem + existing `x/crypto/chacha20poly1305`, API-key policy and Rhiza transactions | [x] Plain and cryptr-compatible Encrypted import; generated-secret library import with authenticated artifact reuse, exact token validation and real-DB retry/recovery tests | [x] Plain/Encrypted and opt-in shared Generate startup; explicit retrieval/purge CLI | [x] schema85 shared initialization, expiry tombstone, scheduled purge and key-lifecycle integration; [x] final single-query candidate standalone lifecycle/expiry and exact-three Kind token agreement/authentication/pod-replacement/log-boundary E2E (2026-09-09); [x] three-peer 300-second export expiry/full rolling restart and standalone TTL0 cold backup/restore; [x] peer-stop majority-loss and recovery; [x] TTL0 three-peer checkpoint/archive restore into fresh PVCs with generated-key continuity; [x] standalone 120-second expiring backup/original-deadline/no-regeneration restore; [x] three-peer 300-second expired-backup/fresh-PVC/no-re-export/full-rollout restore; [x] all-voter SIGKILL/no-local-state/archive-only recovery (2026-09-09); [x] object-store outage/recovery with unchanged app pods and key/JWKS continuity (2026-09-09); [x] malformed archive head rejection/known-good-object restoration (Kind, 2026-09-09); [x] missing archive blocks/intact-head rejection and retained-copy restore (Kind, 2026-09-09); [x] archive block content integrity rejection/original-copy restore (Kind, 2026-09-09); [x] invalid checkpoint CURRENT reference/original-pointer restore (Kind, 2026-09-09); [x] referenced checkpoint root integrity/original-root restore (Kind, 2026-09-09); [x] same-length checkpoint data-block integrity/byte-verified original-copy restore (Kind, 2026-09-09); [x] observed checkpoint download/SIGKILL and retained/fresh local-state subprocess recovery (race, 2026-09-09); [x] real-MinIO interrupted download/SIGKILL/same-pod recovery (Kind, 2026-09-09); [x] post-interruption pod replacement/new-emptyDir recovery (Kind, 2026-09-09); [x] generated-key five-phase Linux journal interruption, retained/fresh recovery and pre-export permissions (2026-09-09); [x] all five MinIO/Kind journal phases with retained-Pod generated-key continuity (2026-09-09); [x] native peer partition/healing with generated key and permissions, minority fail-closed behavior and log redaction (Kind, 2026-09-09); [ ] concurrent bootstrap-write chaos (see status). See [bootstrap contract](api-key-bootstrap-implementation.md). API keys cannot manage API keys | [API keys][api-keys] |
| [ ] | Per-client theme and logo branding | `html/template`, `image`, `mime`, pure-Go WebP, Rhiza94 | [x] typed theme storage/render, guarded HTTP CRUD with Brotli/gzip, client-deletion cleanup, login-page CSS and login-warning email integration; [x] logo resolution schema, atomic guarded client store, SVG filtering and raster processing; [x] full favicon/provider-logo parity; [x] schema95 migration test passed (TestMigrationV95 1.819s) | Mounted theme CRUD/global CSS, client logo GET/PUT/DELETE and unified favicon routes; favicon Kind build passed (exec83518 exit0); standalone favicon exact32WebP retention PASS; extended TestNoPVCThemeRecovery includes exact32WebP favicon plus SVG/theme FS PASS (exec99993 9.260s) | [x] standalone and one-host Kind retained-theme replacement; [x] actual Chromium light/dark login test; [x] standalone logo HTTP and retained restart; [x] one-host Kind three-Pod HTTP and exact retained SVG after Pod replacement; [x] filesystem and real MinIO S3 fresh-directory theme and both logo-table recovery under race; [x] standalone favicon live (FaviconLive 0.15s) and logo live; [x] standalone favicon exact32WebP retention PASS across restart (exec89833 exit0) and Kind Pod replacement (exec83518 exit0, Pod0 UID 289dd073->8bf5bf75, FaviconPersistVerify .37s); extended TestNoPVCThemeRecovery exact32WebP+SVG/theme realMinIO PASS 16.081s (test 14.06s, 95 objects, exit0, owned bucket/container cleaned, docker container absent); Cmd key lifecycle focused PASS (exec77074 8.709s, TestMasterKeyRewrapStep*, TestAuthProviderSecret*, TestMasterKeyRewrapWorkerInvokesAuthProvider*, TestSaaSProviderEnvelopeBlocksRetirement, real keyring oldrefs/rekey/status, not all CAS boundaries); API-key envelope focused PASS (exec91100 10.783s); ProviderLogoStore focused PASS (session60332, small/medium store, own-SVG fallback, revoked authenticated API key mutation denial, no cross-client/global fallback); ProviderLogoHandler httptest PASS (session70254); core rewrap race PASS (session52160); store deletion focused PASS (session1577); mutation/delete HTTP routes not yet mounted; provider-logo lifecycle and full branding UI remain | [README][readme] |
| [ ] | Independent favicon behavior | `html/template`, `image`, `mime` | [x] optional `GOAUTHY_FAVICON_FILE` plus per-client `GET`/`HEAD`/`PUT`/`DELETE /auth/v1/clients/{id}/favicon`, durable schema-v43 storage, and PNG/ICO validation: `internal/branding` | [x] global and per-client responses share ETag/304, CSP, cache-control and no-sniff headers; mutations clear browser cache | [ ] fresh three-node A→B→C and browser cache-isolation E2E evidence remain pending because current Kind runtime is blocked | [README][readme] |
| [ ] | End-user i18n and language extension | stdlib `embed`, `encoding/json`, `html/template` | [x] strict embedded en/ko catalog and deterministic `Accept-Language` q/order/region fallback cover the core login/FedCM and logout confirmation text; unsupported or malformed input falls back to English and template values remain escaped | [x] browser login and logout pages | [x] focused normal/race tests; [ ] recovery/account/admin pages, language extension/configuration and standalone/HA browser E2E remain | [README][readme] |
| [ ] | Sessions, expiry and client peer-IP binding | secure cookies/AEAD + Rhiza | short-lived opaque digest-only Init/Auth sessions, fixation rotation, absolute/90-minute idle expiry, throttled activity touch and `sid` revocation checks: `internal/browser/store_test.go`. Schema v31 adds `peer_ip` column, `LoadSessionForPeer`/`LoadSessionReadOnlyForPeer` atomic load+check, and `peerIPMiddleware` wrapping all production routes. Direct mode binds `RemoteAddr`; configured trusted-proxy mode resolves canonical `Forwarded`/`X-Forwarded-For` only from the immediate trusted peer. Browser-cookie consumers (login/account/claims/RBAC/logout/device/API-key) use peer-bound loads. Bearer/access/device/API tokens remain unbound. Legacy empty `peer_ip` sessions accepted. | partial: browser-login/logout cookies | browser E2E checks cookie flags/fixation rotation, deployed 10-second idle expiry and logout; `[ ]` fresh three-pod Kind v31 E2E validates trusted-proxy mismatch behavior. Implementation verified by unit/race/vet. | [README][readme] |
| [ ] | Administrator session management and forced user logout | existing browser/OAuth stores, RBAC/API-key guards, back-channel outbox, stdlib HTTP/JSON and Rhiza | [x] per-user atomic local revocation/subject-only outbox/event and admin/API-key/delegated-scope local race tests; [x] session list state/default-Auth/empty-result/threshold/stable pagination implementation and local tests; [x] single-session delete with shared OAuth cleanup, same-user/sessionless isolation and rollback tests; [x] global all-session transaction and direct-admin/API-key boundary; [ ] full MFA projection and full administration matrix | Mounted: `GET /auth/v1/sessions`, `DELETE /auth/v1/sessions`, `DELETE /auth/v1/sessions/{subject}` and `DELETE /auth/v1/sessions/id/{session_id}` | [x] per-user standalone/HA fresh-login/session/access-token/POST/SSE plus post-logout restart persistence; actual global/per-user subject-only RP delivery and same-client different-user preservation evidence in [status](status.md); [ ] broader concurrent issuance/revocation, cross-user global live gate, deployed API-key/delegated paths and full session-list E2E matrix remain open. Ordinary RP logout evidence is not completion | [Pinned sessions API](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/sessions.rs), [research](package-research.md) |
| [ ] | Emailed unknown-login revocation | recovery SMTP, browser/OAuth, Rhiza91, encrypted keyring envelope, stdlib templates | [x] shared per-user 48-character code without expiry; atomic consumption/replay protection, location and token/session cleanup, downstream logout outbox, lifecycle events and key rewrap/retirement inventory. [x] browser/password-grant notification, pre-MFA password timing, trusted location header or DB lookup, UA validation. [ ] cookie mode/path and full error/theme parity | Mounted: `GET /auth/v1/users/{subject}/revoke/{code}`; required query IP, generic HTML result, DB-only revoke location | [x] real SMTP-to-redemption, race/replay/rollback, key lifecycle and fresh-directory filesystem and real MinIO S3 object-store recovery race tests. [x] real-login SMTP-to-revoke standalone E2E (activation, login mail, session rejection and replay). [x] one-host Kind three-app-Pod E2E with cross-pod session rejection before/after Pod replacement. [ ] multi-host/full DR qualification remains. Query IP is event metadata, not proof of the original login. [Contract](login-revoke-contract.md) | [Pinned users API](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs), [research](package-research.md) |
| [ ] | CSRF callback state, OIDC nonce and PKCE lifecycle | `crypto/rand`, `crypto/subtle` | PKCE storage plus one-time interaction bound to the Init cookie: `internal/{oauth/grant_storage,browser/store,login/handler}_test.go` | partial: browser login | browser E2E uses the cross-pod bound interaction; full callback-state/nonce lifecycle remains | [README][readme] |
| [ ] | Username-enumeration prevention | direct constant-shape policy | [x] `TestLoginFailureDoesNotRevealOrConsumeInteraction` checks identical 401 body/no cookie for wrong password, unknown and disabled users; it also proves the interaction remains usable | [x] `POST /auth/login` | structural timing mitigation exists; no timing-distribution proof is claimed | [README][readme] |
| [ ] | Login/hash rate limits and delay | stdlib `net`, `crypto/sha256`, `crypto/rand`, `time`/`context` + Rhiza linearizable reads/conditional UPSERT | [x] schema-v12 distributed direct-peer-IP pre-Argon gate, failure counter with 24-hour idle TTL, escalating delay/block schedule, bounded success-timing update and constant-shape credential failure: `internal/loginpolicy` and `internal/login` tests. Success does not clear IP failure state. Trusted-proxy IP resolution is implemented in peer-IP middleware (schema v31). | [x] `POST /auth/login` | [x] fresh sequential three-node `TestLoginBruteForceBlockAcrossPods` PASS (49.851s): failures 1–6=401, 7=429 with bounded `Retry-After`. No concurrent-goroutine/timeouts, real one-minute sleep, or recovery assertion; expiry/recovery is fake-clock unit coverage. The prior EOF was a 15s global `WriteTimeout`; it is now 1m, while deterministic unit coverage proves each later delay tier gets only its computed per-response deadline plus 5s. Account policy and full parity remain `[ ]`. | [README][readme] |
| [ ] | Brute-force, credential-stuffing and basic DoS detection | direct bounded counters/queues | — | — | multi-pod abuse, automatic blacklist and resource ceiling | [README][readme] |
| [x] | Manual/automatic IP blacklist | stdlib `net/http`/`net/netip`/`time` + Rhiza v0.10.0 | [x] schema v32 store, exact IP/CIDR expiry and fail-closed middleware; automatic failed-login admission is atomically appended to the replicated failure transaction, with exact thresholds 7/10/15/20/25 and durations 1m/10m/15m/1h/24h, bounded capacity/expiry pruning, and a two-observation forward-clock skew guard. | [x] opt-in `GOAUTHY_IP_BLACKLIST_ENABLED`; `/auth/v1/blacklist` is source-wired in `cmd/goauthy/main.go` | [x] focused automatic-admission, threshold, capacity, IPv4/IPv6 and skew tests; live Kubernetes E2E is not claimed | [Rauthy blacklist](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/blacklist.rs) |
| [x] | Geolocation restriction (trusted header or MaxMind) | direct adapter with existing `loginpolicy` peer-IP resolution and `maxminddb-golang` local reader | [x] opt-in `GOAUTHY_GEOBLOCK_*` configuration and middleware accept a trusted country header or local MaxMind lookup; header sources require configured trusted proxies; raw database values and configured countries require strict ASCII ISO alpha-2; whitelist/blacklist and unknown-country decisions fail closed as configured | [x] protected routes enforce allow/deny/unknown policy while health remains available | [x] `scripts/e2e-geoblock-standalone.sh` passes trusted-header allow/deny/unknown and malformed/ambiguous forwarding; [x] `scripts/e2e-geoblock-ha-kind.sh` passes all-pod admission, pod-1 replacement, trust-boundary rollout and spoof denial. MaxMind success fixture remains unit-only; no downloader/update scheduler | [README][readme] |
| [ ] | Critical DB-value encryption and master-key rotation | `crypto/aes`, `cipher.AEAD`, `crypto/rand`, `encoding/base64` | [x] Purpose-scoped AES-GCM signing-key, live DCR-idempotency, unexpired upstream-transaction, retained passkey credential/ceremony state, and new passwordless cookies use master-key envelopes; bounded active-key rewrap has all-or-zero cursor/CAS tests in `internal/{oidc,dcr,upstreamprovider,passkey}`. Legacy passkey DB/cookie ciphertext dual-reads only outside GAOP; OAuth persisted forms redact credential, bearer, and one-use fields. | [x] signing-key bootstrap, passkey new-write/dual-read, combined sanitized status, mandatory four-family rewrap worker, and Stage A/B/C retirement barrier are source-wired | [x] strict JSON, tamper/wrong-context/old-key read/concurrent rewrap, guarded exactly-once prepare/fence/ready/abort audit events, Stage B commit-fence, Stage C runtime admission/attestation tests, and live exact-three `KIND_CLUSTER=goauthy-master-key-e2e-20260905c E2E_PORT=19700` evidence (three zero refs, restart boot-ID/sequence 2, Ready, key retention, cleanup); [ ] automatic key removal, CookieKey removal after all legacy DB/cookie TTLs, and remaining nonrotating values remain pending | [README][readme] |
| [x] | TLS and hot certificate reload | `crypto/tls`, atomic certificate holder | [x] fail-closed atomic reloader and HTTPS wiring: `internal/tlsconfig/reloader_test.go`, `cmd/goauthy/main_test.go` | [x] opt-in HTTPS server | [x] `scripts/e2e-tls.sh`: verified initial/rotated certificate and retained last good certificate after invalid projected Secret | [README][readme] |
| [ ] | Events, auditing, persistence option and event stream | Rhiza + stdlib HTTP/JSON/time/crypto; existing authorization stores and `log/slog` | [x] Existing pseudonymous API-key/master-key audit remains separate. Schemas 59–60 add transactional creation lifecycle events, guarded time/level/type query, periodic retention and a durable stream cursor; server-defined Test events use the same schema. See [full event ledger](events.md) for payload/privacy/package boundaries. | [x] Legacy GET audit, lifecycle POST `/auth/v1/events`, GET `/auth/v1/events/stream`, POST `/auth/v1/events/test` | [x] deterministic query/creation/retention/revocation/deletion-gap tests; named live/reconnect gates in [status](status.md). [ ] 20 unemitted types and the remaining password-reset admin branch, configurable levels/persistence and nonpersisted streaming, notification delivery/retry, all-feature live/chaos. | [README][readme] |
| [ ] | Email, Matrix and Slack event notifications | existing `go-mail`; stdlib HTTP/JSON/crypto/context/time; Rhiza durable payload/lease state | [x] Slack/Matrix/SMTP transports, full-hash destination identity, no historical backfill, lease-token acknowledgement, exponential retry and fixed-clock runtime; TLS/redirect/error-redaction checks | [x] opt-in `GOAUTHY_EVENT_NOTIFICATION_TARGETS`, per-target level, server worker start/cancel/join | [x] real SMTP event receipt plus queue restart/concurrency tests; deployed results in [status](status.md). [x] removed-target retirement with generation fencing, delivery retention, [ ] delivery metrics, deployed Slack/Matrix TLS-fixture E2E and full notifier parity; see [contract](event-notifications-implementation.md) | [README][readme] |
| [ ] | Prometheus metrics on a separate port | existing `internal/metrics` registry + stdlib HTTP | [x] oauth/login/readiness registry and current `/oidc/*`/`/auth/*` metric labels have focused coverage (not a full observability parity claim). | [x] separate metrics listener is runtime-wired with bearer authentication and application/metrics endpoint isolation | [x] `scripts/e2e-metrics-standalone.sh` passes on app `19880`/metrics `19881` with auth/isolation, bind-collision failure, and restart-preserved JWKS; [x] final exact-three HA gate `KIND_CLUSTER=goauthy-metrics-e2e-20260905c E2E_PORT=20080 ./scripts/e2e-metrics-kind.sh` passes on ports `20080`-`20085` with all-pod readiness/auth/isolation, pod-1 replacement and byte-identical JWKS recheck. Traces/exporters and broader observability remain incomplete | [README][readme] |
| [ ] | OpenAPI/Swagger UI disabled/admin-only by default | `kin-openapi v0.149.0`, `swaggo/files/v2 v2.0.2`, stdlib HTTP/JSON | [x] embedded UI, configured route catalog, selected Go-type schemas, local-reference validation | [x] default-off, admin-only or explicit public; issuer prefix, no remote config/validator, read-only UI | [x] deterministic spec/policy/route tests and real-browser standalone restart plus exact-three HA private/restart/public/disabled matrix; full branch/schema fidelity remains open. See [contract](openapi.md). | [Swagger][swagger] |
| [x] | Namespaced arbitrary JSON K/V store | Rhiza SQL schema v55 + `encoding/json`, stdlib crypto and existing `oidc.Keyring` | [x] namespace/access/value CRUD, row-bound envelopes, secret rotation, deterministic repeated-write/rename/isolation/credential-revocation tests; old-key reference/tamper, >32-row rewrap and concurrent update CAS regressions | [x] 20 `/auth/v1/kv` admin, namespace-scoped bearer and public exact-key routes | [x] 2026-09-05 standalone cold restart PASS and exact-three `goauthy-kv-ha-audit-20260905` (20800–20802) PASS: JSON/encryption, CRUD/search, credentials, all-pod reads, UID-checked pod replacement and cascade denial. Full administration UI is tracked separately. TTL/CAS APIs are not upstream KV requirements. | [pinned API](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/kv.rs), [contract](kv.md) |
| [ ] | Housekeeping schedules/cron and update checker | `time.Ticker`, contexts | — | — | singleton/idempotent cleanup under leader failure | [README][readme] |
| [ ] | Startup config validation, bootstrap and secrets file | `flag`, `os`, strict TOML package if needed | Rhiza dev/exact-three-member cluster validation, secret validation and optional current-PHC bootstrap user that never resets: `internal/{storage,identity,credential}/*_test.go`, `cmd/goauthy/main_test.go` | bootstrap env in `cmd/goauthy/main.go` | bootstrap login is covered in kind; invalid URL/key/proxy config and complete first-admin lifecycle remain | [v0.36.2 changelog][changelog] |
| [ ] | Secrets TOML and generated-secret bootstrap | stdlib `os`, `flag`, JSON, cryptographic randomness + existing ChaCha20-Poly1305; no new dependency | [x] encrypted API-key import, Generate library, compatible encrypted artifact and explicit retrieval/expiry-purge CLI; real DB and fixed-clock tests | [x] Plain/Encrypted startup and `cmd/goauthy-bootstrap-secrets`; [x] opt-in shared Generate startup | [x] shared DB ownership and scheduled purge; [ ] TOML secret loading and deployed HA/secret-boundary E2E; [bootstrap contract](api-key-bootstrap-implementation.md) | [v0.36.2 changelog][changelog] |
| [ ] | Deterministic Rhiza schema migrations | `github.com/mrchypark/rhiza@v0.12.3` public Go API (commit `97a9d18aadc66d3b5390f6fa64de2d65dd9f0d48`) | [x] idempotence through schema v54: v32 blacklist, v33 rate-limit retention, v34 DCR idempotency, v35--v39 provider/SCIM state, v40 anonymous-DCR cleanup, v41 SCIM snapshots, v42 tombstone generations/fencing, v43 favicons, v44 DCR `client_uri`, v45 append-only audit, v46 DCR contacts, v47 DCR URI metadata, v48 barrier base, v49 audit sequence, v50 barrier compatibility, v51 audit integrity guards, v52 retirement-event constraints/triggers, v53 persisted DCR `software_statement`, and v54 canonical replicated DCR software-statement trust digest/topology fence. | [x] startup migration/readiness | [x] exact-three HA software-statement gate `KIND_CLUSTER=goauthy-software-statement-ha-e2e-20260905i` on ports `19840-19842` started three pods on schema v54 and passed replicated trust/readiness; [ ] arbitrary v54 upgrade-migration E2E remains unclaimed. Deterministic checks use `DB.Ready` plus linearizable schema queries. | [README][readme] |
| [x] | Liveness/readiness probes | `net/http` | [x] `cmd/goauthy/main_test.go` | [x] `GET /livez`, `GET /readyz` | [x] `make e2e-kind`: `TestCurrentProfile`, including quorum loss | [Kubernetes][k8s] |
| [x] | Three-peer HA, linearizable security reads and cross-pod mutation visibility | Rhiza v0.10.0 fixed cluster | [x] exact-three-member config, distinct per-member voter tokens, separate admin token, preferred hostname anti-affinity, and a `minAvailable: 2` PDB | embedded startup | [x] fresh `make e2e-kind KIND_CLUSTER=goauthy-v0100-ha-final4 E2E_PORT=18120` passes cross-pod protocol checks, pod replacement, quorum loss/recovery, and rolling restart | [README][readme] |
| [x] | Backup, encrypted object-store backup, retention and restore | Rhiza v0.12.3 before-ack object-store durability, certified checkpoints/archive; `filippo.io/age v1.3.2`, stdlib `archive/tar`/rooted filesystem | [x] Default no GoAuthy PVC: disposable DataDir/emptyDir, required object store and independently restored master keys/identities. Local cold-copy tests remain historical evidence, not the default DR mechanism. | [x] no-PVC standalone and exact-three Kubernetes profiles; scoped crash/corruption/interruption targets in [DR contract](no-pvc-dr.md) | [x] all-voter SIGKILL plus new emptyDirs, archive-only recovery, object-store outage, corrupt/missing archive and checkpoint objects with original-copy recovery, retained/fresh interrupted downloads; [x] five-phase Linux journal interruption including generated keys. Named live results and limits are in the DR contract. [x] all five MinIO/Kind journal interruption phases with retained-Pod recovery (2026-09-09). [x] native tc peer partition with majority writes, minority availability failure and healed OAuth/JWKS continuity (Kind, 2026-09-09). [x] Bounded encrypted bundle library and authenticated staged extraction; [x] real MinIO snapshot → Hybrid age artifact → fresh-prefix restore with credential continuity (2026-09-09). [x] Versioned encrypted manifest, exact staged inventory and streaming digest verification; product offline restore function with conditional ownership, remote Rhiza verification and corruption rejection before CURRENT. [x] Disk-staged product snapshot exporter with paired-pin renewal and encrypted manifest output. [x] Initial archive-only v2 encrypted product Export/Restore, full genesis-to-tip validation and real-MinIO credential continuity. [x] Manual offline export/restore CLI with independently trusted digest and no-overwrite publication; real-MinIO negative controls and exact-three no-PVC Kind encrypted checkpoint restore with original OAuth/JWKS/generated-key continuity. [x] Signed immutable completion catalog and publish/list/fetch CLI using stdlib Ed25519, x509/PEM and JSON; real-MinIO pipeline and failure controls; final exact-three Kind recovery from an external catalog after removing both original Kind and local artifact. [x] Manual completed-backup retention with dry-run/apply, verified per-source keeper, interrupted/concurrent deletion tests and real-MinIO/Kind DR after pruning. [x] Complete create command with separate source/destination configuration and final external-catalog no-PVC Kind DR after source/local-artifact removal. [x] Standard-library cron parser/calendar with pinned Rust field-set differential tests and chronological DST checks; [x] server opt-in scheduling, replicated lease/completion slots, Create/Prune worker lifecycle and production-runtime real-MinIO fresh-store restore; [x] exact-three live server scheduled backup and external-catalog fresh-Kind DR after source/local-artifact removal (2026-09-09); [x] source-MinIO outage: first-slot failure with empty signed catalog, recovery/second-slot success and full fresh-Kind DR (2026-09-09); [x] two-voter SIGKILL: first-slot ownership timeout/empty catalog, same-Pod recovery with unchanged survivor, second-slot success and full fresh-Kind/emptyDir DR (2026-09-09); [x] bounded native PKIX trust bundles, current-signer admission and overlap rotation with exact scheduled completion markers plus both old/new fresh-prefix restores on real MinIO (2026-09-09); [x] live three-voter rolling signer rotation, old/new signature checks and retention, source/local ciphertext deletion and external-catalog fresh-Kind/emptyDir DR (2026-09-09); [x] bounded checkpoint publisher-contention retry with native claim exhaustion/transient-release real-MinIO regression and updated-candidate full Kind DR (2026-09-09); [x] explicit expire-all completed-backup retention and 0..65535-day range with real-MinIO CLI/runtime verification (2026-09-09); [x] expire-all Kind retention and fresh-cluster no-PVC DR after original source/local ciphertext deletion (2026-09-09); [x] paused-holder SIGSTOP beyond lease TTL, successor completion, resumed-holder failure/marker preservation and fresh-Kind no-PVC DR (2026-09-09); backup-secret auto-distribution is an optional operational enhancement, not pinned Rauthy parity; see [artifact evidence](encrypted-backup-design.md). | [backups][backup] |
| [ ] | Rauthy Hiqlite/Postgres database migration | **Excluded:** Rhiza-only project constraint | — | — | not parity; add import/export only if migration is requested | [README][readme] |
| [ ] | Kubernetes deployment hardening | native manifests; Kubernetes APIs | Kustomize manifests and a digest-pinned Cilium chaos profile render; restricted workload settings are present | — | restricted PSA and probes/PVC/resources pass regular kind; policy enforcement remains blocked on the current Dory kernel | [Kubernetes][k8s] |
| [ ] | PAM/NSS Linux integration | separate licensed Linux artifact | — | — | host login, SSH ephemeral password/key, NSS resolution | [PAM][pam] |

## Direct implementation boundary

Rauthy v0.36.2 has no separate durable, per-scope consent grant. GoAuthy
therefore does not invent a consent table or UI: `prompt=consent` forces a
fresh login just as Rauthy's authorize policy does. The one-time browser
interaction is CSRF/login-continuation state, not a consent record.

The following require product code even after package reuse: Rhiza persistence
adapter/atomic replay state, IdP login/authorize/claims policy around Fosite,
logout redirect/session/fan-out, DCR metadata/management, RFC 8628 device
state/polling, DPoP Rhiza replay/binding, SCIM storage and authorization
contract, Argon2 PHC policy wrapper, one-time recovery-token semantics,
WebAuthn account/recovery policy, distributed abuse controls and PAM/NSS OS
integration. Fosite v0.49 supplies no logout, DCR, device or DPoP server
handlers; unreleased `master` device code is not a pinned dependency. Existing
`go-jose/v4` and the standard library are reused; the evaluated DPoP Axis
package was not selected because it duplicates that JWT stack while replay
state remains direct. Cryptographic primitives are never reimplemented. The
detailed rationale and dependency assessment remain in
[`docs/parity.md`](parity.md); this ledger intentionally does not duplicate it.

Rauthy's fixed-tag `restrict_group_prefix` field lives on full static-client
replacement. GoAuthy does not yet expose full static-client management, so it
implements the smallest explicit public subset instead: `GET`/`PUT
/auth/v1/clients/{id}/login-restriction` for configured bootstrap clients
only. Validation follows the upstream `^[a-zA-Z0-9-_/,:*\s]{2,64}$` grammar,
but enforcement is the same raw case-sensitive `strings.HasPrefix` policy used
by Rauthy, where `*` is a literal character and not a wildcard. A missing row
or stored `NULL` means unrestricted. The current policy is enforced at
authorize completion, authorization-code redemption, refresh and
`forward_auth` using the caller's current full group set and the same Rhiza
transaction/revision guards already used for current claims. Dynamic
registration rejects the field, and unmanaged dynamic/CIMD clients plus
client-credentials remain unaffected.

The earlier follower `no such savepoint: rhiza_command` symptom was traced to a
missing writable SQLite temporary directory under the restricted main
container's `readOnlyRootFilesystem`, not to a retained Rhiza fork. The main
container now mounts `/tmp` as an `emptyDir` and sets `SQLITE_TMPDIR=/tmp`.
Roles/groups claims, rename, refresh and pod-replacement E2E now pass with
that correction, including the final full kind gate. Unrelated feature rows
remain conservative until their own parity scope is complete.

## Completion rule

Before changing any `Done` cell to `[x]`, record the exact public endpoint or
browser flow and the named deterministic local-Kubernetes E2E test in this
table. Unit tests alone must stay in the `Engine` column. Security rows also
need their stated negative case; HA/backup rows need the stated fault case.

Historical HA and probe gates passed on 2026-08-31 with a fresh schema-v7,
dedicated kind cluster (`E2E_PORT=18880`). The run created three embedded Rhiza
peers and verified OAuth and OpenID Provider discovery, including
`userinfo_endpoint` and `end_session_endpoint`. `TestAutomaticRotation` passed in 291.306 seconds,
proving public JWKS pending-key prepublication, active transition, retiring-key
overlap, ETag and cache behavior. The public browser
matrix verified missing/plain PKCE rejection, wrong-verifier non-consumption,
correct exchange and cross-pod code-replay rejection, `prompt=login`,
`prompt=consent`, `max_age=0`, and authenticated/anonymous `prompt=none`.
It also verified public-JWKS ID tokens (nonce, `sid`, `auth_time`, `azp`, `amr`,
`at_hash`), refresh preservation/nonce omission, GET/POST UserInfo subject
equality and fail-closed malformed/query/form/non-`openid`/revoked cases,
and a deployed 10-second idle expiry. `TestRPInitiatedLogoutAcrossPods` used
all three pods directly: malformed, oversized and open-redirect attempts
preserved the session; ID-token-hint and one-time confirmation paths deleted
the cookie and revoked access, refresh and pending-code use across pods; replay
was rejected. The browser suite passed in 19.460 seconds. Focused UserInfo
tests additionally cover expired tokens and disabled subjects. It then deleted
one pod, scaled to one replica and observed readiness fail closed, restored
three replicas, performed a rolling restart, and re-ran the uncached public
black-box test after every recovery step; the cluster was removed. The
bootstrap single-RP back-channel subset has public delivery-mode coverage;
custom CA/TLS 1.2+/SNI/no-proxy/no-redirect and atomic last-known-good CA
reload are unit-tested, and the dedicated `make e2e-kind-backchannel-https`
harness is source/static-wired. Its live HA execution fails preflight because
Docker `fs.inotify.max_user_instances=128` is below the required `256`;
incoming configured-upstream fan-out, pending-pod/quorum delivery chaos,
policy-enforcing CNI, log redaction, trusted-proxy/IP mismatch E2E and
network-policy chaos enforcement remain pending.
This historical run does not verify the current Rhiza v0.10.0 production HA
profile; the row above remains unchecked until the current live gate runs.
The separate direct-TLS kind gate passed the same day and removed its cluster
after proving projected-Secret certificate rotation and invalid-reload retention.
The Cilium policy-enforcement gates currently fail before application deployment:
Cilium v1.20.0 exits from its route reconciler with `protocol not supported` on
the Dory host kernel. The CIMD-specific `make e2e-kind-cimd-cilium` gate is
otherwise deterministic: realized CiliumEndpoint policy revisions bound rollout,
while exact fixture counters judge cached continuity, denied uncached fetch and
recovery. The harness fails closed and removes its cluster; this row
must remain unchecked until a compatible kernel proves the network partition
and recovery assertions. A pinned Calico v3.32.1 fallback was also exercised,
but the same host lacks its nftables `rpfilter` extension and functional legacy
raw tables, so Calico correctly remained unready before application deployment.
Chaos Mesh v2.8.3 does not officially support Kubernetes 1.36, so it is not
introduced for this cluster; deterministic partition/recovery scripts and the
new `scripts/e2e-pod-restart-chaos.sh` OAuth-consistency replacement-pod gate
remain the supported chaos mechanism. The bucket-readiness initContainer
removes the object-store startup race; the script asserts zero GoAuthy
init/main restart counts before fault. `[x]` Fresh `make e2e-kind-chaos
E2E_PORT=28080` issued on pod 0, introspected on pods 1/2, deleted pod 2,
rechecked survivors, waited for its replacement and introspected the same token
there. This does not complete full-chain/DPoP gates; the login gate has separate
sequential kind evidence.

On 2026-09-01, the dedicated roles/groups profile also passed the new
three-pod deterministic `TestBootstrapClientGroupRestrictionAcrossPods` in
1.610 seconds. It uses linearizable cross-pod GET barriers and revision
assertions rather than sleeps, and covers allow, stale `409`, deny and clear
transitions for the static-client group-prefix policy.

[readme]: https://github.com/sebadob/rauthy/tree/v0.36.2#features-list
[changelog]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/CHANGELOG.md
[ephemeral]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/ephemeral_clients.md
[cimd-draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02
[scim]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/scim.md
[providers]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/auth_providers/index.md
[claims]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/custom_scopes_attributes.md
[dynamic-client-request]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/clients.rs#L14-L91
[api-keys]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/api_keys.md
[swagger]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/swagger.md
[k8s]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/getting_started/k8s.md
[backup]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/config/backup.md
[pam]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/pam.md
[routes]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/oidc.rs#L1255-L1298
[authorize]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/authorize.rs#L25-L300
[logout]: https://raw.githubusercontent.com/sebadob/rauthy/v0.36.2/book/src/work/logout.md
[backchannel]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/oidc/logout.rs#L98-L469
[forward-auth]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/oidc.rs#L1197-L1235
[rauthy-reset]: https://github.com/sebadob/rauthy/blob/v0.36.2/src/service/src/password_reset.rs#L139-L210

- [ ] Upstream OIDC incoming back-channel logout: `go-jose/v4`, stdlib JSON/time, existing Rhiza/session/outbox. Token validator, schema83 atomic upstream-to-new-local-session binding and schema84 HTTP logout/replay/local revocation/downstream outbox exist; deployed E2E and chaos remain pending. [Evidence and checklist](upstream-backchannel-implementation.md).

## Default storage acceptance correction (2026-09-09)

The user requires no GoAuthy PVC and object-store DR by default. Historical
fresh-PVC/cold-local-copy tests do not close this deployment requirement. See
[no-PVC DR contract](no-pvc-dr.md) for final-candidate verification gates.

## Password grant qualification (2026-09-11, incomplete)

- [x] Managed and dynamic client password/refresh registration, default-scope selection, ID-token password origin and discovery capability. Packages: `internal/clients`, `internal/dcr`, `internal/oauth`, `internal/oidc`; runtime wiring: `cmd/goauthy`.
- [x] Real-Rhiza HTTP tests cover public/basic/post dynamic clients and public/confidential managed clients, current group admission, credential/client/membership fences, DPoP and refresh. Dynamic usage timestamps are monotonic and unchanged by rejected issuance or refresh.
- [x] Standalone managed password issuance/refresh succeeds before and after server restart; each run creates fresh grants, so this is not retained-token recovery evidence.
- [x] Three-node managed password issuance/cross-node refresh passes before and after UID-verified Pod replacement (2.92s/3.62s, session 95528 exit zero). These are fresh workflows, not retained-token recovery.
- [x] Current password production-candidate verification passed for oidc, dcr, oauth, clients, rbac and cmd/goauthy (53019 exit zero). This is not a whole-repository qualification.
- [x] Focused HTTP recovery chain: expired password → real recovery service → loopback SMTP → delivered reset link with cookie/CSRF → new access/refresh/verified ID token; old password and reset replay rejected. Success clears failure metadata. Evidence: `TestExpiredPasswordGrantDeliversResetSMTP`, `/tmp/goauthy-password-http-smtp-claims.log` (5.445s).
- [x] Login timestamps and schema86 failure counters implemented with credential-generation fences; recovery callback precedes expired-password failure recording. Focused success/failure and concurrent write tests pass. These checks do not qualify distributed schema86 deployment.
- [x] Sessionless password login associations and dynamic/managed backchannel URI updates: focused real TLS deletion delivery, URI removal, and deterministic dynamic in-flight URI update checks pass. This does not qualify all lifecycle races or deployed DR.
- [x] Focused retained dynamic password refresh-token recovery from filesystem and MinIO S3 object storage, with restored signing claims and backchannel association metadata: `TestNoPVCAccountAndSigningKeyRecovery`. This is subprocess fresh-directory recovery, not Kubernetes or multi-host loss.
- [ ] Persisted password tokens across Kubernetes replacement/DR; final-candidate distributed login-counter qualification; remaining login-state lifecycle races; login location checks; remaining upstream failure-side-effect parity. Focused protocol passes do not complete password parity or the overall port.

Detailed evidence and current process handles are maintained in `docs/status.md`.
