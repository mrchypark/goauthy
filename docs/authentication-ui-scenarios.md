# Authentication UI scenarios

Baseline: GoAuthy ea830e24; Rauthy v0.36.2 dd61ac3c84d6b238108dc8438b53043b5177a662.
Status: scenario proposal awaiting Pro review; implementation and browser qualification pending.

## Page correspondence

Rauthy paths below are frontend routes, not necessarily public server mount paths.

| Rauthy page family | GoAuthy surface / evidence | Work |
|---|---|---|
| `/`, `/oidc/authorize` | `/oidc/authorize`, internal/login | Clear identity, destination, password/passkey/provider choices, recovery/registration discovery, responsive form and inline failures |
| `/oidc/callback`, `/providers/callback` | upstream callbacks and OIDC client callback | Preserve protocol redirects; human-readable failure with safe restart; never render authorization codes |
| `/fedcm` | configured FedCM landing and success, internal/login | Same visual language, browser support and completion state |
| `/device` | `/oidc/device/verify`, `/oidc/device/login` | Code entry, authenticated review, explicit allow/deny, expired/used/policy-changed states |
| `/users/register` | POST registration and passkey registration APIs only | Build real registration page, policy-driven fields, proof of work, neutral sent state; feature-gated discovery |
| `/users/password_reset` | POST request_reset API only | Build reset request page and neutral delivery state |
| `/users/{id}/reset/reset` | GET reset returns JSON/cookie; PUT consumes reset | Browser page consuming existing API contract, policy/confirmation, expiry/replay, no token disclosure; preserve API clients |
| `/users/{id}/email_confirm/email_confirm` | email-change backend needs mount verification | Determine actual contract before showing a confirmation action |
| `/users/{id}/revoke/revoke` | login-location revoke HTML | Styled result, no-referrer and no credential leakage |
| `/oidc/logout` | logout confirmation | Explicit confirmation, post-logout destination validation, styled terminal state |
| `/error` and nested error routes | handler errors | Accessible safe error state, no arbitrary redirect or sensitive diagnostics |
| `/account` | embedded account dashboard | Profile/security/passkeys/passwordless/devices/connections/deletion; usable navigation and responsive states |
| `/admin` and dashboard | embedded administrator UI | Consistent navigation and layout; authenticated role boundary |
| admin users, roles, groups, api_keys, scopes, attributes, clients, providers, sessions, events, blacklist | existing administrator scripts/APIs | Inventory individual controls, loading/empty/failure/success, destructive confirmations, stale edits and pagination |
| admin config argon2, backups, encryption, jwks, policy, tos; kv, pam, docs | some APIs/operational tooling, full UI not established | Verify each capability; implement supported screens, explicitly record backend gaps instead of fake controls |
| GoAuthy additions | collections, connection handoffs, OAuth connection completion, email templates | Match account/admin/auth presentation; keep grant review explicit |

## User scenario matrix

Each scenario includes entry/precondition, action, and expected security outcome.

| ID | Scenario | Expected outcome |
|---|---|---|
| AUTH-01 | Anonymous OIDC authorization → password | Validated client destination; code issued only after full authentication/profile requirements |
| AUTH-02 | Account/admin entry with no session, valid session, expired session, ordinary user | Authenticate or resume; admin denies insufficient rights without redirect loop |
| AUTH-03 | Password failure, disabled/expired account, throttling, lockdown | Generic safe failure; recoverable input retained except secrets; no account enumeration |
| AUTH-04 | Password → email OTP, invalid/expired/reused code | Same interaction and subject; no completion before OTP; clear next action |
| AUTH-05 | Passkey login / passkey-only / password + security-key step-up | Native ceremony; cancellation/unsupported browser recoverable; never silently downgrade required MFA |
| AUTH-06 | Upstream provider success/denial/state expiry/disabled provider | Validated callback; preserve original target and logout obligations; no arbitrary return URL |
| AUTH-07 | Required/readonly/optional profile fields after each method | Server policy owns validation; preserve target; correction returns to form |
| AUTH-08 | Existing session, forced reauth, different-subject login, revoked parent | Respect current policy and subject fence; no privilege reuse |
| AUTH-09 | Parallel tabs, refresh/back, replay, network loss, duplicate submit | Single-use interactions and server authority; no optimistic success or blind mutation retries |
| REG-01 | Enabled/disabled/domain-restricted registration | Feature-gated page; server policy and proof of work; neutral existing/new email result |
| REG-02 | Registration fields, password invitation, passkey registration | Real API schema and configured policy; no hardcoded acceptance or false success |
| RESET-01 | Known/unknown email reset request and throttling | Identical sent response; one-use proof, actionable delivery wording without enumeration |
| RESET-02 | Valid/invalid/expired/reused link; password policy mismatch | Existing reset-cookie/CSRF protocol; visible policy; success only after accepted mutation |
| EMAIL-01 | Email confirmation or suspicious-login revoke | Correct one-use backend semantics; no-referrer/no-store; explicit terminal feedback |
| APPROVE-01 | Device code entered or prefilled, signed out → each auth method | Return to review, never auto-approve; show client/scopes/resource and signed-in identity |
| APPROVE-02 | Device allow/deny, expiry/replay, policy changed, required step-up | Revalidate live policy and parent session before granting |
| APPROVE-03 | SaaS handoff signed out → password/OTP/passkey/upstream → profile | Return to exact server-held handoff; show consumer, requested access, connection selection |
| APPROVE-04 | Handoff approve/deny/expired/used/wrong owner/stale grant | Explicit consent, no secret display, no automatic retry after uncertain response |
| ACCOUNT-01 | Profile/username/password edit, policy failure | Confirmed server success; local form errors accessible; secrets cleared appropriately |
| ACCOUNT-02 | Passkey add/remove, passwordless conversion/restoration | Real ceremony and current-password checks; prevent lockout according to backend policy |
| ACCOUNT-03 | Device/session review/revoke | Show only available metadata; revoked access verified on backend |
| ACCOUNT-04 | Connections/API keys/OAuth connect/reconnect/revoke and grants | Secret-safe forms; explicit operation scope; interrupted refresh never blindly retried |
| ACCOUNT-05 | Self deletion, logout, return after revocation | Clear irreversible warning and server-owned confirmation; expired session handled |
| ADMIN-01 | Each supported list/detail/create/edit/delete and permission boundary | Loading/empty/failure states, confirmed mutations, retained stale-edit input, secret reveal bounded |
| ADMIN-02 | Policy/provider/client configuration affects next login | No front-end-only policy; correct live auth options and server enforcement |
| UX-01 | 360px/mobile and desktop, keyboard only, 200% zoom | No form overflow, semantic labels/headings, focus visible, errors announced, reduced motion |
| UX-02 | English/Korean, dark/light/custom client theme, issuer path | No broken asset/form/link paths; appropriate language; sufficient contrast |
| OPS-01 | Standalone restart and exact-three pod replacement | State continuity/rejection follows server contract; browser evidence separate from handler tests |

## Implementation and evidence rules

Reuse Go templates, embedded CSS/JS, native browser inputs and existing API/security boundaries. No new frontend framework. Build one consistent, restrained GoAuthy design with clear application identity, generous form spacing, strong focus treatment, and compact navigable account/admin surfaces. Do not copy Rauthy's appearance.

Coverage is per row and per relevant authentication method, not a Cartesian-product claim. Password, OTP, passkey and upstream must each cover OIDC, Device and handoff continuations where supported; additionally exercise profile completion, cancellation and security-relevant failures. Handler tests do not count as graphical verification. Preview pages must use real handlers, with loopback-only disposable data. Never present a gallery mock as working authentication.

Release/merge is not part of this UI task unless subsequently requested. Unavailable backend capabilities remain explicit gaps; they are not silently counted as completed pages.

## Pro review — 2026-09-26

Completed proposal review: https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46/c/6ab7987d-a2e8-83ee-a56e-5f8f4e51e3fd . Conditional GO; not an implementation audit.

Accepted corrections: recovery remains purpose/subject-specific authority, never authentication or MFA recovery. Keep JSON reset API unchanged; an HTML landing must not consume reset/enrollment on GET/HEAD, and minimal same-origin JS must use existing cookie + X-Pwd-CSRF-Token + magic_link_id for PUT. Test actual delivered links, cold/different-user browsers, two links, issuer prefixes and link scanners. Do not transport approval authority by email. Detours return through normal authentication; an expired/revoked parent requires restarting the owning transaction, never rebinding it.

Add blocked/no-eligible-method and missing-required-readonly-profile states. Browser capability is not server method eligibility or assurance. Method cancellation cannot downgrade MFA. Late responses cannot affect another transaction. Lost mutation responses are outcome-unknown; reconcile only by authoritative reads, otherwise instruct safe restart without automatic mutation retries. Device prefilled codes still require visual matching and explicit consent.

Additional rows: ROOT-01 public entry; OIDC-01 existing session/prompt=none/freshness/protocol cancellation/invalid redirect; LOGOUT-01 confirmation/result; FEDCM-01 browser-owned chooser/cancel/unsupported (not a custom substitute); REG-03 incomplete invitation/enrollment/resend/superseded link; UX-03 JS/cookie/browser API unavailable. Admin permissions and secret exposure must be recorded per action, including session/permission revoked while editing and self-revocation consequences.

### Initial implementation contract

Login `/oidc/authorize`, Device `/oidc/device/login`, handoff `/account/connection-login`: existing Go login template, public session-bound interaction, password POST and WebAuthn start/finish; presentation only. OTP uses existing POST `/auth/v1/users/otp/verify`; profile uses existing GET/POST `/auth/profile` with current authenticated session, interaction and CSRF. These reachable shared-template branches are safe to style without changing authority, continuation, fields or submission semantics. FedCM landing/success is feature-gated and keeps its existing handler contract. Account and admin styling must preserve existing DOM IDs, handler permissions and response confirmation. Recovery/new admin behavior remains pending its detailed API/action mapping and tests.

### Recovery implementation contract

New `/auth/v1/users/password_reset` and GET `/auth/v1/users/register` pages call existing POST request_reset/register, POST pow and GET values_config. Registration uses the public policy, neutral 204 result, and no redirect input. CAPTCHA-enabled registration remains blocked with an explicit unavailable message until the configured widget is supported; passkey-first registration is a confirmed backend gap (`RegisterPasskeyStart` fails closed). Existing account passkey enrollment is unaffected.

Delivered `/auth/v1/users/{subject}/reset/{token}` links negotiate HTML only for explicit `Accept: text/html`; ordinary API requests remain JSON. HTML GET/HEAD does not bind or consume the token. An explicit Continue click requests the existing JSON bootstrap once, then shows password policy/confirmation and PUT. Reset cookie conflicts across tabs fail normally; no automatic retries. Outcome-unknown locks the mutation and instructs checking mail/restarting from a fresh link. Success does not create a login session. Login detours open separately to preserve the original tab; expiry still requires restarting the application request.

## Current implementation evidence (in progress)

Implemented shared responsive login/OTP/profile/FedCM presentation, feature-gated recovery/registration links, recovery and registration HTML/JS, policy-driven registration fields with optional disclosure, reset-link HTML negotiation, account navigation/styles, administrator rail/index/styles and logout shell. Existing protocol authority and mutations are retained. New public UI routes are in the OpenAPI catalog.

Live checks on loopback: password Device login returned to code review without approval; account dashboard rendered after real login; reset form solved proof of work and submitted to the actual SMTP-backed service; the actual delivered reset link opened HTML and explicit continuation loaded the password-policy form. This is not a claim of graphical password mutation, all MFA/provider combinations, or HA coverage. Recovery binding regression proves HTML navigation does not replace an already-issued JSON bootstrap cookie and the subsequent original-cookie reset succeeds. Deterministic JS checks cover neutral success, recoverable rejection, server failure and lost response with no duplicate mutation.

Reproduce the disposable live runtime:

```sh
GOAUTHY_UI_PREVIEW=1 GOAUTHY_STANDALONE_OPEN_REG_PORT=18120 \
  GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1 GOAUTHY_E2E_PROFILE_CLAIMS=1 \
  sh scripts/e2e-open-registration-standalone.sh
```

This reuses the loopback standalone/SMTP fixture, cleans up on exit, and does not run the fixture's mutation suites in preview mode. Test-only credentials are the existing fixture values; never use this profile for deployment.

Still pending: full route/action ledger for previously absent administrator settings/KV/PAM, full bilingual account/admin/profile/error states, signup CAPTCHA widget, account/root sign-in entry, browser errors and impossible-profile remediation, complete OTP/upstream/handoff/browser-method evidence, precise small viewport/zoom and custom-theme checks, and final standalone/exact-three restart qualification. Passkey-first public registration is an explicitly confirmed backend gap, not a completed UI action. Existing email-change confirmation has not been verified as a mounted public flow.

Latest verification: all eight touched Go package groups passed (`internal/login`, `recovery`, `logout`, `branding`, `admin`, `account`, `apidocs`, `cmd/goauthy`). Administrator/dashboard/device/connection/grant Node regressions and the new recovery submission checks passed. Live registration with required name and email reached the neutral sent state; the local SMTP sink confirmed receipt. No production data or credentials were used. Requested viewport 390px did not map to an observed 390 CSS-pixel viewport in the current IAB; no exact-390px qualification is claimed.
