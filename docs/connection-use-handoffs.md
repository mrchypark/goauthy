# Connection use handoff

Schema 81. Supports registered API-key `proxy` and `credential_delivery` consent,
and OAuth2 `credential_delivery` for confidential consumers.
Delivery requires a confidential execution consumer; a proxy ticket never becomes
a delivery grant. Schema 79 preserves existing proxy tickets and completion state.
`review_uri` now opens the GoAuthy HTML approval page. An unauthenticated browser
is sent through `/account/connection-login` and returned to the same ticket after
password login, without approval. Existing authenticated sessions are supported;
full cold-browser MFA/passkey login is not yet wired into this continuation.
Forced MFA rejects password-only login rather than downgrading it. The Backoffice
BFF callback/integration remains separate; this is not a completed consumer-app flow.

## Request and approval

1. The BFF retains a cryptographically random, expiring, one-use `state` bound to
   its own authenticated session and the expected owner/connection/consumer/mode/
   resource/digest. It calls `POST /auth/v1/connection-handoffs` using a human
   `goauthy.connections.write` Bearer token with the exact connections resource
   audience. Cookies are rejected. JSON fields are `collection_id`, `connection_id`,
   `consumer_client_id`, `mode`, `purpose`, `expires_at_unix_ms`, `return_uri`, `state`,
   and optional non-null boolean `allow_refresh` (default `false`). Only explicit
   OAuth2 credential-delivery approval may enable it; legacy omission remains false.
2. GoAuthy validates the current connection, registered provider, bound credential,
   consumer policy, and requester. `return_uri` must exactly match the requester's
   registered HTTPS redirect URI without query/fragment. `state` accepts 32–128
   base64url characters; character validation does not prove entropy or session
   binding, which remain the BFF's responsibility.
3. The 201 response is `{id, review_uri, review}`. `review` contains
   `request_client_id`, `return_uri`, ticket `expires_at_unix_ms`, a `grant` proposal
   with an empty ID, and `review_digest`; the grant includes optional `allow_refresh`
   (default `false`). API-key review contains public `connector`
   metadata; OAuth review contains public `oauth2` status and an empty connector.
   Creation grants no consent.
   Tickets last at most five minutes or the proposed grant lifetime, whichever is
   shorter. At most 16 unexpired tickets (including completed tickets) are retained
   per owner. Grant expiry is in the future and at most 30 days away.
4. `GET /account/connection-handoffs/{id}` shows the requesting client, execution
   client, connection, owner, purpose, resource, operations and response fields,
   grant expiry, ticket expiry and exact return destination. Approval requires an
   initially unchecked native required checkbox. The HTML POST strictly accepts
   `decision=approve`, `reviewed=yes`, `review_digest` (or legacy `connector_digest`), `csrf_token`, or just
   `decision=deny` and `csrf_token`. The form adapter reuses the session/CSRF guard.
   Owner browser-session `GET /auth/v1/account/connection-handoffs/{id}` still serves
   JSON and rechecks the
   proposal. POST to the same endpoint requires the owner's CSRF token and explicit
   `{"approve":true,"review_digest":"<reviewed digest>"}` (or legacy `connector_digest`) or `{"approve":false}`.
   Approval inserts consent and consumes the ticket in one Rhiza transaction.
   OAuth review includes public provider/account/scopes/version/connected/state;
   approval binds the reviewed OAuth credential version snapshot with connection
   generation and provider revision; a refresh before approval requires a fresh
   handoff. After approval, refresh is valid for the same consent and delivery
   reports the current version.
   Concurrent approvals can create only one grant. Denial creates none.
   API-key delivery review explicitly states that the consumer receives the original key,
   that listed operations/projections cannot constrain its use, and that consent
   revocation/expiry cannot recall it. Its button is **Allow API key delivery**;
   no key is rendered or delivered by this page or its completion response.
   OAuth review instead shows **Allow OAuth token delivery** and warns that only
   the access token can be retrieved, never the refresh token or client secret;
   revocation cannot recall tokens already delivered.
5. The JSON POST returns `{return_uri}`. HTML POST renders a completion page with
   an explicit **Return to requesting app** link; neither redirects automatically.
   Approval adds
   only `state` and `grant_id`; denial adds `state` and `error=access_denied`. No key,
   access token, refresh token, or provider client secret is included. Completed or
   expired tickets cannot be replayed.
6. The BFF consumes its session-bound state and fetches the grant through
   `GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}` with
   its own read-scope Bearer token. Compare against **pre-stored expectations**, not
   expectations derived from callback parameters: owner, connection, consumer,
   mode, resource, generation, provider revision, revocation, expiry and
   `allow_refresh` (omission means false; never upgrade it to true implicitly).
   For API keys, also compare the stored `connector_digest`. For OAuth this
   field is empty: **never compare it with `review_digest`**. The latter commits
   to one ticket's review/version, not to a persisted grant or delivered token.
   OAuth delivery must separately validate account, scopes and current token
   expiry. Do not pin post-approval delivery to the old review digest/version:
   a normal refresh under unchanged authorization advances the version.
   Retain the proposed OAuth version for context; grant status does not expose it.
   The execution consumer may use `GET /auth/v1/connection-grants/{grant_id}/credential-status`
   with its own confidential human use token for current public provider/account/scopes/version/
   connected/state metadata; the BFF's read token cannot use this route for another consumer.
   It performs no refresh or upstream call and returns 404 for API-key/proxy grants.
   Stored consent is not proof of current SDK/execution readiness. OAuth delivery returns only the access
   token; client secrets and refresh tokens are never returned and no automatic
   refresh is performed.

Provider revision, requester/consumer generation, current policy, connection
generation and owner authority are checked again at review/commit. Reconnect or
policy changes invalidate stale proposals. The database stores only SHA-256 of the
random handoff identifier. Failed or lost completion responses require restarting
the flow; do not blindly retry approval or treat an ambiguous response as success.

## Verification and implementation

2026-09-08 OAuth follow-up: schema81 version-fenced OAuth handoff and its native
review page passed actual HTTPS Chromium cold login, explicit approval and owner
grant recheck, followed by confidential consumer access-token delivery, owner
refresh and revocation. Standalone before/after restart: 20.24/2.97 seconds, exit 0,
`/tmp/goauthy-oauth-handoff-live-20260908-v2.log`. The first attempt omitted the
documented fixture hostname mapping and failed readiness; it is not acceptance
evidence. This test does not navigate to a real consumer BFF callback or qualify
cold-MFA, production OAuth adapters, automatic refresh or HA.
Older verification paragraphs below record the API-key-only milestone.

Uses existing OAuth resource authorization, managed clients, credential encryption,
consent policy and Rhiza transactions, plus Go stdlib `crypto/sha256`,
`encoding/base64`, `net/url`. No added dependencies or new token protocol.
Rhiza v0.12.0's ordinary batch receipt omits per-statement results unless rows are
requested; `RETURNING` + `WantRows` explicitly returns the inserted/consumed ID.
Checking omitted statement results previously reported a conflict after commit;
the creation/approval regression tests exercise this through real Rhiza.

Actual HTTPS standalone acceptance with real code+PKCE requester tokens passed
before and after restart (`/tmp/goauthy-handoff-final-live-20260907.log`): proposal without
implicit consent, exact callback validation, owner review, digest mismatch,
approval/denial and replay denial. This is HTTP acceptance, not browser/BFF E2E.
Focused storage/OAuth/HTTP boundary race checks passed in
`/tmp/goauthy-handoff-boundaries-race-20260907.log`. Full parity, OAuth
handoffs, full cold-MFA, BFF integration and final HA/chaos verification remain open.

### Browser form security

All handoff/login responses use no-store and no-referrer; the approval page has no
script and allows only self-origin forms/styles, with framing denied. No third-party
assets load. Operators must exclude handoff/state URLs from proxy/access logs.
Native no-referrer forms send `Origin: null`; this was reproduced in Chromium and
is [documented by MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).
Go's [CrossOriginProtection](https://pkg.go.dev/net/http#CrossOriginProtection)
checks browser Fetch Metadata. Null origin is additionally accepted only with one
exact `Sec-Fetch-Site: same-origin`; same-site/cross-site/none/missing/duplicate
metadata is rejected. Session-bound CSRF remains mandatory. The same small fix
applies to the existing shared login origin checker; it does not trust null alone.

`GOAUTHY_E2E_HANDOFF_UI=1` adds actual Chromium cold password login, unchecked-form
non-submission, explicit approval, exact return link, persisted grant/revoke and
separate denial. The browser never navigates to the external callback in this
fixture; Backoffice's own callback/state-consumption tests remain required.

Final browser evidence: `/tmp/goauthy-handoff-page-final-live-20260907.log`, exit 0,
Chromium 1.57s/1.04s before/after restart. Focused login/Device/FedCM and page
boundary race tests passed in `/tmp/goauthy-handoff-page-final-race.log`.
The final screenshot `/tmp/goauthy-handoff-page-final-20260907.png` was inspected.
Full OpenAPI validation and related package vet passed. These do not close the
remaining consumer integration, cold-MFA, OAuth/SDK or HA/chaos requirements.
