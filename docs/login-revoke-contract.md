# Login-location revoke contract

Bounded, read-only parity findings for `GET /auth/v1/users/{id}/revoke/{code}`. Evidence is limited to the pinned `rauthy` tag `v0.36.2` and the local files already inspected.

## Upstream contract

- **Route and response:** `src/api/src/users.rs:1235-1267` defines a public `GET /users/{id}/revoke/{code}` handler. It renders HTML and always returns outer HTTP `200 text/html`; inner failures render an error page using the nominal `400/404` status. It accepts the required typed query parameter `ip` (`src/api_types/src/users.rs:300-304`).
- **Redeem sequence:** `src/api/src/users.rs:1270-1298` loads the per-user `UserRevoke`, compares the path code, then sequentially invalidates sessions, invalidates refresh tokens, deletes all login locations, performs back-channel logout, loads the user, deletes the revoke row, and emits `UserLoginRevoke`. Any error stops the sequence.
- **Storage and code:** `src/data/src/entity/user_revoke.rs:20-67` stores one raw code per user in `user_revoke(user_id PRIMARY KEY, code)`. `upsert` generates a cryptographically secure 48-character alphanumeric code and uses `ON CONFLICT(user_id) DO NOTHING`, so a user keeps one shared code until the row is deleted. There is no expiry, digest, consumed marker, address binding, or cleanup job.
- **Replay and races:** the handler has a code comparison followed by cleanup and a later delete, with no transaction or guarded consume. Replay behavior is therefore incidental to row deletion and failures; upstream does not explicitly guarantee one-winner race handling or expiry.
- **Mail trigger and contents:** `src/data/src/entity/login_locations.rs:170-258` creates/updates a location, then calls `UserRevoke::find_or_upsert` and `login_location::send_login_location`. `src/data/src/email/login_location.rs:41-120` builds the link as `.../auth/v1/users/{id}/revoke/{code}?ip={ip}`, includes IP, user agent, and optional location, and sends the `LoginLocation` text/HTML mail. Delivery uses a ten-second timeout and logs errors without returning them. The template has no expiry claim.
- **Event:** `src/data/src/events/event.rs:822-841` emits `UserLoginRevoke` with configured level, event IP equal to the query `ip`, null data, and text containing the user email, IP, and location or `Unknown Location`. The related new-location event is at `:762-780`.

## Local reuse and smallest implementation decomposition

1. Mount the public HTML route beside the existing recovery/account mounts (`cmd/goauthy/main.go:962-970`, `:1318-1322`) and preserve the upstream outer-200 HTML/error-page behavior. Reuse the existing security-header and HTML response conventions from `internal/recovery/http.go:108-137`.
2. Extend the existing login-location path (`internal/identity/login_location.go:39-171`) only after proving its production caller and request metadata. Its current table is subject/IP/timestamps/count (`internal/storage/migrate.go:3116-3126`); browser ID, user agent, and geolocation are absent locally.
3. Add the minimal per-user revoke record and generation path, preserving the upstream externally visible **shared 48-character code, no expiry, and no automatic address binding**. The existing random/digest helpers and reset-token SQL patterns are reusable (`internal/identity/store.go:978-1048`, `:1585-1623`). Because later new-location mails must re-send the same shared code, digest-only storage is insufficient. If choosing at-rest protection, store a recoverable protected code, or use an equivalent deterministic keyed derivation with a per-user nonce and domain separation, so the original external code remains reproducible.
4. Implement one redemption mutation that preserves the upstream cleanup set and order: revoke browser sessions/refresh state, clear login-location records, enqueue/perform back-channel logout, consume the revoke row, then append `UserLoginRevoke`. `internal/rbac/forced_logout.go:13-65` supplies the atomic mutation and back-channel/session cleanup patterns; `internal/eventlog/events.go:46-185` supplies event validation, deterministic IDs, and statements. Atomic guarded consume is compatible internal safety: it can make one concurrent redemption win while retaining shared-code/no-expiry/query-IP semantics.
5. Add the login-location mail message by extending the existing recovery sender/template boundary (`internal/recovery/sender.go:9-25`, `internal/recovery/smtp.go:212-264`, `internal/recovery/templates.go:15-27`). Preserve the upstream link and fields; delivery may remain best effort only if that is the intended local contract.
6. Add the missing `UserLoginRevoke` constructor and route/event wiring; the type is already present in the local event catalog (`internal/eventlog/events.go:46-75`, `internal/apidocs/catalog_admin.go:258-263`).

## Explicit baseline versus open decisions

The parity baseline is upstream’s shared per-user 48-character code, no automatic expiry, no automatic code-to-original-address binding, query-supplied `ip` in the revoke link and event, HTML outer status `200`, and the cleanup/event sequence above. The docs requirement for expiry, replay, race, and invalid-link tests does not by itself authorize changing those semantics.

The following remain unresolved and should be decided before production implementation:

- Whether local hardening should use a recoverable protected code or an equivalent deterministic keyed derivation with a per-user nonce and domain separation, plus an atomic guarded consume, while keeping the same code format, lifetime, re-send behavior, and query-IP event behavior. Digest-only storage must not be selected because it cannot reproduce the shared code for later new-location mails.
- Whether email delivery is best effort like upstream or must use the existing durable back-channel/outbox approach.
- Whether local cleanup should match the upstream sessions/refresh/login-location/back-channel set or also include the broader OAuth and client state removed by `internal/rbac/forced_logout.go`.
- How new-location detection is actually wired in GoAuthy. Upstream references browser ID, user agent, and `ipgeo`; local inspected code proves only subject/IP/time/count storage, and `RecordLoginLocation` had no production caller in the inspected search. Browser correlation and geolocation behavior are therefore unproven.
- Whether the upstream `ip` query value should be accepted as event metadata exactly as-is; it is not proof of the original login address or a trusted peer address (`docs/package-research.md:349-364`).

No production files were edited.

## Additional pinned browser-location evidence

`migrations/hiqlite/25_browser_id.sql` changes the upstream location primary key to `(user_id, ip, browser_id)`. `entity/login_locations.rs:215-239` matches browser ID first when supplied; only requests without a browser ID use IP lookup. A known browser may update its IP without a new-location notification. The local subject/IP-only schema88 therefore cannot be treated as equivalent by merely wiring its current RecordLoginLocation method. The event constructor uses Notice by default (`rauthy_config.rs:497`), email / user-agent / optional location text, IP, and null data (`events/event.rs:762-780`).

## Browser ID runtime configuration

`GOAUTHY_BROWSER_ID_COOKIE_MODE` accepts `host`, `secure`, or `danger-insecure`.
The default remains Host for an HTTPS issuer and DangerInsecure for a permitted
loopback HTTP issuer. `GOAUTHY_BROWSER_ID_COOKIE_SET_PATH=true` scopes Secure
and DangerInsecure cookies to `/auth`; Host cookies always use `/`. These are
per-instance rbid settings used consistently by page issuance, browser login,
and password-grant reads. Existing issuer validation still applies.

A browser sends an `/auth` cookie only on matching paths; requests to local
`/oidc` routes therefore use the no-browser-ID/IP fallback unless they have an
applicable cookie. Full upstream route/cookie configuration parity, including
session cookies, remains a separate unfinished requirement.

Login-location mail uses `GOAUTHY_EMAIL_SUB_PREFIX`, defaulting to the pinned
`Rauthy IAM` value when unset. Explicit empty values are preserved; CR/LF are
rejected at startup. Subject composition and its real SMTP propagation have
focused coverage. Login-warning email rendering uses validated typed variables from the persisted
global theme, with built-in fallback; other themed page surfaces remain incomplete.
