# Account dashboard

`GET /account` is the authenticated account page. `/account/data` returns the
current active subject's credential-free profile, issuer-bound CSRF token,
password policy and enabled password/passkey flags. Same-origin JS/CSS are
embedded at `/account/app.js` and `/account/account.css`. Issuer path prefixes
are retained in asset and mutation URLs.

Implemented actions reuse existing production handlers:

| Action | Existing API / package |
| --- | --- |
| Profile display | `identity.AccountProfileBySubject`, `encoding/json` |
| Preferred username | `PUT /auth/v1/users/{subject}/self/preferred_username`, RBAC/profile policy |
| Password change | `PUT /auth/v1/users/{subject}/self`, account/password services |
| Editable attributes | `GET …/{subject}/attr/editable`, `PUT …/{subject}/attr`, claims service |
| Sign out | Existing `GET /oidc/logout` confirmation page; GET does not revoke |
| Passkey list/add/remove | Existing account MFA-token, WebAuthn auth/register and delete handlers; native `PublicKeyCredential` JSON methods |
| Disable password sign-in | `POST …/{subject}/self/convert_passkey`, empty body + CSRF; existing MFA/peer-bound session and verified-credential policy |
| Restore password sign-in | Existing `PasswordNew` start/assertion/finish proof, `PUT …/{subject}/self` with `mfa_code,password_new` |
| Delete account | Existing `GET …/{subject}/self/delete` capability (202 only) and empty-body CSRF `DELETE` (204 completion); administrators remain protected |

The page uses `net/http`, `embed`, `html/template`, native form controls and
small same-origin JavaScript. No new dependencies or authentication mechanisms
were added. The existing services already own validation, authorization,
one-time proofs and replicated writes. Direct implementation is limited to the
product-specific view projection and forms that compose those APIs; a new CRUD
or frontend framework would not provide their subject/CSRF/policy contract.

Security: live peer-bound browser session, active subject projection, no bearer
or API-key fallback (including valid cookie plus Authorization), no-store,
strict CSP, frame denial and escaped/textContent output. Password success
preserves the current session according to the existing self-change policy;
old password login is rejected. Passkey-only users do not see the password
form. Attribute failures cannot submit an empty successful save. Typed JSON
attribute values are preserved. UI success follows the completed API response.

## Verification

- `go test ./internal/account -run '^TestDashboard'` covers session/revocation,
  header/path/method denials, CSRF/credential privacy and issuer-prefixed assets.
- `node internal/account/dashboard_ui_test.js` awaits the actual load promise;
  it checks exact payloads, typed values and failed-load save rejection without
  sleeps. `TestAccountDashboardContract` verifies OpenAPI media/security/schema.
- `TestAccountDashboardAcrossPods` uses real Chromium and an ordinary user:
  profile, username, editable attribute and password controls; persisted results
  on all configured nodes; preserved session and old/new password login.
  Enable with `GOAUTHY_E2E_ACCOUNT_DASHBOARD=1` in the combined profile batch.
  Standalone and exact-three Kind passed; exact execution evidence is in
  [status](status.md). Notification Pod replacement was separately checked;
  interruption of each account action is not yet covered.

## Passkey management

When the server enables passkeys, the dashboard lists the current account's
keys and connects add/remove actions to fresh server-issued modification
tokens. A zero-key account authorizes its first registration with a masked
password field. Existing-key accounts use an authenticator assertion followed
by the one-use modification-token exchange. A successful server mutation and
list refresh precede success feedback. Loading/error/busy state guards actions,
password fields are cleared after the attempt, and no proof is persisted in
browser storage. Initial administrator MFA remains optional.

The standard JSON conversion APIs avoid maintaining a custom base64 adapter:
`PublicKeyCredential.parseCreationOptionsFromJSON`,
`parseRequestOptionsFromJSON`, and credential `toJSON()`.
The server's `{publicKey: ...}` wrappers are unwrapped before parsing.
Browsers without these capabilities show an unsupported state; a legacy-browser
support matrix is not yet verified. The authoritative contract is
[W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON).
Server deletion removes the accepted credential, not the key from the user's
physical authenticator. No device-key deletion is claimed.

The deterministic Node test executes first registration, subsequent proof and
registration, removal, native JSON mapping and failed-load rejection. Only
the external browser authenticator boundary is replaced. The real Chromium
virtual-authenticator gate is `TestAccountPasskeyUIAcrossPods`; consult
[status](status.md) for verified execution results rather than treating a
compile-only skipped gate as a pass.

Still incomplete: ordinary-user session management UI, provider links, recovery UI,
full profile-policy discovery/editing, localized text and their browser/chaos
coverage. The broad self-service feature remains unchecked.

## Account mode and deletion

The dashboard now exposes conversion, restoration and self-delete controls.
`features.passkey_conversion` is a point-in-time UI hint from the current
password-enabled, passkey-configured, peer-bound MFA session. Mutation handlers
remain authoritative; changing this JSON flag in the browser grants nothing.
Conversion and restoration refresh `/account/data` before reporting success;
failed refreshes report an error, not a successful mode change. Restoration uses
a new purpose-bound WebAuthn proof on each attempt and clears password inputs.
Native confirmation plus exact email entry precedes self-delete. Capability
denial/failure cannot be bypassed by editing the email input. Only HTTP 204
replaces the account view with a terminal message; no authenticated fetch follows.

Important existing server behavior: user-verified registration atomically
promotes a password session to MFA in `registrationFinishStatements`.
The dashboard refreshes the account projection after registration to observe
that change. A normal passwordless `BeginLogin` returns `webauthn`, not `mfa`;
it must not be inserted as a supposed MFA step. External and non-UV registration
sessions are not promoted. The server's policy and optional initial-admin MFA
were not changed. Explicit reauthentication UX remains a follow-up.

`TestAccountLifecycleUIAcrossPods` creates an ordinary fixture, registers a real
Chromium virtual-authenticator credential, observes the server-issued conversion
capability, disables password sign-in, verifies the old password is rejected,
restores with a fresh `PasswordNew` proof, verifies the restored password and
cross-node mode, then self-deletes and proves the existing cookie is rejected
on all configured nodes. It never creates or patches sessions directly in DB.
See [status](status.md) for actual standalone/HA results. This is not yet a
proof of interruption at every lifecycle transition.
