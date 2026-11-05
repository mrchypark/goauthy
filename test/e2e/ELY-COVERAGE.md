# Ely disposable acceptance gates

Run from the candidate worktree. Parent owns integration/commits and allocates the heavy execution slot. This fixture never reads the installed local bundle, talks to IED, uses external OAuth accounts, or provisions Kubernetes resources.

```sh
sh scripts/test-e2e-ely-standalone.sh
# Only after parent allocates the serial build/browser slot; run sequentially:
# 21 HTTP gates, followed by the separate HTTPS boundary gate (22 distinct gates).
GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run
GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run-boundary
# Optional targeted subset: theme plus three local passkey/provider gates.
GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run-extra
```

`--run` selects 21 HTTP gates; `--run-extra` selects four of those gates (theme, virtual passkey, provider catalog, provider registration). The OAuth2 boundary is exclusive to `--run-boundary`, which creates a disposable local CA and localhost server certificate, enables the server's existing TLS configuration, and supplies fixture CA trust to the HTTP clients. There is no `--run-all` mode. The repeatable 22-gate sequence is `--run` followed by `--run-boundary`; an HTTP run does not establish the HTTPS boundary.

The runner builds current worktree sources with `-mod=readonly -p=1`, creates an owner-only temporary directory, starts real GoAuthy standalone storage and the existing SMTP sink on loopback (18480–18482 by default), reserves 18483–18484 for Demo A/B, and invokes one compiled Go test at a time. The issuer uses `localhost` for WebAuthn RP validation; every listener binds `127.0.0.1`. `GOAUTHY_ELY_E2E_PORT` selects another range. It clears inherited deployment/cloud/proxy/test settings. Only synthetic bootstrap/client/user data is used. Each Chromium test has a fresh browser profile. Existing tests named “AcrossPods” receive the same standalone URL; these results establish single-server behavior, **not replication or HA**.

No raw logs, credentials, cookies, reset URLs, or tokens are printed. Success prints test names and deletes the fixture. Failure kills owned services, releases the existing shared E2E port lock, and leaves private diagnostics in the printed directory; do not publish raw diagnostics. The runner rejects both skipped tests and missing top-level passes. Recovery runs last because it changes the disposable admin password and revokes sessions.

| Behavior | Executable gate | Evidence / limit |
|---|---|---|
| Actual admin login and logout | `TestElyBrowserLoginLogout` | Browser enters password, reaches admin dashboard, confirms logout; authenticated account data becomes inaccessible. |
| Ordinary service-user password and login/logout | `TestElyBrowserLoginLogout` | Synthetic role-free user; browser changes password, logs out, signs in with new password, logs out. |
| Account field edits and old-password rejection | `TestAccountDashboardAcrossPods` | Chromium username/attribute/password forms; API persisted values and rejected old password. Initial session is seeded over HTTP. |
| Account passkey management | `TestAccountPasskeyUIAcrossPods` | Chromium virtual authenticator performs real WebAuthn registration, validation, deletion and list reload. Not physical hardware evidence. Optional passkey-only device subflow is not enabled. |
| Admin users, roles, groups CRUD | `TestAdminUIBrowserAcrossPods` | Real Chromium controls and server state; initial admin cookie seeded over HTTP. |
| Managed client CRUD and secret lifecycle | `TestManagedClientsUIAcrossPods` | Browser-managed public/confidential clients, secret read/hide/rotate; device token use and access boundaries. |
| Scopes, attributes, session management | `TestAdminCatalogSessionsUIAcrossPods` | Chromium controls with backend assertions. |
| Admin API keys | `TestAdminAPIKeyUIAcrossPods` | Chromium create/update/delete and access checks. |
| Auth collections | `TestAuthCollectionsUIAcrossPods` | Chromium admin and ordinary-user surfaces with SMTP fixture. |
| SaaS provider catalog and collection policy | `TestSaaSProvidersCatalog` | Synthetic file-configured provider, actual catalog HTTP and collection editor browser save; no provider endpoint contacted. |
| Provider registration and OAuth2 boundary | `TestProviderRegistrationLive`, `TestConnectionOAuth2ProviderRegistrationBoundary` | Real management HTTP CRUD/revision/secret-redaction; boundary assertions passed separately with the local HTTPS fixture. No external account consent. |
| Common brand save/reload and discard draft | `TestElyBrandUI` | Actual login, editable brand name, save, full reload, reload-saved control, persisted API value. |
| Common logo upload/reload/delete | `TestElyBrandUI` | Real file-input PNG upload, rendered image, full reload, removal confirmation, public endpoint returns 404. |
| Per-client themes and login rendering | `TestThemeLive`, `TestThemeLoginUI` | Passed, including the targeted strengthened check: exact six same-origin CSS links in order (four known Ely assets, global, client), loaded sheets, CSP/200-or-304 responses, computed light/dark brand colors and cache refresh. Backend theme mutation; not client editor controls. |
| Client logo transforms/security/fallback | `TestClientLogoLive` | HTTP upload PNG→WebP, sanitized SVG, unauthenticated-write rejection, delete/fallback. |
| Theme/logo cold restart | `TestThemePersistPrepare` + `TestThemePersistVerify`; `TestClientLogoPersistPrepare` + `TestClientLogoPersistVerify` | Same newly built server process is stopped and restarted on the same disposable data directory. |
| OIDC device login/approval | `TestDeviceOIDCLive` with UI flag | Cold Chromium login, full URI and manual-code approval; real issued tokens, signatures, claims, refresh, revocation. |
| Password recovery/mail | `TestPasswordResetAcrossPods` | Existing SMTP sink, PoW/replay, configured localized email body, reset-link binding, reset, session revocation and old/new login. Recovery form itself is HTTP, not browser-driven. |
| Demo A/B browser SSO | `TestElyDemoSSO` | Builds `cmd/goauthy-demo`; fresh confidential clients and two loopback app processes; equal verified subject/email, B SSO, separate cookies, A local logout and forced re-login while B stays signed in. No installed bundle or external accounts. |

## Explicitly not established by this selected suite

Provider registry UI/external provider OAuth; every event/blacklist/template control; account email-change/recovery UI; passkey/MFA hardware behavior; layout at every viewport; localization completeness; multi-node consistency; production deployment. Existing Node unit tests are separate evidence and do not substitute for these real-browser gates.

## Run status

There are passing results for **22 distinct gates across separate runs** against product commit `c93b0f3`: the original 18 and four additions (`TestAccountPasskeyUIAcrossPods`, `TestSaaSProvidersCatalog`, `TestProviderRegistrationLive`, and `TestConnectionOAuth2ProviderRegistrationBoundary` on the corrected HTTPS fixture). Arendt's final targeted `TestThemeLoginUI` run also passed in 7.32 seconds with the strengthened assertions preserved. That rerun supersedes the earlier weaker theme evidence; it does not add a 23rd distinct gate. This is cumulative verification, not a single unified run or whole-product completion claim.

The strengthened theme timeout came from Chromium's `BySearch` matching selector text inside a hidden passkey script. The harness now uses `ByQuery` to select the actual username input for both initial and reloaded pages. Exact-six links, ordering, loaded sheets, response/CSP checks, and computed brand colors remain asserted. No product change was required for this selector correction.

The HTTPS boundary rerun finished with zero failed gates and recorded source digest `95a86f5af911ae06f6ef1a5bc1b1f75e2b32a68ef12f3cab074594e864daa41c`. Its fingerprint covers the runner's boundary source selection, not every product file. The previous HTTP boundary attempt returned `503` where the test expected `401`: the server intentionally requires HTTPS before checking authorization. The production requirement was preserved; the fixture prerequisite was corrected.

`test/e2e/ELY-RECEIPT.txt` contains ignored, sanitized attempt milestones; do not commit ephemeral receipts. The runner appends only while holding the shared E2E lock, also writes a private per-run receipt, fingerprints its selected sources before building, and rejects changes to that selection at completion. Failure diagnostics stay in the private fixture directory. Independent gates continue after a failed gate, so later results may be affected if that test did not restore state; the overall command fails if any selected gate fails. A fixture/build failure or an unrun gate is not a pass, and this document alone does not declare merge readiness.

First-run harness failures were a login-redirect race, expecting `Content-Encoding: none` instead of an absent header, a stale two-stylesheet count, and rejecting valid HTTP 304 cache revalidation. These were test corrections; no product files were changed by the E2E owner.
