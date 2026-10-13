# Ely frontend migration verification

This page records the local integration and verification boundary for the
GoAuthy browser frontend migration to `github.com/mrchypark/ely-htmx`.

## Integration observed

- Ely is pinned at `v0.1.0` in `go.mod`.
- `internal/ui` owns the embedded Ely templates, the CSS-only shared head,
  issuer-prefixed asset URLs, and the GoAuthy brand token bridge.
- `cmd/goauthy` mounts the shared assets below `/auth/v1/ui/`; the application
  issuer middleware supplies any outer issuer prefix.
- Existing page-owned scripts, forms, CSRF fields, passkey fields, redirects,
  locale selection, and custom theme links remain page-owned.
- The shared head currently serves Ely's `app.css`, controls, and patterns
  stylesheets plus `brand.css` and the three embedded font files. The selected
  Ely CSS is 49,899 bytes before transfer compression. The final check must
  preserve this core-only set and reject accidental all-advanced-CSS loading.

## Runnable checks

The repository-native disposable browser runner uses Go and `chromedp`.
After allocation of the serial execution slot, run the 21 HTTP gates and the
separate HTTPS boundary gate sequentially:

```sh
sh scripts/test-e2e-ely-standalone.sh
GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run
GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run-boundary
```

These two execution commands select 22 distinct gates. `--run-extra` selects
only theme, virtual passkey, provider catalog, and provider registration (four
HTTP gates). The OAuth2 boundary runs exclusively under `--run-boundary` with
a disposable local CA, server certificate, and verified client trust. There
is no `--run-all` mode, and an HTTP run cannot establish this HTTPS boundary.
See [the executable coverage matrix](../test/e2e/ELY-COVERAGE.md) for evidence
and limits. Existing deterministic UI checks are Node programs invoked
directly, for example:

```sh
node --check internal/admin/admin.js
node internal/admin/ui_regression_test.js
node internal/account/dashboard_ui_test.js
node internal/recovery/pages_ui_test.js
```

The focused Go checks should be selected from the changed packages after all
workers finish. The first pass is expected to include:

```sh
go test ./internal/ui ./internal/admin ./internal/account ./internal/login ./internal/device ./internal/recovery ./internal/branding ./internal/i18n ./internal/rbac ./cmd/goauthy
```

The runner supplies the existing `test/e2e/browser` suite with isolated
`GOAUTHY_E2E_*` settings, fresh standalone storage, local SMTP, and synthetic
accounts. Chromium tests use fresh profiles. Tests named `AcrossPods` point
to the same local server here and provide no replication or HA evidence.

## Required synthetic browser coverage

Template and synthetic page checks complement the real-server gates. Their
coverage targets include:

- admin branding and an admin page under a nested issuer prefix;
- login and account pages in English and Korean;
- device verification and recovery pages in English and Korean;
- form actions, hidden security fields, local asset URLs, and custom brand
  stylesheet ordering;
- response CSPs with no new `unsafe-inline`, `unsafe-eval`, CDN, or external
  font dependency.

The fixtures use Go HTTP/template tooling and the existing `chromedp`
dependency. Chrome is available as an installed macOS app; its binary is not
on `PATH`.

## Current status

Toolchain checked on 2026-10-14: Go 1.27.2, Node 26.5.0, npm 11.17.0, Docker,
Kind, and kubectl are installed. Google Chrome is installed at
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` and reports
version 155.0.8059.40, although Chrome, Chromium, and Playwright are not on
`PATH`. CUA exposes two existing Chrome browser surfaces.

The shared UI package compiles with:

```sh
go test -run '^$' ./internal/ui
```

That command passed while the migration workers were still editing. The
repository-native asset and template tests are now present, including nested
issuer routing, escaping, HTTP method and cache behavior, but they do not yet
constitute the complete browser evidence by itself. The existing
`internal/ui/brand_browser_test.go` is the shared chromedp fixture and passed
under installed Chrome with strict CSP, light/dark brand colors, destructive
states, and issuer-local assets. It does not emit a screenshot artifact.

Page completeness tests cover the migrated admin, account, login, device, and
recovery templates. The final broad command passed with exit 0:

```sh
go test ./internal/ui ./internal/login ./internal/device ./internal/recovery ./internal/branding ./internal/i18n ./internal/rbac ./cmd/goauthy
```

Reported timings are login 251.229s, device cached, recovery 208.835s,
branding cached, i18n 2.234s, RBAC 146.249s, and `cmd/goauthy` 364.684s.
The admin/account full suite and all 20 JavaScript UI suites also passed, and
the focused logout final-delta checks passed.

Pascal's actual-page fixture `internal/admin/ely_browser_test.go` passed in
Chrome in 4.37s. Korean admin rendering was checked at 1440px and 375px with
no overflow; controls, menu, preview, and local assets completed successfully.
The saved artifacts are:

- `/Users/cypark/.codex/task-state/goauthy-ely-frontend/admin-visual/admin-branding-ko-1440.png`
- `/Users/cypark/.codex/task-state/goauthy-ely-frontend/admin-visual/admin-branding-ko-375.png`

The parent visually inspected both screenshots and found them good. That
page-rendering fixture does not exercise authentication or persisted mutations.
Separate disposable real-server runs do exercise browser login/logout,
admin CRUD, account edits/password changes, brand save/reload, logo upload and
deletion, Demo A/B SSO, device approval, and recovery through local SMTP.

Those runs have passing results for **22 distinct gates** on product commit
`c93b0f3`: the original 18, virtual passkey management, SaaS provider catalog,
provider registration, and the separately corrected HTTPS OAuth2 boundary.
This is cumulative evidence across runs, not a single unified execution:
the original 18, four additions, and a targeted rerun of the strengthened
theme gate. Arendt's final `TestThemeLoginUI` passed in 7.32 seconds, preserving
the exact-six stylesheet, ordering, loaded-sheet, response/CSP, and computed
brand-color assertions. The rerun replaces the earlier theme evidence and
does not increase the distinct-gate count above 22.

The theme timeout was a harness selector issue: `BySearch` also matched
selector text inside a hidden passkey script. Using `ByQuery` for the actual
username input resolved it without weakening assertions or changing product
behavior.

The initial HTTP boundary failure (`503` instead of `401`) reflected the
server's deliberate HTTPS prerequisite. The local TLS rerun passed without
changing that production requirement. Provider management and boundary checks
do not establish external provider OAuth consent or successful external
account connection. Passkey evidence uses a Chromium virtual authenticator,
not physical hardware. HA, production deployment, and exhaustive viewport or
localization coverage remain excluded. Swagger/API docs and email HTML are
outside this frontend migration; local Demo A/B behavior was nevertheless
tested as an integration consumer.

No live IED or production check is part of this verification record.
