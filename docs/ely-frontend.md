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

The repository has no frontend package manifest, Playwright configuration, or
browser fixture command. Existing deterministic UI checks are Node programs
invoked directly, for example:

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

The existing `test/e2e/browser` package is an opt-in deployed-fixture suite.
Its Chromium tests require `GOAUTHY_E2E_*` fixture settings and a local
Chromium executable, so it is not a substitute for the requested local
synthetic browser fixture.

## Required synthetic browser coverage

Before this migration is called verified, a repository-native Go fixture or
test must render and inspect, without credentials or deployment:

- admin branding and an admin page under a nested issuer prefix;
- login and account pages in English and Korean;
- device verification and recovery pages in English and Korean;
- form actions, hidden security fields, local asset URLs, and custom brand
  stylesheet ordering;
- response CSPs with no new `unsafe-inline`, `unsafe-eval`, CDN, or external
  font dependency.

The fixture should use the existing Go HTTP/template test tooling and, if real
browser pixels are required, the already-declared `chromedp` dependency. It
must not add a JS helper runtime. Chrome is available as an installed macOS app;
the binary is not on `PATH`.

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

The parent visually inspected both screenshots and found them good. Real
authentication, save mutations, and upload mutations remain excluded from the
synthetic fixture. Logout confirmation and SaaS OAuth2 completion are separate
worker scope; Swagger/API docs, email HTML, and demo consumers remain outside
the browser frontend migration. All other reported focused and broad checks
passed.

No live IED or production check is part of this verification record.
