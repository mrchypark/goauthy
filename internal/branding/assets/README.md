# branding/assets

## Overview
`internal/branding/assets` holds static branding assets (CSS, SVG icon, fonts, font licenses) and the client-side localization/form-submission script (`locale.js`) embedded by `internal/branding` via `//go:embed assets/*`.

## Interface
- `[locale.js:GoAuthyI18n]`: Global browser object exposing `{language, messages, t, translate, setBusy}` for English/Korean UI translation (`data-i18n`, `data-i18n-label`, `data-brand-en`/`data-brand-ko`) and login form submission/language-selector state management.
- Static assets: `brand.css`, `gateway.svg`, `manrope.ttf`, `pretendard.woff2`, `Manrope-OFL.txt`, `Pretendard-LICENSE.txt`.

## Invariants
- Embedded whitelist: Only files explicitly mapped in `internal/branding`'s `[../assets.go:serveBrandAsset]` are served over HTTP.
- Double-submit guard: `[locale.js]` prevents duplicate submissions on `#login-form` and disables `[data-language-select]` controls while busy.

## Side Effects
- Mutates DOM text/attributes (`textContent`, `aria-label`, button `disabled` state) and attaches `DOMContentLoaded`/`submit` listeners in the browser.

## Verification
- Run: `go test ./internal/branding`
