# Shared UI Templates & Assets (`internal/ui`)

## Overview
Integrates `github.com/mrchypark/ely-htmx` embedded UI templates and CSS/font assets with GoAuthy's issuer-prefixed asset path and custom brand stylesheet (`brand.css`).

## Interface
- `[ui.go:AssetPath]` — Constant base path `"/auth/v1/ui/"` for shared UI assets.
- `[ui.go:NewTemplates]` — Loads Ely templates and defines the `goauthy-head` template block along with `uiStylesheets` and `uiAssetBase` template functions.
- `[ui.go:BindAssets]` — Registers `GET /auth/v1/ui/<name>` handlers on `mux` for `app.css`, `ely-controls.css`, `ely-patterns.css`, `brand.css`, and font files (`geist.woff2`, `geist-mono.woff2`, `pretendard.woff2`).

## Invariants
- `[ui.go:assetBase]` rejects issuer prefixes starting with `//`, non-clean paths, or paths containing `\`, `?`, `#`, `%`, `\r`, `\n`, or `\t`.
- `[ui.go:BindAssets]` rewrites `/assets/` references inside CSS files to relative paths so fonts resolve within the issuer-prefixed namespace, and serves assets with `ETag`, `Cache-Control: public, no-cache`, and `X-Content-Type-Options: nosniff`.

## Side Effects
- Registers HTTP routes on the provided `*http.ServeMux` and embeds `brand.css` at compile time.

## Verification
- Run: `go test ./internal/ui`
