# admin

## Overview
`internal/admin` serves the browser-only administrator landing page (`Index`) and the embedded single-page administrator dashboard UI (`UI`) with its HTML, CSS, and modular JavaScript assets (`admin.html`, `admin.css`, `admin.js`, `elysdui.js`, `locale.js`, `module_locale.js`, and feature modules).

## Interface
- `[index.go:BrowserAdministrator]`: Callback type `func(http.ResponseWriter, *http.Request, bool) bool` supplied by the caller to enforce same-origin, peer-bound browser-admin authentication.
- `[index.go:Route]`: Concrete, already-mounted administrator GET route (`Label`, `Path`).
- `[index.go:Handler]`, `[index.go:NewIndexHandler]`, `[index.go:SetIssuer]`, `[index.go:Index]`: Serves `/auth/v1/admin` and redirects authenticated admins to `/auth/v1/admin/dashboard`, or renders the access-denied page for HTML clients.
- `[ui.go:CSRFTokenProvider]`: Callback providing the session-bound CSRF token at `/auth/v1/admin/csrf`.
- `[ui.go:EmailTemplateInfo]`, `[ui.go:EmailTemplateProvider]`: Interface and DTO for rendering email template previews in the admin UI.
- `[ui.go:UI]`, `[ui.go:NewUI]`, `[ui.go:SetIssuer]`, `[ui.go:SetCSRFTokenProvider]`, `[ui.go:SetTemplateProvider]`, `[ui.go:SetBrandResolver]`, `[ui.go:ServeHTTP]`: Serves `/auth/v1/admin/dashboard`, `/auth/v1/admin/csrf`, `/auth/v1/admin/email-templates`, and embedded static JS/CSS assets.

## Invariants
- Read-only UI surface: Both `[index.go:Handler.Index]` and `[ui.go:UI.ServeHTTP]` accept only `GET` and invoke `BrowserAdministrator` with `mutation=false`.
- No API-key/bearer fallback: Requests carrying an `Authorization` header are unconditionally rejected with `401 Unauthorized`.
- Validated routes & issuer prefixing: `[index.go:NewIndexHandler]` rejects duplicate paths, control characters, absolute URLs, queries, fragments, or paths outside `/auth/v1/`. `[ui.go:UI.SetIssuer]` rewrites local `/auth/v1/`, `/account`, and `/oidc/` paths in embedded assets to respect the configured issuer base path.
- Strict response security headers: Sets `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a restrictive `Content-Security-Policy`.

## Side Effects
- Reads embedded template and asset files (`indexFS`, `uiFS`), invokes optional `brand` and `templates` providers, and writes HTTP responses/redirects.

## Verification
- Run: `go test ./internal/admin`
