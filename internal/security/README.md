# Security Headers & Middleware (`internal/security`)

## Overview
Provides HTTP security header middleware (following OWASP/NIST guidelines), CORS middleware, Fetch Metadata / Origin-based CSRF protection middleware, and header text validation for upstream login metadata.

## Interface
- `[headers.go:Config]` — Configuration struct for HTTP security headers (`HSTS`, `ContentSecurityPolicy`, `XFrameOptions`, `XContentTypeOptions`, `ReferrerPolicy`, `PermissionsPolicy`, `CrossOriginOpenerPolicy`, `CrossOriginResourcePolicy`, `CrossOriginEmbedderPolicy`, `XPermittedCrossDomainPolicies`, `CacheControl`, `DisableCSPReportOnly`).
- `[headers.go:DefaultConfig]` — Returns OWASP-recommended default `Config`.
- `[headers.go:APIConfig]` — Returns `Config` tailored for API endpoints (`no-store` cache, `no-referrer`).
- `[headers.go:StaticConfig]` — Returns `Config` tailored for immutable static assets (`SAMEORIGIN`, 1-year `Cache-Control`).
- `[headers.go:Middleware]` — Wraps an `http.Handler` to apply non-empty security headers from `Config`.
- `[headers.go:APIMiddleware]` — Convenience wrapper returning `Middleware(APIConfig())`.
- `[headers.go:CORSMiddleware]` — Configures CORS response headers for `allowedOrigins` and handles `OPTIONS` preflight requests with `204 No Content`.
- `[headers.go:CSRFProtectionMiddleware]` — Blocks non-safe methods (`GET`/`HEAD`/`OPTIONS` exempt) when `Sec-Fetch-Site` is `cross-site` or `Origin` host mismatches request host.
- `[header_text.go:ValidHeaderText]` — Reports whether `value` is non-empty and contains only visible ASCII (`32..126`) or horizontal tab (`\t`).

## Invariants
- `[headers.go:Middleware]` only sets `Strict-Transport-Security` when `r.TLS != nil` or `X-Forwarded-Proto == "https"`.
- `[headers.go:CORSMiddleware]` falls back to `Access-Control-Allow-Origin: *` when `allowedOrigins` is empty and an `Origin` header is present.
- `[headers.go:CSRFProtectionMiddleware]` permits requests lacking both `Origin` and `Referer` headers (unless `Sec-Fetch-Site == "cross-site"`).

## Side Effects
- Mutates HTTP response headers on `http.ResponseWriter` and may short-circuit requests with `204 No Content` (CORS preflight) or `403 Forbidden` (CSRF mismatch).

## Verification
- Run: `go test ./internal/security`
