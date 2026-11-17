# ipblacklist

## Overview
`ipblacklist` provides a deterministic, replicated IP/CIDR blacklist backed by Rhiza, an HTTP enforcement middleware, an authenticated admin API (`/auth/v1/blacklist`), and SQL statement builders for automatic failed-login blacklisting.

## Interface
- Store and schema: `ErrInvalid`, `ErrNotFound`, `ErrAlreadyExists`, `ErrTooMany`, `MaxNoteLength`, `DefaultMaxEntries`, `Entry`, `CheckResult`, `Store`, `NewStore`, `CanonicalPrefix`, `Store.Add`, `Store.Update`, `Store.Delete`, `Store.Check`, `Store.List`, `Store.Get`, `Store.Count`, and `SchemaStatements` in [store.go](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/store.go#L19-L513).
- Automatic login-policy integration: `Store.AutomaticFailureStatement`, `Store.AutomaticExpiryPruneStatement`, and `AutomaticFailurePrefix` in [auto.go](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/auto.go#L16-L81).
- HTTP enforcement and admin surface: `Resolver` and `Middleware` in [http.go](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/http.go#L10-L44); `AdminHandler` and `NewAdminHandler` in [admin.go](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/admin.go#L22-L82).

## Invariants
- All prefixes are canonicalized and masked via `CanonicalPrefix` (with IPv4-mapped IPv6 addresses normalized to IPv4); `Store.Check` returns the longest matching non-expired prefix, treating `expires_at_unix_ms <= now` as expired ([store.go:CanonicalPrefix](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/store.go#L60-L76), [store.go:Check](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/store.go#L310-L392)).
- `Middleware` fails closed with a uniform `403 Forbidden` when `Store`, `Resolver`, IP resolution, or storage lookup fails ([http.go:Middleware](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/http.go#L16-L44)).
- `AutomaticFailureStatement` and `AutomaticExpiryPruneStatement` never derive login-policy keys themselves and preserve permanent manual entries (`expires_at_unix_ms IS NULL`) ([auto.go:AutomaticFailureStatement](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/auto.go#L16-L66)).
- `AdminHandler` requires either `API-Key` authorization for `"Blacklist"` or same-site browser admin authorization, enforces strict JSON decoding, and uses `X-Request-ID` idempotency keys for explicit retries while generating fresh IDs otherwise ([admin.go:ServeHTTP](file:///Users/cypark/Documents/project/goauthy/internal/ipblacklist/admin.go#L43-L332)).

## Side Effects
- Executes linearizable queries and replicated mutations on `ip_blacklist_entries` in Rhiza.
- `Middleware` blocks matched or errored HTTP requests with `403 Forbidden`.

## Verification
- Run: `go test ./internal/ipblacklist`
