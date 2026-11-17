# loginpolicy

## Overview
`loginpolicy` implements replicated brute-force protection, distributed credential-stuffing detection, system-wide lockdown enforcement/admin APIs, and trusted-proxy client IP extraction backed by Rhiza.

## Interface
- Constants and errors: `DefaultSuccessFloor`, `DefaultAttemptWindow`, `DefaultAttemptLimit`, `PasswordResetAttemptWindow`, `PasswordResetAttemptLimit`, `OpenRegistrationAttemptWindow`, `OpenRegistrationAttemptLimit`, and `ErrInvalid` in [policy.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L24-L41); `StuffingWindow`, `StuffingThreshold`, `AccountLockDuration`, and `StuffingEntryTTL` in [credential_stuffing.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/credential_stuffing.go#L22-L36).
- Trusted-proxy IP resolution: `PeerIP`, `ParseTrustedProxyCIDRs`, and `PeerIPFromRequest` in [policy.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L62-L116).
- Per-IP brute-force and rate limiting: `Store`, `Status`, `NewStore`, `NewStoreWithBlacklist`, `Store.Allow`, `Store.AllowPasswordReset`, `Store.AllowOpenRegistration`, `Store.Check`, `Store.Failure`, `Store.Success`, and `Delay` in [policy.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L43-L545).
- Credential stuffing: `AccountStatus`, `Store.RecordAccountFailure`, `Store.CheckAccountLock`, `Store.ClearAccountLock`, `Store.CleanupStuffingEntries`, and `AccountStuffingDigest` in [credential_stuffing.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/credential_stuffing.go#L39-L233).
- System lockdown: `LockdownStore`, `NewLockdownStore`, `LockdownStore.SetLockdown`, `LockdownStore.IsLockedDown`, `LockdownStore.ClearExpiredLockdown`, `LockdownStore.IsAdmin`, and `LockdownStore.IsAdminByUsername` in [lockdown.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/lockdown.go#L15-L160); `LockdownHandler`, `NewLockdownHandler`, and `LockdownHandler.ServeHTTP` in [lockdown_handler.go](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/lockdown_handler.go#L13-L34).

## Invariants
- `PeerIPFromRequest` trusts `Forwarded` or `X-Forwarded-For` only when the direct TCP peer is inside `trustedProxies`, and fails closed if both headers are present or malformed ([policy.go:PeerIPFromRequest](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L89-L116)).
- `Store.Success` only updates the global `login_timing` mean and never clears per-IP failure state, preventing an attacker with one valid credential from resetting rate limits against other accounts ([policy.go:Success](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L496-L519)).
- `Store.Failure` atomically increments `login_ip_failures`, emits `eventlog.InvalidLogin`, and (when `blacklist` is configured) prunes/upserts `ip_blacklist_entries` and emits `eventlog.IPBlacklisted` in a single Rhiza transaction ([policy.go:Failure](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/policy.go#L376-L476)).
- `RecordAccountFailure` hashes account subjects (`AccountStuffingDigest`) and locks the account for `AccountLockDuration` once `StuffingThreshold` (5) distinct IPs fail within `StuffingWindow` (10m) ([credential_stuffing.go:RecordAccountFailure](file:///Users/cypark/Documents/project/goauthy/internal/loginpolicy/credential_stuffing.go#L57-L137)).

## Side Effects
- Executes linearizable queries and replicated mutations on `oauth_rate_limits`, `login_ip_failures`, `login_timing`, `login_account_ip_failures`, `login_account_locks`, `system_lockdown`, `event_log`, and (optionally) `ip_blacklist_entries`.
- `LockdownHandler` serves `GET`/`POST`/`DELETE` lockdown management endpoints for browser admins.

## Verification
- Run: `go test ./internal/loginpolicy`
