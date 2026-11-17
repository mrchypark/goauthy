# device

## Overview
`internal/device` implements RFC 8628 OAuth 2.0 Device Authorization Grant (`/oidc/device` and `/oidc/device/verify`), including client/resource bindings, rate-limited device-code creation and polling, browser verification/consent UI, and user device-session listing/revocation backed by `*rhiza.DB`.

## Interface
- `[binding.go:ClientBinding]`, `[binding.go:SetResource]`, `[binding.go:WithClientBinding]`, `[binding.go:SetManagedClient]`, `[binding.go:ClientBindingFromRequest]`: Request-scoped client/resource/managed-client binding helpers.
- `[store.go:ErrInvalid]`, `[store.go:ErrInvalidTarget]`, `[store.go:Grant]`, `[store.go:PollResult]`, `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:NormalizeUserCode]`: Device grant store and user-code normalization.
- `[store.go:Store.Create]`, `[store.go:Store.CreateWithBinding]`, `[store.go:Store.Approve]`, `[store.go:Store.ApproveWithMFA]`, `[store.go:Store.ApproveWithMFAAndSessionGuard]`, `[store.go:Store.Deny]`, `[store.go:Store.DenyWithSessionGuard]`, `[store.go:Store.Allow]`, `[store.go:Store.Poll]`, `[store.go:Store.Complete]`: Device grant lifecycle, rate limiting, and atomic session-guarded approval/denial.
- `[review.go:Review]`, `[review.go:Store.Review]`: Loads a pending device grant for user consent review without approving it.
- `[user_sessions.go:UserSession]`, `[user_sessions.go:Store.ListUserSessions]`, `[user_sessions.go:Store.RevokeUserSession]`: Authority-guarded listing and revocation of a user's device sessions.
- `[http.go:ClientAuthorizer]`, `[http.go:ErrClientAuthentication]`, `[http.go:AuthenticatedSubject]`, `[http.go:Subject]`, `[http.go:Limits]`, `[http.go:Handler]`, `[http.go:Handler.SetReauthentication]`, `[http.go:NewHandler]`, `[http.go:NewHandlerWithLimits]`, `[http.go:Handler.ServeHTTP]`: HTTP handler for device authorization and HTML verification pages.

## Invariants
- Session-guarded consent: `[store.go:Store.ApproveWithMFAAndSessionGuard]` and `[store.go:Store.DenyWithSessionGuard]` evaluate the caller's `SessionGuard` inside the persistence mutation so concurrent browser session revocation cannot race the approval/denial.
- Sign-in != approval: Signing in only allows reviewing the `user_code`; explicit `POST` with CSRF cookie/token validation (`__Host-goauthy_device_csrf` or `goauthy_device_csrf`) is required to approve or deny.
- Rate limits & bounded forms: Default limits are 20 creations/min and 20 verifications/min (`defaultRateWindow = time.Minute`); form bodies are capped at `deviceFormLimit = 8 << 10`.

## Side Effects
- Reads and mutates device grant, rate-limit, and user-session tables in `*rhiza.DB`.
- Sets/validates CSRF cookies and renders localized (English/Korean) HTML verification pages.

## Verification
- Run: `go test ./internal/device`
