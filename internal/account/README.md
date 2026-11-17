# account

## Overview
`internal/account` serves authenticated self-service account-management endpoints, the account dashboard UI (HTML/CSS/JS assets embedded via `dashboardFS`), and browser session routing to the user or admin workspace.

## Interface
- `[handler.go:ErrExternalLinkSession]`: Sentinel error returned when an upstream external-link callback lacks an authenticated, peer-bound local browser session.
- `[handler.go:Handler]`, `[handler.go:New]`, `[handler.go:NewWithPasskeys]`: HTTP handler struct and constructors wiring browser sessions, identity store, credential rules, and optional passkey service.
- `[handler.go:PasskeyResponse]`: JSON response payload describing a registered passkey.
- `[handler.go:IssueModificationToken]`, `[handler.go:BeginMFAWebAuthn]`, `[handler.go:FinishMFAWebAuthn]`: MFA/password proof endpoints for sensitive account mutations.
- `[handler.go:ListPasskeys]`, `[handler.go:BeginPasskeyRegistration]`, `[handler.go:FinishPasskeyRegistration]`, `[handler.go:DeletePasskey]`: Passkey lifecycle endpoints.
- `[handler.go:GetPassword]`, `[handler.go:PutSelfPassword]`, `[handler.go:ConvertSelfPasskey]`: Password state inspection, self-service password update, and passkey-only conversion endpoints.
- `[handler.go:ConfigureSelfDelete]`, `[handler.go:ConfigureAdminForceMFA]`, `[handler.go:DeleteUser]`, `[handler.go:SelfDelete]`: Account deletion configuration and handlers.
- `[handler.go:ConfigurePasskeyAdministrators]`, `[handler.go:ConfigureExternalLinks]`, `[handler.go:ConfigureDynamicExternalLinks]`, `[handler.go:StartExternalLink]`, `[handler.go:UnlinkExternal]`, `[handler.go:CurrentExternalLinkSession]`, `[handler.go:LinkExternalWithSession]`: Admin passkey-management hooks and upstream external-provider linking endpoints.
- `[dashboard.go:SetBrandResolver]`, `[dashboard.go:Dashboard]`: Brand resolver configuration and GET handler serving `/account`, `/account/data`, and embedded JS/CSS assets (`dashboard.html`, `dashboard.js`, `dashboard.css`, `locale.js`, `connections.js`, `connection_grants.js`, `devices.js`).
- `[home.go:Home]`: Redirects authenticated browser sessions to `/account` or `/auth/v1/admin/dashboard` (or `/account/login` when unauthenticated or admin MFA is required).

## Invariants
- Browser-only authority: `[dashboard.go:Dashboard]`, `[home.go:Home]`, and mutation handlers reject any request carrying an `Authorization` header (no bearer or API-key fallback).
- Cross-site protection and strict CSP: `[dashboard.go:Dashboard]` enforces `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy`, and rejects cross-site requests.
- Purpose separation for WebAuthn proofs: `[handler.go:BeginMFAWebAuthn]` separates `MfaModToken` from `PasswordNew` so neither proof can cross purposes.
- Bounded inputs: Password payloads are bounded (`maxPasswordLength = 256`, `passwordRequestLimit = 4 << 10`) and cleared from memory after verification (`defer clear(password)`).

## Side Effects
- Reads and mutates browser sessions, identity records, passkey credentials, and upstream external links via injected `browser.Store`, `identity.Store`, `passkey.Service`, and `apikey.Store`.
- Writes HTTP responses, redirects, and security headers.

## Verification
- Run: `go test ./internal/account`
