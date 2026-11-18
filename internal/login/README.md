# login

## Overview
`login` implements the browser-facing authentication UI and HTTP boundary for OAuth/OIDC authorization, account dashboard login, device-code login, connection handoff login, FedCM landing, passkey/WebAuthn sign-in, email OTP step-up, required profile continuation, and external/upstream provider authentication.

## Interface
- Errors and types: `ErrExternalAuthentication`, `ErrAccountLocked`, `UpstreamProvider` in [handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go#L139-L153); `LoginBranding` in [branding.go](file:///Users/cypark/Documents/project/goauthy/internal/login/branding.go#L9-L13).
- Handler constructor: `New` in [handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go).
- Configuration hooks: `Handler.SetApprovalForceMFA`, `Handler.SetBrowserIDPolicy`, `Handler.SetFedCMForceMFA`, `Handler.SetLockdownStore`, `Handler.SetLoginBrandingResolver`, `Handler.SetLoginLocationObserver`, `Handler.SetMetrics`, `Handler.SetOnPasswordExpired`, `Handler.SetOTPHandler`, `Handler.SetPasskeyService`, `Handler.SetPolicy`, `Handler.SetRecoveryPages`, `Handler.SetThemeURLResolver`, `Handler.SetTrustedProxies`, `Handler.SetUpstreamProviderCatalog`, `Handler.SetUserValuesPolicy`, and `Handler.EnableFedCM` in [handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go) and [branding.go](file:///Users/cypark/Documents/project/goauthy/internal/login/branding.go#L15-L17).
- HTTP endpoints and authentication flows: `Handler.Authorize`, `Handler.Login`, `Handler.FedCMLanding`, `Handler.Profile`, `Handler.OTPVerify`, `Handler.WebAuthnStart`, `Handler.WebAuthnFinish` in [handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go) and [profile_continuation.go](file:///Users/cypark/Documents/project/goauthy/internal/login/profile_continuation.go); `Handler.AccountLoginHandler` in [account_login.go](file:///Users/cypark/Documents/project/goauthy/internal/login/account_login.go#L9-L26); `Handler.DeviceLoginHandler` and `Handler.DeviceReviewReauthentication` in [device.go](file:///Users/cypark/Documents/project/goauthy/internal/login/device.go#L23-L36); `Handler.ConnectionHandoffLoginHandler` in [continuation.go](file:///Users/cypark/Documents/project/goauthy/internal/login/continuation.go); `Handler.PrepareExternalAuthentication`, `Handler.RequireFreshExternalAuthentication`, `Handler.CurrentExternalInitSession`, `Handler.CompleteExternalAuthentication`, `Handler.CompleteUpstreamAuthentication` in [handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go); `UIStylesheet` in [ui.go](file:///Users/cypark/Documents/project/goauthy/internal/login/ui.go#L19-L28).

## Invariants
- All browser state is bound to `browser.Store` sessions and single-use `AuthorizationInteraction` tokens (`interactionLifetime = 5m`, `sessionLifetime = 4h`) with CSRF tokens and `Sec-Fetch-Site` / origin checks ([handler.go](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go#L42-L50), [account_login.go:accountLoginPost](file:///Users/cypark/Documents/project/goauthy/internal/login/account_login.go#L62-L68)).
- CSP `form-action` policies (`authorizationFormCSP`, `authorizationFormCSPWithNonce`) only include an external redirect origin after OAuth redirect-URI registration validation and IDNA ASCII normalization, never from raw query strings ([form_policy.go:authorizationFormCSP](file:///Users/cypark/Documents/project/goauthy/internal/login/form_policy.go#L14-L51)).
- `DeviceLoginHandler` never looks up the device code, preventing code-existence disclosure at the login boundary ([device.go:DeviceLoginHandler](file:///Users/cypark/Documents/project/goauthy/internal/login/device.go#L21-L36)).
- `ErrExternalAuthentication` hides which upstream binding check failed ([handler.go:ErrExternalAuthentication](file:///Users/cypark/Documents/project/goauthy/internal/login/handler.go#L139-L144)).

## Side Effects
- Reads and mutates browser sessions, interactions, identity credentials/profiles, login-policy counters, and OAuth authorization completions in Rhiza.
- Sets browser session/FedCM/CSRF cookies, renders localized HTML pages, and emits metrics, traces, and login-location observer callbacks.

## Verification
- Run: `go test ./internal/login`
