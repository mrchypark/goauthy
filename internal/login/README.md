# login

## Overview
`login` implements the browser-facing authentication UI and HTTP boundary for OAuth/OIDC authorization, account dashboard login, device-code login, connection handoff login, FedCM landing, passkey/WebAuthn sign-in, email OTP step-up, required profile continuation, and external/upstream provider authentication.

## Interface
- Errors and types: `ErrExternalAuthentication`, `ErrAccountLocked`, `UpstreamProvider` in [handler.go](handler.go#L139-L153); `LoginBranding` in [branding.go](branding.go#L9-L13).
- Handler constructor: `New` in [handler.go](handler.go).
- Configuration hooks: `Handler.SetBrowserIDPolicy`, `Handler.SetFedCMForceMFA`, `Handler.SetLockdownStore`, `Handler.SetLoginBrandingResolver`, `Handler.SetLoginLocationObserver`, `Handler.SetMetrics`, `Handler.SetOnPasswordExpired`, `Handler.SetOTPHandler`, `Handler.SetPasskeyService`, `Handler.SetPolicy`, `Handler.SetRecoveryPages`, `Handler.SetThemeURLResolver`, `Handler.SetTrustedProxies`, `Handler.SetUpstreamProviderCatalog`, and `Handler.EnableFedCM` in [handler.go](handler.go) and [branding.go](branding.go#L15-L17); `Handler.SetApprovalForceMFA` in [continuation.go](continuation.go#L39); `Handler.SetUserValuesPolicy` in [profile_continuation.go](profile_continuation.go#L42-L48).
- HTTP endpoints and authentication flows: `Handler.Authorize`, `Handler.Login`, `Handler.FedCMLanding`, `Handler.Profile`, `Handler.OTPVerify`, `Handler.WebAuthnStart`, `Handler.WebAuthnFinish` in [handler.go](handler.go) and [profile_continuation.go](profile_continuation.go); `Handler.AccountLoginHandler` in [account_login.go](account_login.go#L9-L26); `Handler.DeviceLoginHandler` in [device.go](device.go#L23-L36) and `Handler.ConnectionHandoffLoginHandler` in [device.go](device.go#L207-L224); `Handler.DeviceReviewReauthentication` in [continuation.go](continuation.go#L111-L118) and `Handler.RequireFreshExternalAuthentication` in [continuation.go](continuation.go#L161-L175); `Handler.PrepareExternalAuthentication`, `Handler.CurrentExternalInitSession`, `Handler.CompleteExternalAuthentication`, `Handler.CompleteUpstreamAuthentication` in [handler.go](handler.go); `UIStylesheet` in [ui.go](ui.go#L19-L28).

## Invariants
- All browser state is bound to `browser.Store` sessions and single-use `AuthorizationInteraction` tokens (`interactionLifetime = 5m`, `sessionLifetime = 4h`) with CSRF tokens and `Sec-Fetch-Site` / origin checks ([handler.go](handler.go#L42-L50), [account_login.go:accountLoginPost](account_login.go#L62-L68)).
- CSP `form-action` policies (`authorizationFormCSP`, `authorizationFormCSPWithNonce`) only include an external redirect origin after OAuth redirect-URI registration validation and IDNA ASCII normalization, never from raw query strings ([form_policy.go:authorizationFormCSP](form_policy.go#L14-L51)).
- `DeviceLoginHandler` never looks up the device code, preventing code-existence disclosure at the login boundary ([device.go:DeviceLoginHandler](device.go#L21-L36)).
- `ErrExternalAuthentication` hides which upstream binding check failed ([handler.go:ErrExternalAuthentication](handler.go#L139-L144)).

## Side Effects
- Reads and mutates browser sessions, interactions, identity credentials/profiles, login-policy counters, and OAuth authorization completions in Rhiza.
- Sets browser session/FedCM/CSRF cookies, renders localized HTML pages, and emits metrics, traces, and login-location observer callbacks.

## Verification
- Run: `go test ./internal/login`
