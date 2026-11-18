# Account Recovery, Registration & Email OTP (`internal/recovery`)

## Overview
Manages password-reset flows (email reset tokens, PoW-gated requests, enhanced reset tokens), open user registration (password-based; passkey-only registration endpoints currently fail closed pending enrollment-binding support), email OTP login/verification, login-location notifications, login-revoke links, and a durable encrypted email outbox over SMTP.

## Interface
- `[service.go:Service]`, `[service.go:NewService]`, `[service.go:ServiceOption]`, `[service.go:WithOpenRegistration]` — Core recovery and registration service (`RequestReset`, `GetReset`, `PutReset`, `ProofOfWork`, `RegisterOpen`, `RegisterPasskeyStart` [fail-closed], `RegisterPasskeyFinish` [fail-closed], `Page`, `PageScript`, `BindEmail`, `IssueForSubject`, `InvalidateAllResetTokens`, `CleanupExpiredTokens`, `CreateUser`, `CreatePasskeyOnlyUser`, `NotifyUserUpdate`, `SetCaptchaVerifier`, `SetPasskeyService`).
- `[service.go:SchemaStatements]` — Returns Rhiza DDL statements for `identity_recovery_emails`, OTP tables, and email outbox tables.
- `[security_enhanced.go]`: `DefaultEnhancedConfig`, `EnhancedResetConfig`, `EnhancedResetToken`, `Service.IssueEnhancedResetToken`, `Service.ValidateEnhancedResetToken`, `Service.ConsumeEnhancedResetToken`.
- `[otp.go]` & `[otp_http.go]`: `OTPService`, `NewOTPService`, `OTPHandler`, `NewOTPHandler`, `OTPInteractionStore`, `NewOTPInteractionStore`.
- `[pow.go]`: `ProofOfWork`, `NewProofOfWork`, `MaxProofTTL`, `ErrInvalidProof`, `ErrProofIssueLimited`.
- `[email_outbox.go]`: `EmailOutbox`, `NewEmailOutbox`, `EmailOutboxOption`, `WithEnvelopeKeyring`, `OutboxKeyring`.
- `[smtp.go]` & `[sender.go]`: `SMTPConfig`, `SMTPSender`, `NewSMTPSender`, `SMTPSendFunc`, `Sender`, `Message`.
- `[templates.go]`, `[registration.go]`, `[login_revoke_http.go]`: `EmailTemplates`, `LoadEmailTemplates`, `EmailTemplate`, `RegistrationConfig`, `RegistrationRequest`, `RedirectValidator`, `ExactRedirectURIs`, `NewLoginRevokeHandler`, `EmailChangeMessage`, `LoginLocationMessage`, `UserValues`.
- Sentinels: `ErrInvalidEmail`, `ErrEmailBound`, `ErrOTPExpired`, `ErrRegistrationDisabled`, `ErrResetTokenExpired`, `ErrInvalidProof`, `ErrProofIssueLimited`.

## Invariants
- `[service.go:SchemaStatements]` enforces a 1:1 unique mapping between `subject` and lowercase `email` in `identity_recovery_emails`.
- `[http.go:Service.RequestReset]` requires a valid single-use `ProofOfWork` token (`VerifyAndConsume`) and IP rate-limit check (`loginpolicy.Store.AllowPasswordReset`), returning `200 OK` without leaking whether an email exists.
- `[service.go:WithOpenRegistration]` requires an exact-matching contextual redirect URI validator (never prefix-matching).
- `[service.go:Service]` never exposes sender details or reset bearer tokens to callers; `OnError` only receives delivery failures.

## Side Effects
- Reads/writes recovery emails, reset tokens, PoW nonces, OTP challenges, and email outbox jobs in `*rhiza.DB`.
- Sends outbound emails via `Sender` / `SMTPSender` (using `internal/smtptransport`).
- Serves HTML/JS recovery and registration pages and sets `__Host-goauthy_pwd_reset` / `goauthy_pwd_reset` cookies.

## Verification
- Run: `go test ./internal/recovery`
