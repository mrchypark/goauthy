# Passkey / WebAuthn Service (`internal/passkey`)

## Overview
Owns the WebAuthn registration, login, MFA, and modification-proof ceremony lifecycle, encrypted credential/ceremony persistence via Rhiza, passwordless cookie sealing/verification, and master-key envelope inspection/rewrapping.

## Interface
- `[service.go:Config]` — Configuration for RPID, RPDisplayName, Origins, `ForceUV`, TTLs (`CeremonyTTL`, `MfaCodeTTL`, `RenewTTL`, `SessionIdleTimeout`), `CookieKey` (32 bytes), `PreviousCookieKey`, and `Keyring` (`[service.go:EnvelopeKeyring]`).
- `[service.go:EnvelopeKeyring]` — Interface for sealing/opening/inspecting GAOP master-key envelopes (`SealEnvelope`, `OpenEnvelope`, `PurposeEnvelopeKeyID`, `ActiveMasterKeyID`).
- `[service.go:Service]` & `[service.go:New]` — WebAuthn ceremony and credential service backed by `*rhiza.DB`.
- `[service.go:Credential]` & `[service.go:LoginResult]` — Returned credential metadata and login outcome (`Subject`, `InteractionToken`, `AuthenticationMethod`).
- `[service.go:Service.BeginRegistration]`, `[service.go:Service.FinishRegistration]`, `[service.go:Service.FinishPasskeyRegistration]` — WebAuthn credential registration ceremony.
- `[service.go:Service.BeginLogin]`, `[service.go:Service.BeginMFALogin]`, `[service.go:Service.FinishLogin]` — WebAuthn login and MFA assertion ceremonies.
- `[service.go:Service.BeginModificationProof]`, `[service.go:Service.FinishModificationProof]`, `[service.go:Service.BeginPasswordNewProof]`, `[service.go:Service.ExchangeModificationProof]`, `[service.go:Service.IssueModificationToken]`, `[service.go:Service.IssuePasswordModificationToken]`, `[service.go:Service.ConsumeModificationToken]` — Step-up WebAuthn proof and modification token lifecycle.
- `[service.go:Service.List]`, `[service.go:Service.HasCredentials]`, `[service.go:Service.Delete]`, `[service.go:Service.DeleteForAdministrator]` — Credential listing and deletion.
- `[service.go:Service.PasswordlessCookie]`, `[service.go:Service.PasswordlessCookieTTL]`, `[service.go:PasswordlessCookieTTLForConfig]`, `[service.go:Service.SubjectFromCookie]` — Passwordless cookie issuance, TTL calculation, and verification.
- `[inspect.go:Service.InspectEnvelopeReferences]`, `[inspect.go:EnvelopeReferenceStatus]`, `[inspect.go:EnvelopeReferenceFamily]`, `[inspect.go:ErrUnsafeEnvelopeReferences]` — Read-only linearizable audit of retained passkey/ceremony envelopes for master-key retirement.
- `[rewrap.go:Service.RewrapBatch]`, `[rewrap.go:RewrapBatchResult]` — Bounded cursor-based migration of legacy `CookieKey` ciphertexts and older GAOP envelopes to the active master key.
- `[service.go:ErrInvalid]`, `[service.go:ErrConflict]`, `[service.go:ErrNotFound]` — Domain error sentinels.

## Invariants
- `[json_strict.go:decodeStrictJSON]` rejects duplicate JSON keys, unknown fields, and trailing JSON values when decoding stored `wa.Credential` and ceremony state.
- `[inspect.go:Service.InspectEnvelopeReferences]` fails closed on any malformed, tampered, or unknown-key row without fallback.
- `[rewrap.go:Service.RewrapBatch]` scans and rewraps in bounded batches (`32` rows) across three ordered phases: `credentials`, `ceremonies`, and `mfa-ceremonies`.
- `New` requires non-empty `RPID`, `RPDisplayName`, `Origins`, 32-byte `CookieKey`, non-nil `db`, and non-nil `Keyring`.

## Side Effects
- Reads and writes `identity_webauthn_credentials`, ceremony tables, and passwordless cookie key retention watermarks in `*rhiza.DB` (using `storage.ExecuteEnvelope`).
- Generates cryptographic nonces/challenges via `crypto/rand` and seals/opens AES-GCM / GAOP envelopes.

## Verification
- Run: `go test ./internal/passkey`
