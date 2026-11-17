# credential

## Overview
`internal/credential` implements Argon2id password hashing/verification with bounded concurrency and memory admission control, PHC string validation, password strength/policy enforcement, and common-password checks.

## Interface
- `[password.go:ErrInvalidCredential]`, `[password.go:ErrWorkLimit]`: Password hashing/verification and work-limit error sentinels.
- `[password.go:Policy]`, `[password.go:DefaultPolicy]`, `[password.go:Hasher]`, `[password.go:NewHasher]`, `[password.go:Hasher.Hash]`, `[password.go:Hasher.VerifyOrDummy]`, `[password.go:Hasher.ValidateCurrentPHC]`: Configurable Argon2id hasher with slot and weighted memory gates.
- `[password.go:Hash]`, `[password.go:Verify]`, `[password.go:ValidateCurrentPHC]`, `[password.go:ValidatePHC]`, `[password.go:VerifyOrDummy]`, `[password.go:VerifyOrDummyContext]`: Package-level helpers using the default OWASP Argon2id baseline hasher.
- `[policy.go:PasswordPolicy]`, `[policy.go:DefaultPasswordPolicy]`, `[policy.go:ValidatePasswordStrength]`, `[policy.go:PasswordPolicy.PasswordMaxLength]`, `[policy.go:HasExcessiveRepeating]`, `[policy.go:HasSequentialChars]`: Password complexity and character-pattern policy checks.
- `[rules.go:Rules]`, `[rules.go:DefaultRules]`, `[rules.go:Rules.Validate]`, `[rules.go:Rules.ValidatePassword]`, `[rules.go:Rules.ValidatePasswordWithDetails]`, `[rules.go:MaskPassword]`: Configurable password rule validation and log-safe masking.
- `[common.go:IsCommonPassword]`, `[common.go:AddCommonPassword]`: Common-password blocklist lookup and extension.

## Invariants
- Bounded Argon2id work & memory: `[password.go:DefaultPolicy]` uses 19 MiB, 2 iterations, 1 lane, `MaxConcurrency: 4`, `WaitTimeout: 250ms`. `[password.go:Hasher]` gates both concurrency slots and optional `MemoryBudgetKiB` via a weighted semaphore, returning `ErrWorkLimit` on timeout.
- Constant-time & dummy verification: `[password.go:Hasher.VerifyOrDummy]` executes an Argon2id derivation even when the stored PHC is missing/malformed and compares digests with `subtle.ConstantTimeCompare` to mitigate timing/user-enumeration side channels.
- Hard length & cost bounds: `maxPasswordBytes = 1024`, `maxPHCBytes = 512`, `maxMemoryKiB = 128 * 1024`.

## Side Effects
- Acquires in-memory concurrency/memory semaphore permits during Argon2id operations.
- Mutates the in-memory common-password set if `[common.go:AddCommonPassword]` is called.

## Verification
- Run: `go test ./internal/credential`
