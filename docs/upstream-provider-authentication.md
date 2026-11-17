# Upstream Provider Authentication Decision Record

> **Superseded historical record (2026-09-12):** This decision record preserves the initial design and status as of 2026-09-12. Subsequent implementation and qualification (see [status.md](status.md) 2026-09-17 and [capabilities.md](capabilities.md)) wired federated identity creation (`internal/identity/federated_create.go`), autolink, admin claim mapping, and ForceMFA, and **Upstream OIDC login**, **GitHub upstream login**, and **Upstream account linking/unlinking** are now **Qualified** in [capabilities.md](capabilities.md).

**Date:** 2026-09-12
**Status:** Historical (2026-09-12: implementation ongoing; superseded by [status.md](status.md) and [capabilities.md](capabilities.md))
**Source:** Parent + ChatGPT Pro consultation ([Pro consult URL](https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46-codex-request/c/6aa541eb-6650-83ee-b34b-90f01a544eb2) -- 2 responses, advisory not executed)

## Existing custom/Google/OIDC upstream

Strict signed OIDC only. Mandatory: valid issuer, audience, nonce, time checks. Failure is terminal with zero UserInfo return. Profile completion is future-only -- requires valid ID token and exact sub match.

## New: explicit API enum/type oauth_userinfo

Additive extension to the existing type system. Source reference: Rauthy upstream "types 4", custom includes autodiscovered OIDC per pinned "frontend/src/lib/admin/providers/ProviderAddNew.svelte:199".

This selects managed-only generic OAuth trusted userinfo identity. Requirements:

- PKCE S256 mandatory
- Provider-specific redirect URI and code binding
- No JWKS validation, no ID token validation
- ID token claims are ignored -- confer nothing
- Bearer "token_type" with nonempty access token required
- Hardened TLS, no redirect, bounded JSON 64 KiB
- Unique string "sub"; no email/id/uid fallback

## DB schema 97 behavior

Schema 97 trigger atomically rejects "into"/"outmode" updates for the same provider ID. New ID requires no binding transfer. Same-mode updates rotate on every write. Old readers seeing the unknown enum fail closed -- must upgrade before enable.

## Roles, MFA, and unimplemented scope (as of 2026-09-12)

At the time of this 2026-09-12 record, roles and MFA were not auto-accepted from profile, and admin MFA, autolink, and onboarding remained unimplemented. Those items were subsequently implemented and qualified (`internal/identity/federated_create.go`, `cmd/goauthy/federated_resolver.go`); see [status.md](status.md) and [capabilities.md](capabilities.md) for current scope.

## Full source/API parity status

Full parity remains OPEN. Intentional stricter OIDC and additional enum additions create explicit conflicts that are tracked, not marked "complete".

## Evidence note

This record reflects the current implementation state. Tests are not all passed. No claims are invented. Evidence in parity.md upstream row is preserved except for the brief doc link added on this date.

