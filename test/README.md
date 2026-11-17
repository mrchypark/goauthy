# test

## Overview
Integration, end-to-end (E2E), chaos, browser, and compatibility test suites for GoAuthy.

## Subdirectories & Boundaries
- `compat`: [./compat/README.md](./compat/README.md) - Compatibility reference harnesses (`rauthy-cron`, `go-quartz`) for backup scheduling semantics.
- `e2e`: Go E2E test suites (including `browser/`, `chaos/`, `favicon/`, `fedcm/`, `jwks/`, `passkey/`, `software_statement_ha/`, `webid_ha/`, and `fixtures/`).
- `e2e_issuer_path`: E2E tests for non-root issuer path routing (`issuer_path_test.go`).
- `e2e_master_key`: E2E tests for master-key rotation and retirement (`master_key_retirement_test.go`).
- `e2e_tls`: E2E tests for TLS termination and certificate handling (`tls_test.go`).
- `e2e_upstream`: E2E tests for upstream OIDC/OAuth provider federation, audience, claims, and forced MFA (`audience_test.go`, `claims_test.go`, `forced_mfa_test.go`, `managed_provider_test.go`, `upstream_test.go`).
