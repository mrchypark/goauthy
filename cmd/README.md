# cmd

## Overview
Executable entrypoints for GoAuthy: the primary identity provider server, operational/cryptographic CLI utilities, local relying-party demo, and deterministic test/E2E fixtures.

## Subdirectories & Boundaries
- `e2e-saas-isolation-fixture`: [README.md](./e2e-saas-isolation-fixture/README.md) - Bounded local HTTPS SaaS provider fixture for `#113` topology measurement.
- `goauthy`: [README.md](./goauthy/README.md) - Primary GoAuthy identity provider server binary and `config` subcommands.
- `goauthy-backchannel-sink`: [README.md](./goauthy-backchannel-sink/README.md) - Test-only OIDC Back-Channel Logout RP sink with in-memory observations.
- `goauthy-backup`: [README.md](./goauthy-backup/README.md) - Offline `age`-encrypted Rhiza backup/restore and Ed25519-signed catalog CLI.
- `goauthy-bootstrap-secrets`: [README.md](./goauthy-bootstrap-secrets/README.md) - CLI to decrypt or purge generated-secret bootstrap artifacts.
- `goauthy-checkpoint-fault`: [README.md](./goauthy-checkpoint-fault/README.md) - Test-only S3/VersityGW proxy that stalls checkpoint downloads for Kind DR tests.
- `goauthy-cimd-fixture`: [README.md](./goauthy-cimd-fixture/README.md) - Local HTTPS Client ID Metadata Document (CIMD) fixture and loopback admin API.
- `goauthy-demo`: [README.md](./goauthy-demo/README.md) - Local OIDC relying party demo for multi-app SSO and login verification.
- `goauthy-password`: [README.md](./goauthy-password/README.md) - Stdin-to-stdout Argon2id PHC password hashing CLI.
- `goauthy-password-calibrate`: [README.md](./goauthy-password-calibrate/README.md) - Bounded Argon2id parameter calibration CLI.
- `goauthy-rhiza-init`: [README.md](./goauthy-rhiza-init/README.md) - Pre-start Rhiza Local storage recovery binary.
- `goauthy-saas-oauth-fixture`: [README.md](./goauthy-saas-oauth-fixture/README.md) - Test-only HTTPS OAuth 2.0 SaaS provider and synthetic model endpoint fixture.
- `goauthy-scim-fixture`: [README.md](./goauthy-scim-fixture/README.md) - Test-only SCIM 2.0 user/group provisioning provider and loopback admin API.
- `goauthy-smtp-sink`: [README.md](./goauthy-smtp-sink/README.md) - Local-kind-only unauthenticated SMTP mailbox and HTTP inspection sink.
- `goauthy-upstream-fixture`: [README.md](./goauthy-upstream-fixture/README.md) - Test-only HTTPS upstream OIDC and GitHub-style OAuth provider fixture.
