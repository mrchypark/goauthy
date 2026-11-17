# goauthy

## Overview
Primary GoAuthy identity provider server binary (`[main.go:main]`). It wires Rhiza distributed/local SQLite storage, OIDC/OAuth2/CIMD/DCR/FedCM/WebID/Passkey/SCIM/SaaS/upstream-provider subsystems, admin UI/OpenAPI routes, background workers (backup, housekeeping, SCIM, DCR cleanup, account expiry, key rewrap, master-key retirement), and graceful request draining.

## Interface
- CLI subcommands (`[main.go:main]`):
  - Default (no `config` subcommand): Starts the HTTP/HTTPS server (`GOAUTHY_LISTEN_ADDR`, default `:8080`), optional metrics server (`GOAUTHY_METRICS_LISTEN_ADDR`), and background workers `[main.go:run]`.
  - `config check`: Validates `GOAUTHY_*` runtime configuration and exits `[config_runtime.go:runConfigCommand]`.
  - `config dump-effective`: Prints sanitized effective configuration JSON (`[config_runtime.go:effectiveConfig]`) to stdout `[config_runtime.go:runConfigCommand]`.
- Exported symbols in `package main`:
  - `FederatedIdentityResolver` (`[federated_resolver.go:FederatedIdentityResolver]`)
  - `scimRuntime.Step`, `scimRuntime.Wake`, `scimRuntime.Run` (`[scim.go:scimRuntime]`)
- Configuration environment variables (`GOAUTHY_*`):
  - Core server & storage: `GOAUTHY_LISTEN_ADDR`, `GOAUTHY_ISSUER`, `GOAUTHY_TLS_CERT_FILE`, `GOAUTHY_TLS_KEY_FILE`, `GOAUTHY_MASTER_KEY_DIR`, `GOAUTHY_ACTIVE_MASTER_KEY_ID`, `GOAUTHY_RHIZA_PROFILE`, `GOAUTHY_GCS_MUTATION_GATE_ENABLED`, `GOAUTHY_TRUSTED_PROXIES`, `GOAUTHY_METRICS_LISTEN_ADDR`, `GOAUTHY_METRICS_TOKEN_FILE` `[main.go:run]`, `[gcs_mutation_gate.go:configureGCSMutationGate]`.
  - Auth, OIDC/DCR/CIMD/FedCM/Passkey/SMTP/Notifications/SCIM/Backup/User-values: `GOAUTHY_OAUTH_HMAC_SECRET_FILE`, `GOAUTHY_CIMD_ENABLED`, `GOAUTHY_DCR_*`, `GOAUTHY_FEDCM_CONFIG_FILE`, `GOAUTHY_PASSKEY_*`, `GOAUTHY_SMTP_*`, `GOAUTHY_EVENT_NOTIFICATION_*`, `GOAUTHY_SCIM_PROVIDERS_FILE`, `GOAUTHY_SAAS_PROVIDERS_FILE`, `GOAUTHY_UPSTREAM_PROVIDERS_FILE`, `GOAUTHY_BACKUP_*`, `GOAUTHY_SWAGGER_UI_*`, `GOAUTHY_USER_VALUES_*` `[config_runtime.go:loadApplicationConfig]`, `[backup.go:scheduledBackupFromEnv]`, `[openapi.go:swaggerConfigFromEnv]`.

## Invariants
- `startupGate` keeps readiness and all application routes closed until storage readiness, `storage.Migrate`, and master-key runtime admission complete `[main.go:run]`, `[main.go:startupGate]`.
- `requestDrain` enforces shutdown ordering: inbound drain/seal, outbound close, bounded `6s` cleanup wait for in-flight handlers, and only then closing Rhiza storage `[request_drain.go:requestDrain.runLifecycle]`, `[main.go:closeRhizaAfterStartupComplete]`.
- `configureGCSMutationGate` must be installed before `rhiza.Open` when `GOAUTHY_GCS_MUTATION_GATE_ENABLED` is true (requires `standalone` profile, `gcs` provider, `before-ack` durability, non-gRPC) `[gcs_mutation_gate.go:configureGCSMutationGate]`.
- `startupErrorClass` maps startup/Rhiza errors to structured error classes without exposing secret values `[main.go:startupErrorClass]`.

## Side Effects
- Opens/migrates Rhiza storage and reads/writes object-store backups, master keys, TLS certs, and provider config files on disk `[main.go:run]`.
- Binds TCP/HTTPS listeners for the main server and optional metrics server, and runs outbound HTTP/SMTP/SCIM/notification workers `[main.go:run]`.

## Verification
- Run: `go test ./...`
