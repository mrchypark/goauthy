# goauthy

GoAuthy is a pre-alpha Go OAuth 2.0 / OIDC identity provider targeting behavioral parity with **Rauthy `v0.36.2`** (the upstream Rust OIDC provider used as the porting reference) while adding GoAuthy-specific external-connection and credential-delegation capabilities.

- **Current capability matrix**: [docs/capabilities.md](docs/capabilities.md) (Qualified, Preview, Experimental, Unsupported)
- **Dated execution & E2E ledger**: [docs/status.md](docs/status.md) (including [project goals and remaining work (Korean)](docs/status.md))
- **Parity & feature checklist**: [docs/parity.md](docs/parity.md), [docs/features.md](docs/features.md)
- **Independent verification runbook**: [docs/independent-verification.md](docs/independent-verification.md)
- **Consumer login integration rules (Korean)**: [docs/idp-consumer-contract.md](docs/idp-consumer-contract.md#서비스-개발자-로그인-연동-규칙)

---

## Architecture & Dependency Baseline

GoAuthy runs as a single binary (`cmd/goauthy`) with no external database server in the default deployment topology ("no GoAuthy PVC"):

- **Storage & replication (`Rhiza v0.27.3`, `latticedb-go v0.13.0`, schema `v116`)**: State is stored in an embedded `*rhiza.DB` SQLite/consensus engine (`github.com/mrchypark/rhiza`, commit [`234602aeb1783f11f1e878a5e1a4793ff7a473d6`](https://github.com/mrchypark/rhiza/commit/234602aeb1783f11f1e878a5e1a4793ff7a473d6)) using `emptyDir` local storage paired with synchronous `before-ack` object-store publication (S3 or GCS) for disaster recovery.
- **OAuth 2.0 / OIDC core (`ory/fosite` fork `v0.49.0-goauthy.1`)**: Uses a minimally patched `github.com/mrchypark/fosite` fork for security fixes and compatibility; the policy is to return to upstream once published and qualified.
- **Cryptography & WebAuthn**: `go-jose/v4` for EdDSA JWT/JWKS signing, `go-webauthn` for passkeys, Argon2id for password hashing, and `*oidc.Keyring` with **GAOP** (GoAuthy Authenticated Object Protection) AES-256-GCM envelope encryption.
- **Runtime requirement**: Go `1.27.4` minimum (also enforced by the root `Dockerfile`).

---

## Subdirectories & System Boundaries

- `cmd`: [./cmd/README.md](./cmd/README.md) — Executable entrypoints for GoAuthy server, backup/secrets/password CLIs, `goauthy-rhiza-init`, demo RP, and E2E test fixtures.
- `internal`: [./internal/README.md](./internal/README.md) — Core GoAuthy domain, OAuth/OIDC protocol, Rhiza persistence, cryptography, security middleware, and UI packages.
- `deploy`: [./deploy/README.md](./deploy/README.md) — Kubernetes/Kustomize deployment profiles, Kind cluster configs, E2E fixture overlays, and Dockerfiles.
- `scripts`: [./scripts/README.md](./scripts/README.md) — Operational, standalone/Kind E2E orchestration, backup/restore, chaos, and qualification scripts.
- `test`: [./test/README.md](./test/README.md) — Integration, E2E, browser, chaos, and compatibility test suites (including Rauthy `cron` and `go-quartz` scheduling oracles).

---

## Quickstart (`dev` Profile)

`goauthy` reads `secrets/master-keys/`, `secrets/oauth-hmac`, and `secrets/bootstrap-client` from default relative paths unless overridden by environment variables, and uses `GOAUTHY_BOOTSTRAP_CLIENT_ID` (default `goauthy-dev`) as the bootstrap client ID.

```bash
mkdir -p secrets/master-keys
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > secrets/master-keys/dev-1
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > secrets/oauth-hmac
openssl rand -base64 32 | tr -d '\n' > secrets/bootstrap-client
read -rs password; printf '\n'
printf '%s\n' "$password" | go run ./cmd/goauthy-password > secrets/bootstrap-user-password.phc
unset password
go test ./...
GOAUTHY_RHIZA_PROFILE=dev \
GOAUTHY_CLUSTER_ID=goauthy-dev \
GOAUTHY_NODE_ID=goauthy-dev-0 \
GOAUTHY_DATA_DIR=.goauthy-data \
GOAUTHY_BOOTSTRAP_USER=admin \
GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin \
GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE=secrets/bootstrap-user-password.phc \
go run ./cmd/goauthy
curl -i http://localhost:8080/readyz
curl -i http://localhost:8080/oidc/jwks.json
curl -u goauthy-dev:$(cat secrets/bootstrap-client) -d grant_type=client_credentials \
  -d scope=goauthy.read http://localhost:8080/oidc/token
```

Validate startup configuration without opening Rhiza or starting listeners:

```bash
GOAUTHY_RHIZA_PROFILE=dev \
GOAUTHY_CLUSTER_ID=goauthy-dev \
GOAUTHY_NODE_ID=goauthy-dev-0 \
GOAUTHY_DATA_DIR=.goauthy-data \
go run ./cmd/goauthy config check

# Prints a secret-free summary of the same centralized configuration slice.
go run ./cmd/goauthy config dump-effective
```

`config dump-effective` reports only non-secret values and boolean presence for static object-store credentials. `config check` validates the centralized `applicationConfig` slice, referenced files (including `GOAUTHY_OAUTH_HMAC_SECRET_FILE` / `./secrets/oauth-hmac` and `GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE` / `./secrets/bootstrap-client`), and cross-field rules before opening Rhiza or starting listeners; only store-dependent admission and default-path master-key material (`GOAUTHY_MASTER_KEY_DIR`) are deferred until startup. `goauthy-password` reads one password line from stdin and prints its current-policy Argon2id PHC string; the bootstrap identity is created once and never reset on later startups.

---

## Rhiza Production Profiles & Disaster Recovery

GoAuthy supports four Rhiza profiles via `GOAUTHY_RHIZA_PROFILE`:

| Profile | Topology | Local Storage | Object Store | Backup/Restore Support |
| --- | --- | --- | --- | --- |
| `dev` | Single process | Local dir | Disabled | Development only |
| `standalone` | 1-member (`Local: false`) | `emptyDir` | Required (S3/GCS) | `goauthy-backup` (`age` + Ed25519) & `GOAUTHY_BACKUP_ENABLED` |
| `standalone-local` | 1-member (`Local: true`) | `emptyDir` | Required (S3/GCS, `local/v1`) | `goauthy-rhiza-init` pre-start recovery; `goauthy-backup` rejected |
| `cluster` | 3-voter HA (`Local: false`) | `emptyDir` | Required (S3/GCS) | `goauthy-backup` & scheduled snapshots |

- **Current `v0.27.3` qualification scope**: Bounded verification targets single-node `standalone-local` object-store recovery without an operator. Managed HA, Kubernetes, and production-cloud operation on `v0.27.3` remain unqualified; see [docs/no-pvc-dr.md](docs/no-pvc-dr.md#current-v0273-integration).
- **No-PVC DR & consumer integration**: See [deploy/ternal-no-pvc/README.md](deploy/ternal-no-pvc/README.md) (`Ternal` is the reference consumer deployment) and [docs/backup-operator.md](docs/backup-operator.md) for offline `age`/Ed25519 backup and restore workflows.
- **Checkpoint intervals**: `GOAUTHY_RHIZA_CHECKPOINT_INTERVAL` supports durable checkpointing, but avoid aggressive `1s` intervals during schema migrations or heavy writes (observed to trigger `node is not ready` in [docs/no-pvc-dr.md](docs/no-pvc-dr.md)).
- **Archive-statistics compatibility**: Rhiza `v0.21+` removed the archive-statistics API; GoAuthy's protected `/metrics/archive/v1` endpoint retains schema version 1 with `available: false` and `null` count/duration values.
- **Mixed-version constraint**: Mixed-version peers, downgrades, and in-place data migration between `Local: false` and `Local: true` (`local/v1`) are unsupported.

---

## Core Subsystems & Security Contracts

### External Connections & Credential Delegation
GoAuthy extends Rauthy parity with user-owned external SaaS connections and delegated credential access (`internal/authcollection`, `internal/saas`, `internal/rbac`, `docs/connection-use-grants.md`):
- **Custody & trust boundaries**: Administrators define `authcollection` schemas and `saas` provider configs; users authorize and store per-owner OAuth 2.0 / GitHub / API-key credentials sealed with GAOP envelopes (`*oidc.Keyring`).
- **Delegated consumption**: Consumers request short-lived `use-grant` / `use-handoff` approvals or `credential_delivery` / proxy invocations guarded by generation fencing and SSRF-restricted outbound transports (`restrictedTransport` blocks private/special-use IPs and disables redirects).
- **Known capability gaps**: Per [docs/capabilities.md](docs/capabilities.md), `Provider-side remote revoke` and `Provider revision migration` remain **Unsupported**.

### OAuth 2.0 / OIDC, DPoP, CIMD & Federation
- **Grants & tokens**: Supports Authorization Code + PKCE, Refresh Token (with rotation), Client Credentials, Device Authorization Grant (RFC 8628, Preview), Password Grant, Token Exchange (Preview), DPoP (RFC 9449: Qualified for auth-code, refresh, UserInfo, client-credentials, and Device Grant), ForwardAuth, and UserInfo.
- **Dynamic Client Registration & CIMD**: Supports RFC 7591/7592 DCR (global bearer, software statements, anonymous rate-limited mode) and Client ID Metadata Documents (`internal/cimd`) with HTTPS enforcement, SSRF private-IP blocking, and cross-origin redirect rejection (same-origin HTTPS redirects permitted).
- **Upstream providers & WebID**: Supports upstream OIDC/OAuth/GitHub login (`internal/upstreamprovider`), FedCM opt-in endpoints (`internal/fedcm`), and bounded `text/turtle` WebID profiles (`internal/webid`).
- **API keys**: Scoped `API-Key name$secret` authentication with constant-time SHA-256 verification and bootstrap loading ([docs/api-key-bootstrap-implementation.md](docs/api-key-bootstrap-implementation.md)). API keys managing API keys are prohibited by Rauthy parity.

### Password Hashing Policy
GoAuthy writes Argon2id `v=19` credentials using the OWASP baseline (`m=19456` KiB, `t=2`, `p=1`, max 4 concurrent admitted operations per shared identity-store hasher), which is lower than Rauthy `v0.36.2`'s default (`m=131072` KiB) to avoid pod OOM under load while still verifying imported PHCs up to `128 MiB`.
- **Optional memory budget**: `GOAUTHY_ARGON2_MEMORY_BUDGET_KIB` enables a weighted memory semaphore (`250 ms` combined slot + memory wait) and is **off by default**; see [docs/measurements/argon2-109-budget.md](docs/measurements/argon2-109-budget.md).
- **Pod sizing warning**: With `GOAUTHY_ARGON2_MEMORY_BUDGET_KIB` unset, 4 concurrent `128 MiB` verifications can allocate up to `512 MiB` of KDF work arrays alone (excluding Go heap/RSS). Set `GOAUTHY_ARGON2_MEMORY_BUDGET_KIB` on memory-constrained pods, noting that slot-first ordering can introduce head-of-line blocking behind high-cost PHCs.

### Password Recovery, Passkeys & Account Lifecycle
- **Proof-of-Work & recovery (`spow-v1`)**: `internal/recovery` implements Rauthy-compatible `spow-v1` textual proof-of-work challenges (`POST /auth/v1/pow`), opt-in password reset (`POST /auth/v1/users/request_reset`), email OTP, and an encrypted SMTP outbox (Qualified in [docs/capabilities.md](docs/capabilities.md)).
- **Passkeys (opt-in)**: WebAuthn registration, login, MFA step-up, and passwordless cookies (`internal/passkey`, [docs/passkey-bootstrap.md](docs/passkey-bootstrap.md)), using GAOP active-key envelopes with dual-read fallback for legacy `CookieKey` ciphertext.
- **Password composition & expiry**: Enforces length/character rules, common-password checks, password history, and an account expiration worker (`GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES`, default 60m; optional `GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES`; max 128 expirations/deletions per tick). See [the account lifecycle contract (Korean)](docs/user-management.md#만료-worker-운영-계약).

---

## Known Operational Risks & Qualification Boundaries

- **Startup `db.Close()` guard**: `closeRhizaAfterStartupComplete` closes Rhiza on startup failures as well as graceful shutdown (early-close/reopen verified on `v0.27.3` by `TestRhizaV0273EarlyCloseAndReopen`) and skips `db.Close()` only if shutdown draining times out with active handlers.
- **`before-ack` latency sensitivity**: Synchronous `before-ack` object-store publication sits on auth write paths (sessions, DPoP nonces/JTIs, brute-force counters, PoW); degraded object-store latency directly affects auth tail latency.
- **Reverse-proxy rate-limit key**: `peerIPMiddleware` honors configured trusted-proxy headers (including `POST /auth/v1/pow`), whereas the Device flow rate-limiter keys on direct TCP `RemoteAddr`—behind a reverse proxy or Ingress without ProxyProtocol, Device flow clients share one bucket.
- **Legacy session & key-rotation gaps**: Pre-v31 sessions with empty `peer_ip` are accepted without IP binding; password↔passkey account conversions retain existing sessions; `CookieKey` rotation, non-rotating encrypted values, and automatic master-key file removal remain manual/pending.
- **Event-log hash chain & SCIM tombstones**: Production event-log append-chain wiring is incomplete ([docs/capabilities.md](docs/capabilities.md)), and deleting a SCIM provider blocks tombstone cleanup for that provider ID until it is restored.

---

## Global Invariants

- Replicated state and schema migrations (`v116`) are persisted in `*rhiza.DB`; mutations requiring authorization or fencing evaluate predicates inside the same linearizable transaction (`internal/storage`, `internal/audit`, `internal/eventlog`, `internal/rbac`, `internal/clients`).
- Envelope-encrypted secrets (OAuth clients, SaaS providers/credentials, passkey credentials/ceremonies, upstream providers, KV namespaces) are sealed with `*oidc.Keyring` and guarded by master-key retirement writer barriers (`internal/oidc`, `internal/storage`).
- Outbound HTTP/webhook/CIMD/back-channel/SCIM/SaaS callers enforce HTTPS policies, bounded response sizes, redirect restrictions, and private-IP/DNS-rebinding protections (`internal/backchannel`, `internal/cimd`, `internal/notify`, `internal/saas`, `internal/scim`).
- Browser-only endpoints enforce session binding, CSRF tokens, `Sec-Fetch-Site` checks, and reject `Authorization` headers; API-key endpoints enforce constant-time SHA-256 verification and narrow resource rights (`internal/browser`, `internal/apikey`, `internal/admin`, `internal/account`).

---

## Global Side Effects

- Opens and mutates local/replicated `*rhiza.DB` storage and optional S3/GCS object stores (`GOAUTHY_RHIZA_*`).
- Binds HTTP/HTTPS/SMTP/QUIC listeners across server and fixture binaries, reads key/TLS/config files from disk, and executes outbound HTTPS/SMTP calls for OIDC, SCIM, notifications, and upstream providers.

---

## E2E Testing Profiles & System Verification

GoAuthy maintains two E2E profile categories:

- **Deterministic profiles** (default): All `make e2e-kind` profiles inject clock/random seams and assert state transitions rather than elapsed time (`sleep`-based timing assertions are avoided; wall-clock waits are limited to Kubernetes readiness/rollout). These are the standard CI gate.
- **Wall-clock profiles** (opt-in): `make e2e-kind-wall-clock-jwks` and `make e2e-kind-wall-clock-idle-expiry` require `GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1` or `GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=1` and serve as supplementary operational evidence only, not deterministic correctness proof.

### System Verification
- Run: `go test ./...`
- Run: `make test`
