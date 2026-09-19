# GoAuthy capability matrix

이 문서는 **현재 GoAuthy 제품에서 무엇을 사용할 수 있는지**를 판단하는 기준이다.
Rauthy `v0.36.2`와의 세부 동등성은 [features.md](features.md)와
[parity.md](parity.md), 실행 이력은 [status.md](status.md)에서 별도로 추적한다.

기능 상태는 다음 의미를 가진다.

- **Qualified**: production route가 연결되어 있고 현재 소스에서 정상/거절 경로를
  검증한다. 상태 보존이나 다중 Pod 의미가 있는 기능은 해당 standalone 또는 HA
  검증 근거가 있어야 한다.
- **Preview**: production route와 핵심 보안 경계는 구현되어 있으나 실제 소비자,
  외부 공급자, HA/chaos 또는 운영 workflow 중 하나 이상이 아직 닫히지 않았다.
- **Experimental**: opt-in 구현 또는 부분 구현으로, 제한된 검증 범위에서만 사용한다.
- **Unsupported**: 현재 제품 계약에 포함하지 않는다.

이 상태는 API 안정성이나 장기 호환성을 자동으로 의미하지 않는다. 외부 소비자가
의존할 계약은 별도 v1 계약으로 고정하기 전까지 관련 문서의 현재 제한을 함께 확인한다.

## Core identity and OAuth

| Capability | Status | Current boundary / evidence |
| --- | --- | --- |
| OIDC discovery, JWKS, EdDSA ID token | Qualified | Public discovery/JWKS, rotation, restart/cross-Pod evidence. |
| Authorization Code + PKCE | Qualified | Browser code flow, wrong verifier/non-consumption, replay rejection, refresh across Pods. |
| Refresh Token | Qualified | Rotation/reuse rejection and current identity/client guards. |
| Client Credentials | Qualified | Scope/lifetime enforcement and public token/introspection evidence. |
| UserInfo, introspection, revocation | Qualified | Public route and revoked/disabled/invalid-token denial evidence. |
| RP-initiated logout | Qualified | Browser session/OAuth sid binding and redirect validation. |
| Back-channel logout | Preview | Outgoing/incoming subsets are implemented; broader multi-client/Kubernetes qualification remains. |
| Dynamic Client Registration | Preview | RFC 7591/7592 subset, software statements and Device clients are implemented; complete parity/HA surface remains open. |
| Device Authorization Grant | Preview | Bootstrap and standalone dynamic-client flows exist; dynamic-client Kind qualification remains open. |
| DPoP | Qualified | Pinned product scope has auth-code/refresh/UserInfo/client-credentials/Device and continuity evidence. |
| Token Exchange | Preview | User/machine/cross-client subsets and DPoP output exist; complete product contract remains broader than the qualified slices. |
| Resource Indicators | Qualified | Exact resource/audience admission and refresh persistence are wired. |
| RFC 8252 loopback redirects | Preview | Explicit opt-in dynamic-public-client subset only. |

## Accounts and administration

| Capability | Status | Current boundary / evidence |
| --- | --- | --- |
| Password login + Argon2id | Qualified | Constant-shape failure handling, configurable rules and production login path. |
| Password recovery | Qualified | Opt-in PoW + SMTP reset flow with standalone/Kind evidence. |
| Open registration | Preview | Opt-in password-first lifecycle is wired; broader registration methods remain open. |
| Passkeys / WebAuthn | Preview | Registration/login/MFA and conversion slices exist; complete passwordless/recovery/admin parity remains open. |
| Roles, groups, scopes, custom attributes | Preview | Current claims and administration subsets are wired; delegated/full management remains open. |
| Admin API keys | Preview | Scoped API keys and cross-Pod usage exist; complete management/UI parity remains open. |
| Admin UI | Preview | Core user/client/collection management slices exist; it is not yet a complete management console. |
| Account self-service UI | Preview | Profile/session/passkey/connection slices exist; complete self-service parity remains open. |

## Federation

| Capability | Status | Current boundary / evidence |
| --- | --- | --- |
| Upstream OIDC login | Qualified | Managed OIDC lifecycle and Pod replacement E2E are current. |
| GitHub upstream login | Qualified | Same login-federation boundary; used only to authenticate into GoAuthy. |
| Upstream account linking/unlinking | Qualified | Current source guards provider version, identity namespace and current session. |
| FedCM | Experimental | Default-off source wiring exists; broad real-browser/Kind interoperability remains open. |
| WebID profile | Experimental | Default-off profile endpoint has standalone/HA evidence; Solid behavior is outside the current contract. |
| CIMD ephemeral clients | Experimental | Default-off constrained resolver/cache; Kind/CNI/chaos qualification remains open. |

## External user-owned connections

`upstreamprovider`의 로그인 연합과 이 영역은 별개다. 아래 기능은 GoAuthy 사용자가
외부 SaaS/API 계정을 소유하고, 명시적으로 승인한 consumer가 제한적으로 사용하도록
하는 제품 확장이다.

| Capability | Status | Current boundary / evidence |
| --- | --- | --- |
| Auth Collection definitions | Qualified | Admin-defined typed metadata schema, revision/CAS and owner-scoped connection CRUD. |
| User connection metadata | Qualified | Browser owner binding, CSRF, definition revision checks and cross-Pod CRUD evidence. |
| SaaS provider registry | Preview | DB/file providers, encrypted OAuth client secret, revision guards and admin routes are wired. |
| User API-key custody | Preview | Encrypted register/rotate/local revoke and UI evidence exist; arbitrary provider support is intentionally absent. |
| User OAuth connection | Preview | PKCE/state/session/owner binding, encrypted access/refresh storage, reconnect and local revoke are implemented. |
| Connection use grants | Preview | Owner + confidential consumer + connection/generation consent is persisted and checked at use time. |
| Registered API-key proxy invocation | Preview | Fixed registered operations and scalar projection exist; this is not an arbitrary HTTP proxy. |
| OAuth access-token credential delivery | Preview | Explicit `credential_delivery` consent and confidential human consumer checks are implemented. |
| Automatic OAuth refresh orchestration | Experimental | Refresh primitives and fencing exist, but the consumer-facing automatic coordinator is not yet the product contract. |
| Provider-side remote revoke | Unsupported | Local use can be revoked; provider-side credential revocation workflow is not yet a supported contract. |
| Provider revision migration | Unsupported | Unsafe referenced-provider mutation is blocked; guided migration/re-consent workflow is not yet implemented. |
| Consumer SDK / reference adapter | Unsupported | Consumers currently integrate the HTTP contracts directly; stable Go SDK is planned. |

For the current wire contract and remaining consumer work, see
[external-credential-consumer-contract.md](external-credential-consumer-contract.md),
[connection-use-grants.md](connection-use-grants.md), and
[connection-use-handoffs.md](connection-use-handoffs.md).

## Operations

| Capability | Status | Current boundary / evidence |
| --- | --- | --- |
| Exact-three Rhiza HA | Qualified | Pod replacement, quorum fail-closed/recovery and rolling restart evidence. |
| No-GoAuthy-PVC object-store recovery | Qualified | Backup/restore, empty-disk and corruption/interruption gates exist. |
| TLS hot reload | Qualified | Certificate/CA/hostname and last-good behavior are exercised. |
| Metrics | Preview | Dedicated listener and core OAuth/login/readiness metrics are wired; broader observability remains open. |
| OpenTelemetry tracing | Preview | Exporter/startup wiring exists; production breadth and operational guidance remain incomplete. |
| Event log | Preview | Public event records and guarded querying exist. Hash-chain verification code exists, but production append-chain wiring is not complete. |
| SCIM outbound synchronization | Preview | User/group synchronization and deletion slices have live evidence; full SCIM/chaos contract remains open. |

## Explicitly outside the current product contract

- Full Rauthy feature parity as a release criterion. Rauthy `v0.36.2` remains a behavior
  baseline and compatibility ledger, not the sole GoAuthy roadmap.
- PAM/NSS host-login integration.
- Arbitrary external HTTP proxying or arbitrary user-provided execution code.
- Export of OAuth refresh tokens or provider application client secrets to consumers.
- Migration from Rauthy Hiqlite/Postgres storage into Rhiza unless a migration project is
  explicitly started.

When this document conflicts with an older dated implementation note, use current source,
[status.md](status.md), and this matrix. Historical documents should retain their dated
evidence but must not be interpreted as the current support boundary.
