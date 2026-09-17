# Rauthy v0.36.2 Feature Mapping to GoAuthy

**생성일:** 2026-09-12  
**기준:** Rauthy v0.36.2 (commit `dd61ac3c84d6b238108dc8438b53043b5177a662`)

**현재 자격 (2026-09-18):** Runtime image `ghcr.io/mrchypark/ternal@sha256:c1a59b226d1b4933d085b37e33776deac5535dfad8a1eaa861e579237759db32` (runtime `402096573a1799c728df3611fcf29cf1f3bc6a7e`, linux/amd64, UID 65532). Grype 0.118.0 zero matches exit 0. Ternal consumer OIDC + same-cookie auth/session and hosts PASS (GCS standalone + HA-3). New passkey Chrome button PASS 1.95s; profile 2-phase HTTP PASS; profile dedicated race 151.353s; OpenAPI regression PASS; lease focused race PASS; CSP/theme focused race PASS; combined open-registration/password-reset E2E PASS. Current PR-head Unit, Race, and Vet/session-policy checks are required before merge readiness; consult the PR checks for their latest status. Broad parity paused. 상세 [status.md](status.md) 참조.

**검증된 사실 (2026-09-18):**

- Runtime image sha256:c1a59b226d1b… published; Grype zero matches exit 0
- Ternal consumer 52df5050 OIDC + same-cookie auth/session and hosts PASS
- GCS standalone run 2183abd5 + HA-3 run b0f87aa5: same pre-fault token / full JWKS / all 3 physical hosts / survivor / replacement emptyDir loss; all owned K8s resources + secrets + GCS exact prefixes verified absent
- HA startup required four restarts before readiness; physical node failure and enforced CNI isolation remain unqualified.
- New passkey actual Chrome button PASS 1.95s; profile 2-phase HTTP PASS prepare 1.49 / complete 0.77; profile dedicated race 151.353s
- OpenAPI d6293df6 regression PASS; lease e5b7850f focused race count3 PASS 44.440s; CSP/theme 9e568fbf focused race single run 36.280s
- Full 5090 normal FAILED exactly cmd OpenAPI + 2 login assertions then fixed focused; old race pending
- CI 9e568fbf run 35242030951 Vet PASS; Unit Race pending
- Combined real standalone open-registration / password-reset entire E2E PASSED (/tmp/goauthy-openreg-stream-corrected-live-0918.log)
- Broader parity paused; resident credentials / hash-chain requirement not established

> **Historical snapshot (2026-09-12, unverified 2026-09-17):** The rows and counts in all feature tables below reflect the original baseline audit. Do not treat them as current completion metrics. Verified gate results are in [status.md](status.md).

## 1. OIDC/OAuth 코어 (12개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 1 | OIDC Discovery (RFC 8414) | ✅ 완료 | `internal/oidc` | 3-pod E2E 통과 |
| 2 | JWKS (Ed25519, 자동 로테이션) | ✅ 완료 | `internal/oidc` | 291s E2E |
| 3 | Authorization Code + PKCE S256 | ✅ 완료 | `internal/oauth` | 교차 팟 검증 |
| 4 | Refresh Token (회전/재사용 감지) | ✅ 완료 | `internal/oauth` | 3-pod E2E |
| 5 | Client Credentials | ✅ 완료 | `internal/oauth` | configurable lifetime |
| 6 | ID Tokens (EdDSA) | ✅ 완료 | `internal/oidc` | public JWKS 검증 |
| 7 | UserInfo (GET/POST) | ✅ 완료 | `internal/oauth` | 교차 팟 E2E |
| 8 | Token Introspection | ✅ 완료 | `internal/oauth` | active/inactive |
| 9 | Token Revocation | ✅ 완료 | `internal/oauth` | 교차 팟 E2E |
| 10 | DPoP (RFC 9449) | ✅ 완료 | `internal/dpop` | Device 바인딩 포함 |
| 11 | Resource Indicators (RFC 8707) | ✅ 완료 | `internal/oauth` | audience 영속성 |
| 12 | Token Exchange (RFC 8693) | 🔶 부분 | `internal/oauth` | `may_act` 미구현 |

## 2. Dynamic Client Registration (2개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 13 | DCR (RFC 7591/7592) | 🔶 부분 | `internal/dcr` | 소프트웨어 명세서 포함, HA 차단 |
| 14 | CIMD (Ephemeral Clients) | 🔶 부분 | `internal/cimd` | TLS-fixture Kind E2E 미실행 |

## 3. 로그아웃 (2개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 15 | RP-Initiated Logout | ✅ 완료 | `internal/logout` | 3-pod E2E |
| 16 | Back-channel Logout | 🔶 부분 | `internal/backchannel` | 단일 RP만 구현 |

## 4. Device Authorization (1개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 17 | Device Grant (RFC 8628) | 🔶 부분 | `internal/device` | OIDC 확장 포함, Dynamic-client Kind 미검증 |

## 5. 인증/패스키 (8개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 18 | WebAuthn/FIDO2 패스키 | 🔶 부분 | `internal/passkey` | 무비밀번호 생명주기 미완료 |
| 19 | 패스키 전용 계정 전환 | ✅ 완료 | `internal/passkey` | forward/reverse |
| 20 | MFA 수정 토큰 스텝업 | ✅ 완료 | `internal/passkey` | 3-pod E2E |
| 21 | 강제 MFA (부트스트랩) | 🔶 부분 | `internal/passkey` | per-client 정책 미구현 |
| 22 | 패스키 등록 후 세션 MFA 업그레이드 | 🔶 부분 | `internal/passkey` | Kind E2E 미검증 |
| 23 | 패스키+비밀번호 쿠키 흐름 | 🔶 부분 | `internal/passkey` | CookieKey 제거 대기 |
| 24 | 무비밀번호 계정 생명주기 | ❌ 미구현 | — | 계정 생성/등록/복구 없음 |
| 25 | Discoverable Credentials | — | — | not established as required; upstream pinned at ResidentKeyDiscouraged, `require_resident_key=false` ([source](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/webauthn.rs#L981)) |

## 6. 비밀번호/복구 (5개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 26 | 비밀번호 인증/정책/만료 | 🔶 부분 | `internal/identity` | 생명주기 카운터 미완료 |
| 27 | Magic Links/비밀번호 재설정 | 🔶 부분 | `internal/recovery` | PoW 포함, 이메일 OTP 미구현 |
| 28 | Argon2id 캘리브레이션 | ✅ 완료 | `cmd/goauthy-password-calibrate` | CLI 도구 |
| 29 | 비밀번호 히스토리 | 🔶 부분 | `internal/identity` | v14 스키마 |
| 30 | 자기 서비스 비밀번호 변경 | 🔶 부분 | `internal/account` | CSRF 바운더리 |

## 7. 사용자 관리 (7개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 31 | 사용자 삭제 (관리자/셀프) | ✅ 완료 | `internal/identity` | SCIM 통합, 3-pod E2E |
| 32 | 역할/그룹/스코프 | 🔶 부분 | `internal/rbac` | 위임 관리 미완료 |
| 33 | 커스텀 속성/클레임 바인딩 | 🔶 부분 | `internal/claims` | 사용자 편집 가능 속성 미완료 |
| 34 | 위임 그룹 관리자 | 🔶 부분 | `internal/rbac` | Kind E2E 미검증 |
| 35 | 동적 사용자 역할/그룹 할당 | 🔶 부분 | `internal/rbac` | 위임 Kind 미검증 |
| 36 | 사용자 대시보드/셀프 서비스 | 🔶 부분 | `internal/account` | 세션/프로바이더/복구 UI |
| 37 | Open Registration | 🔶 부분 | `internal/recovery` | Captcha 미구현 |

## 8. 관리 UI/API (3개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 38 | Admin UI | 🔶 부분 | `internal/admin` | 전체 화면/설정 미완료 |
| 39 | Fine-grained API Keys | 🔶 부분 | `internal/apikey` | 암호화 다이제스트 패리티 |
| 40 | OpenAPI/Swagger | 🔶 부분 | `internal/apidocs` | 와이어 스키마 패리티 |

## 9. 클라이언트 관리 (3개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 41 | 클라이언트 로그인 제한 (그룹 프리픽스) | ✅ 완료 | `internal/clients` | 3-pod E2E |
| 42 | 클라이언트 테마/로고/favicon | 🔶 부분 | `internal/branding` | 테마 CRUD·압축·메일·로그인 CSS 구현, standalone/Kind retained-theme 교체 및 Chromium light/dark 통과. 로고 저장·처리·HTTP, standalone/Kind 보존·교체 및 FS/실제 MinIO 복구 검증 통과; standalone favicon live 통과 (FaviconLive 0.15s); standalone favicon exact32WebP retention PASS (exec89833 exit0); Kind favicon exact32WebP retention PASS across Pod replacement (exec83518 exit0, 3 app Pods, one Kind host); schema95 migration test PASS (1.819s); extended TestNoPVCThemeRecovery exact32WebP+SVG/theme FS PASS (exec99993 9.260s); realMinIO 95-object recovery PASS 16.081s (test 14.06s, exit0, owned bucket/container cleaned, docker container absent); Cmd key lifecycle focused PASS (exec77074 8.709s, TestMasterKeyRewrapStep*, TestAuthProviderSecret*, TestMasterKeyRewrapWorkerInvokesAuthProvider*, TestSaaSProviderEnvelopeBlocksRetirement, real keyring, not all CAS boundaries); API-key envelope focused PASS (exec91100 10.783s); ProviderLogoStore focused PASS (session60332, small/medium, own-SVG fallback, revoked authenticated API key mutation denial, no cross-client/global fallback); ProviderLogoHandler httptest PASS (session70254); core rewrap race PASS (session52160); store deletion focused PASS (session1577); server shared unconditional routes integrated (POST/providers list, GETminimal/delete_safe, POST/create PUT/DELETE{id}, logoGET/PUT/DELETEimg); 43 writeHTTP tests PASS56.546s; writeHTTP race PASS362.426s (no data race); 15 registry+logo sharedmux parent tests PASS62.884s; DB dynamic runtime, full callback/userinfo parity, standalone+Kind provider E2E still open; token exchange 미검증; 전체 UI 미완료 |
| 43 | 클라이언트 크리덴셜 커스텀 클레임 | 🔶 부분 | `internal/claims` | 정적 클라이언트만 |

## 10. SCIM (2개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 44 | SCIM 사용자 동기화 | 🔶 부분 | `internal/scim` | 전체 패리티 미완료 |
| 45 | SCIM 그룹 동기화 | 🔶 부분 | `internal/scim` | PATCH-delta 미구현 |

## 11. 보안 (6개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 46 | IP 블랙리스트/로그인 지연 | 🔶 부분 | `internal/ipblacklist` | 자동 임계값, 전체 DoS 미구현 |
| 47 | 사용자명 열거 방지 | 🔶 부분 | `internal/loginpolicy` | 타이밍 분산 증명 없음 |
| 48 | 크리덴셜 스터핑 감지 | ❌ 미구현 | — | 분산 시도 감지 |
| 49 | Geolocation 정책 | ✅ 완료 | `internal/geoblock` | MaxMind/헤더, HA |
| 50 | Forward Auth | 🔶 부분 | `internal/oauth` | 프록시 모드/ACL 미완료 |
| 51 | 세션 관리/피어 IP 바인딩 | 🔶 부분 | `internal/browser` | Kind E2E 미검증 |

## 12. 데이터베이스/암호화 (4개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 52 | 중요 DB 값 암호화/키 로테이션 | 🔶 부분 | `internal/masterkeyretirement` | 자동 키 제거 미구현; real replacement-key persisted encrypted-secret oldwriter fence PASS2.061s (realkeyring, keyIDverified, nooldwrite/guards) |
| 53 | TLS 인증서 핫 리로드 | ✅ 완료 | `internal/tlsconfig` | E2E 검증 |
| 54 | Namespaced KV Store | ✅ 완료 | `internal/kv` | HA 교체 |
| 55 | Rhiza 마이그레이션 | ✅ 완료 | `internal/storage` | v102 스키마 |

## 13. HA/백업 (2개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 56 | Three-peer HA | ✅ 완료 | `internal/storage` | Rhiza v0.12.3 |
| 57 | 백업/복구/빈 디스크 복구 | ✅ 완료 | `internal/backup` | no-PVC, S3 |

## 14. 이벤트/알림 (3개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 58 | 이벤트/감사 | 🔶 부분 | `internal/eventlog` | SSE/외부 스트림 미완료 |
| 59 | 이메일/Matrix/Slack 알림 | 🔶 부분 | `internal/notify` | Matrix/Slack 미구현 |
| 60 | 설정 가능한 이메일 템플릿 | 🔶 부분 | `internal/recovery` | 프리뷰/관리 UI 없음 |

## 15. 기타 (6개)

| # | Rauthy Feature | GoAuthy Status | 패키지 | 비고 |
|---|----------------|----------------|--------|------|
| 61 | Prometheus 메트릭/트레이스 | 🔶 부분 | `internal/metrics` | OpenTelemetry 미구현 |
| 62 | 하우스키핑/업데이트 확인 | ❌ 미구현 | — | 싱글톤 정리 |
| 63 | 설정/부트스트랩 검증 | 🔶 부분 | `cmd/goauthy` | TOML 시크릿 없음 |
| 64 | Upstream Providers (OIDC/GitHub) | 🔶 부분 | `internal/upstreamprovider` | Kind V4 E2E PASS 11.946s (7/7 lifecycle, 3 Pods 1 Kind, Pod0 replacement + 60s login window); race PASS all packages; focused upstream tests PASS. Broad parity not claimed. See [status.md](status.md). |
| 65 | Machine Subject Mapping | ✅ 완료 | `internal/oauth` | default/mapped Kind |
| 66 | WebID/FedCM | 🔶 부분 | `internal/webid`, `internal/fedcm` | 브라우저 E2E 없음 |

---

## 통계 요약

> **Historical snapshot (2026-09-12, unverified 2026-09-17):** The counts and percentages below reflect the original baseline audit and have not been re-verified against current production code. Some features counted as 미구현 or 부분 may have been implemented or advanced since. Do not treat these as current completion metrics. See [status.md](status.md) for verified gate results.

| 상태 | 수 | 비율 |
|------|-----|------|
| ✅ 완료 | 18 | 27% |
| 🔶 부분 구현 | 36 | 55% |
| ❌ 미구현 | 12 | 18% |
| **합계** | **66** | **100%** |

---

## 우선순위별 미완료 기능

### P1 (즉시 필요 - 핵심 패리티)

1. **무비밀번호 계정 생명주기** (#24)
   - 계정 생성, 등록, 복구
   - 관리자 라이프사이클
   - Kind E2E


2. **크리덴셜 스터핑 감지** (#48)
   - 분산 시도 감지
   - 자동 IP 차단

3. **하우스키핑/업데이트 확인** (#62)
   - 싱글톤 정리 작업
   - 버전 체크

### P2 (단기 - 기능 완성)

5. **Back-channel 멀티 클라이언트** (#16)
   - 레지스트리
   - chaos 검증

6. **강제 MFA per-client** (#21)
   - 관리자 관리 정책
   - API 구현

7. **SCIM 전체 패리티** (#44, #45)
   - chaos 검증
   - 중복 전달

8. **Admin UI 완전한 화면** (#38)
   - 클라이언트/프로바이더/설정
   - 위임 UI

9. **사용자 대시보드 완성** (#36)
   - 세션/프로바이더 UI
   - MFA 재인증

10. **이벤트 알림 완성** (#59)
    - Matrix/Slack 통합
    - 재시도/아웃박스

### P3 (중기 - 운영 강화)

11. **Prometheus/Traces** (#61)
    - OpenTelemetry 통합
    - 내보내기

12. **OpenAPI 완전성** (#40)
    - 와이어 스키마 패리티

13. **Upstream Providers 검증** (#64)
    - Kind/chaos 실행

14. **WebID/FedCM 브라우저 E2E** (#66)
    - 상호운용성 검증

### P4 (장기 - 확장)

15. **클라이언트 테마 전체** (#42)
    - 로고, 색상, i18n

16. **i18n 확장**
    - 다국어 지원

17. **Kubernetes 배포 강화**
    - Cilium NetworkPolicy

---

## 기술적 제약사항

1. ~~**Docker inotify 제한**: `fs.inotify.max_user_instances=128`로 HA E2E 차단~~ **해결됨 (과거 이슈)**: Kind V4 E2E preflight PASS, inotify 제한 우회 확인; 2026-09-17.
2. **Cilium 호스팅 커널**: `protocol not supported` 오류
3. **Chaos Mesh**: Kubernetes 1.36 미지원
4. **Fosite v0.49 한계**: DCR, Device, DPoP 핸들러 없음

---

## 다음 단계

1. P1 기능 구현 시작 (무비밀번호 계정, 크리덴셜 스터핑)
2. Kind E2E 환경 inotify 해결 완료; 전체 upstream lifecycle 패리티 검증
3. SCIM 전체 패리티 검증
4. Admin UI 화면 완성
