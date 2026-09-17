# 범용 IdP 소비 계약

2026-09-07. GoAuthy는 OAuth2/OIDC IdP다. 소비자의 업무 DB, workspace membership,
에이전트/SSH/relay 실행 정책은 소비자가 소유한다. 외부 provider 인증 관리와 사용자별
복수 프로파일·credential lifecycle·허가된 사용은 GoAuthy의 명시적 선택 확장이 소유한다.
AI/SaaS 도메인으로 모델을 나누지 않고 실제 OAuth2/API key 인증 방식과 provider capability로
구분한다. 각 프로젝트는 공개 API/adapter를 통해 독립적으로 실행·검증한다. 이 확장은
표준 IdP 로그인에 필수가 아니며 소비자에 credential lifecycle을 복제하지 않는다.

확장 전달 방식은 아직 미확정이다. Beesuh HTTPClient/RoundTripper와 Conductor AMP의
서버 HTTP 인증 주입 요구를 기준으로 검토한다. 기존 fixed GET bound-call은 첫 fixture만
지원하며 범용 SDK/CLI 연결 완료가 아니다. Codex CLI의 CodexHome adapter는 별도 미해결이다.
공통 사용 경계는 owner, consumer consent, profile ID, 논리 authorization generation,
purpose, destination/operation이다. 일반 OAuth refresh는 논리 generation 변경이 아니다.

사용자 계정 연결·관리·선택과 consumer 사용동의는 GoAuthy 확장 책임이다. Beesuh는
선택·승인된 profile별 실행 context를 격리하며 별도 authoritative 계정 registry를 만들지 않는다.
Beesuh가 제안한 실험적 Codex adapter의 `initial`/`unauthorized` credential callback은
통합 요구사항이지 제공 중인 GoAuthy HTTP API가 아니다. 기대 upstream account identity,
profile 승인 세대, refresh CAS/tombstone, durable save 후 access-token 전달 검증이 필요하다.
GoAuthy 사용자 토큰은 upstream 공급자 토큰을 대신하지 않는다. 실제 토큰 취득·이관은 미구현이다.

## 실행 상태와 기본 경로

현재 상시 로컬 issuer는 제공되지 않았다. `http://localhost:17889`는 종료된 임시
standalone 연동 테스트 주소이며 실행 중 서비스로 사용하면 안 된다. 실제 배포 후
`GOAUTHY_ISSUER`의 정확한 값을 사용하고 브라우저와 backend 모두 같은 issuer에
접근할 수 있어야 한다. 다른 Pod의 localhost는 이 서버를 가리키지 않는다.

| 용도 | issuer 기준 경로 / 계약 |
| --- | --- |
| OIDC discovery | `/.well-known/openid-configuration` |
| OAuth metadata | `/.well-known/oauth-authorization-server` |
| 로그인 | `/oidc/authorize`, authorization_code + S256 PKCE 필수(confidential 포함) |
| 토큰 | `/oidc/token`, 등록된 client에 따라 none / client_secret_basic / client_secret_post |
| 공개키 | `/oidc/jwks.json`, 현재 ID token 서명 EdDSA |
| 사용자 정보 | `/oidc/userinfo`, access token Bearer, scope별 허용된 정보만 |
| 토큰 상태 | `/oidc/introspect`, confidential HTTP Basic; 코드상 별도 등록 caller도 가능, audience별 조회 ACL 없음 |
| 토큰 폐기 | `/oidc/revoke`, stateful access/refresh 폐기 |
| RP 로그아웃 | `/oidc/logout`, 등록 redirect 및 ID token 검증; back-channel 지원은 client 설정 필요 |
| Device | `/oidc/device`, RFC 8628; OIDC openid/groups/ID token·refresh standalone HTTP E2E 통과, 소비자 통합은 미검증 |
| client 등록 | opt-in `/oidc/register`(RFC 7591), registration token 기반 `/oidc/register/{id}` 관리 |

Discovery는 실제 runtime 설정을 확인하는 기준이다. 표 전체가 모든 OAuth-only
구성에서 활성이라는 뜻은 아니다. ID token을 API access token으로 사용하지 않는다.
OIDC 검증에는 signature, exact issuer, aud/azp, exp/nbf, 요청 nonce를 확인한다.
안정적인 계정 식별자는 `(issuer, sub)`이며 이메일 자동 계정 병합은 하지 않는다.

## 비밀 없는 client 등록 예제

운영자가 `GOAUTHY_DCR_REGISTRATION_TOKEN_FILE`로 등록 권한을 활성화하고 허용
scope를 설정한 경우, `POST /oidc/register`에 등록 Bearer를 별도 주입한다.
아래는 요청 body 예제이며 실제 client ID/secret은 등록 응답으로 생성된다.

```json
{
  "client_name": "Example web application",
  "redirect_uris": ["https://app.example.test/auth/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

응답의 client_secret과 registration_access_token은 비공개 파일/secret manager로
전달한다. 브라우저·argv·작업 메시지·로그에 넣지 않는다. 로컬 fixture는 0700 디렉터리와
0600 regular file을 사용한다. Public client는 secret을 만들지 않고 등록 auth method
`none`을 사용한다. Callback은 정확히 등록하고 origin이나 localhost/127.0.0.1을 혼용하지 않는다.
관리자 session+CSRF의 `/auth/v1/clients`는 운영 UI용 별도 등록 경로다.

현재 DCR 요청은 `scope` 필드를 받지 않는다(strict unknown-field rejection).
허용 scope는 운영자의 `GOAUTHY_DCR_ALLOWED_SCOPES`로 설정한다. 위 JSON에 scope를
추가하면 등록이 실패한다. HTTP loopback redirect 예외도 public `none` client만
지원한다. Confidential client는 로컬 pilot에서도 HTTPS callback이 필요하다.
`compos.api` 같은 custom scope는 DCR allowlist뿐 아니라 관리 API
`POST /auth/v1/scopes`의 활성 catalog에도 등록해야 한다. catalog에 없는 custom scope가
포함된 dynamic client는 authorization 시 거절된다. 순수 application permission scope는
attribute 목록을 생략하거나 빈 배열로 등록할 수 있으며 사용자 정보를 투영하지 않는다.
등록/갱신/빈 projection 및 잘못된 attribute·예약 scope 거절을 claims 테스트로 검증했다.
인증된 DCR 등록/갱신은 GoAuthy 확장 `audience` 배열로 클라이언트별 resource를 선택한다.
각 값은 `GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES` 전역 허용 목록에도 있어야 한다.
익명 등록은 이 필드를 거절한다. PUT에서 생략하거나 빈 배열이면 기존 audience를 지운다.
예를 들어 별도 RP에 `audience:["https://compos.local.test"]`를 등록한 뒤
authorization의 `resource=https://compos.local.test`로 토큰을 발급한다.
이 설정은 introspection caller의 audience별 조회 ACL을 제공하지 않는다.

관리자 생성 클라이언트도 `/auth/v1/clients` POST와 `/{id}` PUT의 `audience` 배열로
resource를 등록한다. 최대 32개, 항목당 2048 bytes의 중복 없는 절대 HTTPS 주소이며
userinfo/query/fragment는 허용하지 않는다. 서버 resource allow-list에도 있어야 한다.
POST 생략/`[]`는 빈 허용 목록이다. **DCR PUT과 달리 managed PUT 생략은 기존 값을
유지**하고 명시적 `[]`만 제거한다. 변경은 client generation을 바꿔 이전 access/refresh
token과 진행 중 authorization을 무효화하며 기존 client secret 자체는 보존한다.
관리 화면 Resource audiences 필드에서도 편집한다. code+PKCE뿐 아니라
`POST /oidc/device`에서도 `resource` 하나를 전달할 수 있다. 생략하면 구성된 client
기본 audience를 저장하고, 기본값도 없으면 audience 없이 발급한다. 승인 후 Device
코드를 교환하거나 refresh할 때는 `resource`/`audience`를 다시 보내지 않는다.
최초에 저장한 대상을 유지하며 교환 시점에도 서버·클라이언트 허용 목록을 검사한다.
schema v75 이전 Device grant의 resource는 NULL로 보존되며 소급 부여하지 않는다.
또한 현재 DCR은 `refresh_token` 등록을 device grant 동반 시에만 허용한다.
위 예제는 code-only 등록이며 browser refresh 등록 완료 예제가 아니다.

## Scope·권한·생명주기

`openid/profile/email/address/phone/offline_access`와 설정된 scope를 사용한다.
`groups`와 `roles` projection은 이 IdP의 확장 계약이며 모든 OIDC 공급자가 보장하는
표준 업무 권한이 아니다. 앱은 자기 RBAC로 권한을 판단한다. `openid`가 실행 권한은 아니다.
Resource audience는 RFC 8707 절대 HTTPS 식별자를 allowlist로 설정한다. 각 API는
자기 audience와 필요한 scope를 확인하며 하나의 token을 모든 API/SaaS로 중계하지 않는다.

Refresh rotation과 token revoke는 제공하지만 앱이 자체 session으로 교환한 경우
그 session의 폐기·TTL·back-channel 처리는 소비자 책임이다. JWT signature 검증만으로
즉시 철회를 보장하지 않는다. 현재 token exchange는 same-client/single-audience
제한 구현이며 cross-client 사용자 위임 완료로 해석하지 않는다.

Device OIDC는 브라우저 session ID/AMR/auth_time을 임의로 만들지 않는다. 2026-09-07
standalone 재시작 전·후 HTTP form E2E에서 subject/client audience, at_hash, 현재 groups,
그룹 변경 후 refresh, 코드 재사용 거절과 access/refresh 폐기를 확인했다.
이는 Ternal 실제 앱 통합·Chromium UI·HA 검증 완료가 아니다.

## 증거의 버전 경계

현재 작업 HEAD `2645c0d92c367811d5c158567c1f967ccc858b59`만으로 실행 구현을 재현할 수 없다.
대부분 구현이 untracked인 dirty worktree이며 Rhiza `v0.12.0`, schema70이다. 기존 actual
Compos 연동 결과는 이 로컬 worktree 기반이며 release/production 증거가 아니다.
세부 성공·거절·SKIP은 [소비자 연동 기록](consumer-integrations.md)에 분리해 기록한다.
