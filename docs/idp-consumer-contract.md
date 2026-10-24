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
| RP 로그아웃 | `/oidc/logout`; Managed/DCR은 ID token hint로 현재 client를 확인하고 redirect 없이 issuer root로 로그아웃. 제공한 post-logout redirect는 거절되며 OAuth callback URI를 logout allowlist로 쓰지 않음. Bootstrap redirect는 별도 `GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS` 설정만 사용 |
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
현재 DCR은 `refresh_token`을 `authorization_code`, device, 또는 `password` grant와
함께 등록할 수 있다. `client_credentials` 단독 등록에는 refresh grant를 붙일 수 없다.
위 예제는 code-only 등록이며 browser refresh 등록 완료 예제가 아니다. DCR grant 목록은
token exchange를 지원하지 않는다.

## Scope·권한·생명주기

`openid/profile/email/address/phone/offline_access`와 설정된 scope를 사용한다.
`groups`와 `roles` projection은 이 IdP의 확장 계약이며 모든 OIDC 공급자가 보장하는
표준 업무 권한이 아니다. 앱은 자기 RBAC로 권한을 판단한다. `openid`가 실행 권한은 아니다.
Resource audience는 RFC 8707 절대 HTTPS 식별자를 allowlist로 설정한다. 각 API는
자기 audience와 필요한 scope를 확인하며 하나의 token을 모든 API/SaaS로 중계하지 않는다.

Refresh rotation과 token revoke는 제공하지만 앱이 자체 session으로 교환한 경우
그 session의 폐기·TTL·back-channel 처리는 소비자 책임이다. JWT signature 검증만으로
즉시 철회를 보장하지 않는다. 현재 token exchange는 활성화된 managed confidential client의
별도 grant다. 다른 client가 발급한 access token을 subject token으로 교환할 수 있고 actor
token도 선택적으로 받을 수 있다. 출력 resource는 한 개만 지정할 수 있으며 exchanger가
허용한 resource여야 한다. 교환 결과는 refresh token을 포함하지 않는다. DCR consumer는
token exchange를 사용할 수 없고, 이 기능을 완성된 범용 사용자 위임이나 앱 세션의
철회·수명주기 관리로 해석해서는 안 된다.

Device OIDC는 브라우저 session ID/AMR/auth_time을 임의로 만들지 않는다. 2026-09-07
standalone 재시작 전·후 HTTP form E2E에서 subject/client audience, at_hash, 현재 groups,
그룹 변경 후 refresh, 코드 재사용 거절과 access/refresh 폐기를 확인했다.
이는 Ternal 실제 앱 통합·Chromium UI·HA 검증 완료가 아니다.

## 서비스 개발자 로그인 연동 규칙

### 소비자 앱의 구현 권장사항

다음은 서비스 개발자가 앱에서 지켜야 할 규칙이다. GoAuthy가 앱의 세션이나 재시도를
대신 관리한다는 보장은 아니다. 구현 예제는 [로컬 데모](../cmd/goauthy-demo/main.go),
검증 항목은 [브라우저 로그인 여정](../test/e2e/browser/login_journey_test.go)을 참고한다.
아래 거래·앱 세션 예시는 서버 웹 앱/BFF를 기준으로 하며, 브라우저 전용 public client에
별도 backend를 요구한다는 뜻은 아니다. Public client의 브라우저 코드에 secret을 넣지 않는다.

1. **인증 이동과 API 호출을 구분한다.** 일반 서비스는 `/oidc/authorize`로 사용자 에이전트를
   redirect하고, 등록된 callback에서 code를 받아 `/oidc/token`으로 교환한다. 브라우저의
   인증 이동과 코드 교환·refresh API 호출은 서로 다른 단계다. IdP 로그아웃도 제공된
   브라우저 흐름에 따라 처리한다. 앱 내부의 same-origin 로그아웃 POST는 CSRF 방어와
   명시적인 최종 화면 이동을 갖추면 `fetch`로 구현할 수 있다.

2. **로그인 시도마다 별도 거래를 만든다.** 예측할 수 없는 `state`, `nonce`, S256 PKCE
   verifier를 만들고 브라우저 바인딩과 만료를 서버 측에 함께 저장한다. 콜백의 state와
   바인딩을 검증한 뒤 거래를 원자적으로 한 번만 소비한다. nonce와 verifier도 그 거래에만
   사용한다. 다른 탭의 거래를 덮어쓰거나 콜백 URL을 새 로그인에 재사용하지 않는다.
   데모의 `takePending`은 중복·만료·바인딩 오류를 거절하고 교환 전에 거래를 제거한다.

3. **검증과 앱 세션 저장을 끝낸 뒤 앱으로 이동한다.** 코드 교환 후 ID token의 서명,
   issuer, audience, 만료, nonce와 제공된 `at_hash`를 검증한다. 성공한 사용자만 앱의
   불투명 세션에 저장하고 쿠키를 설정한 뒤 최종 앱 경로로 redirect한다. 임의의 return URL을
   그대로 신뢰하지 말고 앱이 허용한 경로만 사용한다. 관리자 역할은 앱 권한 판단에 사용하되
   OIDC 콜백을 관리자 대시보드로 우회시키는 분기를 만들지 않는다.

4. **홈 주소와 콜백 주소를 구분한다.** `client_uri`는 서비스 홈 메타데이터이고,
   `redirect_uri`는 코드와 state를 받는 정확히 등록된 콜백이다. `client_uri`로 진행 중인
   authorize 거래의 콜백 목적지를 덮어쓰지 않는다. 홈 주소 보존은 코드 교환이나 앱 복귀를
   대신하지 않는다. Managed client의 현재 저장·갱신 동작은
   [client store](../internal/clients/store.go)를 기준으로 확인한다.

5. **issuer와 쿠키의 실제 origin을 맞춘다.** 브라우저와 앱 backend가 같은 공개 issuer를
   사용하도록 하고 scheme, host, port 및 배포 경로를 혼용하지 않는다. 운영 환경의 HTTPS,
   Secure/HttpOnly/SameSite 정책과 reverse proxy 설정을 함께 검토한다. 로컬 데모는 HTTP
   loopback 전용이며 localhost 쿠키가 port로 격리되지 않아 client별 쿠키 이름을 사용한다.
   이 설정을 운영용 쿠키 정책으로 복사하지 않는다.

6. **네트워크 작업과 재시도에는 끝을 둔다.** discovery·token 교환·JWKS·refresh 호출에
   유한한 timeout과 전체 처리 기한을 정하고, 진행 상태와 종료 오류를 표시한다. 앱의
   loading 상태는 `finally`에서 해제하고 브라우저 복원 시에도 제출 상태를 초기화한다. 데모의
   HTTP client timeout은 10초지만 운영 권장 임계값이나 GoAuthy 응답 SLA는 아니다.
   콜백과 refresh의 재시도 횟수·총 시간을 제한하고 동일 세션의 refresh를 직렬화한다.
   응답을 잃으면 코드가 이미 소비되었거나 refresh가 회전했을 수 있으므로 같은 코드나
   이전 refresh token을 맹목적으로 재전송하지 않는다. 저장된 최신 상태를 확인할 수 없으면
   새 로그인 거래를 시작한다. 데모는 실패한 콜백을 자동 재전송하지 않는다.

7. **인증 실패와 일시 장애를 구분한다.** 잘못된 자격 증명은 수정 가능한 로그인 오류로,
   backend의 일시적인 503은 서비스 오류로 표시한다. 503을 잘못된 비밀번호로 바꾸거나
   무한 로그인 루프로 처리하지 않는다. 429와 `Retry-After`도 존중한다. 로그인 정책에는
   의도적인 실패 지연이 있으므로 대기 중임을 보여 주고 중복 제출을 막는다.
   현재 분류와 지연 처리는 [로그인 handler](../internal/login/handler.go)와
   [정책](../internal/loginpolicy/policy.go)을 참고한다.

8. **로그아웃 범위와 진단 기록을 명시한다.** 앱 세션 삭제, GoAuthy 세션 로그아웃,
   다른 앱·upstream provider 로그아웃을 구분한다. 진단에는 단계명, 상관관계 ID, 경과 시간,
   HTTP 상태와 정제한 오류 종류를 남긴다. 비밀번호, secret, 쿠키, 토큰, authorization code,
   전체 콜백 query나 인증 요청·응답 body는 앱과 proxy 로그 모두에서 제외한다.

### 현재 구현에서 확인한 지원 범위

- 데모는 검증된 ID token으로 앱 세션을 만든 뒤 `/`로 303 이동한다. `/logout` POST는
  정확한 앱 Origin을 확인하고 **그 앱 세션만** 지운다. GoAuthy와 다른 앱의 세션은 유지한다.
- RP 로그아웃은 위 경로 표와 [logout handler](../internal/logout/http.go)가 기준이다.
  Managed/DCR client는 유효한 ID token hint와 현재 registry로 확인하며 redirect를 생략하면
  issuer root에서 완료한다. 요청한 post-logout redirect는 거절한다. OAuth callback을
  logout allowlist로 전용하지 않는다. Bootstrap은 별도 설정의 정확한 allowlist를 사용한다.
- 브라우저 여정은 실패 후 테마·interaction 유지, 올바른 비밀번호로 재시도, 콜백을 통한
  앱 복귀, 관리자 권한과 앱 세션의 공존, 앱 로그아웃 후 새로고침을 검사한다.
  데모는 OAuth refresh를 구현하지 않는다. 페이지 새로고침 검사를 refresh-token 검증으로
  해석하면 안 된다.

### 서비스 인수 검사와 과거 증거의 한계

합성 계정으로 실패 → 오류 표시 → 수정 후 재시도 → 앱 세션 생성 → 앱 복귀를 검사한다.
실패·재시도·브라우저 뒤로 가기에서도 테마와 로그인 문맥을 유지하고 중복 POST가 없는지
확인한다. 앱 새로고침, 지원하는 경우의 token refresh와 회전·실패·응답 유실, 앱 로그아웃과
IdP 로그아웃의 서로 다른 결과도 검사한다. 콜백 재사용·잘못된 state/nonce/PKCE는 거절해야 한다.

2026-10-23의 정제된 로컬 기록은 오류 페이지의 테마 문제와 `client_uri` 보존 결함을
뒷받침한다. 의도적인 실패 지연과 요청 제한은 현재 소스로 확인할 수 있지만 당시 멈춤의
정확한 원인·지연 시간·실패 횟수는 입증되지 않았다. 네트워크 timeout이나 콜백 재시도가
당시 원인이었다고 단정하지 않는다. 위 권장사항과 테스트 소스의 존재는
특정 배포의 장애 원인이나 운영 성능을 보증하지 않는다.

## 증거의 버전 경계

당시 로컬 검증·측정에 사용한 worktree에는 커밋되지 않은 변경이 포함되어 있었고,
측정 시점의 소스 snapshot을 별도로 보존하지 않았으므로 당시 HEAD만으로 실행 구현을 재현할 수 없다.
현재 문서가 설명하는 소스의 `go.mod` Rhiza dependency는 `v0.19.1-0.20261008214459-3895b723e194`이고
GoAuthy schema는 v112다. 이 버전 표시는 당시 측정 소스의 정확한 식별이나
release/production 배포 또는 runtime qualification의 증거가 아니다.
기존 Compos 연동 결과는 해당 시험 시점의 로컬 worktree 기반이며 release/production 증거가 아니다.
세부 성공·거절·SKIP은 [소비자 연동 기록](consumer-integrations.md)에 분리해 기록한다.
