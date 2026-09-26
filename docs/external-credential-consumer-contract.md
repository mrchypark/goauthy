# 외부 인증 연결: 소비자 계약과 현재 구현

2026-09-07, 현재 dirty worktree 기준. 표준 OAuth2/OIDC 로그인과 선택적 외부 인증
관리 확장은 별개다. 사용자별 여러 외부 계정의 등록·관리·선택·사용동의는 GoAuthy가
소유한다. 같은 provider에 여러 connection/profile을 둘 수 있으며 AI/SaaS로 모델을 나누지 않는다.
Beesuh/Conductor는 실행 의미와 선택된 인증 context의 격리를 소유한다.

## 현재 공개 경로

| 기능 | 실제 경로 | 인증·범위 |
| --- | --- | --- |
| 공급자 목록·등록 | `GET/POST /auth/v1/saas/providers` | full-admin browser 또는 전용 scope/audience 관리자 Bearer. browser POST는 CSRF; DB OAuth2/API-key 제공자 등록. GET은 파일 제공자와 DB metadata 통합 |
| 공급자 상세·수정·삭제 | `GET/PUT/DELETE /auth/v1/saas/providers/{provider_id}` | full-admin browser 또는 관리자 Bearer; 변경은 `If-Match`, browser는 CSRF도 필요. 파일 제공자는 read-only, 참조 중 변경/삭제는 409 |
| 컬렉션 정의 CRUD | `/auth/v1/auth-collections[/{collection_id}]` | 관리자 API. 필드/인증 방식/provider 허용 목록 정의 |
| 내 컬렉션 목록 | `GET /auth/v1/account/auth-collections` | GoAuthy owner browser session |
| 내 연결 metadata CRUD | `/auth/v1/account/connections/{collection_id}[/{connection_id}]` | owner browser; mutation CSRF; owner를 body에서 받지 않음 |
| API Key 보관·교체·로컬 폐기 | `/auth/v1/account/connections/{collection_id}/{connection_id}/api-key` | owner browser + CSRF. GET 상태, PUT `api_key`+`version`, DELETE 현재 `version` |
| Bearer metadata CRUD | `/auth/v1/connection-collections`, `/auth/v1/connections/{collection_id}[/{connection_id}]` | human access token, `goauthy.connections.read/write`; cookie 혼합 거절. credential 사용 권한 아님 |
| 사용자 OAuth 연결 시작 | `POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2` | owner browser + CSRF, body `{"provider_id":"..."}` → `authorization_url` |
| 사용자 OAuth 연결 callback | `GET /auth/v1/saas/callback/{provider_id}` | 시작한 owner/session과 일회성 state/code, 검증·저장 후 `connected`, `account_id`, `scopes`; 비밀 반환 없음 |
| OAuth 연결 상태 | `GET /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2` | owner browser, 현재 credential 상태/version/provider/account/scopes metadata만 반환 |
| OAuth 연결 로컬 해제 | `DELETE /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2` | owner browser + CSRF, body `{"version":1}`, 성공 204. 공급자 측 토큰 폐기와 다름 |
| OAuth 재연결 준비 | `POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/reconnect` | owner browser + CSRF, body 현재 `version`, 해제된 연결만 허용. 성공 200 상태 응답 후 OAuth 시작 API를 별도로 호출 |

Provider 목록의 비밀 없는 예시:

```json
[{"id":"example","kind":"oauth2","callback_uri":"https://id.example.test/saas/example/callback","scopes":["read"]}]
```

이는 응답 형태의 예시이며 example provider가 등록되어 있다는 뜻이 아니다.
API Key GET은 `registered`, `version`만 반환하며 원문 조회는 없다. 암호화는 기존
AES-GCM envelope/keyring·문맥 바인딩을 재사용한다. 로컬 폐기는 공급자 측 키 폐기와 다르다.
GoAuthy browser cookie를 Backoffice가 복사하거나 대신 보관하는 통합은 하지 않는다.

### 제공자 등록 계약 (schema v72)

OAuth2 POST의 필수 필드는 `id`, `name`, `kind: "oauth2"`, `enabled`, `client_id`,
`client_secret`, `callback_uri`, `auth_endpoint`, `token_endpoint`, `scopes`,
`auth_style`(`header` 또는 `params`)다. 기존 OAuth2 adapter의 HTTPS/PKCE/endpoint
검증을 재사용한다. 등록은 네트워크 요청이나 실제 공급자 인증을 실행하지 않는다.
선택 설정 `identity_endpoint`(HTTPS 계정 조회 URL)와 `subject_field`(최상위 계정 ID
필드명)는 함께 설정한다. 기존 제공자는 둘 다 생략할 수 있고, PUT에서 둘 다 생략하면
이 설정은 제거된다. API-key 제공자에는 허용하지 않는다. 조회 adapter는 access token을
Bearer로 사용하고 문자열 또는 정확한 int64 ID만 받는다. 이메일 자동 병합은 하지 않는다.
일반 OAuth2 계정 조회이며 OIDC ID-token 검증기는 아니다.
`client_secret`은 쓰기 전용 AES-GCM envelope이며 metadata 응답에는 포함되지 않는다.
PUT은 `id`를 body에 넣지 않고 나머지 설정을 교체하며, `client_secret` 생략은 유지다.
생성과 수정의 ETag는 각각 `"1"`, 증가한 revision이다. 변경에 `If-Match`가 없으면 428,
오래된 revision이면 409다. 삭제는 tombstone이며 같은 ID를 재사용하지 않는다.

API-key 제공자는 `id`, `name`, `kind: "api_key"`, `enabled`, `connector`를 받는다.
connector는 동일한 `id`, `header`(`X-API-Key` 또는 `Authorization`), `prefix`,
`operations` 배열이다. 각 operation은 `id`, HTTPS `url`, `response_fields`
(필드명 → `string|integer|boolean`)다. 기존 고정 GET+결과 필드 선택 엔진의 설정이며
일반 SaaS SDK/임의 메서드 지원 완료가 아니다. OAuth 전용 필드는 거절하고 사용자
API Key 자체는 이 관리자 등록 body에 넣지 않는다. 삭제되지 않은 제공자는 최대 32개다.

`Authorization` prefix는 정확히 빈 문자열(원문 키), `Bearer ` 또는 `Token `을
허용하며 `X-API-Key`는 빈 문자열만 허용한다. Prefix는 digest의 일부이므로
기존 동의의 인증 방식을 자동 변경하지 않는다. GoAuthy 자체 호출의 human Bearer
검사와 이 외부 제공자 API-key 주입 규칙은 별개다.

이 API는 **GoAuthy full-admin browser session** 또는 **관리자 OIDC access token**을
받는다. Bearer 요청에는 Cookie를 넣지 않는다. GET은 `goauthy.providers.read`,
POST/PUT/DELETE는 `goauthy.providers.write`가 필요하고 현재 DB의 full
`rauthy_admin` 역할도 확인한다. 토큰/역할은 저장 시점에도 다시 검사한다.
`GOAUTHY_PROVIDERS_RESOURCE`가 비어 있으면 Bearer 관리는 거절한다. 설정된 값은
`GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES`에 있어야 하며, 해당 resource가 토큰의
granted audience에 정확히 포함돼야 한다(client ID audience만으로는 부족하다).

Backoffice BFF 준비: 관리 permission scope 두 개를 GoAuthy의 custom scope catalog와
클라이언트 allowed scopes에 등록한다. DCR을 쓴다면 운영 DCR allowed scopes에도
포함하고 RP 등록 body의 `audience`에 관리 resource를 넣는다. 로그인 code+PKCE
authorize 요청에 `resource`와 필요한 `scope`를 보내고, 받은 **access token**을
서버 측 API 호출에 사용한다(ID token/GoAuthy cookie/공급자 client_secret 사용 금지).
실제 Backoffice 앱의 연결 검증은 별도이며, GoAuthy standalone HTTP E2E는 통과했다.

### 서로 다른 두 종류의 비밀

관리자가 등록한 제공자 `client_secret`은 GoAuthy가 OAuth 공급자에게 앱을 인증하는
비밀이다. 실행 서비스에 내보내지 않는다. Beesuh·Conductor의 실행에는 사용자가
연결한 계정의 access token 또는 등록한 API Key가 필요하다. OAuth refresh token은
GoAuthy가 보관·갱신한다. 이 사용 경로에는 별도 사용자/consumer 사용동의가 필요하며,
제공자 CRUD의 관리자 Bearer 권한이 사용자 credential 사용권을 대신하지 않는다.

### 사용자 OAuth 연결 runtime (schema v74)

관리자 제공자의 `callback_uri`는 정확히 GoAuthy issuer +
`/auth/v1/saas/callback/{provider_id}`여야 한다. 연결마다 다른 callback URI를
공급자에 등록할 필요는 없다. 시작 요청의 connection은 현재 사용자가 소유하고,
활성 OAuth2 컬렉션에서 해당 provider를 허용해야 한다. 계정 식별 설정 쌍도 필수다.
시작 응답의 URL로 브라우저를 이동한다. callback은 외부 사이트에서 오는 GET을
허용하지만 동일한 현재 사용자/session을 요구하며 Bearer/cookie 혼합은 거절한다.
Backoffice가 GoAuthy cookie를 복사하는 BFF 방식은 지원하지 않는다.

PKCE verifier는 독립된 SaaS 상태 row의 envelope에 보관한다. owner/collection/
connection/provider/generation/session/정책 digest/만료를 암호문에 함께 묶으며,
로그인용 upstream OAuth 상태와 공유하지 않는다. callback은 먼저 일회성 상태를
소비하고, 토큰 교환 → 허용 scope 확인 → 계정 조회 → 현재 권한을 다시 검사한
암호화 저장을 수행한다. 실패/불확실한 교환은 같은 state로 재시도하지 않는다.
반환 scope가 요청보다 넓으면 거절하고, 좁으면 실제 값을 저장한다.

저장 성공 후 단일 `Sec-Fetch-Mode: navigate`와 단일
`Sec-Fetch-Dest: document` 헤더가 있는 브라우저 탐색에는 완료 HTML을 반환한다.
그 외 API 요청은 기존 JSON 응답을 유지한다. 완료 화면은 고정된 계정 페이지로만
돌아가며 code/state/자격증명을 표시하지 않는다. 연결 저장은 실행 서비스에 대한
사용 동의를 대신하지 않는다.

현재 증거는 real Rhiza + TLS 공급자 경계 테스트와 격리된 합성 제공자를 사용한
실제 Chromium 시작/리다이렉트/완료/동의/갱신/해제, 두 차례 standalone 재시작
중 동일 연결 유지다. 외부 SaaS 자체 로그인 UI와 OAuth/Backoffice handoff,
실제 downstream OAuth adapter는 남았다. 컬렉션 metadata의 `draft` 상태를
OAuth 연결 상태로 해석하지 않는다.

OAuth 상태 응답은 `connected`, `state`, `version`, `provider_id`, `account_id`,
`scopes`다. credential이 없으면 `draft`, version 0이다. 그 외 `ready`, `refreshing`,
`uncertain`, `revoked`, `reconnecting`을 반환한다. `connected`는 저장 상태가 ready라는 뜻이며
access token의 현재 유효성이나 외부 서비스 가용성을 보증하지 않는다.
`refreshing`을 무한 대기하지 않는다. 동일 grant/version을 처음 관찰한 시점부터
최대 1분 동안 5초보다 자주 조회하지 않고, 계속 같은 상태면 owner 해제·재연결로
안내한다. 이 시간은 claim 만료나 자동 재시도 허가가 아니다. 비밀을 제외한 관찰
기록과 충돌 처리 절차는 [중단된 갱신 복구](connection-use-grants.md#interrupted-refresh-recovery)를 따른다.
비활성 컬렉션/provider도 owner가 확인·해제할 수 있다. 사용자 자체가 비활성화되거나
현재 session이 무효하면 접근할 수 없다. scopes는 비어 있어도 배열이며 비밀은 없다.

해제 body의 version은 GET 응답에서 받은 credential version이다(컬렉션 metadata
revision이나 ETag가 아님). `If-Match`와 혼용하지 않는다. stale version/이미 해제/
credential이 없는 연결은 409, version 0·잘못된 body는 400이다. 해제는 ciphertext를
삭제하지 않고 로컬 사용을 차단한다. 늦은 refresh 완료의 재활성화를 거절하고,
해제 이후 아직 소비하지 않은 pending callback의 상태 소비도 거절한다.
이미 전송된 외부 요청을 취소하거나 공급자 권한을 폐기하는 것은 아니다.

재연결은 **해제 → 재연결 준비 → OAuth 시작 → callback** 순서다. 준비 요청의
version은 현재 credential version이며 `If-Match`와 혼용하지 않는다. 준비는 연결
ID/metadata를 유지하면서 generation과 metadata revision만 변경한다. 기존 암호문은
revoked 상태로 보존하며 상태 응답은 `reconnecting`, 이전 version, 빈 account/scopes다.
새 callback 성공 시 기존 credential을 원자적으로 교체하고 version을 1 증가시킨다.
버전을 1로 초기화하지 않으므로 오래된 화면의 해제 요청은 새 연결을 해제할 수 없다.
ready/refreshing/uncertain은 먼저 해제해야 하고, 준비 중복·stale version은 409다.
준비 응답이 유실되면 GET 상태를 확인한다. 준비를 반복하지 않고 새 OAuth 시작을
시도할 수 있다. 기존 generation의 callback/refresh는 새 연결에 적용되지 않는다.
준비 API는 외부 요청을 보내지 않으며 공급자 측 원격 폐기를 수행하지 않는다.

## 아직 없는 공개 API / 검증

- 사용자 SaaS OAuth 전체 브라우저 E2E, UI handoff 및 공급자 측 원격 폐기.
- OAuth consumer handoff와 실제 서비스 adapter 통합.
  Owner 동의 생성·조회·취소, API-key proxy 승인 화면·delivery handoff,
  version/generation으로 보호된 등록 API-key invoke와 API-key/OAuth 전달 API는
  구현되었다([현재 계약](connection-use-grants.md)). OAuth owner 승인 화면도
  계정·scope 확인 및 reviewed `credential_version` 전제조건으로 연결됐고,
  실제 Chromium 승인/소비자 전달은 standalone 재시작 전후 검증했다.
- 소비자 SDK용 OAuth 인증 주입 transport와 자동 refresh 연계.
  Access-token-only 전달 공개 API와 synthetic consumer E2E는 완료했지만,
  Beesuh/Conductor OAuth adapter가 구현되었다는 뜻은 아니다.
- Codex 실제 계정 토큰 취득/이관/갱신·실제 provider 실행 검증.

Bearer metadata 경로는 `GOAUTHY_CONNECTIONS_RESOURCE`의 정확한 granted audience와
scope를 함께 검사하며, 동일 audience 조건을 DB 변경 시점에도 검사한다. 해당 설정이
없으면 Bearer 접근은 거절한다(기존 owner browser 경로와 별개). 설정값은
`GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES`에 등록된 리소스여야 한다.
목록/metadata CRUD 성공은 외부 credential 사용을 허가하지 않는다.
managed Device Flow도 최초 `/oidc/device` 요청에 등록된 `resource`를 보내 audience를
발급받을 수 있다. 토큰 교환/refresh 요청에는 resource를 다시 보내지 않는다.
기존 `TestConnectionResourcesPilot`은 새 계약에 맞춘 재검증 전까지 과거 PASS를
현재 후보의 증거로 사용하지 않는다. 신규 Device resource 검증 범위는 status.md에 기록한다.

## 필요한 최소 공통 계약 (미구현 요구사항)

사용자 확인: 아래 기능은 소비자가 별도로 만들어야 할 기능이 아니라 **GoAuthy가
공개 API로 먼저 구현할 제품 범위**다. 컬렉션 CRUD만으로 완료 처리하지 않는다.
Backoffice는 검증된 API가 제공된 이후 연결하며, Backoffice pilot 준비는 이 구현의
선행조건이 아니다. 실제 SaaS 업무 API와 agent 실행은 소비자 서비스에 남긴다.

1. 관리자 provider 정의: `provider_id`, 인증 방식, 서버가 검증한 목적지/주입 규칙,
   OAuth grant·client authentication·refresh/revoke·upstream identity capability.
2. 사용자 profile: `profile_id`, `provider_id`, 검증된 upstream account identity,
   상태, 논리 authorization generation. 비밀 값은 일반 목록에 포함하지 않는다.
3. 사용동의: owner + consumer client + profile + purpose + destination/operation.
   같은 profile의 두 consumer 사용은 명시적으로 허용할 때만 가능하다.
4. 사용할 때 현재 owner/consumer/grant/generation/revoke를 재검증한다. OAuth refresh는
   논리 승인 세대 변경이 아니며, CAS/refresh claim/tombstone으로 경쟁과 재활성화를 막는다.

HTTP SDK를 위한 proxy와 제한된 credential 전달을 함께 제공한다. 기존
fixed GET+scalar projection engine은 일반 SDK/CLI 사용 계약이 아니다.
Beesuh의 실험적 Codex `initial`/`unauthorized` callback은 기대 account identity와
선택 profile에 묶인 adapter seam이다. GoAuthy refresh 처리·저장이 완료된 후의 access
token 전달이 필요하다는 요구이며, 위 API가 이미 제공된다는 뜻은 아니다.

구현 증거와 패키지 선택은 [auth-collections.md](auth-collections.md),
표준 로그인 계약은 [idp-consumer-contract.md](idp-consumer-contract.md)를 참조한다.
새 endpoint 이름이나 비밀 전달 방식을 소비자에서 추측 구현하지 않는다.

### 사용 요청의 소비자 인증 기반

`oauth.Server.AuthorizeConnectionUse`는 기존 human bearer 검증을 재사용하고,
검증된 토큰의 subject와 client ID를 함께 반환한다. `goauthy.connections.use`와
명시된 정확한 resource audience가 모두 필요하다. 요청 body/query의 owner/client ID는
인증 신원이 될 수 없다. Cookie 혼합, 기계 client-credentials, token-exchange/act,
DPoP 토큰은 이 human bearer 경로에서 거절한다. 반환되는 SQL authority는 토큰 만료/
폐기, 현재 사용자·세션·클라이언트 및 그룹 정책을 DB 사용 시 다시 확인한다.

이 helper는 **사용 동의가 있다는 증거가 아니다**. 현재 등록 API-key invoke route는
검증된 client ID와 owner, 선택 연결의 generation, 등록된 목적지/operation과
현재 grant revision을 함께 검사한다. 이 scope만으로 외부 비밀을 받을 수 없으며,
등록 API-key 전달 API는 별도 `credential_delivery` 동의를 요구한다.
OAuth access-token 전달은 동일 endpoint의 별도 `kind=oauth2` 응답으로 연결됐다.
기존 동의/현재 confidential consumer 검사와 알려진 미래 만료가 필요하며, 조회는
refresh나 외부 요청을 실행하지 않는다. Synthetic confidential 소비자의 실제 사용자
code+PKCE 인증, 동의, v1/v2 토큰 전달·제공자 사용, 다른 소비자/철회 후 차단은
격리 Dory의 공개 API E2E로 통과했다. Beesuh/Conductor OAuth adapter 통합은 별도다.
OAuth refresh의 token version 증가는 동의를 취소하지 않지만 재연결 generation 변경은
이전 동의를 무효화해야 한다. 일반 SDK용 제한된 전달 요구는 여전히 범위에 포함되며,
고정 GET proxy만 구현하고 전체 요구를 완료 처리하지 않는다.

Owner의 명시적 갱신은 이제 session+CSRF로
`POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh`
에 현재 `version`을 보내는 경로로 연결됐다. 등록 제공자 refresh 한 번과 새 토큰의
계정 조회 후 동일 계정·scope 비확대·현재 권한을 확인해 저장한다. 실패가 불확실하면
재시도하지 않고 상태 조회 후 해제/재연결한다. 응답은 metadata이며 이 endpoint는
실행 서비스의 Bearer 호출용이나 background 갱신이 아니다. 로컬 TLS 엔진과 실제
HTTPS 거절 경계에 이어 성공 OAuth public HTTP 연결·갱신·전달도 검증했다.
실제 Chromium owner 승인 UI도 검증했으며 downstream adapter E2E는 아직 남았다.

관리자 생성 클라이언트는 이제 `audience` 배열을 등록할 수 있고 code+PKCE 및 refresh
경로에서 이를 사용한다. POST 생략은 빈 허용 목록, PUT 생략은 유지, 명시적 `[]`는
제거다. audience 변경은 client generation을 변경하여 이전 토큰·진행 중 grant를
무효화한다. 실제 HTTPS 관리자 Bearer 호출과 제거 후 거절이 검증됐다.
Device에서도 초기 resource를 저장·발급·갱신한다. Owner 동의 저장 API와 등록 API-key의
고정 GET operation 호출 API는 연결됐다. [현재 계약](connection-use-grants.md)을 따른다.
등록 API-key proxy의 native owner 승인 화면과 일회성 HTML handoff는 추가됐다.
등록 API-key delivery handoff도 별도 원문 전달 경고·승인으로 연결됐다.
OAuth 승인 생성 화면은 provider/account/scopes 확인 후 access-token 전달 동의를
생성한다. 화면의 `credential_version`과 현재 버전이 다르면 409로 거절하여 다시
확인하게 한다. 공개 HTTP 및 Chromium 승인 E2E는 검증됐지만 OAuth 대리 호출,
handoff, 소비자 SDK 통합/자동 갱신은 아직 남았다.
API-key 전달 및 이미 전달한 키의 회수 불가능성은 위 현재 계약을 따른다.
audience 발급만으로 외부 credential 사용을 허가하지 않는다.

실제 Beesuh Runtime API-key bridge는 다음 프로필로 재현한다(절대 checkout 경로 필요):

```sh
GOAUTHY_E2E_TLS=1 GOAUTHY_E2E_USE_GRANTS=1 GOAUTHY_E2E_CREDENTIAL_DELIVERY=1 \
GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR='<consumer-repo>/beesuh' \
GOAUTHY_STANDALONE_OPEN_REG_PORT=18190 sh scripts/e2e-open-registration-standalone.sh
```

실제 issuer에서 같은 owner의 두 연결에 별도 키/동의를 생성하고, 인증서 검증
로컬 모델에 각 키가 정확히 주입되는지 확인한다. 한 동의 철회 후 해당 profile의
추가 모델 호출은 0이며 다른 profile은 계속 성공해야 한다. 토큰은 0600 임시
파일로만 자식에게 전달하며, 키나 자식 출력은 부모 로그에 기록하지 않는다.
이 프로필은 standalone 재시작 전후 통과했다. Beesuh 공개 로그인/인증은 fixture
callback으로 대체하므로 제품 전체 인증 E2E나 외부 SaaS 검증을 뜻하지 않는다.

Backoffice의 별도 `goauthy.connections.read` 토큰은 이제
`GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}`로
owner의 저장된 동의와 현재 연결 generation을 조회할 수 있다. 실행 consumer와
조회 client가 달라도 되지만 owner와 정확한 resource는 일치해야 한다.
응답은 `{grant, connection_generation}`이며 취소/만료된 동의도 포함한다.
실행 권한이나 SDK readiness가 아니고 비밀도 반환하지 않는다. 실제 HTTPS에서
별도 read-only client와 실행 client의 권한 분리를 검증했다. 일회성 승인 handoff는
구현됐으며 Backoffice 실제 앱 통합은 여전히 남아 있다.
